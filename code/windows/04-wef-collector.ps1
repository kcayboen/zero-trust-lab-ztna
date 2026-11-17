#Requires -Version 5.1
<#
.SYNOPSIS
    04 - Configure DC01 as the Windows Event Forwarding (WEF) collector.

.DESCRIPTION
    Thesis context (Chapter 2, additional control 4): "Windows Event Forwarding
    will collect workstation security events at the domain controller ... so that
    authentication, authorization, and enforcement events are available in one
    location for analysis."

    This script:
      * enables the Windows Event Collector service (wecutil qc)
      * opens the WinRM listener/firewall path the forwarders need
      * grants the collector service read access to the Security log
      * creates a *source-initiated* subscription ZTNA-Workstations covering
        Security, System and Application records from the lab workstations
      * enlarges the ForwardedEvents log and verifies the subscription

    The matching forwarder side is 05-wef-forwarder.ps1, which must run on each
    workstation after this script.

.EXAMPLE
    PS> .\04-wef-collector.ps1

.EXAMPLE
    PS> .\04-wef-collector.ps1 -Recreate -SubscriptionName ZTNA-Workstations

.NOTES
    Run elevated on DC01 after 03-gpo-logon-lockout.ps1.
    Logs: C:\ZTNA\logs\04-wef-collector_*.log
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SubscriptionName = 'ZTNA-Workstations',
    [string]$CollectorFqdn,

    # Workstations allowed to push. The DD/DC SIDs below already scope the
    # subscription to domain computers; this list documents the lab inventory.
    [string[]]$ExpectedForwarders = @('Student1', 'Student2', 'Instructor1'),

    [int]$MaxLogSizeBytes = 536870912,   # 512 MB
    [switch]$Recreate,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

$script:LogRoot = 'C:\ZTNA\logs'
if (-not (Test-Path -LiteralPath $script:LogRoot)) { New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null }
$script:ScriptTag = '04-wef-collector'
try { Start-Transcript -Path (Join-Path $script:LogRoot ('{0}_{1}.log' -f $script:ScriptTag, (Get-Date -Format 'yyyyMMdd_HHmmss'))) -Append | Out-Null } catch { }

function Write-Step {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Warning $line }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
}

# ---------------------------------------------------------------------------
# Subscription document (source-initiated: each workstation pushes to DC01)
# ---------------------------------------------------------------------------
function Get-SubscriptionXml {
    param([string]$Name)

    # Event IDs mapped to the manuscript indicators:
    #   4624/4625/4648/4740 -> authentication + unauthorized blocking + lockout
    #   4768/4769/4771/4776 -> Kerberos/NTLM credential validation (DC side)
    #   4688                -> process creation for privilege-escalation review
    #   4100/4101/4102      -> ZTNA PDP allow / deny / batch-summary events
    # The QueryList must be wrapped in <Query><![CDATA[...]]></Query>; without
    # the wrapper wecutil cs fails with 0x3AED "No active channel is found".
    # ContentFormat=Events (not RenderedText): with rendered message text the
    # Security batches were never delivered while System/Application were; the
    # collector has the same Security publisher, so it renders them itself.
    $xml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>$Name</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>D202 ZTNA - workstation Security/System/Application events to DC01</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>100</MaxItems>
      <MaxLatencyTime>5000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="60000"/>
    </PushSettings>
  </Delivery>
  <Query><![CDATA[
  <QueryList>
    <Query Id="0" Path="Security">
      <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4672 or EventID=4740 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776 or EventID=4688)]]</Select>
    </Query>
    <Query Id="1" Path="System">
      <Select Path="System">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
    </Query>
    <Query Id="2" Path="Application">
      <Select Path="Application">*[System[(Level=1 or Level=2 or (Provider[@Name='ZTNA-PDP']))]]</Select>
    </Query>
  </QueryList>
  ]]></Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>Events</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)(A;;GA;;;DD)</AllowedSourceDomainComputers>
</Subscription>
"@
    return $xml
}

# ---------------------------------------------------------------------------
# Collector prerequisites
# ---------------------------------------------------------------------------
function Initialize-Collector {
    Write-Step 'Enabling Windows Event Collector service (wecutil qc)'
    $qcOutput = & wecutil.exe qc /q 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Step ("wecutil qc returned {0}: {1}" -f $LASTEXITCODE, ($qcOutput -join ' ')) WARN
    } else {
        Write-Step 'Windows Event Collector is configured' OK
    }

    Set-Service -Name Wecsvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name Wecsvc -ErrorAction SilentlyContinue

    # The collector service reads the local Security log as Network Service.
    try {
        Add-LocalGroupMember -Group 'Event Log Readers' -Member 'NT AUTHORITY\NETWORK SERVICE' -ErrorAction Stop
        Write-Step 'NETWORK SERVICE added to Event Log Readers' OK
    } catch {
        # Already a member is the normal re-run path.
        $members = @()
        try { $members = (Get-LocalGroupMember -Group 'Event Log Readers' -ErrorAction Stop).Name } catch { }
        if ($members -match 'NETWORK SERVICE') {
            Write-Step 'NETWORK SERVICE already in Event Log Readers' OK
        } else {
            Write-Step ("Could not add NETWORK SERVICE to Event Log Readers: {0}" -f $_.Exception.Message) WARN
        }
    }

    # WinRM listener + firewall for incoming forwarder connections.
    try {
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Step ("Enable-PSRemoting warning: {0}" -f $_.Exception.Message) WARN
    }
    foreach ($group in @('Windows Remote Management', 'Windows Event Collector')) {
        $rules = Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue
        if ($rules) {
            $rules | Enable-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Step "Firewall group enabled: $group" OK
        }
    }
    # Explicit rule so the intent is visible even if the built-in group changes.
    if (-not (Get-NetFirewallRule -DisplayName 'ZTNA-WEF-Collector-In' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'ZTNA-WEF-Collector-In' `
            -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress '10.20.11.0/24', '10.20.20.0/24' `
            -Action Allow -Profile Domain -Description 'D202 ZTNA: WEF forwarders (student/instructor VLANs)' -ErrorAction Stop | Out-Null
        Write-Step 'Created firewall rule ZTNA-WEF-Collector-In' OK
    }

    # The ForwardedEvents log must be large enough for a 100-event trial batch.
    & wevtutil.exe sl ForwardedEvents /ms:$MaxLogSizeBytes 2>&1 | Out-Null
    Write-Step ("ForwardedEvents log size set to {0} bytes" -f $MaxLogSizeBytes) OK
}

# ---------------------------------------------------------------------------
# Subscription management
# ---------------------------------------------------------------------------
function Get-ExistingSubscriptions {
    $raw = & wecutil.exe es 2>&1
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($raw | Where-Object { $_ -and $_.Trim().Length -gt 0 })
}

function Install-CollectorSubscription {
    param([string]$Name)

    $existing = Get-ExistingSubscriptions
    if ($existing -contains $Name) {
        if (-not $Recreate) {
            Write-Step "Subscription $Name already exists (use -Recreate to rebuild)" OK
            return
        }
        Write-Step "Removing existing subscription $Name (-Recreate)"
        # 'ds' takes no /q switch (only 'qc' does); passing it fails with 0x57.
        & wecutil.exe ds $Name 2>&1 | Out-Null
    }

    $xmlDir = 'C:\ZTNA\config'
    if (-not (Test-Path -LiteralPath $xmlDir)) { New-Item -ItemType Directory -Path $xmlDir -Force | Out-Null }
    $xmlPath = Join-Path $xmlDir ('{0}.xml' -f $Name)
    # UTF-8 without BOM: wecutil parses the file as XML directly.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($xmlPath, (Get-SubscriptionXml -Name $Name), $utf8NoBom)
    Write-Step "Subscription manifest written: $xmlPath"

    if (-not $PSCmdlet.ShouldProcess($Name, 'Create WEF subscription')) { return }

    $output = & wecutil.exe cs $xmlPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("wecutil cs failed ({0}): {1}" -f $LASTEXITCODE, ($output -join ' '))
    }
    Write-Step "Source-initiated subscription $Name created" OK
}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
function Test-SubscriptionHealth {
    param([string]$Name)

    $results = @()
    $list = Get-ExistingSubscriptions
    $results += [pscustomobject]@{ Check = 'Subscription exists'; Result = ($list -contains $Name); Detail = ($list -join ', ') }

    $status = & wecutil.exe gr $Name 2>&1
    $runtimeLine = ($status | Select-String -Pattern 'Runtime status' -SimpleMatch | Select-Object -First 1)
    $isActive = ($runtimeLine -and $runtimeLine.Line -match 'Active')
    $results += [pscustomobject]@{ Check = 'Runtime status Active'; Result = [bool]$isActive; Detail = ($runtimeLine.Line -replace '\s+', ' ') }

    $log = Get-WinEvent -ListLog ForwardedEvents -ErrorAction SilentlyContinue
    $results += [pscustomobject]@{ Check = 'ForwardedEvents log enabled'; Result = [bool]($log -and $log.IsEnabled); Detail = ('MaxSize={0}' -f $log.MaximumSizeInBytes) }

    $results += [pscustomobject]@{ Check = 'Wecsvc running'; Result = ((Get-Service Wecsvc).Status -eq 'Running'); Detail = (Get-Service Wecsvc).Status }

    $results | Format-Table -AutoSize
    $failed = @($results | Where-Object { -not $_.Result })
    if ($failed.Count -gt 0) {
        Write-Step ("{0} WEF check(s) failed" -f $failed.Count) WARN
        return $false
    }
    Write-Step 'WEF collector checks passed' OK
    return $true
}

# ===========================================================================
# Main
# ===========================================================================
$exitCode = 0
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script elevated on DC01.'
    }

    if (-not $CollectorFqdn) {
        $CollectorFqdn = '{0}.{1}' -f $env:COMPUTERNAME.ToLower(), (Get-ADDomain).DNSRoot
    }
    Write-Step ("Collector: {0}" -f $CollectorFqdn) OK
    Write-Step ("Expected forwarders: {0}" -f ($ExpectedForwarders -join ', '))

    Initialize-Collector
    Install-CollectorSubscription -Name $SubscriptionName

    if (-not $SkipVerify) {
        $healthy = Test-SubscriptionHealth -Name $SubscriptionName
        if (-not $healthy) { $exitCode = 2 }
    }

    Write-Step 'Confirm delivery on the collector with:' INFO
    Write-Host '    Get-WinEvent -LogName ForwardedEvents -MaxEvents 20 | Group-Object ProviderName | Sort-Object Count -Descending'
    Write-Host '    wecutil gr ZTNA-Workstations'
    Write-Step 'STAGE COMPLETE. Next: run 05-wef-forwarder.ps1 on Student1, Student2, Instructor1' OK
}
catch {
    Write-Step ("FAILED: {0}" -f $_.Exception.Message) ERROR
    Write-Step ($_.ScriptStackTrace) ERROR
    $exitCode = 1
}
finally {
    try { Stop-Transcript | Out-Null } catch { }
}

exit $exitCode
