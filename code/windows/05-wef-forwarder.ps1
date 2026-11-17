#Requires -Version 5.1
<#
.SYNOPSIS
    05 - Configure a lab workstation as a Windows Event Forwarding source.

.DESCRIPTION
    Thesis context (Chapter 2, additional control 4 and "monitoring and logging
    systems"): every workstation must push its authentication, authorization and
    access events to DC01 so that logging completeness can be evaluated from one
    place.

    Run this script on each of Student1, Student2 and Instructor1 (or push it with
    Invoke-Command from DC01). It is idempotent: re-running only rewrites the
    SubscriptionManager values if they differ.

    Steps:
      1. Verify the host is domain joined (device validation also depends on it).
      2. Enable and start WinRM (the WEF transport) + firewall rules.
      3. Point the SubscriptionManager at http://DC01.internal.lab:5985/wsman/...
      4. Emit a marked test event and confirm it arrives in ForwardedEvents.

.PARAMETER CollectorFqdn
    FQDN of the collector (DC01.internal.lab).

.EXAMPLE
    PS> .\05-wef-forwarder.ps1 -CollectorFqdn DC01.internal.lab

.EXAMPLE
    # From DC01, configure all three workstations at once
    PS> Invoke-Command -ComputerName Student1,Student2,Instructor1 -FilePath .\05-wef-forwarder.ps1 -ArgumentList 'DC01.internal.lab'

.NOTES
    Run elevated on the workstation. Logs: C:\ZTNA\logs\05-wef-forwarder_*.log
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$CollectorFqdn = 'DC01.internal.lab',
    [int]$CollectorPort = 5985,

    [int]$RefreshSeconds = 60,
    [int]$TimeoutSeconds = 180,
    [string]$TestSource = 'ZTNA-WEF-Test',
    [int]$TestEventId = 9000,

    [switch]$SkipTest,
    [switch]$UseTrustedHosts
)

$ErrorActionPreference = 'Stop'

$script:LogRoot = 'C:\ZTNA\logs'
if (-not (Test-Path -LiteralPath $script:LogRoot)) { New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null }
$script:ScriptTag = '05-wef-forwarder'
try { Start-Transcript -Path (Join-Path $script:LogRoot ('{0}_{1}_{2}.log' -f $script:ScriptTag, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))) -Append | Out-Null } catch { }

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
# Helpers
# ---------------------------------------------------------------------------
function Test-DomainJoined {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    return [pscustomobject]@{
        PartOfDomain = [bool]$cs.PartOfDomain
        Domain       = $cs.Domain
        Name         = $cs.Name
    }
}

function Initialize-WinRm {
    Write-Step 'Configuring WinRM (WEF transport)'
    $svc = Get-Service -Name WinRM -ErrorAction Stop
    if ($svc.StartupType -ne 'Automatic') {
        Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
        Write-Step 'WinRM startup type set to Automatic' OK
    }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name WinRM -ErrorAction Stop
        Write-Step 'WinRM service started' OK
    } else {
        Write-Step 'WinRM service already running' OK
    }

    # Enable-PSRemoting creates the listener and the WinRM firewall group.
    try {
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop | Out-Null
        Write-Step 'PS remoting listener ensured' OK
    } catch {
        Write-Step ("Enable-PSRemoting warning: {0}" -f $_.Exception.Message) WARN
    }

    $rules = Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Enable-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Step 'WinRM firewall group enabled' OK
    }

    # The forwarder runs inside WinRM as NETWORK SERVICE, which cannot read the
    # Security log by default: without this, Security events (4624/4625/4740)
    # are silently never forwarded. Group membership is the persistent fix but
    # only applies after WinRM restarts, so a read ACE (S-1-5-20) is also added
    # to the Security channel, which takes effect immediately.
    try {
        Add-LocalGroupMember -SID 'S-1-5-32-573' -Member 'S-1-5-20' -ErrorAction Stop
        Write-Step 'NETWORK SERVICE added to Event Log Readers' OK
    } catch {
        Write-Step 'NETWORK SERVICE already in Event Log Readers' OK
    }
    $sddl = ((& wevtutil.exe gl Security) | Select-String '^channelAccess:').ToString().Split(':', 2)[1].Trim()
    if ($sddl -notmatch '\(A;;0x1;;;S-1-5-20\)|\(A;;0x1;;;NS\)') {
        & wevtutil.exe sl Security "/ca:$sddl(A;;0x1;;;S-1-5-20)"
        Write-Step 'Security channel: read access granted to NETWORK SERVICE' OK
    } else {
        Write-Step 'Security channel already readable by NETWORK SERVICE' OK
    }

    # Larger envelopes keep 100-event batches from being fragmented.
    try { & winrm.exe set winrm/config '@{MaxEnvelopeSizekb="2048"}' 2>&1 | Out-Null } catch { }

    if ($UseTrustedHosts) {
        # Only needed if Kerberos/Negotiate cannot be used (e.g. workgroup
        # collector). Domain-joined lab hosts should not need this.
        $current = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        if ($current -notlike "*$CollectorFqdn*") {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $CollectorFqdn -Concatenate -Force -ErrorAction Stop
            Write-Step "TrustedHosts updated with $CollectorFqdn" WARN
        }
    }
}

function Set-SubscriptionManager {
    param([string]$Collector, [int]$Port, [int]$Refresh)

    $keyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    if (-not (Test-Path -LiteralPath $keyPath)) {
        if (-not $PSCmdlet.ShouldProcess($keyPath, 'Create SubscriptionManager key')) { return }
        New-Item -Path $keyPath -Force | Out-Null
    }

    $target = 'Server=http://{0}:{1}/wsman/SubscriptionManager/WEC,Refresh={2}' -f $Collector, $Port, $Refresh
    $properties = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    $valueNames = @($properties.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name)

    $alreadySet = $false
    if ($valueNames -contains '1') {
        $current = [string]$properties.'1'
        if ($current -eq $target) { $alreadySet = $true }
    }

    if ($alreadySet) {
        Write-Step "SubscriptionManager already points to $target" OK
    } else {
        # Remove stale entries (e.g. an old collector address) then write index 1.
        foreach ($name in $valueNames) {
            if ($name -match '^\d+$') {
                Remove-ItemProperty -Path $keyPath -Name $name -Force -ErrorAction SilentlyContinue
            }
        }
        New-ItemProperty -Path $keyPath -Name '1' -Value $target -PropertyType String -Force -ErrorAction Stop | Out-Null
        Write-Step "SubscriptionManager -> $target" OK
    }

    # Read back for the transcript/verification.
    Get-ItemProperty -Path $keyPath | Select-Object -Property * -ExcludeProperty PS* | Format-List | Out-String | Write-Host
}

function Send-TestEvent {
    param([string]$Source, [int]$EventId)
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
        try {
            New-EventLog -LogName Application -Source $Source -ErrorAction Stop
            Write-Step "Event source $Source registered" OK
        } catch {
            Write-Step ("Could not register event source {0}: {1}" -f $Source, $_.Exception.Message) WARN
            return $null
        }
    }
    $message = 'ZTNA-WEF-TEST host={0} utc={1} marker={2}' -f $env:COMPUTERNAME, (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), [guid]::NewGuid()
    # Error level is deliberately used: the subscription forwards Level<=3, so an
    # error-level probe is guaranteed to match the collector query.
    Write-EventLog -LogName Application -Source $Source -EventId $EventId -EntryType Error -Message $message -ErrorAction Stop
    Write-Step "Test event written to Application log (source=$Source id=$EventId)" OK
    return $message
}

function Wait-ForwardedTestEvent {
    param([string]$Collector, [string]$Source, [string]$Marker, [int]$TimeoutSec)

    Write-Step ("Waiting up to {0}s for the test event on {1}:ForwardedEvents" -f $TimeoutSec, $Collector)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $events = Get-WinEvent -ComputerName $Collector -LogName ForwardedEvents -MaxEvents 200 -ErrorAction Stop
            $match = $events | Where-Object { $_.ProviderName -eq $Source -and $_.Message -like "*$Marker*" } | Select-Object -First 1
            if ($match) {
                Write-Step ("Test event delivered at {0} (record {1})" -f $match.TimeCreated, $match.RecordId) OK
                return $true
            }
        } catch {
            Write-Step ("Collector query failed: {0}" -f $_.Exception.Message) WARN
        }
        Start-Sleep -Seconds 10
    }
    Write-Step 'Test event not observed within the timeout. Check the subscription and WinRM connectivity.' WARN
    return $false
}

# ===========================================================================
# Main
# ===========================================================================
$exitCode = 0
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script elevated on the workstation.'
    }

    $hostInfo = Test-DomainJoined
    Write-Step ("Host {0} domain-joined={1} domain={2}" -f $hostInfo.Name, $hostInfo.PartOfDomain, $hostInfo.Domain)
    if (-not $hostInfo.PartOfDomain) {
        throw 'This workstation is not domain joined. Device validation requires domain membership - join the domain before configuring WEF.'
    }

    Initialize-WinRm
    Set-SubscriptionManager -Collector $CollectorFqdn -Port $CollectorPort -Refresh $RefreshSeconds

    # Connectivity to the collector (WS-Man handshake).
    try {
        $wsman = Test-WSMan -ComputerName $CollectorFqdn -ErrorAction Stop
        Write-Step ("WS-Man reachable: {0} {1}" -f $wsman.ProductVendor, $wsman.ProductVersion) OK
    } catch {
        Write-Step ("Test-WSMan failed ({0}). WEF delivery cannot work until this is fixed." -f $_.Exception.Message) ERROR
        $exitCode = 2
    }

    # Force a policy refresh so the SubscriptionManager value is picked up even
    # if the Event Forwarding service cached the previous configuration.
    & gpupdate.exe /target:computer 2>&1 | Out-Null
    # The forwarder lives inside the WinRM service. A value written straight
    # under Policies\ raises no policy-change notification, and the Event Log
    # Readers membership only applies to a new service token, so WinRM must be
    # restarted. It runs from a one-shot SYSTEM task (a child process of a
    # WinRM shell would be killed with the shell) and is delayed so a run of
    # this script over WinRM can finish first.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument '-NoProfile -Command "Start-Sleep -Seconds 15; Restart-Service -Name WinRM -Force"'
    Register-ScheduledTask -TaskName 'ZTNA-WinRM-Restart' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName 'ZTNA-WinRM-Restart'
    Write-Step 'WinRM restart scheduled in 15s (forwarder reloads SubscriptionManager)' OK

    if (-not $SkipTest -and $exitCode -eq 0) {
        $marker = Send-TestEvent -Source $TestSource -EventId $TestEventId
        if ($marker) {
            $delivered = Wait-ForwardedTestEvent -Collector $CollectorFqdn -Source $TestSource -Marker $marker -TimeoutSec $TimeoutSeconds
            if (-not $delivered) { $exitCode = 3 }
        }
    }

    # Local state summary (source side of the logging-completeness indicator).
    $sec = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    $count4624 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-1) } -ErrorAction SilentlyContinue).Count
    $count4625 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-1) } -ErrorAction SilentlyContinue).Count
    [pscustomobject]@{
        Host                 = $env:COMPUTERNAME
        SecurityLogEnabled   = [bool]($sec -and $sec.IsEnabled)
        LogonsLastHour       = $count4624
        FailedLogonsLastHour = $count4625
        SubscriptionManager  = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue).'1'
    } | Format-List

    if ($exitCode -eq 0) {
        Write-Step 'STAGE COMPLETE. Next: 06-policy-decision.ps1 (PDP) or 07-verify-baseline.ps1' OK
    }
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
