#Requires -Version 5.1
<#
.SYNOPSIS
    06 - ZTNA Policy Decision Point (PDP): evaluate (user, role, device,
         resource, port) and return Allow/Deny with a reason and timing.

.DESCRIPTION
    Thesis context (Chapter 2 / Statement of the Problem 3): the PDP is the
    component that performs "structured evaluation processes based on predefined
    institutional security policies" - identity authentication, role validation,
    device verification and contextual policy assessment. Table 2 requires:

        policy decision latency      <= 200 ms  (mean, 5 trials)
        RBAC enforcement accuracy    >= 99 %
        unauthorized auth blocking   >= 99 %
        logging completeness         = 100 %

    This script produces the authorization half of those measurements:
      * every decision is a JSON line + CSV row with UTC timestamps at ms
        resolution and an explicit machine-readable reason code
      * every decision also writes a Windows Application event (4100 Allow,
        4101 Deny) so the WEF/logging-completeness indicator can be measured
      * -Batch -Count 100 generates exactly one trial (SOP 3) and prints the
        mean / p95 decision latency plus RBAC accuracy against the matrix

    Device validation:
      * the device must exist as an AD computer object, be enabled, and be a
        member of GG-LabWorkstations (domain membership)
      * the MAC observed for the device is compared with the MAC registered on
        the object (serialNumber) or in the OPNsense reservation export
        C:\ZTNA\config\device-macs.csv
      * unregistered devices and MAC mismatches are denied

    The policy matrix D202-ZTNA-1.1 (least privilege, default deny; frozen in
    simulation/plan/policy-matrix.md). Target = Local when the resource is the
    device the user sits at, otherwise the resource's zone:
        Role        From zone      Target        Allowed ports
        Student     any permitted  Local         445,139
        Student     any permitted  Server        53,88,389 (auth only)
        Instructor  any permitted  Local         445,139,3389
        Instructor  any permitted  Server        53,88,389 (auth only)
        ZTNA-Admin  any permitted  Local         445,3389,5985
        ZTNA-Admin  StudentWS/InstructorWS  Server  53,88,389,445,5985
        ZTNA-Admin  Server         StudentWS/InstructorWS  5985
      Peer workstations and all other zone pairs are denied (lateral movement).
      Ports in the global deny list (21,23,25,69,111,1433,3306,5432) are never
      allowed. The PDP never allows what the PEP (OPNsense + host firewall) blocks.

    The matrix lives in Get-ZtnaPolicyMatrix. RBAC accuracy is NOT scored against
    it: trials use -CaseFile (plan/cases/*.csv), whose Expected values are derived
    independently from policy-matrix.md. Edit the matrix only with a documented
    policy change and a new -PolicyVersion.

.PARAMETER User
    sAMAccountName being authenticated (e.g. student01).

.PARAMETER Device
    Hostname of the device the request originates from (e.g. Student1).

.PARAMETER DeviceMac
    MAC observed for that device (DHCP lease / ARP). Optional: when omitted the
    registered MAC is used, which means the MAC check passes by definition.

.PARAMETER Resource
    Target hostname or IP (e.g. DC01, Student2, 10.20.30.10).

.PARAMETER Port
    Destination service port (445, 139, 3389, 5985, 53, 88, 389...).

.PARAMETER Batch
    Generate -Count decisions for one SOP 3 trial and print statistics.

.PARAMETER Scenario
    S1 successful authentication, S2 RBAC matrix, S3 unauthorized attempts,
    S4 additional controls (device validation), S5 lateral movement,
    S6 logging mix. Aliases: auth, rbac, unauthorized, device, lateral, logging.

.EXAMPLE
    PS> .\06-policy-decision.ps1 -User student01 -Device Student1 -Resource Student1 -Port 445

.EXAMPLE
    PS> .\06-policy-decision.ps1 -Batch -Count 100 -Scenario S2 -Trial T1

.EXAMPLE
    # over WinRM from the analyst workstation
    PS> Invoke-Command -ComputerName DC01 -FilePath .\06-policy-decision.ps1 `
            -ArgumentList '-Batch','-Count','100','-Scenario','S2','-Trial','T1'

.NOTES
    Requires a domain-joined Windows host (5.1+). No RSAT/AD module needed: AD is
    read through System.DirectoryServices. Logs:
        C:\ZTNA\logs\pdp-decisions.jsonl / .csv
        C:\ZTNA\results\raw\pdp-<scenario>-<trial>.csv
#>
[CmdletBinding()]
param(
    [string]$User,
    [string]$Device,
    [string]$DeviceMac,
    [string]$Resource,
    [int]$Port,

    [string]$Scenario = 'manual',
    [ValidateSet('', 'T1', 'T2', 'T3', 'T4', 'T5')]
    [string]$Trial = '',

    [switch]$Batch,
    [int]$Count = 100,
    # Fixed case file (CaseId,User,ExpectedRole,Device,Resource,Port,Expected[,DeviceMac]).
    # When given, -Batch runs exactly these cases, shuffled with seed = trial number,
    # after one discarded warm-up decision.
    [string]$CaseFile,

    [switch]$Offline,
    [switch]$NoEventLog,
    [switch]$NoFileLog,

    [string]$LogRoot = 'C:\ZTNA\logs',
    [string]$ResultRoot = 'C:\ZTNA\results',
    [string]$MacMapPath = 'C:\ZTNA\config\device-macs.csv',
    [string]$PolicyVersion = 'D202-ZTNA-1.1'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Logging plumbing
# ---------------------------------------------------------------------------
$script:JsonLog = Join-Path $LogRoot 'pdp-decisions.jsonl'
$script:CsvLog = Join-Path $LogRoot 'pdp-decisions.csv'
$script:EventSource = 'ZTNA-PDP'
$script:EventSourceReady = $false
$script:PolicyVersion = $PolicyVersion

foreach ($dir in @($LogRoot, (Join-Path $ResultRoot 'raw'), (Join-Path $ResultRoot 'processed'), (Split-Path -Parent $MacMapPath))) {
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Warning $line }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

# ---------------------------------------------------------------------------
# Fixed inventory (design decisions) + optional CSV overlay from OPNsense
# ---------------------------------------------------------------------------
function Get-ZtnaInventory {
    @(
        [pscustomobject]@{ Name = 'Student1';    IP = '10.20.11.21'; Mac = 'BC:24:11:AA:00:01'; Zone = 'StudentWS';    Vlan = 11 }
        [pscustomobject]@{ Name = 'Student2';    IP = '10.20.11.22'; Mac = 'BC:24:11:AA:00:06'; Zone = 'StudentWS';    Vlan = 11 }
        [pscustomobject]@{ Name = 'Instructor1'; IP = '10.20.20.21'; Mac = 'BC:24:11:AA:00:04'; Zone = 'InstructorWS'; Vlan = 20 }
        [pscustomobject]@{ Name = 'DC01';        IP = '10.20.30.10'; Mac = '';                  Zone = 'Server';       Vlan = 30 }
    )
}

function Initialize-DeviceMap {
    # The DHCP reservations live on OPNsense (another engineer). This script
    # accepts their export as a CSV so the PDP and the DHCP service agree on the
    # same MAC<->host mapping. When absent, the built-in inventory is written out
    # so the file always exists and can be edited.
    if (-not (Test-Path -LiteralPath $MacMapPath)) {
        try {
            $rows = Get-ZtnaInventory | ForEach-Object {
                [pscustomobject]@{
                    Hostname = $_.Name
                    IP       = $_.IP
                    MAC      = $_.Mac
                    VLAN     = $_.Vlan
                    Zone     = $_.Zone
                }
            }
            $rows | Export-Csv -LiteralPath $MacMapPath -NoTypeInformation -Encoding ASCII
            Write-Log "Created device MAC map template: $MacMapPath"
        } catch {
            Write-Log ("Could not create {0}: {1}" -f $MacMapPath, $_.Exception.Message) WARN
        }
    }
}

function Get-ZtnaDeviceInventory {
    $inventory = @{}
    foreach ($item in Get-ZtnaInventory) {
        $inventory[$item.Name.ToLower()] = $item
    }
    if (Test-Path -LiteralPath $MacMapPath) {
        try {
            foreach ($row in (Import-Csv -LiteralPath $MacMapPath)) {
                $name = [string]$row.Hostname
                if (-not $name) { continue }
                $existing = $inventory[$name.ToLower()]
                $zone = if ($row.Zone) { $row.Zone } elseif ($existing) { $existing.Zone } else { 'Unknown' }
                $vlan = if ($row.VLAN) { [int]$row.VLAN } elseif ($existing) { $existing.Vlan } else { 0 }
                $inventory[$name.ToLower()] = [pscustomobject]@{
                    Name = $name
                    IP   = if ($row.IP) { $row.IP } elseif ($existing) { $existing.IP } else { '' }
                    Mac  = if ($row.MAC) { $row.MAC } elseif ($existing) { $existing.Mac } else { '' }
                    Zone = $zone
                    Vlan = $vlan
                }
            }
        } catch {
            Write-Log ("Device map unreadable ({0}); using built-in inventory" -f $_.Exception.Message) WARN
        }
    }
    return $inventory
}

$script:DeviceInventory = @{}
Initialize-DeviceMap
$script:DeviceInventory = Get-ZtnaDeviceInventory

function Resolve-ZtnaDeviceInfo {
    param([string]$Name)
    if (-not $Name) { return $null }
    $key = $Name.ToLower()
    if ($script:DeviceInventory.ContainsKey($key)) { return $script:DeviceInventory[$key] }
    # Accept an IP address as the device identifier as well.
    foreach ($item in $script:DeviceInventory.Values) {
        if ($item.IP -eq $Name) { return $item }
    }
    return $null
}

function Resolve-ZtnaResourceZone {
    param([string]$Name)
    $info = Resolve-ZtnaDeviceInfo -Name $Name
    if ($info) { return $info.Zone }
    return $null
}

function ConvertTo-ZtnaMac {
    param([string]$Mac)
    if (-not $Mac) { return '' }
    return (($Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
}

# ---------------------------------------------------------------------------
# Policy matrix (single source of truth)
# ---------------------------------------------------------------------------
function Get-ZtnaPolicyMatrix {
    # FromZone '*' = any device zone the role may sit at; Target 'Local' = the
    # resource is the device in use. No row = default deny (peer workstations,
    # cross-zone lateral movement).
    @(
        [pscustomobject]@{ Role = 'Student';    FromZone = '*';            Target = 'Local';        AllowedPorts = @(445, 139);                Rationale = 'Own workstation local resources.' }
        [pscustomobject]@{ Role = 'Student';    FromZone = '*';            Target = 'Server';       AllowedPorts = @(53, 88, 389);             Rationale = 'Authentication services only; no SMB/RDP/WinRM to servers.' }
        [pscustomobject]@{ Role = 'Instructor'; FromZone = '*';            Target = 'Local';        AllowedPorts = @(445, 139, 3389);          Rationale = 'Own (or currently used) workstation.' }
        [pscustomobject]@{ Role = 'Instructor'; FromZone = '*';            Target = 'Server';       AllowedPorts = @(53, 88, 389);             Rationale = 'Authentication services only.' }
        [pscustomobject]@{ Role = 'ZTNA-Admin'; FromZone = '*';            Target = 'Local';        AllowedPorts = @(445, 3389, 5985);         Rationale = 'Administration of the device in use.' }
        [pscustomobject]@{ Role = 'ZTNA-Admin'; FromZone = 'StudentWS';    Target = 'Server';       AllowedPorts = @(53, 88, 389, 445, 5985);  Rationale = 'OPNsense DOMAIN_PORTS (no RDP from workstation zones).' }
        [pscustomobject]@{ Role = 'ZTNA-Admin'; FromZone = 'InstructorWS'; Target = 'Server';       AllowedPorts = @(53, 88, 389, 445, 5985);  Rationale = 'OPNsense DOMAIN_PORTS (no RDP from workstation zones).' }
        [pscustomobject]@{ Role = 'ZTNA-Admin'; FromZone = 'Server';       Target = 'StudentWS';    AllowedPorts = @(5985);                    Rationale = 'OPNsense LAN rule 850 (WinRM only).' }
        [pscustomobject]@{ Role = 'ZTNA-Admin'; FromZone = 'Server';       Target = 'InstructorWS'; AllowedPorts = @(5985);                    Rationale = 'OPNsense LAN rule 860 (WinRM only).' }
    )
}

# Local when the resource is the device the request comes from (by name or IP).
function Get-ZtnaTarget {
    param([string]$Device, [string]$Resource)
    $dev = Resolve-ZtnaDeviceInfo -Name $Device
    $res = Resolve-ZtnaDeviceInfo -Name $Resource
    if (-not $res) { return $null }
    if ($dev -and $dev.Name -eq $res.Name) { return 'Local' }
    return $res.Zone
}

# Which device zones a role may physically sit at. A student may use any student
# workstation (the manuscript explicitly allows moving to another unit) but not
# an instructor workstation or a server console.
function Get-ZtnaRoleDeviceZones {
    @{
        'Student'    = @('StudentWS')
        'Instructor' = @('StudentWS', 'InstructorWS')
        'ZTNA-Admin' = @('StudentWS', 'InstructorWS', 'Server')
    }
}

$script:GlobalDenyPorts = @(21, 23, 25, 69, 111, 1433, 3306, 5432)

function Get-ZtnaMatrixEntry {
    # An exact FromZone row wins over the '*' row.
    param([string]$Role, [string]$FromZone, [string]$Target)
    $rows = @(Get-ZtnaPolicyMatrix | Where-Object { $_.Role -eq $Role -and $_.Target -eq $Target -and ($_.FromZone -eq $FromZone -or $_.FromZone -eq '*') })
    @($rows | Where-Object { $_.FromZone -ne '*' }) + @($rows | Where-Object { $_.FromZone -eq '*' }) | Select-Object -First 1
}

function Get-ZtnaExpectedDecision {
    <#
        Table-only decision (no AD, no device trust) from this script's matrix.
        Used by the legacy scenario generator and to cross-check case files; trial
        scoring uses the case file's independently derived Expected column.
    #>
    param([string]$Role, [string]$DeviceZone, [string]$Target, [int]$Port)

    if (-not $Role -or -not $DeviceZone -or -not $Target) { return 'Deny' }

    $zoneTable = Get-ZtnaRoleDeviceZones
    if (-not $zoneTable.ContainsKey($Role)) { return 'Deny' }
    if ($zoneTable[$Role] -notcontains $DeviceZone) { return 'Deny' }
    if ($script:GlobalDenyPorts -contains $Port) { return 'Deny' }

    $entry = Get-ZtnaMatrixEntry -Role $Role -FromZone $DeviceZone -Target $Target
    if (-not $entry) { return 'Deny' }
    if ($entry.AllowedPorts -contains $Port) { return 'Allow' }
    return 'Deny'
}

# ---------------------------------------------------------------------------
# Directory lookups (System.DirectoryServices - works without RSAT)
# ---------------------------------------------------------------------------
function Get-ZtnaDirectoryObject {
    param([string]$Filter, [string[]]$Properties)

    $root = [ADSI]'LDAP://RootDSE'
    $baseDn = $root.defaultNamingContext.Value
    if (-not $baseDn) { throw 'Cannot read defaultNamingContext - host is not domain joined.' }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]"LDAP://$baseDn"
    $searcher.Filter = $Filter
    $searcher.SearchScope = 'Subtree'
    $searcher.PageSize = 10
    foreach ($prop in $Properties) { [void]$searcher.PropertiesToLoad.Add($prop) }

    $result = $searcher.FindOne()
    if (-not $result) { return $null }
    return $result.Properties
}

# First value of a DirectorySearcher property. The values are
# ResultPropertyValueCollections: .Value on them is always empty, which made every
# account/computer look enabled and never locked (fixed in refinement cycle 2).
function Get-ZtnaProp {
    param($Props, [string]$Name)
    $v = $Props[$Name]
    if ($v -and $v.Count -gt 0) { return $v[0] }
    return $null
}

function Get-ZtnaUserState {
    param([string]$SamAccountName)

    $state = [pscustomobject]@{
        User      = $SamAccountName
        Exists    = $false
        Enabled   = $false
        LockedOut = $false
        Role      = 'Unknown'
        Groups    = @()
    }
    if (-not $SamAccountName) { return $state }

    if ($Offline) {
        $key = $SamAccountName.ToLower()
        $state.Exists = $true
        $state.Enabled = $true
        switch -Regex ($key) {
            '^student99$'     { $state.Exists = $false; $state.Role = 'Unknown'; break }
            '^student\d+$'    { $state.Role = 'Student'; break }
            '^instructor\d+$' { $state.Role = 'Instructor'; break }
            '^admin-ztna\d+$' { $state.Role = 'ZTNA-Admin'; break }
            '^probe-ztna\d+$' { $state.Role = 'Student'; break }
            '^svc-'           { $state.Role = 'Service'; $state.Enabled = $false; break }
            default           { $state.Role = 'Unknown' }
        }
        $state.Groups = @('GG-' + $state.Role)
        return $state
    }

    try {
        $safe = $SamAccountName.Replace('\', '').Replace('(', '').Replace(')', '')
        $props = Get-ZtnaDirectoryObject -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$safe))" `
            -Properties @('samaccountname', 'useraccountcontrol', 'msds-user-account-control-computed', 'memberof', 'distinguishedname')
        if (-not $props) { return $state }

        $state.Exists = $true
        $uac = [int](Get-ZtnaProp $props 'useraccountcontrol')
        $state.Enabled = (($uac -band 2) -eq 0)
        # lockoutTime stays set after the 15-minute lockout expires; the computed
        # UF_LOCKOUT bit (0x10) is true only while the account is actually locked.
        $computed = [int](Get-ZtnaProp $props 'msds-user-account-control-computed')
        $state.LockedOut = (($computed -band 0x10) -ne 0)
        $state.Groups = @($props['memberof'] | ForEach-Object { [string]$_ })

        if ($state.Groups -match 'CN=GG-ZTNA-Admins,') { $state.Role = 'ZTNA-Admin' }
        elseif ($state.Groups -match 'CN=GG-Instructors,') { $state.Role = 'Instructor' }
        elseif ($state.Groups -match 'CN=GG-Students,') { $state.Role = 'Student' }
        else { $state.Role = 'Unknown' }
    } catch {
        Write-Log ("AD user lookup failed for {0}: {1}" -f $SamAccountName, $_.Exception.Message) WARN
        $state.Role = 'Unknown'
    }
    return $state
}

function Get-ZtnaDeviceState {
    param([string]$Name, [string]$ObservedMac)

    $info = Resolve-ZtnaDeviceInfo -Name $Name
    $inventoryZone = $null
    $inventoryMac = ''
    if ($info) {
        $inventoryZone = $info.Zone
        $inventoryMac = $info.Mac
    }

    $state = [pscustomobject]@{
        Device        = $Name
        Exists        = $false
        InAd          = $false
        Enabled       = $false
        InLabGroup    = $false
        Zone          = $inventoryZone
        RegisteredMac = $inventoryMac
        ObservedMac   = $ObservedMac
        MacMatch      = $true
        Reason        = ''
    }
    if (-not $Name) { $state.Reason = 'DEVICE_MISSING'; return $state }
    if (-not $info) { $state.Reason = 'DEVICE_UNREGISTERED'; return $state }
    $state.Exists = $true

    if ($Offline) {
        $state.InAd = $true
        $state.Enabled = $true
        $state.InLabGroup = $true
        if ($ObservedMac) {
            $state.MacMatch = (ConvertTo-ZtnaMac $ObservedMac) -eq (ConvertTo-ZtnaMac $info.Mac)
        }
        if (-not $state.MacMatch) { $state.Reason = 'MAC_MISMATCH' }
        return $state
    }

    try {
        $safe = $Name.Replace("'", "")
        $props = Get-ZtnaDirectoryObject -Filter "(&(objectCategory=computer)(name=$safe))" `
            -Properties @('name', 'useraccountcontrol', 'memberof', 'description', 'serialnumber', 'department', 'dnshostname')
        if (-not $props) {
            $state.Reason = 'DEVICE_NOT_DOMAIN_JOINED'
            return $state
        }
        $state.InAd = $true
        $uac = [int](Get-ZtnaProp $props 'useraccountcontrol')
        $state.Enabled = (($uac -band 2) -eq 0)

        $memberOf = @($props['memberof'] | ForEach-Object { [string]$_ })
        # Workstations must be in GG-LabWorkstations; a Server-zone device is trusted
        # when its AD object is a domain controller (SERVER_TRUST_ACCOUNT 0x2000).
        # (Refinement cycles 1-2: cycle-0 T1 denied every request from DC01.)
        $isDc = (($uac -band 0x2000) -ne 0)
        $state.InLabGroup = [bool]($memberOf -match 'CN=GG-LabWorkstations,') -or ($inventoryZone -eq 'Server' -and $isDc)

        # Registered MAC: serialNumber first, then the Description 'MAC=...' tag.
        $registered = ''
        $serial = Get-ZtnaProp $props 'serialnumber'
        $descr = Get-ZtnaProp $props 'description'
        if ($serial) { $registered = [string]$serial }
        if (-not $registered -and $descr) {
            $m = [regex]::Match([string]$descr, 'MAC=([0-9A-Fa-f:\.\-]{12,17})')
            if ($m.Success) { $registered = $m.Groups[1].Value }
        }
        if (-not $registered) { $registered = $info.Mac }
        $state.RegisteredMac = $registered

        if ($ObservedMac) {
            $state.MacMatch = (ConvertTo-ZtnaMac $ObservedMac) -eq (ConvertTo-ZtnaMac $registered)
        }
        if (-not $state.MacMatch) { $state.Reason = 'MAC_MISMATCH' }
    } catch {
        Write-Log ("AD computer lookup failed for {0}: {1}" -f $Name, $_.Exception.Message) WARN
        $state.Reason = 'DEVICE_LOOKUP_FAILED'
    }
    return $state
}

# ---------------------------------------------------------------------------
# Event log
# ---------------------------------------------------------------------------
function Initialize-ZtnaEventSource {
    if ($NoEventLog -or $script:EventSourceReady) { return }
    $sourceExists = $false
    try {
        $sourceExists = [System.Diagnostics.EventLog]::SourceExists($script:EventSource)
    } catch {
        Write-Log ("Event log API unavailable on this host: {0}" -f $_.Exception.Message) WARN
        return
    }
    if (-not $sourceExists) {
        try {
            New-EventLog -LogName Application -Source $script:EventSource -ErrorAction Stop
            Write-Log "Registered event source $script:EventSource"
        } catch {
            Write-Log ("Event source registration failed: {0}" -f $_.Exception.Message) WARN
            return
        }
    }
    $script:EventSourceReady = $true
}

function Write-ZtnaDecisionLog {
    param([pscustomobject]$Decision)

    if (-not $NoFileLog) {
        $json = $Decision | Select-Object TimestampUtc, Decision, Reason, Detail, User, Role, Device, DeviceZone,
            DeviceMac, Resource, ResourceZone, Port, LatencyMs, Scenario, CaseId, Trial, Expected, PolicyVersion |
            ConvertTo-Json -Compress -Depth 5
        # UTF-8 without BOM: JSON-lines consumers must see pure JSON on line 1.
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($script:JsonLog, $json + [Environment]::NewLine, $utf8NoBom)

        $csvExists = Test-Path -LiteralPath $script:CsvLog
        if (-not $csvExists) {
            'Trial,Scenario,CaseId,TimestampUtc,Decision,Reason,User,Role,Device,DeviceZone,DeviceMac,Resource,ResourceZone,Port,LatencyMs,Expected,Match,PolicyVersion' |
                Set-Content -LiteralPath $script:CsvLog -Encoding ASCII
        }
        $match = ''
        if ($Decision.Expected) { $match = ([string]$Decision.Decision -eq [string]$Decision.Expected) }
        $row = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17}' -f `
            $Decision.Trial, $Decision.Scenario, $Decision.CaseId, $Decision.TimestampUtc,
            $Decision.Decision, $Decision.Reason, $Decision.User, $Decision.Role, $Decision.Device,
            $Decision.DeviceZone, $Decision.DeviceMac, $Decision.Resource, $Decision.ResourceZone,
            $Decision.Port, $Decision.LatencyMs, $Decision.Expected, $match, $Decision.PolicyVersion
        Add-Content -LiteralPath $script:CsvLog -Value $row -Encoding ASCII
    }

    if (-not $NoEventLog -and $script:EventSourceReady) {
        $eventId = if ($Decision.Decision -eq 'Allow') { 4100 } else { 4101 }
        $entryType = if ($Decision.Decision -eq 'Allow') { 'Information' } else { 'Warning' }
        $message = 'ZTNA PDP decision={0} reason={1} user={2} role={3} device={4} resource={5} port={6} latency={7}ms case={8} trial={9}' -f `
            $Decision.Decision, $Decision.Reason, $Decision.User, $Decision.Role, $Decision.Device,
            $Decision.Resource, $Decision.Port, $Decision.LatencyMs, $Decision.CaseId, $Decision.Trial
        try {
            Write-EventLog -LogName Application -Source $script:EventSource -EventId $eventId `
                -EntryType $entryType -Message $message -ErrorAction Stop
        } catch {
            Write-Log ("Event write failed: {0}" -f $_.Exception.Message) WARN
        }
    }
}

# ---------------------------------------------------------------------------
# The decision function
# ---------------------------------------------------------------------------
function Invoke-ZtnaPolicyDecision {
    [CmdletBinding()]
    param(
        [string]$User,
        [string]$Device,
        [string]$DeviceMac,
        [string]$Resource,
        [int]$Port,
        [string]$Scenario = 'manual',
        [string]$CaseId = '',
        [string]$Trial = '',
        [string]$Expected = ''
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)

    $decision = 'Deny'
    $reason = 'DENY_DEFAULT'
    $detail = ''
    $role = 'Unknown'
    $deviceZone = ''
    $resourceZone = ''

    if ($Port -lt 1 -or $Port -gt 65535) {
        $reason = 'DENY_INVALID_PORT'
        $detail = "Port $Port outside 1-65535"
    } else {
        # 1. Identity and role (authentication/authorization input)
        $userState = Get-ZtnaUserState -SamAccountName $User
        $role = $userState.Role

        if (-not $userState.Exists) {
            $reason = 'DENY_USER_UNKNOWN'
            $detail = "No directory account for '$User'"
        } elseif (-not $userState.Enabled) {
            $reason = 'DENY_USER_DISABLED'
            $detail = 'Account is disabled or is a non-interactive service identity'
        } elseif ($userState.LockedOut) {
            $reason = 'DENY_USER_LOCKED'
            $detail = 'Account locked out by the 5/15/15 policy'
        } elseif ($role -eq 'Unknown' -or $role -eq 'Service') {
            $reason = 'DENY_ROLE_UNKNOWN'
            $detail = "Account '$User' has no RBAC role group"
        } else {
            # 2. Device trust (domain membership + registered MAC)
            $deviceState = Get-ZtnaDeviceState -Name $Device -ObservedMac $DeviceMac
            $deviceZone = if ($deviceState.Zone) { $deviceState.Zone } else { '' }

            if (-not $deviceState.Exists) {
                $reason = 'DENY_DEVICE_UNREGISTERED'
                $detail = "Device '$Device' is not in the lab inventory"
            } elseif (-not $deviceState.InAd) {
                $reason = 'DENY_DEVICE_NOT_DOMAIN_JOINED'
                $detail = "Device '$Device' has no AD computer object"
            } elseif (-not $deviceState.Enabled) {
                $reason = 'DENY_DEVICE_DISABLED'
                $detail = "AD computer object '$Device' is disabled"
            } elseif (-not $deviceState.InLabGroup) {
                $reason = 'DENY_DEVICE_NOT_IN_LAB_GROUP'
                $detail = "Device '$Device' is not a member of GG-LabWorkstations"
            } elseif (-not $deviceState.MacMatch) {
                $reason = 'DENY_MAC_MISMATCH'
                $detail = ("Observed MAC {0} != registered {1}" -f $DeviceMac, $deviceState.RegisteredMac)
            } else {
                # 3. Resource zone
                $resourceZone = Resolve-ZtnaResourceZone -Name $Resource
                if (-not $resourceZone) {
                    $reason = 'DENY_RESOURCE_UNKNOWN'
                    $detail = "Resource '$Resource' is not in the lab inventory"
                } else {
                    # 4. Role may only sit at its own device class
                    $zoneTable = Get-ZtnaRoleDeviceZones
                    if (-not $zoneTable.ContainsKey($role) -or $zoneTable[$role] -notcontains $deviceZone) {
                        $reason = 'DENY_DEVICE_ROLE_MISMATCH'
                        $detail = ("Role {0} may not use device zone {1}" -f $role, $deviceZone)
                    } elseif ($script:GlobalDenyPorts -contains $Port) {
                        $reason = 'DENY_GLOBAL_PORT'
                        $detail = "Port $Port is globally prohibited in the lab"
                    } else {
                        # 5. Matrix lookup (least privilege, default deny)
                        $target = Get-ZtnaTarget -Device $Device -Resource $Resource
                        $entry = Get-ZtnaMatrixEntry -Role $role -FromZone $deviceZone -Target $target
                        if (-not $entry) {
                            if ($target -eq $deviceZone) {
                                $reason = 'DENY_PEER_WORKSTATION'
                                $detail = "Lateral access to a peer $target device is not permitted for $role"
                            } else {
                                $reason = 'DENY_NO_POLICY_ENTRY'
                                $detail = "No matrix entry for $role at $deviceZone -> $target"
                            }
                        } elseif ($entry.AllowedPorts -contains $Port) {
                            $decision = 'Allow'
                            $reason = 'ALLOW_MATRIX'
                            $detail = ('{0} at {1} -> {2}:{3} permitted ({4})' -f $role, $deviceZone, $target, $Port, $entry.Rationale)
                        } else {
                            $reason = 'DENY_PORT_NOT_PERMITTED'
                            $detail = ('Port {0} not in allowed set {1} for {2} at {3} -> {4}' -f $Port, ($entry.AllowedPorts -join '/'), $role, $deviceZone, $target)
                        }
                    }
                }
            }
        }
    }

    $stopwatch.Stop()
    $latencyMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)

    $result = [pscustomobject]@{
        TimestampUtc  = $timestamp
        Decision      = $decision
        Reason        = $reason
        Detail        = $detail
        User          = $User
        Role          = $role
        Device        = $Device
        DeviceZone    = $deviceZone
        DeviceMac     = $DeviceMac
        Resource      = $Resource
        ResourceZone  = $resourceZone
        Port          = $Port
        LatencyMs     = $latencyMs
        Scenario      = $Scenario
        CaseId        = $CaseId
        Trial         = $Trial
        Expected      = $Expected
        PolicyVersion = $script:PolicyVersion
    }

    Write-ZtnaDecisionLog -Decision $result
    return $result
}

# ---------------------------------------------------------------------------
# Scenario definitions (one trial = -Count decisions, SOP 3)
# ---------------------------------------------------------------------------
function New-ZtnaCase {
    param(
        [string]$User,
        [string]$Device,
        [string]$Resource,
        [int]$Port,
        [string]$DeviceMac = '',
        [string]$Expected,
        [string]$Label = ''
    )
    $deviceInfo = Resolve-ZtnaDeviceInfo -Name $Device
    $deviceZone = if ($deviceInfo) { $deviceInfo.Zone } else { '' }
    $target = Get-ZtnaTarget -Device $Device -Resource $Resource
    $userState = Get-ZtnaUserState -SamAccountName $User
    $role = $userState.Role

    if (-not $PSBoundParameters.ContainsKey('Expected') -or -not $Expected) {
        $Expected = Get-ZtnaExpectedDecision -Role $role -DeviceZone $deviceZone -Target $target -Port $Port
        if ($DeviceMac -and $deviceInfo -and (ConvertTo-ZtnaMac $DeviceMac) -ne (ConvertTo-ZtnaMac $deviceInfo.Mac)) {
            $Expected = 'Deny'   # MAC mismatch is a device-trust failure, not a matrix rule
        }
    }

    [pscustomobject]@{
        User     = $User
        Device   = $Device
        Resource = $Resource
        Port     = $Port
        DeviceMac = $DeviceMac
        Expected = $Expected
        Label    = $Label
    }
}

function Get-ZtnaScenarioCases {
    param([string]$Scenario, [int]$Count)

    $normalized = switch -Regex ($Scenario.ToLower()) {
        '^(s1|auth)'         { 'S1'; break }
        '^(s2|rbac)'         { 'S2'; break }
        '^(s3|unauth)'       { 'S3'; break }
        '^(s4|device|lockout)' { 'S4'; break }
        '^(s5|lateral)'      { 'S5'; break }
        '^(s6|logging)'      { 'S6'; break }
        default              { 'S2' }
    }

    $cases = New-Object System.Collections.Generic.List[object]
    switch ($normalized) {
        'S1' {
            # Successful authentication / authorised resource use
            $cases.Add((New-ZtnaCase -User 'student01' -Device 'Student1' -Resource 'Student1' -Port 445 -Label 'student-local-share'))
            $cases.Add((New-ZtnaCase -User 'student02' -Device 'Student2' -Resource 'Student2' -Port 445 -Label 'student-local-share'))
            $cases.Add((New-ZtnaCase -User 'student03' -Device 'Student1' -Resource 'Student1' -Port 139 -Label 'student-move-unit'))
            $cases.Add((New-ZtnaCase -User 'instructor01' -Device 'Instructor1' -Resource 'Instructor1' -Port 3389 -Label 'instructor-rdp-own'))
            $cases.Add((New-ZtnaCase -User 'instructor02' -Device 'Student1' -Resource 'Student1' -Port 3389 -Label 'instructor-support'))
            $cases.Add((New-ZtnaCase -User 'admin-ztna01' -Device 'Instructor1' -Resource 'DC01' -Port 5985 -Label 'admin-winrm-dc'))
            $cases.Add((New-ZtnaCase -User 'student04' -Device 'Student2' -Resource 'Student2' -Port 445 -Label 'student-local-share'))
            $cases.Add((New-ZtnaCase -User 'student05' -Device 'Student1' -Resource 'DC01' -Port 389 -Label 'student-ldap-auth'))
        }
        'S2' {
            # Full matrix sweep: every role x resource zone x representative port
            foreach ($user in @('student01', 'instructor01', 'admin-ztna01')) {
                foreach ($target in @(
                        @{ Device = 'Student1'; Resource = 'Student1' },
                        @{ Device = 'Instructor1'; Resource = 'Instructor1' },
                        @{ Device = 'Student1'; Resource = 'DC01' })) {
                    foreach ($port in @(445, 139, 3389, 5985, 53, 23)) {
                        $cases.Add((New-ZtnaCase -User $user -Device $target.Device -Resource $target.Resource -Port $port `
                                    -Label ("matrix-{0}-{1}-{2}" -f $user, $target.Resource, $port)))
                    }
                }
            }
        }
        'S3' {
            # Credential/role misuse attempts that must be denied at the PDP
            $cases.Add((New-ZtnaCase -User 'student01' -Device 'Student1' -Resource 'Instructor1' -Port 3389 -Label 'student-to-instructor'))
            $cases.Add((New-ZtnaCase -User 'student02' -Device 'Student2' -Resource 'DC01' -Port 3389 -Label 'student-rdp-server'))
            $cases.Add((New-ZtnaCase -User 'student03' -Device 'Student1' -Resource 'DC01' -Port 445 -Label 'student-smb-server'))
            $cases.Add((New-ZtnaCase -User 'instructor01' -Device 'Instructor1' -Resource 'DC01' -Port 3389 -Label 'instructor-rdp-server'))
            $cases.Add((New-ZtnaCase -User 'instructor02' -Device 'Student1' -Resource 'DC01' -Port 5985 -Label 'instructor-winrm-server'))
            $cases.Add((New-ZtnaCase -User 'student04' -Device 'Student1' -Resource 'Student1' -Port 23 -Label 'telnet-prohibited'))
            $cases.Add((New-ZtnaCase -User 'student99' -Device 'Student1' -Resource 'Student1' -Port 445 -Label 'unknown-identity' -Expected 'Deny'))
            $cases.Add((New-ZtnaCase -User 'svc-ztna-pdp' -Device 'Student1' -Resource 'Student1' -Port 445 -Label 'service-identity' -Expected 'Deny'))
        }
        'S4' {
            # Additional controls: device validation (MAC + domain membership)
            $cases.Add((New-ZtnaCase -User 'student01' -Device 'Student1' -Resource 'Student1' -Port 445 -Label 'valid-device'))
            $cases.Add((New-ZtnaCase -User 'student02' -Device 'Student1' -Resource 'Student1' -Port 445 -DeviceMac 'AA:BB:CC:DD:EE:01' -Label 'mac-mismatch' -Expected 'Deny'))
            $cases.Add((New-ZtnaCase -User 'student03' -Device 'Laptop-X' -Resource 'Student1' -Port 445 -Label 'unregistered-device' -Expected 'Deny'))
            $cases.Add((New-ZtnaCase -User 'student04' -Device 'Student2' -Resource 'Student2' -Port 445 -DeviceMac 'BC:24:11:AA:00:06' -Label 'valid-device-mac'))
            $cases.Add((New-ZtnaCase -User 'student05' -Device 'Instructor1' -Resource 'Instructor1' -Port 445 -Label 'student-on-instructor-device' -Expected 'Deny'))
            $cases.Add((New-ZtnaCase -User 'instructor01' -Device 'Instructor1' -Resource 'Instructor1' -Port 3389 -Label 'instructor-valid-device'))
            $cases.Add((New-ZtnaCase -User 'probe-ztna01' -Device 'Student1' -Resource 'Student1' -Port 445 -Label 'lockout-probe'))
            $cases.Add((New-ZtnaCase -User 'admin-ztna01' -Device 'Student1' -Resource 'DC01' -Port 3389 -Label 'admin-valid-device'))
        }
        'S5' {
            # Lateral movement across VLAN boundaries (PDP half; drop counters are
            # measured on OPNsense by the network engineer)
            $cases.Add((New-ZtnaCase -User 'student01' -Device 'Student1' -Resource 'Instructor1' -Port 445 -Label 'student-cross-to-instructor'))
            $cases.Add((New-ZtnaCase -User 'student02' -Device 'Student2' -Resource 'DC01' -Port 445 -Label 'student-cross-to-server'))
            $cases.Add((New-ZtnaCase -User 'student03' -Device 'Student1' -Resource 'DC01' -Port 3389 -Label 'student-cross-rdp'))
            $cases.Add((New-ZtnaCase -User 'instructor01' -Device 'Instructor1' -Resource 'DC01' -Port 5985 -Label 'instructor-cross-winrm'))
            $cases.Add((New-ZtnaCase -User 'instructor02' -Device 'Instructor1' -Resource 'Student2' -Port 3389 -Label 'instructor-to-student'))
            $cases.Add((New-ZtnaCase -User 'student04' -Device 'Student2' -Resource 'Student2' -Port 445 -Label 'student-intra-student'))
            $cases.Add((New-ZtnaCase -User 'admin-ztna01' -Device 'Student1' -Resource 'DC01' -Port 5985 -Label 'admin-cross'))
        }
        default {
            # S6 - logging completeness mix: granted and denied events together
            $cases.Add((New-ZtnaCase -User 'student01' -Device 'Student1' -Resource 'Student1' -Port 445 -Label 'log-allow-1'))
            $cases.Add((New-ZtnaCase -User 'student02' -Device 'Student2' -Resource 'Instructor1' -Port 445 -Label 'log-deny-1'))
            $cases.Add((New-ZtnaCase -User 'instructor01' -Device 'Instructor1' -Resource 'DC01' -Port 3389 -Label 'log-deny-2'))
            $cases.Add((New-ZtnaCase -User 'instructor02' -Device 'Student1' -Resource 'Student1' -Port 3389 -Label 'log-allow-2'))
            $cases.Add((New-ZtnaCase -User 'student03' -Device 'Student1' -Resource 'DC01' -Port 389 -Label 'log-allow-3'))
            $cases.Add((New-ZtnaCase -User 'admin-ztna01' -Device 'Instructor1' -Resource 'DC01' -Port 3389 -Label 'log-allow-4'))
            $cases.Add((New-ZtnaCase -User 'student04' -Device 'Laptop-X' -Resource 'Student1' -Port 445 -Label 'log-deny-3' -Expected 'Deny'))
            $cases.Add((New-ZtnaCase -User 'student05' -Device 'Student2' -Resource 'Student2' -Port 23 -Label 'log-deny-4'))
        }
    }

    if ($Count -le 0) { return $cases.ToArray() }

    # Repeat the case set until exactly $Count decisions exist (SOP 3: one trial
    # is a fixed batch of 100 events).
    $expanded = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($expanded.Count -lt $Count) {
        $case = $cases[$i % $cases.Count]
        $copy = $case.PSObject.Copy()
        $copy.Label = '{0}-{1:D3}' -f $case.Label, ($i + 1)
        $expanded.Add($copy)
        $i++
    }
    return $expanded.ToArray()
}

function Get-ZtnaLatencyStats {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) {
        return [pscustomobject]@{ Count = 0; Mean = 0; P95 = 0; Min = 0; Max = 0 }
    }
    $sorted = @($Values | Sort-Object)
    $index = [int][math]::Ceiling($sorted.Count * 0.95) - 1
    if ($index -lt 0) { $index = 0 }
    if ($index -ge $sorted.Count) { $index = $sorted.Count - 1 }
    [pscustomobject]@{
        Count = $sorted.Count
        Mean  = [math]::Round(($Values | Measure-Object -Average).Average, 3)
        P95   = [math]::Round($sorted[$index], 3)
        Min   = [math]::Round($sorted[0], 3)
        Max   = [math]::Round($sorted[$sorted.Count - 1], 3)
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$exitCode = 0
try {
    Initialize-ZtnaEventSource

    if ($Batch) {
        if ($Count -le 0) { throw '-Count must be greater than 0 in batch mode.' }
        $trialLabel = if ($Trial) { $Trial } else { (Get-Date -Format 'HHmmss') }
        $scenarioLabel = $Scenario

        $seed = $null
        $caseHash = ''
        $warmUpMs = $null
        if ($CaseFile) {
            # Fixed case file: Expected comes from the file (independent derivation),
            # order is shuffled reproducibly with seed = trial number.
            if (-not (Test-Path -LiteralPath $CaseFile)) { throw "Case file not found: $CaseFile" }
            $caseHash = (Get-FileHash -LiteralPath $CaseFile -Algorithm SHA256).Hash
            $seed = if ($trialLabel -match '^T(\d)$') { [int]$Matches[1] } else { 0 }
            $rng = New-Object System.Random $seed
            $cases = @(Import-Csv -LiteralPath $CaseFile | ForEach-Object {
                    [pscustomobject]@{
                        User         = $_.User
                        Device       = $_.Device
                        DeviceMac    = if ($_.PSObject.Properties['DeviceMac']) { $_.DeviceMac } else { '' }
                        Resource     = $_.Resource
                        Port         = [int]$_.Port
                        Expected     = $_.Expected
                        ExpectedRole = if ($_.PSObject.Properties['ExpectedRole']) { $_.ExpectedRole } else { '' }
                        Label        = $_.CaseId
                    } } | Sort-Object { $rng.Next() })
        } else {
            $cases = Get-ZtnaScenarioCases -Scenario $Scenario -Count $Count
        }
        Write-Log ("PDP batch: scenario={0} trial={1} cases={2} offline={3} casefile={4} seed={5}" -f $scenarioLabel, $trialLabel, $cases.Count, [bool]$Offline, $CaseFile, $seed)

        if ($CaseFile) {
            # Declared warm-up: one decision before collection, discarded from the
            # statistics (cold start ~177 ms vs ~4 ms warm). Logged as CaseId WARMUP.
            $w = $cases[0]
            $warm = Invoke-ZtnaPolicyDecision -User $w.User -Device $w.Device -DeviceMac $w.DeviceMac `
                -Resource $w.Resource -Port $w.Port -Scenario ($scenarioLabel + '-warmup') -CaseId 'WARMUP' -Trial $trialLabel
            $warmUpMs = $warm.LatencyMs
        }

        $totalWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $results = New-Object System.Collections.Generic.List[object]
        foreach ($case in $cases) {
            $decision = Invoke-ZtnaPolicyDecision -User $case.User -Device $case.Device -DeviceMac $case.DeviceMac `
                -Resource $case.Resource -Port $case.Port -Scenario $scenarioLabel -CaseId $case.Label `
                -Trial $trialLabel -Expected $case.Expected
            $expectedRole = if ($case.PSObject.Properties['ExpectedRole']) { $case.ExpectedRole } else { '' }
            $decision | Add-Member -NotePropertyName ExpectedRole -NotePropertyValue $expectedRole
            $results.Add($decision)
        }
        $totalWatch.Stop()

        $latencies = @($results | Select-Object -ExpandProperty LatencyMs)
        $stats = Get-ZtnaLatencyStats -Values $latencies
        $allowed = @($results | Where-Object { $_.Decision -eq 'Allow' }).Count
        $denied = @($results | Where-Object { $_.Decision -eq 'Deny' }).Count
        $scored = @($results | Where-Object { $_.Expected })
        $correct = @($scored | Where-Object { $_.Decision -eq $_.Expected }).Count
        $accuracy = if ($scored.Count -gt 0) { [math]::Round(100 * $correct / $scored.Count, 3) } else { 0 }

        $batchPath = Join-Path (Join-Path $ResultRoot 'raw') ('pdp-{0}-{1}.csv' -f $scenarioLabel, $trialLabel)
        $roleMismatches = @($results | Where-Object { $_.ExpectedRole -and $_.ExpectedRole -ne $_.Role }).Count
        $results | Select-Object Trial, Scenario, CaseId, TimestampUtc, Decision, Expected,
            @{ n = 'Match'; e = { if ($_.Expected) { [string]($_.Decision -eq $_.Expected) } else { '' } } },
            Reason, User, ExpectedRole, Role, Device, DeviceZone, Resource, ResourceZone, Port, LatencyMs, PolicyVersion |
            Export-Csv -LiteralPath $batchPath -NoTypeInformation -Encoding ASCII

        $summary = [pscustomobject]@{
            Scenario          = $scenarioLabel
            Trial             = $trialLabel
            Count             = $results.Count
            Allowed           = $allowed
            Denied            = $denied
            LatencyMeanMs     = $stats.Mean
            LatencyP95Ms      = $stats.P95
            LatencyMinMs      = $stats.Min
            LatencyMaxMs      = $stats.Max
            LatencyThreshold  = 200
            LatencyPass       = ($stats.Mean -le 200)
            RbacCorrect       = $correct
            RbacScored        = $scored.Count
            RbacAccuracyPct   = $accuracy
            RbacThreshold     = 99
            RbacPass          = ($accuracy -ge 99)
            RoleMismatches    = $roleMismatches
            WarmUpMs          = $warmUpMs
            Seed              = $seed
            CaseFile          = $CaseFile
            CaseFileSha256    = $caseHash
            WallClockMs       = [math]::Round($totalWatch.Elapsed.TotalMilliseconds, 3)
            Offline           = [bool]$Offline
            BatchCsv          = $batchPath
            JsonLog           = $script:JsonLog
            CsvLog            = $script:CsvLog
            PolicyVersion     = $script:PolicyVersion
        }
        $summaryPath = Join-Path (Join-Path $ResultRoot 'raw') ('pdp-{0}-{1}-summary.json' -f $scenarioLabel, $trialLabel)
        $summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

        # Batch marker event (4102) keeps the logging-completeness denominator
        # verifiable when the CSV is compared with the event log.
        if (-not $NoEventLog -and $script:EventSourceReady) {
            try {
                Write-EventLog -LogName Application -Source $script:EventSource -EventId 4102 -EntryType Information `
                    -Message ('ZTNA PDP batch scenario={0} trial={1} count={2} allowed={3} denied={4} mean={5}ms p95={6}ms accuracy={7}%' -f `
                        $scenarioLabel, $trialLabel, $results.Count, $allowed, $denied, $stats.Mean, $stats.P95, $accuracy) -ErrorAction Stop
            } catch { }
        }

        Write-Host ''
        Write-Host ('Batch {0} / {1} : {2} decisions in {3} ms' -f $scenarioLabel, $trialLabel, $results.Count, $summary.WallClockMs)
        Write-Host ('  allow={0} deny={1}  latency mean={2} ms p95={3} ms (threshold 200)' -f $allowed, $denied, $stats.Mean, $stats.P95)
        Write-Host ('  RBAC accuracy={0}% ({1}/{2}) threshold 99%' -f $accuracy, $correct, $scored.Count)
        Write-Host ('  results: {0}' -f $batchPath)

        # Returned object is what 08-test-helpers.ps1 consumes over WinRM.
        Write-Output $summary
    }
    else {
        if (-not $User -or -not $Device -or -not $Resource -or -not $Port) {
            throw 'Supply -User, -Device, -Resource and -Port, or use -Batch -Count <n> -Scenario <S1..S6>.'
        }
        $decision = Invoke-ZtnaPolicyDecision -User $User -Device $Device -DeviceMac $DeviceMac `
            -Resource $Resource -Port $Port -Scenario $Scenario -CaseId 'single' -Trial $Trial
        Write-Output $decision
    }
}
catch {
    Write-Log ("FAILED: {0}" -f $_.Exception.Message) ERROR
    Write-Log ($_.ScriptStackTrace) ERROR
    $exitCode = 1
}

# Do not kill the caller when this file is dot-sourced (used by 08 helpers).
if ($MyInvocation.InvocationName -ne '.') { exit $exitCode }
