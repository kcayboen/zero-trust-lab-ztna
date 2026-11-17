#Requires -Version 5.1
<#
.SYNOPSIS
    12 - One SOP 3 trial of network-access cases (S6 Network family, S5 lateral movement).

.DESCRIPTION
    Thesis context (Table 2, logging completeness): every granted and denied cross-zone
    access must appear in the OPNsense firewall log. This runner produces the ground
    truth: for each case of the case file whose Workstation is this computer and whose
    Mechanism is Tcp, it opens one TCP connection to DstIp:Port from a FIXED local port
    (PortBase + PortOffset) and records the attempt with its UTC time. The fixed
    (source IP, source port, destination IP, destination port) tuple is the exact key
    the counting script looks for in the OPNsense filter log (plan/s6-logging-design.md).

    Order: shuffled with seed = trial number. 300 ms pause between attempts.

.PARAMETER PortBase
    Default 40000 + 1000 x trial number, so source ports never repeat across trials
    (a closed connection holds its port in TIME_WAIT for ~2 minutes).

.EXAMPLE
    PS> .\12-net-trial.ps1 -CaseFile C:\ZTNA\cases\S6-logging-cases.csv -Trial T1

.NOTES
    Output: C:\ZTNA\results\raw\net-<Scenario>-<Trial>-<HOST>.csv and -summary.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaseFile,
    [Parameter(Mandatory = $true)][ValidateSet('T1', 'T2', 'T3', 'T4', 'T5')][string]$Trial,
    [ValidateSet('S5', 'S6')][string]$Scenario = 'S6',
    [int]$PortBase = 0,
    [int]$TimeoutMs = 1500,
    [string]$ResultRoot = 'C:\ZTNA\results\raw'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $ResultRoot -Force | Out-Null
$hostName = $env:COMPUTERNAME
$seed = [int]$Trial.Substring(1)
if ($PortBase -le 0) { $PortBase = 40000 + 1000 * $seed }
$rng = New-Object System.Random $seed

# Source address = this host's lab IPv4 address (the one OPNsense sees).
$srcIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '10.20.*' } | Select-Object -First 1).IPAddress
if (-not $srcIp) { throw 'No 10.20.x.x address on this host.' }

$rows = @(Import-Csv -LiteralPath $CaseFile | Where-Object { $_.Workstation -eq $hostName -and $_.Mechanism -eq 'Tcp' } |
        Sort-Object CaseId | Sort-Object { $rng.Next() })
if ($rows.Count -eq 0) { throw "No Tcp cases for $hostName in $CaseFile" }

$caseHash = (Get-FileHash -LiteralPath $CaseFile -Algorithm SHA256).Hash
$startUtc = (Get-Date).ToUniversalTime()
$results = foreach ($c in $rows) {
    $srcPort = $PortBase + [int]$c.PortOffset
    $client = New-Object System.Net.Sockets.TcpClient
    $connected = $false
    $errorText = ''
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    try {
        $client.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($srcIp), $srcPort)))
        $task = $client.ConnectAsync($c.DstIp, [int]$c.Port)
        $connected = $task.Wait($TimeoutMs) -and $client.Connected
    } catch {
        $errorText = $_.Exception.InnerException.Message
        if (-not $errorText) { $errorText = $_.Exception.Message }
    } finally {
        $client.Close()
    }
    [pscustomobject]@{
        Trial        = $Trial
        Scenario     = $Scenario
        CaseId       = $c.CaseId
        Workstation  = $hostName
        TimestampUtc = $ts
        SrcIp        = $srcIp
        SrcPort      = $srcPort
        DstIp        = $c.DstIp
        DstPort      = $c.Port
        Expected     = $c.Expected
        Granted      = $c.Granted
        Connected    = $connected
        Error        = $errorText
    }
    Start-Sleep -Milliseconds 300
}
$endUtc = (Get-Date).ToUniversalTime()

$csv = Join-Path $ResultRoot ('net-{0}-{1}-{2}.csv' -f $Scenario, $Trial, $hostName)
$results | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding ASCII
[pscustomobject]@{
    Scenario = $Scenario; Trial = $Trial; Workstation = $hostName; Cases = @($results).Count
    Connected = @($results | Where-Object { $_.Connected }).Count; PortBase = $PortBase; Seed = $seed
    CaseFileSha256 = $caseHash
    StartUtc = $startUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'); EndUtc = $endUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
} | ConvertTo-Json | Set-Content -LiteralPath ($csv -replace '\.csv$', '-summary.json') -Encoding UTF8
'{6} {0} {1} net: cases={2} connected={3} (granted expected {4}) portBase={5}' -f $Trial, $hostName, @($results).Count,
    @($results | Where-Object { $_.Connected }).Count, @($results | Where-Object { $_.Granted -eq 'True' }).Count, $PortBase, $Scenario
