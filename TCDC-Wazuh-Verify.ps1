#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ManagerHost = 'wazuh.blackteam.playtcdc.org',
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$ManagerIP,
    [ValidateRange(1, 30)]
    [int]$TimeoutSeconds = 5,
    [string]$ReportRoot = 'C:\TCDC_Backup\wazuh-verification',
    [switch]$AllowFirewall
)

$ErrorActionPreference = 'Stop'
Write-Host 'Black Team confirms each host already has one managed, pre-enrolled agent.' -ForegroundColor Cyan
Write-Host 'This verifier protects that agent. A separate team agent is allowed only with its own ports, files, service, and configuration.' -ForegroundColor Yellow
if ($AllowFirewall -and -not $ManagerIP) {
    throw 'Use -ManagerIP with -AllowFirewall so the outbound rule has exactly one destination.'
}
if ($ManagerIP) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($ManagerIP, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'ManagerIP must be one IPv4 address.'
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this verifier from an elevated PowerShell session.'
}

New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null
$run = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $run -Force | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not restrict report ACL: $run"
}

$services = @(
    Get-CimInstance Win32_Service |
        Where-Object { $_.Name -match '^(Wazuh|ossec)' } |
        Select-Object Name, DisplayName, State, StartMode, PathName
)
$services | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'agent-services.json') -Encoding UTF8

$dns = @()
try {
    $dns = @(
        Resolve-DnsName -Name $ManagerHost -Type A -DnsOnly -ErrorAction Stop |
            Select-Object Name, Type, Address, TTL
    )
} catch {
    [pscustomobject]@{ Error = $_.Exception.Message } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'dns.json') -Encoding UTF8
}
if ($dns.Count) {
    $dns | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'dns.json') -Encoding UTF8
}

$destination = if ($ManagerIP) { $ManagerIP } else { $ManagerHost }
$client = New-Object Net.Sockets.TcpClient
try {
    $task = $client.ConnectAsync($destination, 1514)
    $completed = $task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))
    $connected = $completed -and $client.Connected
    $transport = [pscustomobject]@{
        Destination = "${destination}:1514"
        Connected = $connected
        TimedOut = -not $completed
        CheckedAt = Get-Date -Format o
        Error = $null
    }
} catch {
    $transport = [pscustomobject]@{
        Destination = "${destination}:1514"
        Connected = $false
        TimedOut = $false
        CheckedAt = Get-Date -Format o
        Error = $_.Exception.Message
    }
} finally {
    $client.Dispose()
}
$transport | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'transport.json') -Encoding UTF8

$log = @(
    'C:\Program Files (x86)\ossec-agent\ossec.log',
    'C:\Program Files\ossec-agent\ossec.log'
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ($log) {
    Get-Content -LiteralPath $log -Tail 50 | Set-Content -LiteralPath (Join-Path $run 'ossec-tail.txt') -Encoding UTF8
}

$rule = $null
if ($AllowFirewall) {
    $displayName = "TCDC-Wazuh-TCP-1514-$ManagerIP"
    $rule = @(Get-NetFirewallRule -DisplayName $displayName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    if ($rule.Count -eq 0) {
        $rule = @(New-NetFirewallRule -DisplayName $displayName -Direction Outbound -Action Allow `
            -Protocol TCP -RemoteAddress $ManagerIP -RemotePort 1514 -Profile Any)
    } elseif ($rule.Count -ne 1) {
        throw "Multiple firewall rules named '$displayName' exist; inspect them before continuing."
    }
}

$summary = [pscustomobject]@{
    ReportDirectory = $run
    AgentFound = $services.Count -gt 0
    AgentRunning = @($services | Where-Object State -eq 'Running').Count -gt 0
    ManagerHost = $ManagerHost
    ManagerIP = $ManagerIP
    Tcp1514 = $transport
    FirewallRule = if ($rule) { $displayName } else { $null }
    ChangedAgentConfiguration = $false
    Note = 'TCP reachability does not prove Wazuh enrollment or central event receipt.'
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'summary.json') -Encoding UTF8
$summary | Format-List

if (-not $summary.AgentFound) {
    Write-Warning 'No Wazuh/ossec service was found even though the managed agent should be pre-installed. Report the missing agent to Black Team.'
} elseif (-not $summary.AgentRunning) {
    Write-Warning 'The agent service is not running. Ask Black Team; do not restart or tamper with it.'
}
if (-not $transport.Connected) {
    Write-Warning 'TCP 1514 is not reachable. Check DNS, route, and firewall; no agent configuration was changed.'
}
if ($AllowFirewall) {
    Write-Warning 'Only one exact outbound TCP 1514 firewall allow was added or retained.'
}
