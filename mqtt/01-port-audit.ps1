#requires -Version 5.1
[CmdletBinding()]
param([string]$ReportRoot = 'C:\TCDC_Backup\ports')

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated PowerShell.'
}

$run = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict report directory: $run"}

$mosquitto = @(
    Get-CimInstance Win32_Service |
        Where-Object { $_.Name -match 'mosquitto' -or $_.DisplayName -match 'mosquitto' }
)
$mqttPid = if ($mosquitto.Count -eq 1) { [int]$mosquitto[0].ProcessId } else { 0 }
$processes = @{}
Get-CimInstance Win32_Process | ForEach-Object { $processes[[int]$_.ProcessId] = $_.Name }

$rows = @()
foreach ($socket in @(Get-NetTCPConnection -State Listen)) {
    $rows += [pscustomobject]@{
        Protocol = 'TCP'; LocalAddress = $socket.LocalAddress; LocalPort = $socket.LocalPort
        ProcessId = $socket.OwningProcess; Process = $processes[[int]$socket.OwningProcess]
        Classification = if ($mqttPid -gt 0 -and [int]$socket.OwningProcess -eq $mqttPid) { 'SCORED-MQTT' } else { 'REVIEW' }
    }
}
foreach ($socket in @(Get-NetUDPEndpoint)) {
    $rows += [pscustomobject]@{
        Protocol = 'UDP'; LocalAddress = $socket.LocalAddress; LocalPort = $socket.LocalPort
        ProcessId = $socket.OwningProcess; Process = $processes[[int]$socket.OwningProcess]
        Classification = if ([int]$socket.OwningProcess -eq 4) { 'SYSTEM-REVIEW' } else { 'REVIEW' }
    }
}
$rows = @($rows | Sort-Object Protocol, LocalPort, LocalAddress)
$rows | Export-Csv -LiteralPath (Join-Path $run 'listeners.csv') -NoTypeInformation
Write-Host "MQTT port audit: $run\listeners.csv" -ForegroundColor Cyan
$rows | Format-Table -AutoSize
Write-Host 'Review every REVIEW listener before opening a firewall port.' -ForegroundColor Yellow
