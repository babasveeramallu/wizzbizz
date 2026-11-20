#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateRange(1,65535)][int[]]$Port,
    [string]$BackupRoot = 'C:\TCDC_Backup\mqtt-protect',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated PowerShell.'
}
$service = @(Get-CimInstance Win32_Service |
    Where-Object { $_.Name -match 'mosquitto' -or $_.DisplayName -match 'mosquitto' })
if ($service.Count -ne 1) {
    throw "Expected exactly one Mosquitto service; found $($service.Count)."
}
$pid = [int]$service[0].ProcessId
if ($pid -le 0) { throw 'Mosquitto service is not running.' }
$open = @(Get-NetTCPConnection -State Listen -OwningProcess $pid |
    Select-Object -ExpandProperty LocalPort -Unique)
$missing = @($Port | Where-Object { $_ -notin $open })
if ($missing.Count) {
    throw "Mosquitto is not listening on: $($missing -join ', '). Run the 01 port audit first."
}

$run = Join-Path $BackupRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $run -Force | Out-Null
& netsh.exe advfirewall export (Join-Path $run 'before.wfw') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Firewall export failed.' }

if (-not $Apply) {
    "Would allow TCP port(s) from Any: $($Port -join ', ')" | Set-Content (Join-Path $run 'plan.txt')
    Write-Host "Plan only. Review $run\plan.txt; rerun with -Apply." -ForegroundColor Yellow
    return
}

Set-Service -Name $service[0].Name -StartupType Automatic
if ((Get-Service -Name $service[0].Name).Status -ne 'Running') {
    Start-Service -Name $service[0].Name
}
foreach ($p in $Port | Sort-Object -Unique) {
    $name = "WizzBizz-MQTT-TCP-$p"
    $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $name -ErrorAction SilentlyContinue)
    if ($existing.Count -eq 0) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $p -RemoteAddress Any -Profile Any | Out-Null
    } elseif ($existing.Count -gt 1) {
        throw "Multiple MQTT protection rules named '$name' exist; inspect before continuing."
    }
}
Get-NetTCPConnection -State Listen -OwningProcess $pid |
    Select-Object LocalAddress,LocalPort |
    Export-Csv (Join-Path $run 'mosquitto-after.csv') -NoTypeInformation
Write-Host "MQTT remains listening on: $(($Port -join ', ')); firewall backup: $run\before.wfw" -ForegroundColor Green
