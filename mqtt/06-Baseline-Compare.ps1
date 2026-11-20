#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ReportRoot='C:\TCDC_Backup\drift',
    [string]$CompareOld,
    [string]$CompareNew
)

if ($CompareOld -and $CompareNew) {
    $old=Join-Path $CompareOld 'state.json'
    $new=Join-Path $CompareNew 'state.json'
    if (-not (Test-Path $old) -or -not (Test-Path $new)) { throw 'Both runs must contain state.json.' }
    Compare-Object (Get-Content $old) (Get-Content $new) |
        Format-Table -AutoSize
    return
}

$ErrorActionPreference='Stop'
$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $run -Force | Out-Null
$state=[ordered]@{
    Services=@(Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName | Sort-Object Name)
    Listeners=@(
        Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
        Get-NetUDPEndpoint | Select-Object @{n='Protocol';e={'UDP'}},LocalAddress,LocalPort,OwningProcess
    )
    Firewall=@(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile)
    Tasks=@(Get-ScheduledTask | Select-Object TaskPath,TaskName,State,@{n='Actions';e={($_.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments)"})-join';'}})
    Users=@(Get-LocalUser | Select-Object Name,Enabled,Description)
}
$state | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $run 'state.json') -Encoding UTF8
& netsh.exe advfirewall export (Join-Path $run 'firewall.wfw') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Firewall export failed.' }
Write-Host "Baseline saved: $run"
