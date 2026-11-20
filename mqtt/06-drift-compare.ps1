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
    $before=Get-Content $old -Raw | ConvertFrom-Json
    $after=Get-Content $new -Raw | ConvertFrom-Json
    foreach($section in @('Services','Listeners','Firewall','Tasks','Users')) {
        $left=@($before.$section | ForEach-Object {$_ | ConvertTo-Json -Compress -Depth 5} | Sort-Object)
        $right=@($after.$section | ForEach-Object {$_ | ConvertTo-Json -Compress -Depth 5} | Sort-Object)
        $changes=Compare-Object $left $right
        if($changes){
            Write-Host "`n$section changes:" -ForegroundColor Yellow
            $changes | Format-Table SideIndicator,InputObject -AutoSize -Wrap
        } else {
            Write-Host "${section}: no drift" -ForegroundColor Green
        }
    }
    return
}

$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated PowerShell.'
}
$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict report directory: $run"}
$state=[ordered]@{
    Services=@(Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName | Sort-Object Name)
    Listeners=@(
        Get-NetTCPConnection -State Listen | Select-Object @{n='Protocol';e={'TCP'}},LocalAddress,LocalPort,
            @{n='ProcessName';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
            Sort-Object Protocol,LocalPort,LocalAddress,ProcessName
        Get-NetUDPEndpoint | Select-Object @{n='Protocol';e={'UDP'}},LocalAddress,LocalPort,
            @{n='ProcessName';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
            Sort-Object Protocol,LocalPort,LocalAddress,ProcessName
    )
    Firewall=@(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile | Sort-Object Name)
    Tasks=@(Get-ScheduledTask | Select-Object TaskPath,TaskName,State,@{n='Actions';e={($_.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments)"})-join';'}} | Sort-Object TaskPath,TaskName)
    Users=@(Get-LocalUser | Select-Object Name,Enabled,Description | Sort-Object Name)
}
$state | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $run 'state.json') -Encoding UTF8
& netsh.exe advfirewall export (Join-Path $run 'firewall.wfw') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Firewall export failed.' }
Write-Host "Baseline saved: $run"
