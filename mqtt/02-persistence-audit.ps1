#requires -Version 5.1
[CmdletBinding()]
param([string]$ReportRoot = 'C:\TCDC_Backup\persistence')

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated PowerShell.'
}
$run = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict report directory: $run"}

$tasks = Get-ScheduledTask |
    Where-Object TaskPath -notlike '\Microsoft\*' |
    Select-Object TaskPath, TaskName, State, Author,
        @{n='Actions';e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ' }}
$services = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName
$wmi = foreach ($class in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
    Get-CimInstance -Namespace root\subscription -ClassName $class |
        Select-Object @{n='Class';e={$class}}, *
}
$defender = Get-MpPreference -ErrorAction SilentlyContinue |
    Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring
$sessions = @()
try {
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & quser.exe 2>$null | ForEach-Object { $sessions += $_ }
} finally {
    $ErrorActionPreference = $previousEap
}
$shareAcls = @()
foreach($share in @(Get-SmbShare -ErrorAction SilentlyContinue)) {
    try {
        $shareAcls += Get-SmbShareAccess -Name $share.Name |
            Select-Object @{n='Share';e={$share.Name}},AccountName,AccessControlType,AccessRight
    } catch {
        $shareAcls += [pscustomobject]@{Share=$share.Name;AccountName='ERROR';AccessControlType='';AccessRight=$_.Exception.Message}
    }
}

$autoruns = @()
foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion'
)) {
    foreach ($key in @('Run','RunOnce')) {
        $path = Join-Path $root $key
        if (Test-Path -LiteralPath $path) {
            $item = Get-ItemProperty -LiteralPath $path
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -notmatch '^PS') {
                    $autoruns += [pscustomobject]@{ Key=$path; Name=$property.Name; Value=[string]$property.Value }
                }
            }
        }
    }
}

$tasks | Export-Csv (Join-Path $run 'tasks.csv') -NoTypeInformation
$services | Export-Csv (Join-Path $run 'services.csv') -NoTypeInformation
$autoruns | Export-Csv (Join-Path $run 'autoruns.csv') -NoTypeInformation
$wmi | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'wmi.json') -Encoding UTF8
$defender | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'defender.json') -Encoding UTF8
$sessions | Set-Content (Join-Path $run 'sessions.txt') -Encoding UTF8
$shareAcls | Export-Csv (Join-Path $run 'share-acls.csv') -NoTypeInformation
Write-Host "Persistence evidence: $run" -ForegroundColor Cyan
Write-Warning 'Audit only. Nothing was disabled or removed.'
