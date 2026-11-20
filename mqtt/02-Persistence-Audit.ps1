#requires -Version 5.1
[CmdletBinding()]
param([string]$ReportRoot = 'C:\TCDC_Backup\persistence')

$ErrorActionPreference = 'Stop'
$run = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $run -Force | Out-Null

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
Write-Host "Persistence evidence: $run" -ForegroundColor Cyan
Write-Warning 'Audit only. Nothing was disabled or removed.'
