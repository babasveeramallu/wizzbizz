#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateRange(0,999)][int]$LockoutThreshold=5
)

$ErrorActionPreference='Stop'
$protected=@('blackteam','whiteteam','washington','kennedy','teddy','lincoln','ross','streep','franklin','parks','armstrong','hamilton','mlk','tubman','manziel','deniro','bush')
Write-Host "Protected users are never disabled or removed: $($protected -join ', ')"
Write-Host "Planned local lockout policy: threshold=$LockoutThreshold, duration=30 minutes, window=30 minutes"
Write-Host 'Scored/service accounts can be locked by failed checks; update the scoreboard plan before applying.'
if (-not $Apply) { Write-Host 'PLAN ONLY. Rerun with -Apply after testing a disposable account and keeping console access.'; return }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated.'
}
& net.exe accounts /lockoutthreshold:$LockoutThreshold /lockoutduration:30 /lockoutwindow:30
if ($LASTEXITCODE -ne 0) { throw 'net accounts failed.' }
& net.exe accounts
