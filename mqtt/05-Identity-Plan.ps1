#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateRange(0,999)][int]$LockoutThreshold=0
)

$ErrorActionPreference='Stop'
$protected=@('blackteam','whiteteam','washington','kennedy','teddy','lincoln','ross','streep','franklin','parks','armstrong','hamilton','mlk','tubman','manziel','deniro','bush')
Write-Host "Protected users are never disabled or removed: $($protected -join ', ')"
Write-Host "Planned local lockout policy: threshold=$LockoutThreshold (0 keeps lockout disabled)"
Write-Host 'Attack-and-defense scoring accounts can be deliberately locked by bad-login attempts; default is to leave lockout disabled.'
if (-not $Apply) { Write-Host 'PLAN ONLY. Rerun with -Apply after testing a disposable account and keeping console access.'; return }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated.'
}
& net.exe accounts /lockoutthreshold:$LockoutThreshold
if ($LASTEXITCODE -ne 0) { throw 'net accounts failed.' }
& net.exe accounts
