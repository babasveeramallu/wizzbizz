#requires -Version 5.1
[CmdletBinding()]
param([string]$ReportRoot='C:\TCDC_Backup\compliance')

$ErrorActionPreference='Stop'
$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $run -Force | Out-Null
$rows=@()
function Add-Check([string]$Control,[bool]$Passed,[string]$Detail) {
    $script:rows += [pscustomobject]@{Control=$Control;Status=$(if($Passed){'PASS'}else{'FAIL'});Detail=$Detail}
}

$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
Add-Check 'NET-FirewallProfiles' (@($profiles | Where-Object Enabled -ne 'True').Count -eq 0) 'All three Windows Firewall profiles should be enabled.'
$pol=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
Add-Check 'OS-LLMNRDisabled' ($pol.EnableMulticast -eq 0) 'DNSClient EnableMulticast should be 0.'
$smb=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
Add-Check 'OS-SMBv1Disabled' ($smb.State -in @('Disabled','DisablePending')) 'SMBv1 should be disabled unless a scored dependency is documented.'
$ps=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
Add-Check 'LOG-PowerShell4104' ($ps.EnableScriptBlockLogging -eq 1) 'PowerShell ScriptBlock Logging should be enabled.'
$admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)
Add-Check 'ID-AdministratorsReviewed' ($admins.Count -gt 0) "Review all $($admins.Count) local administrator members manually."

$mosq=Get-CimInstance Win32_Service | Where-Object Name -match 'mosquitto'
Add-Check 'SVC-MosquittoRunning' (@($mosq | Where-Object State -eq 'Running').Count -eq 1) 'Exactly one Mosquitto service should be running.'
Add-Check 'SVC-MosquittoAutomatic' (@($mosq | Where-Object StartMode -eq 'Auto').Count -eq 1) 'Mosquitto startup should be Automatic.'

$rows | Export-Csv (Join-Path $run 'compliance.csv') -NoTypeInformation
$rows | Format-Table -AutoSize
[pscustomobject]@{Pass=@($rows | Where-Object Status -eq PASS).Count;Fail=@($rows | Where-Object Status -eq FAIL).Count;Report=$run} |
    ConvertTo-Json | Set-Content (Join-Path $run 'summary.json') -Encoding UTF8
Write-Host 'These are explicit TCDC-safe controls, not a claim of full CIS/STIG compliance.'
