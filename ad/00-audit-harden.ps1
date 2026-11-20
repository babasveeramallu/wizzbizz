#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ReportRoot='C:\TCDC_Backup\ad-audit',
    [switch]$Apply,
    [switch]$DisableSpooler
)

$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from elevated PowerShell.'}
if(-not (Get-Module -ListAvailable ActiveDirectory)){throw 'ActiveDirectory PowerShell module is unavailable.'}
Import-Module ActiveDirectory -ErrorAction Stop

$computer=Get-CimInstance Win32_ComputerSystem
if([int]$computer.DomainRole -lt 4){throw 'This script must run on the Active Directory domain controller.'}
$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict AD report directory: $run"}

& netsh.exe advfirewall export (Join-Path $run 'firewall-before.wfw') | Out-Null
if($LASTEXITCODE -ne 0){throw 'Firewall export failed; aborting.'}
& auditpol.exe /backup "/file:$(Join-Path $run 'audit-policy-before.csv')" | Out-Null
if($LASTEXITCODE -ne 0){Write-Warning 'Audit policy backup failed; no audit policy will be changed.'}

Get-ADDomainController -Filter * |
    Select-Object Name,HostName,IPv4Address,Site,OperatingSystem,IsGlobalCatalog |
    Export-Csv (Join-Path $run 'domain-controllers.csv') -NoTypeInformation
Get-ADUser -Filter * -Properties MemberOf,AdminCount,DoesNotRequirePreAuth,ServicePrincipalName,PasswordNeverExpires,LastLogonDate |
    Select-Object SamAccountName,Enabled,AdminCount,DoesNotRequirePreAuth,PasswordNeverExpires,LastLogonDate,
        @{n='SPNs';e={$_.ServicePrincipalName-join ';'}},
        @{n='MemberOf';e={$_.MemberOf-join ';'}} |
    Export-Csv (Join-Path $run 'ad-users.csv') -NoTypeInformation

$privileged=@('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
    'Account Operators','Backup Operators','Server Operators','DnsAdmins','Group Policy Creator Owners')
$privilegeRows=foreach($groupName in $privileged){
    try{
        Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
            Select-Object @{n='Group';e={$groupName}},SamAccountName,ObjectClass,DistinguishedName
    }catch{}
}
$privilegeRows|Export-Csv (Join-Path $run 'privileged-groups.csv') -NoTypeInformation

Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName,Enabled |
    Export-Csv (Join-Path $run 'attack-asrep-roastable.csv') -NoTypeInformation
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName |
    Where-Object {$_.SamAccountName -ne 'krbtgt'} |
    Select-Object SamAccountName,Enabled,@{n='SPNs';e={$_.ServicePrincipalName-join '; '}} |
    Export-Csv (Join-Path $run 'attack-kerberoastable.csv') -NoTypeInformation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object SamAccountName,Enabled,TrustedForDelegation |
    Export-Csv (Join-Path $run 'attack-unconstrained-delegation-users.csv') -NoTypeInformation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object Name,Enabled,TrustedForDelegation |
    Export-Csv (Join-Path $run 'attack-unconstrained-delegation-computers.csv') -NoTypeInformation
Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,LastLogonDate,IPv4Address |
    Select-Object Name,Enabled,OperatingSystem,OperatingSystemVersion,LastLogonDate,IPv4Address |
    Export-Csv (Join-Path $run 'ad-computers.csv') -NoTypeInformation
if(Get-Command Get-GPO -ErrorAction SilentlyContinue){
    Get-GPO -All |
        Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime |
        Export-Csv (Join-Path $run 'gpos.csv') -NoTypeInformation
}

if(Test-Path 'C:\Windows\SYSVOL'){
    Get-ChildItem 'C:\Windows\SYSVOL' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {$_.Extension -in @('.ps1','.bat','.cmd','.vbs','.exe','.xml')} |
        Select-Object FullName,Length,LastWriteTime |
        Export-Csv (Join-Path $run 'sysvol-scripts.csv') -NoTypeInformation
}
$oldEap=$ErrorActionPreference
try{
    $ErrorActionPreference='Continue'
    & dcdiag.exe /q > (Join-Path $run 'dcdiag.txt') 2>&1
}finally{
    $ErrorActionPreference=$oldEap
}

Get-MpPreference -ErrorAction SilentlyContinue |
    Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess,ExclusionExtension |
    ConvertTo-Json -Depth 4 |
    Set-Content (Join-Path $run 'defender.json') -Encoding UTF8
$shareAcls=foreach($share in @(Get-SmbShare -ErrorAction SilentlyContinue)){
    try{
        Get-SmbShareAccess -Name $share.Name |
            Select-Object @{n='Share';e={$share.Name}},AccountName,AccessControlType,AccessRight
    }catch{
        [pscustomobject]@{Share=$share.Name;AccountName='ERROR';AccessControlType='';AccessRight=$_.Exception.Message}
    }
}
$shareAcls|Export-Csv (Join-Path $run 'share-acls.csv') -NoTypeInformation

$sessions=@()
$oldEap=$ErrorActionPreference
try{$ErrorActionPreference='Continue';& quser.exe 2>$null|ForEach-Object {$sessions+=$_}}
finally{$ErrorActionPreference=$oldEap}
$sessions|Set-Content (Join-Path $run 'sessions.txt') -Encoding UTF8

$wazuh=@(Get-CimInstance Win32_Service|Where-Object {$_.Name -match '^(Wazuh|ossec)'})
if($wazuh.Count -eq 0 -or @($wazuh|Where-Object State -ne 'Running').Count -gt 0){
    Write-Warning 'Managed Wazuh agent is missing or stopped. Report to Black Team; do not alter it.'
}

if(-not $Apply){
    Write-Host "PLAN ONLY. Review $run and rerun with -Apply." -ForegroundColor Yellow
    return
}

Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
$smb1=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if($smb1 -and $smb1.State -notin @('Disabled','DisablePending')){
    $result=Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Write-Host "SMBv1 disable requested; restart needed: $($result.RestartNeeded)"
}
$llmnr='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
New-Item -Path $llmnr -Force|Out-Null
New-ItemProperty -LiteralPath $llmnr -Name EnableMulticast -PropertyType DWord -Value 0 -Force|Out-Null
$scriptBlock='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $scriptBlock -Force|Out-Null
New-ItemProperty -LiteralPath $scriptBlock -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force|Out-Null
$module='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path (Join-Path $module 'ModuleNames') -Force|Out-Null
New-ItemProperty -LiteralPath $module -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force|Out-Null
New-ItemProperty -LiteralPath (Join-Path $module 'ModuleNames') -Name '*' -PropertyType String -Value '*' -Force|Out-Null

if($DisableSpooler){
    $spooler=Get-Service Spooler -ErrorAction SilentlyContinue
    if($spooler){
        Stop-Service Spooler -Force
        Set-Service Spooler -StartupType Disabled
    }
}
Write-Host "AD hardening complete. Verify DNS, Kerberos, LDAP, SMB, and WinRM scoring before hands-off." -ForegroundColor Green
