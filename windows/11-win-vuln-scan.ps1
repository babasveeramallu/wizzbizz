#requires -Version 5.1
[CmdletBinding()]
param([string]$ReportRoot='C:\TCDC_Backup\vuln-scan')

$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from elevated PowerShell.'}

$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force|Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'|Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict scan directory: $run"}

$findings=New-Object 'System.Collections.Generic.List[object]'
function Add-Finding([string]$Severity,[string]$Check,[string]$Target,[string]$Detail){
    $findings.Add([pscustomobject]@{Severity=$Severity;Check=$Check;Target=$Target;Detail=$Detail})
}
function Get-CommandExecutable([string]$CommandLine){
    if(-not $CommandLine){return $null}
    $match=[regex]::Match($CommandLine,'^\s*(?:"([^"]+\.exe)"|(.+?\.exe)(?:\s|$))','IgnoreCase')
    if(-not $match.Success){return $null}
    $raw=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
    [Environment]::ExpandEnvironmentVariables($raw.Trim())
}

$lowPrivSids=New-Object 'System.Collections.Generic.HashSet[string]'
foreach($sid in @('S-1-1-0','S-1-5-4','S-1-5-11','S-1-5-32-545','S-1-5-32-546')){
    [void]$lowPrivSids.Add($sid)
}
$writeMask=[System.Security.AccessControl.FileSystemRights]::Write -bor
    [System.Security.AccessControl.FileSystemRights]::Modify -bor
    [System.Security.AccessControl.FileSystemRights]::FullControl -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

function Get-WeakWriteAces([string]$Path){
    if(-not $Path -or -not (Test-Path -LiteralPath $Path)){return @()}
    try{
        $hits=foreach($ace in (Get-Acl -LiteralPath $Path -ErrorAction Stop).Access){
            if($ace.AccessControlType -ne 'Allow'){continue}
            try{$sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}catch{continue}
            if($lowPrivSids.Contains($sid) -and ([int]($ace.FileSystemRights -band $writeMask) -ne 0)){
                "$($ace.IdentityReference) ($($ace.FileSystemRights))"
            }
        }
        @($hits|Sort-Object -Unique)
    }catch{@()}
}

foreach($service in @(Get-CimInstance Win32_Service)){
    $command=[string]$service.PathName
    $exe=Get-CommandExecutable $command
    if($command -notmatch '^\s*"' -and $exe -and $exe -match '\s' -and
        $exe -notmatch '^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\'){
        Add-Finding 'HIGH' 'UnquotedServicePath' $service.Name "StartName=$($service.StartName); PathName=$command"
    }
    if($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)){
        $weak=Get-WeakWriteAces $exe
        if($weak.Count){Add-Finding 'CRITICAL' 'WritableServiceBinary' $service.Name "Binary '$exe' writable by: $($weak-join '; ')"}
        $parent=Split-Path -Parent $exe
        if($parent -and $parent -notmatch '^[A-Za-z]:\\Windows(\\System32|\\SysWOW64)?$'){
            $weak=Get-WeakWriteAces $parent
            if($weak.Count){Add-Finding 'HIGH' 'WritableServiceDirectory' $service.Name "Directory '$parent' writable by: $($weak-join '; ')"}
        }
    }
}

foreach($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object {$_.TaskPath -notlike '\Microsoft\*'})){
    foreach($action in @($task.Actions)){
        if(-not $action.Execute){continue}
        $exe=Get-CommandExecutable $action.Execute
        if(-not $exe){$exe=[Environment]::ExpandEnvironmentVariables($action.Execute.Trim('"'))}
        if(Test-Path -LiteralPath $exe -PathType Leaf){
            $weak=Get-WeakWriteAces $exe
            if($weak.Count){
                Add-Finding 'CRITICAL' 'WritableTaskBinary' "$($task.TaskPath)$($task.TaskName)" "RunAs=$($task.Principal.UserId); binary '$exe' writable by: $($weak-join '; ')"
            }
        }
    }
}

foreach($directory in ($env:Path -split ';'|Where-Object {$_}|Sort-Object -Unique)){
    $expanded=[Environment]::ExpandEnvironmentVariables($directory.Trim('" '))
    $weak=Get-WeakWriteAces $expanded
    if($weak.Count){Add-Finding 'HIGH' 'WritablePathDirectory' $expanded "PATH directory writable by: $($weak-join '; ')"}
}

$installer='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
$installerUser='HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'
$aieHklm=(Get-ItemProperty $installer -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aieHkcu=(Get-ItemProperty $installerUser -ErrorAction SilentlyContinue).AlwaysInstallElevated
if($aieHklm -eq 1 -or $aieHkcu -eq 1){
    $severity=if($aieHklm -eq 1 -and $aieHkcu -eq 1){'CRITICAL'}else{'MEDIUM'}
    Add-Finding $severity 'AlwaysInstallElevated' 'Registry' "HKLM=$aieHklm; HKCU=$aieHkcu"
}

$winlogon=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if($winlogon -and $winlogon.DefaultPassword){
    Add-Finding 'CRITICAL' 'AutoLogonSecretPresent' 'Winlogon' "A DefaultPassword value exists for '$($winlogon.DefaultUserName)'; value was not read into the report."
}

foreach($file in @(
    'C:\Windows\Panther\Unattend.xml','C:\Windows\Panther\Unattended.xml',
    'C:\Windows\Panther\Unattend\Unattend.xml','C:\Windows\System32\sysprep\sysprep.xml',
    'C:\Windows\System32\sysprep\Panther\unattend.xml','C:\unattend.xml')){
    if(Test-Path -LiteralPath $file -PathType Leaf){
        Add-Finding 'HIGH' 'UnattendFilePresent' $file 'Inspect privately for stored credentials; file contents were not copied.'
    }
}

$wdigest=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
if($wdigest -eq 1){Add-Finding 'CRITICAL' 'WDigestCleartext' 'WDigest' 'UseLogonCredential=1'}
$lsa=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
if($lsa -notin 1,2){Add-Finding 'MEDIUM' 'LSASSProtection' 'Lsa' "RunAsPPL=$lsa"}
$uac=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
if($uac -ne 1){Add-Finding 'HIGH' 'UACDisabled' 'EnableLUA' "EnableLUA=$uac"}
$rdp=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if($rdp -and $rdp.UserAuthentication -ne 1){Add-Finding 'MEDIUM' 'RDP-NLA' 'RDP-Tcp' 'Network Level Authentication is not required.'}
try{$smb=Get-SmbServerConfiguration -ErrorAction Stop;if(-not $smb.RequireSecuritySignature){Add-Finding 'MEDIUM' 'SMBSigning' 'SmbServer' 'Server signing is not required.'}}catch{}
$defender=Get-MpPreference -ErrorAction SilentlyContinue
if($defender -and $defender.DisableRealtimeMonitoring){Add-Finding 'CRITICAL' 'DefenderDisabled' 'WindowsDefender' 'Real-time protection is disabled.'}

$hotfixes=@(Get-HotFix -ErrorAction SilentlyContinue|Select-Object HotFixID,Description,InstalledOn|Sort-Object InstalledOn -Descending)
$hotfixes|Export-Csv (Join-Path $run 'hotfixes.csv') -NoTypeInformation
$latest=if($hotfixes.Count){$hotfixes[0].InstalledOn}else{'NONE_REPORTED'}
Add-Finding 'INFO' 'PatchInventory' $env:COMPUTERNAME "Hotfixes=$($hotfixes.Count); latest=$latest. Compare with an approved update baseline."

$ordered=@($findings|Sort-Object @{e={switch($_.Severity){'CRITICAL'{1}'HIGH'{2}'MEDIUM'{3}default{4}}}},Check,Target)
$ordered|Export-Csv (Join-Path $run 'findings.csv') -NoTypeInformation
$ordered|Format-Table Severity,Check,Target,Detail -Wrap -AutoSize
Write-Host "Full report: $run" -ForegroundColor Cyan
