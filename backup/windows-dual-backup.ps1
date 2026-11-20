#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$LocalBackupRoot='C:\TCDC_Backup\local-vault',
    [string]$JumpboxShare,
    [string]$ScpTarget,
    [string[]]$ExtraPaths=@()
)

$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from elevated PowerShell.'}
if(-not $JumpboxShare -and -not $ScpTarget){
    Write-Warning 'No off-host target supplied; only a local backup will be created.'
}

$timestamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$hostTag=$env:COMPUTERNAME
$run=Join-Path $LocalBackupRoot "$hostTag-$timestamp"
New-Item -ItemType Directory -Path $LocalBackupRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict backup directory: $run"}

& netsh.exe advfirewall export (Join-Path $run 'firewall.wfw') | Out-Null
if($LASTEXITCODE -ne 0){Write-Warning 'Firewall export failed.'}
& auditpol.exe /backup "/file:$(Join-Path $run 'audit-policy.csv')" | Out-Null
if($LASTEXITCODE -ne 0){Write-Warning 'Audit policy export failed.'}

Get-CimInstance Win32_Service |
    Select-Object Name,DisplayName,State,StartMode,StartName,ProcessId,PathName |
    Export-Csv (Join-Path $run 'services.csv') -NoTypeInformation
Get-ScheduledTask |
    Where-Object {$_.TaskPath -notlike '\Microsoft\*'} |
    Select-Object TaskPath,TaskName,State,Author,@{n='Actions';e={
        ($_.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments)"})-join '; '
    }} | Export-Csv (Join-Path $run 'custom-tasks.csv') -NoTypeInformation

if(Get-Command Get-LocalUser -ErrorAction SilentlyContinue){
    try{
        Get-LocalUser | Select-Object Name,Enabled,LastLogon,Description |
            Export-Csv (Join-Path $run 'local-users.csv') -NoTypeInformation
        $admins=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        Get-LocalGroupMember -Group $admins.Name |
            Select-Object Name,ObjectClass,PrincipalSource,SID |
            Export-Csv (Join-Path $run 'local-admins.csv') -NoTypeInformation
    }catch{Write-Warning "Local account export incomplete: $($_.Exception.Message)"}
}

$mosquitto=@(Get-CimInstance Win32_Service |
    Where-Object {$_.Name -match 'mosquitto' -or $_.DisplayName -match 'mosquitto'}) |
    Select-Object -First 1
if($mosquitto){
    $command=[string]$mosquitto.PathName
    $match=[regex]::Match($command,'^\s*(?:"([^"]+\.exe)"|(.+?\.exe)(?:\s|$))','IgnoreCase')
    $exe=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
    if($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)){
        $install=Split-Path -Parent $exe
        $output=Join-Path $run 'mosquitto'
        New-Item -ItemType Directory -Path $output -Force | Out-Null
        Copy-Item -LiteralPath $install -Destination (Join-Path $output 'install') -Recurse -Force
        $cfgMatch=[regex]::Match($command,'(?:-c|--config-file)\s+(?:"([^"]+)"|(\S+))','IgnoreCase')
        if($cfgMatch.Success){
            $config=if($cfgMatch.Groups[1].Success){$cfgMatch.Groups[1].Value}else{$cfgMatch.Groups[2].Value}
            if(Test-Path -LiteralPath $config -PathType Leaf){
                Copy-Item -LiteralPath $config -Destination (Join-Path $output 'mosquitto.conf') -Force
            }
        }
    }
}

if(Get-Module -ListAvailable ActiveDirectory){
    try{
        Import-Module ActiveDirectory -ErrorAction Stop
        Get-ADUser -Filter * -Properties MemberOf,AdminCount,DoesNotRequirePreAuth,ServicePrincipalName |
            Select-Object SamAccountName,Enabled,AdminCount,DoesNotRequirePreAuth,
                @{n='MemberOf';e={$_.MemberOf-join ';'}} |
            Export-Csv (Join-Path $run 'ad-users.csv') -NoTypeInformation
        Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory,DistinguishedName |
            Export-Csv (Join-Path $run 'ad-groups.csv') -NoTypeInformation
        if(Get-Command Get-GPO -ErrorAction SilentlyContinue){
            Get-GPO -All | Select-Object DisplayName,Id,GpoStatus,ModificationTime |
                Export-Csv (Join-Path $run 'ad-gpos.csv') -NoTypeInformation
        }
    }catch{Write-Warning "Active Directory export incomplete: $($_.Exception.Message)"}
}

foreach($extra in $ExtraPaths){
    if(Test-Path -LiteralPath $extra){
        Copy-Item -LiteralPath $extra -Destination (Join-Path $run ('extra-'+(Split-Path -Leaf $extra))) -Recurse -Force
    }else{Write-Warning "Extra path not found: $extra"}
}

$zip="$run.zip"
$hashFile="$zip.sha256"
Compress-Archive -Path (Join-Path $run '*') -DestinationPath $zip -Force
$hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
"$hash  $(Split-Path -Leaf $zip)" | Set-Content -LiteralPath $hashFile -Encoding ASCII
foreach($file in @($zip,$hashFile)){
    & icacls.exe $file /inheritance:r /grant:r "*${identity}:F" '*S-1-5-18:F' | Out-Null
    if($LASTEXITCODE -ne 0){throw "Could not restrict backup file: $file"}
}
Write-Host "Local archive: $zip" -ForegroundColor Green

if($JumpboxShare){
    if(-not (Test-Path -LiteralPath $JumpboxShare -PathType Container)){
        throw "Jumpbox share not reachable: $JumpboxShare"
    }
    $destination=Join-Path $JumpboxShare $hostTag
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $copy=Join-Path $destination (Split-Path -Leaf $zip)
    $copyHash=Join-Path $destination (Split-Path -Leaf $hashFile)
    Copy-Item -LiteralPath $zip -Destination $copy -Force
    Copy-Item -LiteralPath $hashFile -Destination $copyHash -Force
    if((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne $hash){
        throw "Jumpbox share verification failed: $copy"
    }
    Write-Host "Verified jumpbox copy: $copy" -ForegroundColor Green
}

if($ScpTarget){
    $scp=Get-Command scp.exe -ErrorAction SilentlyContinue
    if(-not $scp){throw 'scp.exe was not found.'}
    & $scp.Source $zip $hashFile $ScpTarget
    if($LASTEXITCODE -ne 0){throw "Interactive SCP transfer failed: $ScpTarget"}
    Write-Warning 'SCP transport completed, but this script did not read back the remote hash. Verify it on the jumpbox.'
}
