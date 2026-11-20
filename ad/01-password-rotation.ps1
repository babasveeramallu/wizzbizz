#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=0)][string[]]$Account,
    [switch]$Apply,
    [string]$ReportRoot='C:\TCDC_Backup\ad-password-rotation'
)

$ErrorActionPreference='Stop'
if($Apply -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run elevated before applying.'}
if(-not (Get-Module -ListAvailable ActiveDirectory)){throw 'ActiveDirectory module is unavailable.'}
Import-Module ActiveDirectory -ErrorAction Stop
$protected=@('blackteam','whiteteam','krbtgt','Guest','DefaultAccount')
if(@($Account|Where-Object {$_ -in $protected}).Count){throw 'A protected AD identity was selected.'}
$users=@(foreach($name in ($Account|Sort-Object -Unique)){Get-ADUser -Identity $name -ErrorAction Stop})

$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force|Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not restrict AD credential directory.'}

function New-ComplexPassword {
    $alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%^_*'
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try{
        while($true){
            $bytes=New-Object byte[] 24
            $rng.GetBytes($bytes)
            $password=-join($bytes|ForEach-Object{$alphabet[$_%$alphabet.Length]})
            if($password -cmatch '[A-Z]' -and $password -cmatch '[a-z]' -and $password -match '[0-9]' -and $password -match '[!#%^_*]'){
                return $password
            }
        }
    }finally{$rng.Dispose()}
}

$csv=Join-Path $run 'credentials.csv'
$rows=foreach($user in $users){
    $password='NOT_GENERATED';$status='PLAN_ONLY'
    if($Apply){
        try{
            $password=New-ComplexPassword
            Set-ADAccountPassword -Identity $user.SamAccountName -Reset `
                -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force) -ErrorAction Stop
            $status='CHANGED'
        }catch{$password='FAILED';$status="ERROR: $($_.Exception.Message)"}
    }
    $row=[pscustomobject]@{Username=$user.SamAccountName;Password=$password;DashboardSync='REQUIRED';Status=$status}
    $row|Export-Csv -LiteralPath $csv -NoTypeInformation -Append
    $row
}
& icacls.exe $csv /inheritance:r /grant:r "*${identity}:F" '*S-1-5-18:F'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not restrict credentials.csv.'}
$rows|Format-Table -AutoSize
Write-Host "Private AD credential sheet: $csv" -ForegroundColor Cyan
Write-Warning 'Immediately update https://dash.playtcdc.org/team/passwords for every changed account.'
$failed=@($rows|Where-Object {$_.Status -like 'ERROR:*'}).Count
if($failed){throw "$failed AD password change(s) failed; review $csv"}
