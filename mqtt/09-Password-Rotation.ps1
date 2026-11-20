#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=0)][string[]]$Account,
    [switch]$Apply,
    [string]$ReportRoot='C:\TCDC_Backup\password-rotation'
)

$ErrorActionPreference='Stop'
if($Apply -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run elevated before changing passwords.'
}
$protected=@('blackteam','whiteteam','Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
if (@($Account | Where-Object {$_ -in $protected}).Count) { throw 'A protected competition account was selected.' }
$users=@(foreach($name in ($Account|Sort-Object -Unique)){Get-LocalUser -Name $name -ErrorAction Stop})
$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not restrict credential directory.'}

$alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-+='
$rows=foreach($user in $users){
    $password='NOT_GENERATED'
    $status='PLAN_ONLY'
    if($Apply){
        $bytes=New-Object byte[] 24
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
        $password=-join ($bytes | ForEach-Object {$alphabet[$_ % $alphabet.Length]})
        Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $password -AsPlainText -Force)
        $status='CHANGED'
    }
    [pscustomobject]@{Username=$user.Name;Password=$password;DashboardSync='REQUIRED';Status=$status}
}
$rows | Export-Csv (Join-Path $run 'credentials.csv') -NoTypeInformation
& icacls.exe (Join-Path $run 'credentials.csv') /inheritance:r /grant:r "*${identity}:F" '*S-1-5-18:F' | Out-Null
$rows | Format-Table -AutoSize
Write-Warning 'Immediately update https://dash.playtcdc.org/team/passwords for every changed score user.'
