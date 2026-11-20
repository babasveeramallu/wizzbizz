#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ReportRoot='C:\TCDC_Backup\mosquitto-check',
    [ValidateRange(1,65535)][int]$ProbePort=1883,
    [switch]$FunctionalTest
)

$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated PowerShell.'
}
$service=@(Get-CimInstance Win32_Service |
    Where-Object {$_.Name -match 'mosquitto' -or $_.DisplayName -match 'mosquitto'})
if($service.Count -ne 1){throw "Expected exactly one Mosquitto service; found $($service.Count)."}
$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict report directory: $run"}

$service[0] | Select-Object Name,DisplayName,State,StartMode,StartName,ProcessId,PathName |
    ConvertTo-Json | Set-Content (Join-Path $run 'service.json') -Encoding UTF8
$command=[string]$service[0].PathName
$match=[regex]::Match($command,'^\s*(?:"([^"]+\.exe)"|(.+?\.exe)(?:\s|$))','IgnoreCase')
$exe=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
if(-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)){throw "Could not resolve Mosquitto executable from PathName: $command"}
$install=Split-Path -Parent $exe
$configMatch=[regex]::Match($command,'(?:-c|--config-file)\s+(?:"([^"]+)"|(\S+))','IgnoreCase')
$config=if($configMatch.Success){
    if($configMatch.Groups[1].Success){$configMatch.Groups[1].Value}else{$configMatch.Groups[2].Value}
}elseif(Test-Path (Join-Path $install 'mosquitto.conf')){Join-Path $install 'mosquitto.conf'}else{$null}
if(-not $config -or -not (Test-Path $config)){throw 'Could not locate mosquitto.conf; inspect the service PathName.'}
Copy-Item -LiteralPath $config -Destination (Join-Path $run 'mosquitto.conf.bak')
$lines=Get-Content -LiteralPath $config | Where-Object {$_ -match '^\s*(listener|allow_anonymous|password_file|acl_file|cafile|certfile|keyfile|require_certificate|use_identity_as_username|include_dir)\b'}
$lines | Set-Content (Join-Path $run 'security-settings.txt') -Encoding UTF8

$client=New-Object Net.Sockets.TcpClient
try {
    $task=$client.ConnectAsync('127.0.0.1',$ProbePort)
    $connected=$task.Wait([TimeSpan]::FromSeconds(3)) -and $client.Connected
} catch {$connected=$false} finally {$client.Dispose()}

$pub=@(
    Get-Command mosquitto_pub.exe -ErrorAction SilentlyContinue
    Get-Item -LiteralPath (Join-Path $install 'mosquitto_pub.exe') -ErrorAction SilentlyContinue
) | Where-Object {$_} | Select-Object -First 1
$sub=@(
    Get-Command mosquitto_sub.exe -ErrorAction SilentlyContinue
    Get-Item -LiteralPath (Join-Path $install 'mosquitto_sub.exe') -ErrorAction SilentlyContinue
) | Where-Object {$_} | Select-Object -First 1
$anonymous=@($lines | Where-Object {$_ -match '^\s*allow_anonymous\s+true(\s+#.*)?$'}).Count -gt 0
$functional='NOT_REQUESTED'
if($FunctionalTest){
    if(-not $pub -or -not $sub){
        $functional='UNAVAILABLE'
    } elseif(-not $anonymous){
        $functional='AUTH_REQUIRED_NOT_ATTEMPTED'
        Write-Warning 'Authenticated MQTT publish/subscribe was not attempted; do not place credentials in this script or process arguments.'
    } else {
        $topic="wizzbizz/health/$([guid]::NewGuid().ToString('N'))"
        $message='ok'
        $subPath=if($sub -is [IO.FileInfo]){$sub.FullName}else{$sub.Source}
        $pubPath=if($pub -is [IO.FileInfo]){$pub.FullName}else{$pub.Source}
        $subOut=Join-Path $run 'functional-sub.txt'
        $subErr=Join-Path $run 'functional-sub.err'
        $listener=Start-Process -FilePath $subPath `
            -ArgumentList @('-h','127.0.0.1','-p',"$ProbePort",'-t',$topic,'-C','1') `
            -RedirectStandardOutput $subOut -RedirectStandardError $subErr -NoNewWindow -PassThru
        Start-Sleep -Milliseconds 500
        $publish=Start-Process -FilePath $pubPath `
            -ArgumentList @('-h','127.0.0.1','-p',"$ProbePort",'-t',$topic,'-m',$message) `
            -NoNewWindow -PassThru -Wait
        if(-not $listener.WaitForExit(5000)){
            Stop-Process -Id $listener.Id -Force -ErrorAction SilentlyContinue
            $functional='TIMEOUT'
        } elseif($publish.ExitCode -eq 0 -and
            (Test-Path -LiteralPath $subOut) -and ("$(Get-Content -LiteralPath $subOut -Raw)").Trim() -eq $message){
            $functional='PASS'
        } else {
            $functional='FAIL'
        }
    }
}
[pscustomobject]@{
    Config=$config; ProbePort=$ProbePort; LocalTcpConnected=$connected
    MosquittoPubAvailable=[bool]$pub; MosquittoSubAvailable=[bool]$sub
    AnonymousPublishSubscribe=$anonymous; FunctionalTest=$functional
    Note='An open port alone is not a functional MQTT publish/subscribe pass.'
} | ConvertTo-Json | Set-Content (Join-Path $run 'summary.json') -Encoding UTF8
if(-not $connected){Write-Warning "Mosquitto did not accept a local TCP connection on $ProbePort."}
if(-not $pub -or -not $sub){Write-Warning 'mosquitto_pub/sub are unavailable; install only from an approved source and test with the official MQTT credentials.'}
Write-Host "Mosquitto check: $run"
