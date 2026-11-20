#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ReportRoot='C:\TCDC_Backup\mosquitto-check',
    [ValidateRange(1,65535)][int]$ProbePort=1883
)

$ErrorActionPreference='Stop'
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
$match=[regex]::Match($command,'^\s*(?:"([^"]+)"|(\S+))')
$exe=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
$install=Split-Path -Parent $exe
$configMatch=[regex]::Match($command,'(?:-c|--config-file)\s+(?:"([^"]+)"|(\S+))','IgnoreCase')
$config=if($configMatch.Success){
    if($configMatch.Groups[1].Success){$configMatch.Groups[1].Value}else{$configMatch.Groups[2].Value}
}elseif(Test-Path (Join-Path $install 'mosquitto.conf')){Join-Path $install 'mosquitto.conf'}else{$null}
if(-not $config -or -not (Test-Path $config)){throw 'Could not locate mosquitto.conf; inspect the service PathName.'}
Copy-Item -LiteralPath $config -Destination (Join-Path $run 'mosquitto.conf.bak')
$lines=Get-Content -LiteralPath $config | Where-Object {$_ -match '^\s*(listener|allow_anonymous|password_file|acl_file|cafile|certfile|keyfile|require_certificate|use_identity_as_username)\b'} 
$lines | Set-Content (Join-Path $run 'security-settings.txt') -Encoding UTF8

$client=New-Object Net.Sockets.TcpClient
try {
    $task=$client.ConnectAsync('127.0.0.1',$ProbePort)
    $connected=$task.Wait([TimeSpan]::FromSeconds(3)) -and $client.Connected
} catch {$connected=$false} finally {$client.Dispose()}

$pub=Get-Command mosquitto_pub.exe -ErrorAction SilentlyContinue
$sub=Get-Command mosquitto_sub.exe -ErrorAction SilentlyContinue
[pscustomobject]@{
    Config=$config; ProbePort=$ProbePort; LocalTcpConnected=$connected
    MosquittoPubAvailable=[bool]$pub; MosquittoSubAvailable=[bool]$sub
    Note='An open port alone is not a functional MQTT publish/subscribe pass.'
} | ConvertTo-Json | Set-Content (Join-Path $run 'summary.json') -Encoding UTF8
if(-not $connected){Write-Warning "Mosquitto did not accept a local TCP connection on $ProbePort."}
if(-not $pub -or -not $sub){Write-Warning 'mosquitto_pub/sub are unavailable; install only from an approved source and test with the official MQTT credentials.'}
Write-Host "Mosquitto check: $run"
