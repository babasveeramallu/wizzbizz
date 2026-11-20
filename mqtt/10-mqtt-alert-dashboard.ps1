#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1,65535)][int[]]$MqttPorts=@(1883),
    [ValidateRange(5,300)][int]$IntervalSeconds=15,
    [ValidateRange(1,100)][int]$FailedLogonBurstThreshold=5,
    [ValidateRange(0,1000)][int]$Cycles=0,
    [string]$WazuhManagerIP='10.100.0.11',
    [string]$ReportRoot='C:\TCDC_Backup\dashboard',
    [switch]$OpenHtml
)

$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from elevated PowerShell.'}

$run=Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $ReportRoot,$run -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw "Could not restrict dashboard directory: $run"}
$htmlPath=Join-Path $run 'dashboard.html'
$alertLog=Join-Path $run 'alerts.log'
$alerts=New-Object 'System.Collections.Generic.List[object]'
$state=@{}
$lastRecord=@{}

function ConvertTo-HtmlText([AllowNull()][string]$Value){
    if($null -eq $Value){return ''}
    [Net.WebUtility]::HtmlEncode($Value)
}
function Add-Alert([string]$Severity,[string]$Category,[string]$Message){
    $entry=[pscustomobject]@{
        FullTime=Get-Date -Format 'o'; Time=Get-Date -Format 'HH:mm:ss'
        Severity=$Severity; Category=$Category; Message=$Message
    }
    $alerts.Insert(0,$entry)
    while($alerts.Count -gt 150){$alerts.RemoveAt($alerts.Count-1)}
    Add-Content -LiteralPath $alertLog -Value "[$($entry.FullTime)] [$Severity] [$Category] $Message" -Encoding UTF8
}
function Get-HostProcessMap {
    $map=@{}
    foreach($process in @(Get-CimInstance Win32_Process)){
        $map[[int]$process.ProcessId]=$process
    }
    $map
}
function Get-MosquittoStatus {
    $svc=@(Get-CimInstance Win32_Service |
        Where-Object {$_.Name -match 'mosquitto' -or $_.DisplayName -match 'mosquitto'}) |
        Select-Object -First 1
    if(-not $svc){
        return [pscustomobject]@{Found=$false;State='MISSING';ProcessId=0;ConfigPath=$null;ConfigHash=$null}
    }
    $command=[string]$svc.PathName
    $exeMatch=[regex]::Match($command,'^\s*(?:"([^"]+\.exe)"|(.+?\.exe)(?:\s|$))','IgnoreCase')
    $exe=if($exeMatch.Groups[1].Success){$exeMatch.Groups[1].Value}else{$exeMatch.Groups[2].Value}
    $install=if($exe){Split-Path -Parent $exe}else{$null}
    $cfgMatch=[regex]::Match($command,'(?:-c|--config-file)\s+(?:"([^"]+)"|(\S+))','IgnoreCase')
    $config=if($cfgMatch.Success){
        if($cfgMatch.Groups[1].Success){$cfgMatch.Groups[1].Value}else{$cfgMatch.Groups[2].Value}
    }elseif($install -and (Test-Path -LiteralPath (Join-Path $install 'mosquitto.conf'))){
        Join-Path $install 'mosquitto.conf'
    }else{$null}
    $hash=if($config -and (Test-Path -LiteralPath $config -PathType Leaf)){
        (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
    }else{$null}
    [pscustomobject]@{Found=$true;State=$svc.State;ProcessId=[int]$svc.ProcessId;ConfigPath=$config;ConfigHash=$hash}
}
function Get-Set([scriptblock]$Command){@(& $Command | Sort-Object -Unique)}
function Add-StateChange([string]$Key,[object]$Current,[string]$Severity,[string]$Category,[string]$Message){
    $value=[string]$Current
    if($state.ContainsKey($Key) -and $state[$Key] -ne $value){
        Add-Alert $Severity $Category $Message
    }
    $state[$Key]=$value
}
function Add-NewItems([string]$Prefix,[string[]]$Baseline,[string[]]$Current,[string]$Severity,[string]$Category,[string]$Label){
    foreach($item in @($Current | Where-Object {$_ -notin $Baseline})){
        $key="$Prefix`:$item"
        if(-not $state.ContainsKey($key)){
            Add-Alert $Severity $Category "$Label`: $item"
            $state[$key]=$true
        }
    }
}
function Get-AdminNames {
    try{Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {$_.Name}|Sort-Object -Unique}
    catch{@()}
}
function Get-CustomTasks {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} |
        ForEach-Object{
            $actions=($_.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments)"})-join '; '
            "$($_.TaskPath)$($_.TaskName) => $actions"
        } | Sort-Object -Unique
}
function Get-Autoruns {
    $rows=foreach($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')){
        if(Test-Path -LiteralPath $key){
            $item=Get-ItemProperty -LiteralPath $key
            foreach($property in $item.PSObject.Properties){
                if($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$'){
                    "$key\$($property.Name)=$($property.Value)"
                }
            }
        }
    }
    @($rows|Sort-Object -Unique)
}
function Get-RecentEvents([string]$LogName,[int[]]$Ids){
    $after=[int64]0
    if($lastRecord.ContainsKey($LogName)){$after=$lastRecord[$LogName]}
    else{$after=(Get-LatestRecordId $LogName)}
    try{
        $events=@(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=$Ids} -MaxEvents 500 -ErrorAction Stop |
            Where-Object {[int64]$_.RecordId -gt $after}|Sort-Object RecordId)
    }catch{return @()}
    if($events.Count){$lastRecord[$LogName]=[int64]$events[-1].RecordId}
    @($events)
}
function Get-LatestRecordId([string]$LogName){
    try{[int64](Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop).RecordId}catch{[int64]0}
}
function New-SessionLines {
    $previous=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';@(& quser.exe 2>$null|ForEach-Object {$_.Trim()})}
    finally{$ErrorActionPreference=$previous}
}

$procMap=Get-HostProcessMap
$baseMqtt=Get-MosquittoStatus
$baseListeners=Get-Set {Get-NetTCPConnection -State Listen|ForEach-Object{
    $procId=[int]$_.OwningProcess
    "$($_.LocalAddress):$($_.LocalPort) [$($procMap[$procId].Name)]"
}}
$baseAdmins=Get-AdminNames
$baseTasks=Get-CustomTasks
$baseAutoruns=Get-Autoruns
$baseSessions=New-SessionLines
foreach($log in @('Security','System','Microsoft-Windows-PowerShell/Operational')){
    $lastRecord[$log]=Get-LatestRecordId $log
}
$state['mqtt-running']=$baseMqtt.State
$state['mqtt-hash']=$baseMqtt.ConfigHash
Add-Alert 'INFO' 'STARTUP' "Dashboard started on $env:COMPUTERNAME; MQTT ports: $($MqttPorts -join ', ')"
if(-not $baseMqtt.Found -or $baseMqtt.State -ne 'Running'){
    Add-Alert 'CRITICAL' 'SCORED-MQTT' "Mosquitto is not running at startup: $($baseMqtt.State)."
}
if(-not $baseMqtt.ConfigHash){
    Add-Alert 'HIGH' 'BASELINE' 'Could not resolve and hash mosquitto.conf at startup.'
}

function Write-Dashboard([object]$Mqtt,[int[]]$OpenPorts,[object]$Wazuh,[object]$Established,[string[]]$Sessions){
    $mqttOk=$Mqtt.State -eq 'Running' -and @($MqttPorts|Where-Object {$_ -notin $OpenPorts}).Count -eq 0
    $configOk=-not $baseMqtt.ConfigHash -or $Mqtt.ConfigHash -eq $baseMqtt.ConfigHash
    $wazuhOk=$Wazuh -and $Wazuh.State -eq 'Running'
    $alertRows=foreach($alert in $alerts){
        "<tr><td>$(ConvertTo-HtmlText $alert.Time)</td><td>$(ConvertTo-HtmlText $alert.Severity)</td><td>$(ConvertTo-HtmlText $alert.Category)</td><td>$(ConvertTo-HtmlText $alert.Message)</td></tr>"
    }
    $connectionRows=foreach($connection in $Established){
        "<tr><td>$(ConvertTo-HtmlText $connection.Process)</td><td>$(ConvertTo-HtmlText "$($connection.LocalAddress):$($connection.LocalPort)")</td><td>$(ConvertTo-HtmlText "$($connection.RemoteAddress):$($connection.RemotePort)")</td></tr>"
    }
    $sessionsText=if($Sessions.Count){ConvertTo-HtmlText ($Sessions -join "`n")}else{'No active interactive sessions.'}
    $html=@"
<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="$IntervalSeconds">
<title>MQTT Alert Dashboard - $(ConvertTo-HtmlText $env:COMPUTERNAME)</title>
<style>body{background:#0d1117;color:#e6edf3;font:14px Consolas,monospace;margin:20px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{background:#161b22;border:1px solid #30363d;padding:12px}.ok{border-left:5px solid #2ea043}.bad{border-left:5px solid #f85149}table{width:100%;border-collapse:collapse;background:#161b22;margin-top:12px}th,td{padding:7px;border-bottom:1px solid #30363d;text-align:left}th{background:#21262d}pre{background:#161b22;padding:10px}</style></head>
<body><h1>MQTT Alert Dashboard - $(ConvertTo-HtmlText $env:COMPUTERNAME)</h1>
<p>Updated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Refresh ${IntervalSeconds}s | Read-only, no listener port</p>
<div class="grid"><div class="card $(if($mqttOk){'ok'}else{'bad'})">MQTT: $(ConvertTo-HtmlText $Mqtt.State)<br>Ports: $(ConvertTo-HtmlText ($OpenPorts -join ', '))</div>
<div class="card $(if($configOk){'ok'}else{'bad'})">Config: $(if($configOk){'baseline'}else{'MODIFIED'})</div>
<div class="card $(if($wazuhOk){'ok'}else{'bad'})">Managed Wazuh: $(if($Wazuh){ConvertTo-HtmlText $Wazuh.State}else{'NOT FOUND'})</div></div>
<h2>Alerts</h2><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Details</th></tr>$($alertRows -join "`n")</table>
<h2>Remote connections</h2><table><tr><th>Process</th><th>Local</th><th>Remote</th></tr>$($connectionRows -join "`n")</table>
<h2>Interactive sessions</h2><pre>$sessionsText</pre></body></html>
"@
    $temp="$htmlPath.tmp"
    Set-Content -LiteralPath $temp -Value $html -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $htmlPath -Force
}

$opened=$false
$cycle=0
$suspicious='(?i)(encodedcommand|downloadstring|downloadfile|invoke-expression|\biex\b|frombase64string|net\.webclient|set-mppreference|invoke-webrequest|mimikatz)'
Write-Host "Dashboard report: $run" -ForegroundColor Cyan
while($true){
    $procMap=Get-HostProcessMap
    $mqtt=Get-MosquittoStatus
    $mqttPorts=@()
    if($mqtt.ProcessId -gt 0){
        $mqttPorts=@(Get-NetTCPConnection -State Listen -OwningProcess $mqtt.ProcessId -ErrorAction SilentlyContinue|
            Select-Object -ExpandProperty LocalPort -Unique|Sort-Object)
    }
    $wazuh=@(Get-CimInstance Win32_Service|Where-Object {$_.Name -match '^(Wazuh|ossec)'})|Select-Object -First 1
    Add-StateChange 'mqtt-running' $mqtt.State 'CRITICAL' 'SCORED-MQTT' "Mosquitto changed state to $($mqtt.State)."
    $missing=@($MqttPorts|Where-Object {$_ -notin $mqttPorts})
    Add-StateChange 'mqtt-ports' ($mqttPorts -join ',') 'CRITICAL' 'SCORED-MQTT' "MQTT listener ports changed; missing expected: $($missing -join ', ')."
    if($baseMqtt.ConfigHash){
        Add-StateChange 'mqtt-hash' $mqtt.ConfigHash 'CRITICAL' 'CONFIG-DRIFT' "mosquitto.conf hash changed from the baseline."
    }
    Add-StateChange 'wazuh' $(if($wazuh){$wazuh.State}else{'MISSING'}) 'HIGH' 'WAZUH-RO' 'Managed Wazuh service state changed.'
    $defender=$null
    try{$defender=Get-MpPreference -ErrorAction SilentlyContinue}catch{}
    if($defender){
        Add-StateChange 'defender-rtp' $defender.DisableRealtimeMonitoring 'CRITICAL' 'DEFENDER' `
            "Defender real-time protection state changed."
        Add-NewItems 'defender-path' @() @($defender.ExclusionPath|Where-Object {$_}) 'HIGH' 'DEFENDER' 'Defender path exclusion present'
        Add-NewItems 'defender-process' @() @($defender.ExclusionProcess|Where-Object {$_}) 'HIGH' 'DEFENDER' 'Defender process exclusion present'
    }

    $listeners=Get-Set {Get-NetTCPConnection -State Listen|ForEach-Object{
        $procId=[int]$_.OwningProcess
        "$($_.LocalAddress):$($_.LocalPort) [$($procMap[$procId].Name)]"
    }}
    Add-NewItems 'listener' $baseListeners $listeners 'HIGH' 'NEW-LISTENER' 'New listener'
    Add-NewItems 'admin' $baseAdmins (Get-AdminNames) 'CRITICAL' 'LOCAL-ADMIN' 'New local administrator'
    Add-NewItems 'task' $baseTasks (Get-CustomTasks) 'HIGH' 'NEW-TASK' 'New scheduled task'
    Add-NewItems 'autorun' $baseAutoruns (Get-Autoruns) 'HIGH' 'AUTORUN' 'New autorun entry'
    $sessions=New-SessionLines
    Add-NewItems 'session' $baseSessions $sessions 'MEDIUM' 'SESSION' 'New interactive session'

    $security=Get-RecentEvents 'Security' @(1102,4625,4698,4720,4726,4728,4732,4756)
    $failed=@($security|Where-Object {$_.Id -eq 4625})
    if($failed.Count -ge $FailedLogonBurstThreshold){Add-Alert 'HIGH' 'BRUTE-FORCE' "$($failed.Count) failed logons since the last poll."}
    foreach($event in @($security|Where-Object {$_.Id -ne 4625})){
        $message=($event.Message -replace '\s+',' ')
        if($message.Length -gt 300){$message=$message.Substring(0,300)+'...'}
        Add-Alert $(if($event.Id -in 1102,4728,4732,4756){'CRITICAL'}else{'HIGH'}) "SEC-$($event.Id)" $message
    }
    foreach($event in @(Get-RecentEvents 'System' @(7045))){
        Add-Alert 'CRITICAL' 'SYS-7045' (($event.Message -replace '\s+',' '))
    }
    foreach($event in @(Get-RecentEvents 'Microsoft-Windows-PowerShell/Operational' @(4104))){
        if($event.Message -match $suspicious){
            $message=($event.Message -replace '\s+',' ')
            if($message.Length -gt 300){$message=$message.Substring(0,300)+'...'}
            Add-Alert 'CRITICAL' 'PS-4104' $message
        }
    }

    $established=@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object {$_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') -and
            -not($_.RemoteAddress -eq $WazuhManagerIP -and $_.RemotePort -eq 1514)} |
        ForEach-Object{
            $procId=[int]$_.OwningProcess
            [pscustomobject]@{Process=$(if($procMap.ContainsKey($procId)){$procMap[$procId].Name}else{"PID:$procId"});
                LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort}
        }|Sort-Object RemoteAddress,RemotePort)
    Write-Dashboard $mqtt $mqttPorts $wazuh $established $sessions
    if($OpenHtml -and -not $opened){Start-Process $htmlPath;$opened=$true}
    Clear-Host
    Write-Host "MQTT dashboard: $htmlPath" -ForegroundColor Cyan
    Write-Host "MQTT=$($mqtt.State) ports=$($mqttPorts -join ',') alerts=$($alerts.Count) remote=$($established.Count)"
    foreach($alert in @($alerts|Select-Object -First 10)){
        $color=switch($alert.Severity){'CRITICAL'{'Red'}'HIGH'{'DarkYellow'}'MEDIUM'{'Yellow'}default{'Gray'}}
        Write-Host "[$($alert.Time)] [$($alert.Severity)] $($alert.Category): $($alert.Message)" -ForegroundColor $color
    }
    $cycle++
    if($Cycles -gt 0 -and $cycle -ge $Cycles){break}
    Start-Sleep -Seconds $IntervalSeconds
}
