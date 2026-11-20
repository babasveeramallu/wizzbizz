#requires -Version 5.1
[CmdletBinding()]
param([string]$ReportRoot = 'C:\TCDC_Backup\system-audit')

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell session.'
}

$run = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $run -Force | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $run /inheritance:r /grant:r "*${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not restrict report directory: $run" }
$failures = 0

function Save-Audit {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Command,
        [ValidateSet('Csv','Json','Text')][string]$Format = 'Csv'
    )
    try {
        $value = @(& $Command)
        $path = Join-Path $run $Name
        if ($Format -eq 'Csv') {
            $value | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        } elseif ($Format -eq 'Json') {
            $value | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $path -Encoding UTF8
        } else {
            $value | Out-String -Width 240 | Set-Content -LiteralPath $path -Encoding UTF8
        }
        Write-Host "[OK] $Name"
    } catch {
        $script:failures++
        "[ERROR] $Name :: $($_.Exception.Message)" | Add-Content -LiteralPath (Join-Path $run 'errors.txt')
        Write-Warning "$Name incomplete"
    }
}

$processes = @{}
foreach ($process in @(Get-CimInstance Win32_Process)) {
    $processes[[int]$process.ProcessId] = $process
}

Save-Audit 'system.json' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    [pscustomobject]@{
        Hostname=$env:COMPUTERNAME; CollectedAt=Get-Date -Format o
        OS=$os.Caption; Version=$os.Version; Build=$os.BuildNumber
        InstallDate=$os.InstallDate; LastBootUp=$os.LastBootUpTime
        Domain=$cs.Domain; PartOfDomain=$cs.PartOfDomain
        Manufacturer=$cs.Manufacturer; Model=$cs.Model
        TimeZone=(Get-TimeZone).Id
    }
} Json

Save-Audit 'adapters.csv' {
    Get-NetAdapter -IncludeHidden |
        Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed,
            DriverName, DriverVersion, MediaConnectionState
}
Save-Audit 'addresses.csv' {
    Get-NetIPAddress | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily,
        IPAddress, PrefixLength, PrefixOrigin, SuffixOrigin
}
Save-Audit 'ip-configuration.json' { Get-NetIPConfiguration } Json
Save-Audit 'routes.csv' {
    Get-NetRoute | Select-Object AddressFamily, DestinationPrefix, NextHop,
        RouteMetric, ifIndex, InterfaceAlias, PolicyStore
}
Save-Audit 'dns.csv' {
    Get-DnsClientServerAddress |
        Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses
}
Save-Audit 'neighbors.csv' {
    Get-NetNeighbor | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily,
        IPAddress, LinkLayerAddress, State, Store
}
Save-Audit 'arp.txt' { Get-NetNeighbor } Text
Save-Audit 'proxy.csv' {
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue |
        Select-Object ProxyEnable, ProxyServer, AutoConfigURL
}

Save-Audit 'listeners.csv' {
    $rows = foreach ($socket in @(Get-NetTCPConnection -State Listen)) {
        $pid = [int]$socket.OwningProcess
        [pscustomobject]@{ Protocol='TCP'; LocalAddress=$socket.LocalAddress; LocalPort=$socket.LocalPort;
            ProcessId=$pid; ProcessName=$processes[$pid].Name; ExecutablePath=$processes[$pid].ExecutablePath }
    }
    foreach ($socket in @(Get-NetUDPEndpoint)) {
        $pid = [int]$socket.OwningProcess
        [pscustomobject]@{ Protocol='UDP'; LocalAddress=$socket.LocalAddress; LocalPort=$socket.LocalPort;
            ProcessId=$pid; ProcessName=$processes[$pid].Name; ExecutablePath=$processes[$pid].ExecutablePath }
    }
    $rows
}
Save-Audit 'established.csv' {
    Get-NetTCPConnection -State Established |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{n='ProcessName';e={$processes[[int]$_.OwningProcess].Name}},
            @{n='ExecutablePath';e={$processes[[int]$_.OwningProcess].ExecutablePath}}
}
Save-Audit 'firewall-profiles.csv' {
    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
            AllowInboundRules, AllowLocalFirewallRules
}
Save-Audit 'firewall-rules.json' {
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore)) {
        $port = $rule | Get-NetFirewallPortFilter
        $address = $rule | Get-NetFirewallAddressFilter
        [pscustomobject]@{
            Name=$rule.Name; DisplayName=$rule.DisplayName; Enabled=[string]$rule.Enabled
            Direction=[string]$rule.Direction; Action=[string]$rule.Action; Profile=[string]$rule.Profile
            Protocol=$port.Protocol; LocalPort=$port.LocalPort; RemotePort=$port.RemotePort
            LocalAddress=$address.LocalAddress; RemoteAddress=$address.RemoteAddress
            SourceType=[string]$rule.PolicyStoreSourceType
        }
    }
} Json

Save-Audit 'local-users.csv' {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
        PasswordExpires, Description, UserMayChangePassword, PasswordRequired
}
Save-Audit 'local-groups.json' {
    foreach ($group in @(Get-LocalGroup)) {
        $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue |
            Select-Object Name, ObjectClass, PrincipalSource, SID)
        [pscustomobject]@{ Group=$group.Name; Description=$group.Description; Members=$members }
    }
} Json
Save-Audit 'services.csv' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName
}
Save-Audit 'processes.csv' {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
}
Save-Audit 'scheduled-tasks.csv' {
    Get-ScheduledTask | ForEach-Object {
        [pscustomobject]@{
            TaskPath=$_.TaskPath; TaskName=$_.TaskName; State=$_.State; Author=$_.Author
            RunAs=$_.Principal.UserId
            Actions=(($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ')
        }
    }
}
Save-Audit 'startup-folders.csv' {
    $paths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            Get-ChildItem -LiteralPath $path -Force -File |
                Select-Object @{n='StartupPath';e={$path}}, Name, FullName, LastWriteTime, Length
        }
    }
}
Save-Audit 'shares.csv' {
    Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, ScopeName, Path,
        Description, Special, CurrentUsers
}
Save-Audit 'volumes.csv' {
    Get-Volume -ErrorAction SilentlyContinue |
        Select-Object DriveLetter, FriendlyName, FileSystem, HealthStatus,
            OperationalStatus, SizeRemaining, Size
}
Save-Audit 'software.csv' {
    $roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $roots -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}

$summary = [pscustomobject]@{
    CollectedAt=Get-Date -Format o
    Hostname=$env:COMPUTERNAME
    ReportDirectory=$run
    Failures=$failures
    IPv4Addresses=@(Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)
    DefaultRoutes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Select-Object DestinationPrefix, NextHop, InterfaceAlias)
}
$summary | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'summary.json') -Encoding UTF8
$summary | Format-List
Write-Host 'Read-only audit. No password hashes, environment variables, private keys, or shell history were collected.' -ForegroundColor Cyan
