[CmdletBinding()]
param(
    [string]$ConfigPath = "\\vmware-host\Shared Folders\TTTN\config\dpdk-passive.json",
    [string]$OutputPath = "\\vmware-host\Shared Folders\TTTN\run_log\t0.4\windows-prepare.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-UtcTimestamp {
    [DateTime]::UtcNow.ToString("o")
}

function Normalize-MacAddress([string]$Value) {
    $Value.Replace("-", ":").ToLowerInvariant()
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-NewJson([string]$Path, [object]$Document) {
    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to overwrite existing receipt: $Path"
    }
    $parent = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $json = $Document | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite existing receipt: $OutputPath"
}

$startedAt = Get-UtcTimestamp
$mutationStarted = $false
$rollbackStatus = "not_needed"
$originalDhcp = $null
$originalAddresses = @()
$finalAddresses = @()
$hasDefaultRoute = $null
$dhcpAfter = $null
$config = $null
$victim = $null
$adapter = $null
$checks = @()
$failure = $null

try {
    if (-not (Test-IsAdministrator)) {
        throw "Run this script from an elevated PowerShell session"
    }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ($config.schema_version -ne "1.0.0" -or $config.task -ne "T0.4") {
        throw "Config schema/task mismatch"
    }
    if (-not $OutputPath.StartsWith([string]$config.artifacts.windows_unc_root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputPath must remain under $($config.artifacts.windows_unc_root)"
    }

    $victim = $config.windows_victim
    if ($env:COMPUTERNAME -ne [string]$victim.hostname) {
        throw "Hostname mismatch: expected $($victim.hostname), observed $env:COMPUTERNAME"
    }
    $adapter = Get-NetAdapter -InterfaceIndex ([int]$victim.interface_index)
    if ($adapter.Name -ne [string]$victim.interface_alias) {
        throw "Interface alias mismatch: expected $($victim.interface_alias), observed $($adapter.Name)"
    }
    if ((Normalize-MacAddress $adapter.MacAddress) -ne (Normalize-MacAddress $victim.expected_mac)) {
        throw "Interface MAC mismatch"
    }
    if ($adapter.InterfaceDescription -notmatch [Regex]::Escape([string]$victim.expected_driver_pattern)) {
        throw "Interface driver mismatch: observed $($adapter.InterfaceDescription)"
    }
    if ($adapter.Status -ne "Up") {
        throw "Victim data interface must be Up"
    }

    $interfaceIndex = [int]$victim.interface_index
    $defaultsBefore = @(Get-NetRoute -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
    if ($defaultsBefore.Count -ne 0) {
        throw "Victim data interface must not own a default route"
    }
    $originalIpInterface = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4
    $originalDhcp = [string]$originalIpInterface.Dhcp
    $originalAddresses = @(
        Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object IPAddress, PrefixLength
    )
    $targetIp = [string]$victim.data_ipv4
    $targetPrefix = [int]$victim.prefix_length
    $alreadyConfigured = @($originalAddresses | Where-Object {
        $_.IPAddress -eq $targetIp -and [int]$_.PrefixLength -eq $targetPrefix
    }).Count -eq 1

    if (-not $alreadyConfigured) {
        & ping.exe -n 1 -w 750 $targetIp | Out-Null
        $neighbor = Get-NetNeighbor -InterfaceIndex $interfaceIndex -IPAddress $targetIp -ErrorAction SilentlyContinue
        if ($null -ne $neighbor -and $neighbor.State -notin @("Unreachable", "Incomplete")) {
            throw "Target address $targetIp appears to be in use by $($neighbor.LinkLayerAddress)"
        }

        $mutationStarted = $true
        Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -Dhcp Disabled
        Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false
        New-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -IPAddress $targetIp -PrefixLength $targetPrefix | Out-Null
    }
    elseif ($originalDhcp -eq "Enabled") {
        $mutationStarted = $true
        Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -Dhcp Disabled
    }

    $addressesAfter = @(Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4)
    $finalAddresses = @($addressesAfter | Select-Object IPAddress, PrefixLength)
    $targetMatches = @($addressesAfter | Where-Object {
        $_.IPAddress -eq $targetIp -and [int]$_.PrefixLength -eq $targetPrefix
    })
    $defaultsAfter = @(Get-NetRoute -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
    $hasDefaultRoute = $defaultsAfter.Count -ne 0
    $dhcpAfter = [string](Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4).Dhcp
    $checks = @(
        [ordered]@{ name = "host.matches"; status = "passed" },
        [ordered]@{ name = "interface.identity"; status = "passed" },
        [ordered]@{ name = "interface.driver"; status = "passed" },
        [ordered]@{ name = "interface.link"; status = "passed" },
        [ordered]@{ name = "interface.ipv4"; status = $(if ($targetMatches.Count -eq 1 -and $addressesAfter.Count -eq 1) { "passed" } else { "failed" }) },
        [ordered]@{ name = "interface.dhcp_disabled"; status = $(if ($dhcpAfter -eq "Disabled") { "passed" } else { "failed" }) },
        [ordered]@{ name = "interface.no_default_route"; status = $(if ($defaultsAfter.Count -eq 0) { "passed" } else { "failed" }) }
    )
    if (@($checks | Where-Object { $_.status -ne "passed" }).Count -ne 0) {
        throw "Post-configuration validation failed"
    }
}
catch {
    $failure = $_.Exception.Message
    if ($mutationStarted -and $null -ne $victim) {
        try {
            $interfaceIndex = [int]$victim.interface_index
            Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Remove-NetIPAddress -Confirm:$false
            if ($originalDhcp -eq "Enabled") {
                Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -Dhcp Enabled
                & ipconfig.exe /renew ([string]$victim.interface_alias) | Out-Null
            }
            else {
                foreach ($address in $originalAddresses) {
                    New-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -IPAddress $address.IPAddress -PrefixLength $address.PrefixLength | Out-Null
                }
            }
            $rollbackStatus = "passed"
        }
        catch {
            $rollbackStatus = "failed: $($_.Exception.Message)"
        }
    }
}

$status = if ($null -eq $failure) { "passed" } else { "failed" }
$receipt = [ordered]@{
    schema_version = "1.0.0"
    task = "T0.4"
    kind = "windows_prepare"
    status = $status
    generated_at_utc = Get-UtcTimestamp
    started_at_utc = $startedAt
    host = $env:COMPUTERNAME
    config = [ordered]@{
        file = $ConfigPath
        sha256 = $(if (Test-Path -LiteralPath $ConfigPath) { (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null })
    }
    interface = $(if ($null -ne $adapter) {
        [ordered]@{
            index = [int]$adapter.ifIndex
            alias = [string]$adapter.Name
            description = [string]$adapter.InterfaceDescription
            mac = Normalize-MacAddress $adapter.MacAddress
            addresses = $finalAddresses
            dhcp = $dhcpAfter
            has_default_route = $hasDefaultRoute
        }
    } else { $null })
    changed = $mutationStarted
    checks = $checks
    rollback_on_failure = $rollbackStatus
    error = $failure
}

Write-NewJson $OutputPath $receipt
Write-Host "wrote $OutputPath ($status)"
if ($status -ne "passed") {
    exit 1
}
