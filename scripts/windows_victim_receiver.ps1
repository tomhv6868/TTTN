[CmdletBinding()]
param(
    [string]$ConfigPath = "\\vmware-host\Shared Folders\TTTN\config\dpdk-passive.json",
    [string]$OutputPath = "\\vmware-host\Shared Folders\TTTN\run_log\t0.4\windows-receiver.json",
    [ValidateRange(60, 3600)]
    [int]$ArmTimeoutSeconds = 600,
    [ValidateRange(1, 30)]
    [int]$PostSenderGraceSeconds = 3
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
$senderReceiptPath = Join-Path (Split-Path -Parent $OutputPath) "kali-sender.json"
if (Test-Path -LiteralPath $senderReceiptPath) {
    throw "Stale Kali sender receipt exists; run the Ubuntu retry subcommand first"
}

$startedAt = Get-UtcTimestamp
$stopwatch = $null
$config = $null
$victim = $null
$adapter = $null
$udp = $null
$firewallCreated = $false
$firewallRemoved = $false
$failure = $null
$networkPrepared = $false
$receivedTotal = 0
$matchingTotal = 0
$invalidTotal = 0
$firstMatchAt = $null
$lastMatchAt = $null
$senderCompletedAtSeconds = $null
$sequences = New-Object 'System.Collections.Generic.HashSet[UInt32]'

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
        throw "Hostname mismatch"
    }
    $interfaceIndex = [int]$victim.interface_index
    $adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex
    if ($adapter.Name -ne [string]$victim.interface_alias -or
        (Normalize-MacAddress $adapter.MacAddress) -ne (Normalize-MacAddress $victim.expected_mac) -or
        $adapter.InterfaceDescription -notmatch [Regex]::Escape([string]$victim.expected_driver_pattern) -or
        $adapter.Status -ne "Up") {
        throw "Victim interface identity/link validation failed"
    }
    $targetAddresses = @(Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -eq [string]$victim.data_ipv4 -and [int]$_.PrefixLength -eq [int]$victim.prefix_length
    })
    if ($targetAddresses.Count -ne 1) {
        throw "Victim static IPv4 is not prepared"
    }
    $defaultRoutes = @(Get-NetRoute -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
    if ($defaultRoutes.Count -ne 0) {
        throw "Victim data interface owns a default route"
    }
    $networkPrepared = $true

    $ruleName = [string]$victim.firewall_rule_name
    if ($null -ne (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
        throw "Firewall rule already exists: $ruleName"
    }
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort ([int]$victim.udp_port) -Profile Any -InterfaceAlias ([string]$victim.interface_alias) | Out-Null
    $firewallCreated = $true

    $localEndpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Parse([string]$victim.data_ipv4), [int]$victim.udp_port)
    $udp = [Net.Sockets.UdpClient]::new($localEndpoint)
    $udp.Client.ReceiveTimeout = 500
    $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    $magic = [Text.Encoding]::ASCII.GetBytes([string]$config.traffic.payload_magic_ascii)
    if ($magic.Length -ne 8 -or [int]$config.traffic.payload_size_bytes -ne 12) {
        throw "T0.4 payload contract must be 8-byte magic plus 4-byte sequence"
    }
    $expectedSourceIp = [string]$config.kali.data_ipv4
    $expectedSourcePort = [int]$config.kali.udp_source_port
    $expectedCount = [int]$config.traffic.packet_count
    $timeoutSeconds = $ArmTimeoutSeconds

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    Write-Host "READY: armed up to $timeoutSeconds seconds; exits at $expectedCount packets or shortly after Kali finishes"
    while ($stopwatch.Elapsed.TotalSeconds -lt $timeoutSeconds -and $sequences.Count -lt $expectedCount) {
        try {
            $datagram = $udp.Receive([ref]$remote)
            $receivedTotal++
            $valid = $remote.Address.ToString() -eq $expectedSourceIp -and
                $remote.Port -eq $expectedSourcePort -and
                $datagram.Length -eq [int]$config.traffic.payload_size_bytes
            if ($valid) {
                for ($index = 0; $index -lt $magic.Length; $index++) {
                    if ($datagram[$index] -ne $magic[$index]) {
                        $valid = $false
                        break
                    }
                }
            }
            if ($valid) {
                [uint32]$sequence = (([uint32]$datagram[8] -shl 24) -bor
                    ([uint32]$datagram[9] -shl 16) -bor
                    ([uint32]$datagram[10] -shl 8) -bor
                    [uint32]$datagram[11])
                $matchingTotal++
                $sequences.Add($sequence) | Out-Null
                if ($null -eq $firstMatchAt) {
                    $firstMatchAt = Get-UtcTimestamp
                }
                $lastMatchAt = Get-UtcTimestamp
            }
            else {
                $invalidTotal++
            }
        }
        catch [Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -ne [Net.Sockets.SocketError]::TimedOut) {
                throw
            }
        }
        if (Test-Path -LiteralPath $senderReceiptPath) {
            if ($null -eq $senderCompletedAtSeconds) {
                $senderCompletedAtSeconds = $stopwatch.Elapsed.TotalSeconds
            }
            elseif (($stopwatch.Elapsed.TotalSeconds - $senderCompletedAtSeconds) -ge $PostSenderGraceSeconds) {
                break
            }
        }
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($null -ne $udp) {
        $udp.Close()
    }
    if ($firewallCreated -and $null -ne $victim) {
        try {
            Remove-NetFirewallRule -Name ([string]$victim.firewall_rule_name) -ErrorAction Stop
            $firewallRemoved = $null -eq (Get-NetFirewallRule -Name ([string]$victim.firewall_rule_name) -ErrorAction SilentlyContinue)
        }
        catch {
            if ($null -eq $failure) {
                $failure = "Could not remove temporary firewall rule: $($_.Exception.Message)"
            }
        }
    }
    if ($null -ne $stopwatch) {
        $stopwatch.Stop()
    }
}

$minimumCount = if ($null -ne $config) { [int]$config.acceptance.minimum_packet_count } else { 190 }
$deliveryPassed = $sequences.Count -ge $minimumCount
$status = if ($null -eq $failure -and $deliveryPassed -and $firewallRemoved) { "passed" } else { "failed" }
$endedAt = Get-UtcTimestamp
$elapsedSeconds = if ($null -ne $stopwatch) { [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3) } else { 0.0 }
$checks = @(
    [ordered]@{ name = "interface.prepared"; status = $(if ($networkPrepared) { "passed" } else { "failed" }) },
    [ordered]@{ name = "udp.unique_sequences"; status = $(if ($deliveryPassed) { "passed" } else { "failed" }); expected = ">=$minimumCount"; observed = $sequences.Count },
    [ordered]@{ name = "firewall.rule_removed"; status = $(if ($firewallRemoved) { "passed" } else { "failed" }) }
)
$receipt = [ordered]@{
    schema_version = "1.0.0"
    task = "T0.4"
    kind = "windows_receiver"
    status = $status
    generated_at_utc = $endedAt
    started_at_utc = $startedAt
    ended_at_utc = $endedAt
    duration_seconds = $elapsedSeconds
    arm_timeout_seconds = $ArmTimeoutSeconds
    post_sender_grace_seconds = $PostSenderGraceSeconds
    listen = $(if ($null -ne $victim) { [ordered]@{ ip = [string]$victim.data_ipv4; port = [int]$victim.udp_port } } else { $null })
    expected_sender = $(if ($null -ne $config) { [ordered]@{ ip = [string]$config.kali.data_ipv4; port = [int]$config.kali.udp_source_port } } else { $null })
    received_datagrams = $receivedTotal
    matching_datagrams = $matchingTotal
    unique_sequences = $sequences.Count
    sequence_ids = @($sequences | Sort-Object)
    invalid_datagrams = $invalidTotal
    first_match_at_utc = $firstMatchAt
    last_match_at_utc = $lastMatchAt
    firewall = [ordered]@{
        name = $(if ($null -ne $victim) { [string]$victim.firewall_rule_name } else { $null })
        created = $firewallCreated
        removed = $firewallRemoved
    }
    config = [ordered]@{
        file = $ConfigPath
        sha256 = $(if (Test-Path -LiteralPath $ConfigPath) { (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null })
    }
    checks = $checks
    error = $failure
}

Write-NewJson $OutputPath $receipt
Write-Host "wrote $OutputPath ($status); unique=$($sequences.Count)"
if ($status -ne "passed") {
    exit 1
}
