[CmdletBinding()]
param(
    [ValidateSet("Prepare", "Serve", "Rollback")]
    [string]$Action,
    [Parameter(Mandatory)]
    [ValidatePattern("^[a-z0-9][a-z0-9._-]{2,63}$")]
    [string]$RunId,
    [string]$Root = "\\vmware-host\Shared Folders\TTTN"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scenarioRoot = Join-Path $Root "run_log\t8.5\scenarios\$RunId"
$windowsRoot = Join-Path $scenarioRoot "windows"
$scenarioPath = Join-Path $scenarioRoot "scenario.json"
$statePath = Join-Path $windowsRoot "state.json"
$ruleName = "NIDS-T85-$RunId"
$listenAddress = "192.168.252.20"

function Write-NewJson([string]$Path, [object]$Value) {
    if (Test-Path -LiteralPath $Path) { throw "Refusing to overwrite evidence: $Path" }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    $json = $Value | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Evidence([string]$Status, [string]$Kind) {
    [ordered]@{
        schema_version = "1.0.0"
        kind = "diagnostic_demo_evidence"
        evidence_type = $Kind
        mode = "demo_critical_path"
        formal_acceptance = $false
        roadmap_mutated = $false
        status = $Status
        run_id = $RunId
        generated_at_utc = [DateTime]::UtcNow.ToString("o")
    }
}

if (-not (Test-Path -LiteralPath $scenarioPath)) {
    throw "Initialize the scenario first: $scenarioPath"
}

switch ($Action) {
    "Prepare" {
        if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
            throw "Firewall rule already exists: $ruleName"
        }
        $address = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $listenAddress)
        if ($address.Count -ne 1) { throw "Expected exactly one Windows data address $listenAddress" }
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort 21,22,80,443 `
            -RemoteAddress "192.168.252.0/24" -Profile Any | Out-Null
        $services = @(
            [ordered]@{ name = "http"; port = 80; implementation = "temporary HttpListener"; available = $true },
            [ordered]@{ name = "ssh"; port = 22; implementation = "OpenSSH Server"; available = [bool](Get-Service sshd -ErrorAction SilentlyContinue) },
            [ordered]@{ name = "ftp"; port = 21; implementation = "operator-provided disposable FTP service"; available = [bool](Get-NetTCPConnection -State Listen -LocalPort 21 -ErrorAction SilentlyContinue) }
        )
        $state = Evidence "prepared" "windows_lab_state"
        $state["firewall_rule"] = $ruleName
        $state["listen_address"] = $listenAddress
        $state["services"] = $services
        Write-NewJson $statePath $state
        Write-NewJson (Join-Path $windowsRoot "prepare.json") $state
        Write-Host "Prepared VMnet-only firewall. Run Serve for the disposable HTTP endpoints."
    }
    "Serve" {
        if (-not (Test-Path -LiteralPath $statePath)) { throw "Run Prepare first" }
        $listener = [Net.HttpListener]::new()
        $listener.Prefixes.Add("http://$listenAddress`:80/")
        try {
            $listener.Start()
            Write-Host "READY http://$listenAddress/ (Ctrl+C to stop)"
            while ($listener.IsListening) {
                $context = $listener.GetContext()
                $request = $context.Request
                $body = if ($request.Url.AbsolutePath -eq "/login") { "Invalid" } else { "NIDS T8.5 disposable lab endpoint" }
                $bytes = [Text.Encoding]::UTF8.GetBytes($body)
                $context.Response.StatusCode = 200
                $context.Response.ContentType = "text/plain; charset=utf-8"
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.Close()
            }
        }
        finally {
            $listener.Close()
        }
    }
    "Rollback" {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        $receipt = Evidence "passed_demo" "windows_lab_rollback"
        $receipt["firewall_rule_removed"] = $null -eq (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
        Write-NewJson (Join-Path $windowsRoot "rollback.json") $receipt
        if (-not $receipt["firewall_rule_removed"]) { throw "Could not remove firewall rule $ruleName" }
    }
}
