[CmdletBinding()]
param(
    [ValidateSet("Prepare", "Status", "Rollback", "Serve")]
    [string]$Action = "Status",
    [Parameter(Mandatory = $true)]
    [string]$ContractPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ExpectedBanner = "220 NIDS T9.1 disposable FTP"

function Read-Contract {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing contract: $Path"
    }
    $contract = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if ($contract.schema_version -cne "2.0.0" -or $contract.task -cne "T9.1") {
        throw "Invalid T9.1 contract header"
    }
    if ($contract.kind -ne "terminal_live_run_contract") {
        throw "Invalid contract kind"
    }
    foreach ($fieldName in @("scenario_label", "expected_model_family")) {
        $property = $contract.PSObject.Properties[$fieldName]
        if (
            $null -eq $property -or
            $property.Value -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$property.Value)
        ) {
            throw "Contract missing $fieldName"
        }
    }
    if ([string]$contract.attempt_id -cnotmatch "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$") {
        throw "Invalid attempt_id"
    }
    if ([int]$contract.bounds.windows_ttl_seconds -le 0) {
        throw "Contract Windows TTL must be positive"
    }
    return $contract
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator"
    }
}

function Test-ObjectProperty {
    param(
        [AllowNull()]
        [object]$Object,
        [string]$Name
    )

    return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name
}

function Write-NewJson {
    param(
        [string]$Path,
        [object]$Document
    )

    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Document | ConvertTo-Json -Depth 16) + "`n"
    )
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Copy-NewFile {
    param(
        [string]$Source,
        [string]$Destination
    )

    $directory = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $inputStream = $null
    $outputStream = $null
    try {
        $inputStream = [IO.File]::Open(
            $Source,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $outputStream = [IO.File]::Open(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $inputStream.CopyTo($outputStream)
        $outputStream.Flush($true)
    }
    finally {
        if ($null -ne $outputStream) {
            $outputStream.Dispose()
        }
        if ($null -ne $inputStream) {
            $inputStream.Dispose()
        }
    }
}

function Read-JsonIfPresent {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
}

function Contract-Root {
    param([string]$Path)

    return (Split-Path -Parent ([IO.Path]::GetFullPath($Path)))
}

function Evidence-Paths {
    param([string]$Root)

    $windowsRoot = Join-Path $Root "windows"
    return [ordered]@{
        root = $windowsRoot
        state = Join-Path $windowsRoot "state.json"
        serve = Join-Path $windowsRoot "serve.json"
        ready = Join-Path $windowsRoot "ready.json"
        rollback = Join-Path $windowsRoot "rollback.json"
        post_status = Join-Path $windowsRoot "post-status.json"
        rollback_attempts = Join-Path $windowsRoot "rollback-attempts"
        lock = Join-Path $windowsRoot "rollback.lock"
        log = Join-Path $windowsRoot "target.log"
    }
}

function Staging-Paths {
    param($Contract)

    $root = Join-Path (Join-Path $env:ProgramData "NIDS-T91") ([string]$Contract.attempt_id)
    return [ordered]@{
        root = $root
        script = Join-Path $root "windows_t91_live_target.ps1"
        contract = Join-Path $root "run-contract.json"
    }
}

function Task-Names {
    param($Contract)

    return [ordered]@{
        serve = "NIDS-T91-Serve-$($Contract.attempt_id)"
        rollback = "NIDS-T91-Rollback-$($Contract.attempt_id)"
    }
}

function Firewall-RuleName {
    param($Contract)

    return "$($Contract.target.firewall_rule_prefix)-$($Contract.attempt_id)"
}

function Test-SamePath {
    param(
        [string]$Left,
        [string]$Right
    )

    $leftFull = [IO.Path]::GetFullPath($Left).TrimEnd("\")
    $rightFull = [IO.Path]::GetFullPath($Right).TrimEnd("\")
    return $leftFull -ieq $rightFull
}

function Protect-StagingRoot {
    param([string]$Path)

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sidType in @(
        [Security.Principal.WellKnownSidType]::LocalSystemSid,
        [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid
    )) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidType, $null)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Publish-LocalEvidence {
    param(
        $LocalPaths,
        $ExternalPaths
    )

    if (Test-SamePath -Left $LocalPaths.root -Right $ExternalPaths.root) {
        return
    }
    foreach ($name in @("state", "serve", "ready", "rollback", "post_status")) {
        $source = [string]$LocalPaths[$name]
        $destination = [string]$ExternalPaths[$name]
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            continue
        }
        if (Test-Path -LiteralPath $destination -PathType Leaf) {
            $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
            $destinationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash
            if ($sourceHash -cne $destinationHash) {
                throw "Published evidence differs from authoritative local evidence: $destination"
            }
            continue
        }
        Copy-NewFile -Source $source -Destination $destination
    }
    if (Test-Path -LiteralPath $LocalPaths.log -PathType Leaf) {
        New-Item -ItemType Directory -Force -Path $ExternalPaths.root | Out-Null
        Copy-Item -LiteralPath $LocalPaths.log -Destination $ExternalPaths.log -Force
    }
}

function Get-TaskIdentityFacts {
    param(
        [string]$TaskName,
        [string]$ExpectedAction,
        $Staging
    )

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        return [ordered]@{
            registered = $false
            state = "missing"
            action_exact = $false
            principal_exact = $false
            healthy = $false
        }
    }

    $actions = @($task.Actions)
    $actionExact = $false
    if ($actions.Count -eq 1) {
        $taskAction = $actions[0]
        $arguments = [string]$taskAction.Arguments
        $executeExact = (Test-SamePath -Left ([string]$taskAction.Execute) -Right $script:PowerShellPath)
        $workingDirectoryExact = Test-SamePath `
            -Left ([string]$taskAction.WorkingDirectory) `
            -Right ([string]$Staging.root)
        $argumentsExact = $arguments.IndexOf(
            "-Action $ExpectedAction",
            [StringComparison]::OrdinalIgnoreCase
        ) -ge 0 -and $arguments.IndexOf(
            [string]$Staging.script,
            [StringComparison]::OrdinalIgnoreCase
        ) -ge 0 -and $arguments.IndexOf(
            [string]$Staging.contract,
            [StringComparison]::OrdinalIgnoreCase
        ) -ge 0
        $actionExact = $executeExact -and $workingDirectoryExact -and $argumentsExact
    }

    $userId = [string]$task.Principal.UserId
    $principalExact = ($userId -ieq "SYSTEM" -or $userId -eq "S-1-5-18") -and `
        [string]$task.Principal.LogonType -eq "ServiceAccount" -and `
        [string]$task.Principal.RunLevel -eq "Highest"
    $state = [string]$task.State
    $healthyStates = if ($ExpectedAction -eq "Serve") {
        @("Running")
    } else {
        @("Ready", "Running")
    }
    return [ordered]@{
        registered = $true
        state = $state
        action_exact = $actionExact
        principal_exact = $principalExact
        healthy = $actionExact -and $principalExact -and $state -in $healthyStates
    }
}

function Get-ResponderFacts {
    param(
        $Contract,
        $State,
        $Staging,
        $LocalPaths,
        $TaskNames
    )

    $task = Get-TaskIdentityFacts `
        -TaskName $TaskNames.serve `
        -ExpectedAction "Serve" `
        -Staging $Staging
    $marker = Read-JsonIfPresent -Path $LocalPaths.serve
    $markerValid = $false
    $markerPid = 0
    $markerStartTime = 0L
    if (
        (Test-ObjectProperty -Object $marker -Name "process_id") -and
        (Test-ObjectProperty -Object $marker -Name "start_time_filetime_utc") -and
        (Test-ObjectProperty -Object $marker -Name "attempt_id") -and
        (Test-ObjectProperty -Object $marker -Name "run_token") -and
        (Test-ObjectProperty -Object $marker -Name "script_sha256") -and
        (Test-ObjectProperty -Object $marker -Name "contract_sha256")
    ) {
        $markerPid = [int]$marker.process_id
        $markerStartTime = [long]$marker.start_time_filetime_utc
        $markerValid = [string]$marker.attempt_id -ceq [string]$Contract.attempt_id -and `
            [string]$marker.run_token -ceq [string]$Contract.run_token -and `
            $null -ne $State -and `
            [string]$marker.script_sha256 -ceq [string]$State.script_sha256 -and `
            [string]$marker.contract_sha256 -ceq [string]$State.contract_sha256
    }

    $processStartExact = $false
    $commandLineExact = $false
    if ($markerValid) {
        $process = Get-Process -Id $markerPid -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            try {
                $processStartExact = $process.StartTime.ToUniversalTime().ToFileTimeUtc() -eq `
                    $markerStartTime
            }
            catch {
                $processStartExact = $false
            }
        }
        if ($processStartExact) {
            $cimProcess = Get-CimInstance `
                -ClassName Win32_Process `
                -Filter "ProcessId = $markerPid" `
                -ErrorAction SilentlyContinue
            if ($null -ne $cimProcess) {
                $commandLine = [string]$cimProcess.CommandLine
                $commandLineExact = $commandLine.IndexOf(
                    [string]$Staging.script,
                    [StringComparison]::OrdinalIgnoreCase
                ) -ge 0 -and $commandLine.IndexOf(
                    [string]$Staging.contract,
                    [StringComparison]::OrdinalIgnoreCase
                ) -ge 0 -and $commandLine.IndexOf(
                    "-Action Serve",
                    [StringComparison]::OrdinalIgnoreCase
                ) -ge 0
            }
        }
    }

    $listeners = @(
        Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -eq [string]$Contract.topology.target_ip }
    )
    $listenerOwned = $markerValid -and $listeners.Count -eq 1 -and `
        [int]$listeners[0].OwningProcess -eq $markerPid
    $processIdentityExact = $markerValid -and $processStartExact -and $commandLineExact
    return [ordered]@{
        task = $task
        marker_valid = $markerValid
        process_id = $markerPid
        start_time_filetime_utc = $markerStartTime
        process_identity_exact = $processIdentityExact
        listener_count = $listeners.Count
        listener_owned = $listenerOwned
        healthy = $task.healthy -and $processIdentityExact -and $listenerOwned
    }
}

function Get-FirewallFacts {
    param(
        $Contract,
        [string]$RuleName
    )

    $rules = @(Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)
    if ($rules.Count -ne 1) {
        return [ordered]@{
            exists = $rules.Count -gt 0
            exact = $false
            remote_addresses = @()
            local_ports = @()
        }
    }

    $rule = $rules[0]
    $remoteAddresses = @()
    foreach ($filter in @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule)) {
        foreach ($address in @($filter.RemoteAddress)) {
            $remoteAddresses += [string]$address
        }
    }
    $localPorts = @()
    $protocols = @()
    foreach ($filter in @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule)) {
        foreach ($port in @($filter.LocalPort)) {
            $localPorts += [string]$port
        }
        $protocols += [string]$filter.Protocol
    }
    $protocolExact = $protocols.Count -eq 1 -and $protocols[0] -in @("TCP", "6")
    $exact = [string]$rule.Direction -eq "Inbound" -and `
        [string]$rule.Action -eq "Allow" -and `
        [string]$rule.Enabled -eq "True" -and `
        $remoteAddresses.Count -eq 1 -and `
        $remoteAddresses[0] -ceq [string]$Contract.topology.source_ip -and `
        $localPorts.Count -eq 1 -and `
        $localPorts[0] -ceq [string]$Contract.target.firewall_tcp_ports -and `
        $protocolExact
    return [ordered]@{
        exists = $true
        exact = $exact
        remote_addresses = $remoteAddresses
        local_ports = $localPorts
    }
}

function Get-FtpServiceFacts {
    $service = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
    return [ordered]@{
        exists = $null -ne $service
        status = $(if ($null -eq $service) { "missing" } else { [string]$service.Status })
    }
}

function Test-FtpProbe {
    param([string]$Address)

    $client = $null
    $asyncResult = $null
    try {
        $client = [Net.Sockets.TcpClient]::new()
        $client.ReceiveTimeout = 2000
        $client.SendTimeout = 2000
        $asyncResult = $client.BeginConnect($Address, 21, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne(2000)) {
            throw "TCP/21 connect timed out"
        }
        $client.EndConnect($asyncResult)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 2000
        $stream.WriteTimeout = 2000
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII)
        $writer = [IO.StreamWriter]::new($stream, [Text.Encoding]::ASCII)
        $writer.NewLine = "`r`n"
        $writer.AutoFlush = $true
        $observedBanner = $reader.ReadLine()
        if ($observedBanner -cne $script:ExpectedBanner) {
            throw "Unexpected FTP banner: $observedBanner"
        }
        $writer.WriteLine("QUIT")
        $quitResponse = $reader.ReadLine()
        if ($quitResponse -cne "221 Goodbye") {
            throw "Unexpected FTP QUIT response: $quitResponse"
        }
        return [ordered]@{
            success = $true
            observed_banner = $observedBanner
            quit_response = $quitResponse
            error = $null
        }
    }
    catch {
        return [ordered]@{
            success = $false
            observed_banner = $null
            quit_response = $null
            error = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $asyncResult) {
            $asyncResult.AsyncWaitHandle.Dispose()
        }
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

function Acquire-LifecycleLock {
    param([string]$Path)

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    while ($true) {
        try {
            return [IO.File]::Open(
                $Path,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
        }
        catch [IO.IOException] {
            if ([DateTimeOffset]::UtcNow -ge $deadline) {
                throw "Timed out acquiring lifecycle lock: $Path"
            }
            Start-Sleep -Milliseconds 100
        }
    }
}

function Get-LifecycleFacts {
    param(
        $Contract,
        $Staging,
        $LocalPaths,
        $TaskNames,
        [string]$RuleName
    )

    $state = Read-JsonIfPresent -Path $LocalPaths.state
    $receipt = Read-JsonIfPresent -Path $LocalPaths.rollback
    $responder = Get-ResponderFacts `
        -Contract $Contract `
        -State $state `
        -Staging $Staging `
        -LocalPaths $LocalPaths `
        -TaskNames $TaskNames
    $rollbackTask = Get-TaskIdentityFacts `
        -TaskName $TaskNames.rollback `
        -ExpectedAction "Rollback" `
        -Staging $Staging
    $firewall = Get-FirewallFacts -Contract $Contract -RuleName $RuleName
    $service = Get-FtpServiceFacts
    $probe = if ($responder.healthy) {
        Test-FtpProbe -Address ([string]$Contract.topology.target_ip)
    } else {
        [ordered]@{
            success = $false
            observed_banner = $null
            quit_response = $null
            error = "Responder identity is not healthy"
        }
    }

    $stateValid = $null -ne $state -and `
        (Test-ObjectProperty -Object $state -Name "attempt_id") -and `
        (Test-ObjectProperty -Object $state -Name "run_token") -and `
        (Test-ObjectProperty -Object $state -Name "script_sha256") -and `
        (Test-ObjectProperty -Object $state -Name "contract_sha256") -and `
        [string]$state.attempt_id -ceq [string]$Contract.attempt_id -and `
        [string]$state.run_token -ceq [string]$Contract.run_token -and `
        (Test-Path -LiteralPath $Staging.script -PathType Leaf) -and `
        (Test-Path -LiteralPath $Staging.contract -PathType Leaf)
    $hashesExact = $false
    if ($stateValid) {
        $hashesExact = (Get-FileHash -Algorithm SHA256 -LiteralPath $Staging.script).Hash.ToLowerInvariant() -ceq `
            ([string]$state.script_sha256).ToLowerInvariant() -and `
            (Get-FileHash -Algorithm SHA256 -LiteralPath $Staging.contract).Hash.ToLowerInvariant() -ceq `
            ([string]$state.contract_sha256).ToLowerInvariant()
    }

    $restoreRequired = $stateValid -and [bool]$state.ftp_service_was_running
    $servicePrepared = -not $restoreRequired -or $service.status -eq "Stopped"
    $serviceRestored = -not $restoreRequired -or $service.status -eq "Running"
    $deadlineValid = $stateValid -and (Test-ObjectProperty -Object $state -Name "expires_at_utc")
    $deadlineOverrun = $false
    if ($deadlineValid) {
        $deadlineOverrun = [DateTimeOffset]::UtcNow -gt `
            [DateTimeOffset]::Parse([string]$state.expires_at_utc)
    }

    $rolledBackAt = [DateTimeOffset]::MinValue
    $rolledBackAtValid = $false
    if (
        $null -ne $receipt -and
        (Test-ObjectProperty -Object $receipt -Name "rolled_back_at_utc")
    ) {
        $rolledBackAtValid = [DateTimeOffset]::TryParse(
            [string]$receipt.rolled_back_at_utc,
            [ref]$rolledBackAt
        )
    }
    $receiptValid = $stateValid -and $hashesExact -and `
        $null -ne $receipt -and `
        (Test-ObjectProperty -Object $receipt -Name "schema_version") -and `
        (Test-ObjectProperty -Object $receipt -Name "task") -and `
        (Test-ObjectProperty -Object $receipt -Name "kind") -and `
        (Test-ObjectProperty -Object $receipt -Name "attempt_id") -and `
        (Test-ObjectProperty -Object $receipt -Name "run_token") -and `
        (Test-ObjectProperty -Object $receipt -Name "status") -and `
        (Test-ObjectProperty -Object $receipt -Name "firewall_rule") -and `
        (Test-ObjectProperty -Object $receipt -Name "firewall_rule_removed") -and `
        (Test-ObjectProperty -Object $receipt -Name "responder_task") -and `
        (Test-ObjectProperty -Object $receipt -Name "responder_task_removed") -and `
        (Test-ObjectProperty -Object $receipt -Name "responder_identity_stopped") -and `
        (Test-ObjectProperty -Object $receipt -Name "rollback_task") -and `
        (Test-ObjectProperty -Object $receipt -Name "rollback_task_removed") -and `
        (Test-ObjectProperty -Object $receipt -Name "ftp_service_restore_required") -and `
        (Test-ObjectProperty -Object $receipt -Name "ftp_service_restored") -and `
        [string]$receipt.schema_version -ceq "1.0.0" -and `
        [string]$receipt.task -ceq "T9.1" -and `
        [string]$receipt.kind -ceq "windows_target_rollback" -and `
        [string]$receipt.attempt_id -ceq [string]$Contract.attempt_id -and `
        [string]$receipt.run_token -ceq [string]$Contract.run_token -and `
        [string]$receipt.status -ceq "passed" -and `
        [string]$receipt.firewall_rule -ceq [string]$RuleName -and `
        $receipt.firewall_rule_removed -is [bool] -and `
        [bool]$receipt.firewall_rule_removed -and `
        [string]$receipt.responder_task -ceq [string]$TaskNames.serve -and `
        $receipt.responder_task_removed -is [bool] -and `
        [bool]$receipt.responder_task_removed -and `
        $receipt.responder_identity_stopped -is [bool] -and `
        [bool]$receipt.responder_identity_stopped -and `
        [string]$receipt.rollback_task -ceq [string]$TaskNames.rollback -and `
        $receipt.rollback_task_removed -is [bool] -and `
        [bool]$receipt.rollback_task_removed -and `
        $receipt.ftp_service_restore_required -is [bool] -and `
        [bool]$receipt.ftp_service_restore_required -eq $restoreRequired -and `
        $receipt.ftp_service_restored -is [bool] -and `
        [bool]$receipt.ftp_service_restored -and `
        $rolledBackAtValid
    $readyExists = Test-Path -LiteralPath $LocalPaths.ready -PathType Leaf
    $running = $stateValid -and $hashesExact -and $readyExists -and `
        $responder.healthy -and $rollbackTask.healthy -and $firewall.exact -and `
        $servicePrepared -and $probe.success -and -not $deadlineOverrun
    $activeMutation = $firewall.exists -or $responder.task.registered -or `
        $responder.process_identity_exact -or $responder.listener_owned -or `
        ($restoreRequired -and -not $serviceRestored)
    $safe = -not $firewall.exists -and -not $responder.task.registered -and `
        -not $responder.process_identity_exact -and -not $responder.listener_owned -and `
        -not $rollbackTask.registered -and $serviceRestored

    $status = "pending"
    if ($running) {
        $status = "running"
    } elseif ($receiptValid -and $safe) {
        $status = "rolled_back"
    } elseif ($activeMutation -or $readyExists -or ($null -ne $receipt -and -not $safe)) {
        $status = "orphaned_unsafe"
    } elseif ($stateValid -and $rollbackTask.healthy -and -not $deadlineOverrun) {
        $status = "preparing"
    } elseif ($stateValid -or $null -ne $receipt) {
        $status = "orphaned_unsafe"
    }

    return [ordered]@{
        status = $status
        running = $running
        safe = $safe
        state_valid = $stateValid
        staged_hashes_exact = $hashesExact
        ready_receipt_exists = $readyExists
        deadline_overrun = $deadlineOverrun
        rollback_receipt_valid = $receiptValid
        responder = $responder
        rollback_task = $rollbackTask
        firewall = $firewall
        ftp_service = $service
        ftp_probe = $probe
    }
}

function Write-RollbackAttempt {
    param(
        $Contract,
        $LocalPaths,
        [string[]]$Failures
    )

    $stamp = [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffffffZ")
    $path = Join-Path $LocalPaths.rollback_attempts "$stamp-$([Guid]::NewGuid().ToString('N')).json"
    Write-NewJson -Path $path -Document ([ordered]@{
        schema_version = "1.0.0"
        task = "T9.1"
        kind = "windows_target_rollback_attempt"
        status = "failed"
        attempt_id = $Contract.attempt_id
        run_token = $Contract.run_token
        failures = $Failures
        attempted_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    })
}

function Invoke-Rollback {
    param(
        $Contract,
        $Staging,
        $LocalPaths,
        $ExternalPaths,
        $TaskNames,
        [string]$RuleName
    )

    $lock = Acquire-LifecycleLock -Path $LocalPaths.lock
    try {
        $state = Read-JsonIfPresent -Path $LocalPaths.state
        $existingReceipt = Read-JsonIfPresent -Path $LocalPaths.rollback
        $responderBefore = Get-ResponderFacts `
            -Contract $Contract `
            -State $state `
            -Staging $Staging `
            -LocalPaths $LocalPaths `
            -TaskNames $TaskNames

        Remove-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
        if ($responderBefore.task.registered) {
            Stop-ScheduledTask -TaskName $TaskNames.serve -ErrorAction SilentlyContinue
        }
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
        while (
            $responderBefore.process_identity_exact -and
            [DateTimeOffset]::UtcNow -lt $deadline
        ) {
            Start-Sleep -Milliseconds 100
            $responderBefore = Get-ResponderFacts `
                -Contract $Contract `
                -State $state `
                -Staging $Staging `
                -LocalPaths $LocalPaths `
                -TaskNames $TaskNames
        }
        if ($responderBefore.process_identity_exact) {
            Stop-Process -Id $responderBefore.process_id -Force -ErrorAction SilentlyContinue
        }
        if (Get-ScheduledTask -TaskName $TaskNames.serve -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask `
                -TaskName $TaskNames.serve `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }

        $restoreRequired = $null -ne $state -and `
            (Test-ObjectProperty -Object $state -Name "ftp_service_was_running") -and `
            [bool]$state.ftp_service_was_running
        if ($restoreRequired) {
            $ftpService = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
            if ($null -ne $ftpService -and $ftpService.Status -ne "Running") {
                Start-Service -Name FTPSVC
                $ftpService.WaitForStatus("Running", [TimeSpan]::FromSeconds(15))
            }
        }
        if (Get-ScheduledTask -TaskName $TaskNames.rollback -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask `
                -TaskName $TaskNames.rollback `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }

        $firewallRemoved = $null -eq (
            Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
        )
        $serveTaskRemoved = $null -eq (
            Get-ScheduledTask -TaskName $TaskNames.serve -ErrorAction SilentlyContinue
        )
        $rollbackTaskRemoved = $null -eq (
            Get-ScheduledTask -TaskName $TaskNames.rollback -ErrorAction SilentlyContinue
        )
        $responderAfter = Get-ResponderFacts `
            -Contract $Contract `
            -State $state `
            -Staging $Staging `
            -LocalPaths $LocalPaths `
            -TaskNames $TaskNames
        $serviceAfter = Get-FtpServiceFacts
        $ftpServiceRestored = -not $restoreRequired -or $serviceAfter.status -eq "Running"
        $responderStopped = -not $responderAfter.process_identity_exact -and `
            -not $responderAfter.listener_owned

        $failures = @()
        if (-not $firewallRemoved) { $failures += "firewall_rule_present" }
        if (-not $serveTaskRemoved) { $failures += "serve_task_present" }
        if (-not $rollbackTaskRemoved) { $failures += "rollback_task_present" }
        if (-not $responderStopped) { $failures += "responder_identity_present" }
        if (-not $ftpServiceRestored) { $failures += "ftp_service_not_restored" }
        if ($failures.Count -ne 0) {
            Write-RollbackAttempt `
                -Contract $Contract `
                -LocalPaths $LocalPaths `
                -Failures $failures
            throw "Windows rollback failed: $($failures -join ', ')"
        }

        if ($null -eq $existingReceipt) {
            Write-NewJson -Path $LocalPaths.rollback -Document ([ordered]@{
                schema_version = "1.0.0"
                task = "T9.1"
                kind = "windows_target_rollback"
                status = "passed"
                attempt_id = $Contract.attempt_id
                run_token = $Contract.run_token
                firewall_rule = $RuleName
                firewall_rule_removed = $firewallRemoved
                responder_task = $TaskNames.serve
                responder_task_removed = $serveTaskRemoved
                responder_identity_stopped = $responderStopped
                rollback_task = $TaskNames.rollback
                rollback_task_removed = $rollbackTaskRemoved
                ftp_service_restore_required = $restoreRequired
                ftp_service_restored = $ftpServiceRestored
                rolled_back_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
            })
        } else {
            if (
                -not (Test-ObjectProperty -Object $existingReceipt -Name "attempt_id") -or
                -not (Test-ObjectProperty -Object $existingReceipt -Name "run_token") -or
                [string]$existingReceipt.attempt_id -cne [string]$Contract.attempt_id -or
                [string]$existingReceipt.run_token -cne [string]$Contract.run_token
            ) {
                throw "Existing rollback receipt does not match this contract"
            }
        }
        Publish-LocalEvidence -LocalPaths $LocalPaths -ExternalPaths $ExternalPaths
        return (Get-Content -Raw -LiteralPath $LocalPaths.rollback | ConvertFrom-Json)
    }
    finally {
        $lock.Dispose()
    }
}

$contractFullPath = [IO.Path]::GetFullPath($ContractPath)
$contract = Read-Contract -Path $contractFullPath
$externalPaths = Evidence-Paths -Root (Contract-Root -Path $contractFullPath)
$staging = Staging-Paths -Contract $contract
$localPaths = Evidence-Paths -Root $staging.root
$taskNames = Task-Names -Contract $contract
$ruleName = Firewall-RuleName -Contract $contract
$PowerShellPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

Assert-Administrator

if ($Action -eq "Serve") {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsSystem) {
        throw "Serve must run as SYSTEM"
    }
    if (-not (Test-SamePath -Left $contractFullPath -Right $staging.contract)) {
        throw "Serve must use the staged local contract"
    }
    $state = Read-JsonIfPresent -Path $localPaths.state
    if ($null -eq $state) {
        throw "Serve requires the local lifecycle state"
    }
    $scriptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $staging.script).Hash.ToLowerInvariant()
    $contractHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $staging.contract).Hash.ToLowerInvariant()
    if (
        $scriptHash -cne ([string]$state.script_sha256).ToLowerInvariant() -or
        $contractHash -cne ([string]$state.contract_sha256).ToLowerInvariant()
    ) {
        throw "Staged Serve artifacts do not match lifecycle state"
    }

    $listener = [Net.Sockets.TcpListener]::new(
        [Net.IPAddress]::Parse([string]$contract.topology.target_ip),
        21
    )
    $listener.Start()
    try {
        $process = Get-Process -Id $PID
        Write-NewJson -Path $localPaths.serve -Document ([ordered]@{
            schema_version = "1.0.0"
            task = "T9.1"
            kind = "windows_target_serve_identity"
            status = "running"
            attempt_id = $contract.attempt_id
            run_token = $contract.run_token
            process_id = $PID
            start_time_filetime_utc = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
            script_sha256 = $scriptHash
            contract_sha256 = $contractHash
            started_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
        })
        while ($true) {
            $client = $listener.AcceptTcpClient()
            $resetAfterResponse = $false
            try {
                $stream = $client.GetStream()
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII)
                $writer = [IO.StreamWriter]::new($stream, [Text.Encoding]::ASCII)
                $writer.NewLine = "`r`n"
                $writer.AutoFlush = $true
                $writer.WriteLine($ExpectedBanner)
                $userAccepted = $false
                $closeAfterResponse = $false
                while ($client.Connected) {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) { break }
                    Add-Content -LiteralPath $localPaths.log -Value $line
                    $parts = $line.Split(" ", 2)
                    $command = $parts[0].ToUpperInvariant()
                    $argument = if ($parts.Count -eq 2) { $parts[1] } else { "" }
                    switch ($command) {
                        "USER" {
                            $userAccepted = $argument -eq [string]$contract.target.ftp_username
                            $writer.WriteLine("331 Password required")
                        }
                        "PASS" {
                            if (
                                $userAccepted -and
                                $argument -eq [string]$contract.target.ftp_valid_password
                            ) {
                                $writer.WriteLine("230 Login successful")
                            } else {
                                $writer.WriteLine("530 Login incorrect")
                                $resetAfterResponse = $true
                            }
                            $closeAfterResponse = $true
                        }
                        "SYST" { $writer.WriteLine("215 Windows_NT") }
                        "QUIT" {
                            $writer.WriteLine("221 Goodbye")
                            $closeAfterResponse = $true
                        }
                        default { $writer.WriteLine("502 Command not implemented") }
                    }
                    if ($closeAfterResponse) { break }
                }
            }
            catch {
                Add-Content -LiteralPath $localPaths.log -Value `
                    "client_error=$($_.Exception.GetType().FullName)"
            }
            finally {
                if ($resetAfterResponse) {
                    try {
                        $client.Client.LingerState = [Net.Sockets.LingerOption]::new($true, 0)
                    }
                    catch {
                    }
                }
                $client.Dispose()
            }
        }
    }
    finally {
        $listener.Stop()
    }
    exit 0
}

if ($Action -eq "Status") {
    Publish-LocalEvidence -LocalPaths $localPaths -ExternalPaths $externalPaths
    $facts = Get-LifecycleFacts `
        -Contract $contract `
        -Staging $staging `
        -LocalPaths $localPaths `
        -TaskNames $taskNames `
        -RuleName $ruleName
    if ($facts.status -eq "rolled_back") {
        $statusLock = Acquire-LifecycleLock -Path $localPaths.lock
        try {
            $facts = Get-LifecycleFacts `
                -Contract $contract `
                -Staging $staging `
                -LocalPaths $localPaths `
                -TaskNames $taskNames `
                -RuleName $ruleName
            $state = Read-JsonIfPresent -Path $localPaths.state
            if (
                $facts.status -cne "rolled_back" -or
                -not $facts.safe -or
                -not $facts.state_valid -or
                -not $facts.staged_hashes_exact -or
                -not $facts.rollback_receipt_valid -or
                $facts.deadline_overrun
            ) {
                throw "Windows post-status preconditions changed under lifecycle lock"
            }
            $contractHash = (
                Get-FileHash -Algorithm SHA256 -LiteralPath $contractFullPath
            ).Hash.ToLowerInvariant()
            $statusScriptHash = (
                Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath
            ).Hash.ToLowerInvariant()
            if (
                $contractHash -cne ([string]$state.contract_sha256).ToLowerInvariant() -or
                $statusScriptHash -cne ([string]$state.script_sha256).ToLowerInvariant()
            ) {
                throw "Status source artifacts do not match staged lifecycle state"
            }
            $stateHash = (
                Get-FileHash -Algorithm SHA256 -LiteralPath $localPaths.state
            ).Hash.ToLowerInvariant()
            $rollbackHash = (
                Get-FileHash -Algorithm SHA256 -LiteralPath $localPaths.rollback
            ).Hash.ToLowerInvariant()
            $postStatus = [ordered]@{
                schema_version = "1.0.0"
                task = "T9.1"
                kind = "windows_target_post_status"
                operation = "status"
                role = "windows"
                status = "rolled_back"
                ready = $false
                safe = $true
                attempt_id = $contract.attempt_id
                run_token = $contract.run_token
                scenario_label = $contract.scenario_label
                expected_model_family = $contract.expected_model_family
                run_contract_sha256 = $contractHash
                state_sha256 = $stateHash
                rollback_receipt_sha256 = $rollbackHash
                status_script_sha256 = $statusScriptHash
                observed_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
                facts = $facts
            }
            $existingPostStatus = Read-JsonIfPresent -Path $localPaths.post_status
            $observedAt = [DateTimeOffset]::MinValue
            if ($null -eq $existingPostStatus) {
                Write-NewJson -Path $localPaths.post_status -Document $postStatus
            } elseif (
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "schema_version") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "task") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "kind") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "operation") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "role") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "attempt_id") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "run_token") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "scenario_label") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "expected_model_family") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "status") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "ready") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "safe") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "run_contract_sha256") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "state_sha256") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "rollback_receipt_sha256") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "status_script_sha256") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "observed_at_utc") -or
                -not (Test-ObjectProperty -Object $existingPostStatus -Name "facts") -or
                -not (Test-ObjectProperty -Object $existingPostStatus.facts -Name "status") -or
                -not (Test-ObjectProperty -Object $existingPostStatus.facts -Name "safe") -or
                -not (Test-ObjectProperty -Object $existingPostStatus.facts -Name "state_valid") -or
                -not (Test-ObjectProperty -Object $existingPostStatus.facts -Name "staged_hashes_exact") -or
                -not (Test-ObjectProperty -Object $existingPostStatus.facts -Name "rollback_receipt_valid") -or
                -not (Test-ObjectProperty -Object $existingPostStatus.facts -Name "deadline_overrun") -or
                [string]$existingPostStatus.schema_version -cne "1.0.0" -or
                [string]$existingPostStatus.task -cne "T9.1" -or
                [string]$existingPostStatus.kind -cne "windows_target_post_status" -or
                [string]$existingPostStatus.operation -cne "status" -or
                [string]$existingPostStatus.role -cne "windows" -or
                [string]$existingPostStatus.attempt_id -cne [string]$contract.attempt_id -or
                [string]$existingPostStatus.run_token -cne [string]$contract.run_token -or
                [string]$existingPostStatus.scenario_label -cne [string]$contract.scenario_label -or
                [string]$existingPostStatus.expected_model_family -cne [string]$contract.expected_model_family -or
                [string]$existingPostStatus.status -cne "rolled_back" -or
                $existingPostStatus.ready -isnot [bool] -or
                [bool]$existingPostStatus.ready -or
                $existingPostStatus.safe -isnot [bool] -or
                -not [bool]$existingPostStatus.safe -or
                [string]$existingPostStatus.run_contract_sha256 -cne $contractHash -or
                [string]$existingPostStatus.state_sha256 -cne $stateHash -or
                [string]$existingPostStatus.rollback_receipt_sha256 -cne $rollbackHash -or
                [string]$existingPostStatus.status_script_sha256 -cne $statusScriptHash -or
                -not [DateTimeOffset]::TryParse(
                    [string]$existingPostStatus.observed_at_utc,
                    [ref]$observedAt
                ) -or
                [string]$existingPostStatus.facts.status -cne "rolled_back" -or
                $existingPostStatus.facts.safe -isnot [bool] -or
                -not [bool]$existingPostStatus.facts.safe -or
                $existingPostStatus.facts.state_valid -isnot [bool] -or
                -not [bool]$existingPostStatus.facts.state_valid -or
                $existingPostStatus.facts.staged_hashes_exact -isnot [bool] -or
                -not [bool]$existingPostStatus.facts.staged_hashes_exact -or
                $existingPostStatus.facts.rollback_receipt_valid -isnot [bool] -or
                -not [bool]$existingPostStatus.facts.rollback_receipt_valid -or
                $existingPostStatus.facts.deadline_overrun -isnot [bool] -or
                [bool]$existingPostStatus.facts.deadline_overrun
            ) {
                throw "Existing Windows post-status receipt is invalid"
            }
            Publish-LocalEvidence -LocalPaths $localPaths -ExternalPaths $externalPaths
        }
        finally {
            $statusLock.Dispose()
        }
    }
    [ordered]@{
        schema_version = "1.0.0"
        operation = "status"
        role = "windows"
        attempt_id = $contract.attempt_id
        status = $facts.status
        ready = $facts.running
        local_root = $staging.root
        state = $externalPaths.state
        rollback = $externalPaths.rollback
        facts = $facts
    } | ConvertTo-Json -Depth 16
    if ($facts.status -eq "orphaned_unsafe") {
        exit 2
    }
    exit 0
}

if ($Action -eq "Rollback") {
    Invoke-Rollback `
        -Contract $contract `
        -Staging $staging `
        -LocalPaths $localPaths `
        -ExternalPaths $externalPaths `
        -TaskNames $taskNames `
        -RuleName $ruleName |
        ConvertTo-Json -Depth 16
    exit 0
}

if ($Action -ne "Prepare") {
    throw "Unsupported action: $Action"
}
if (Test-SamePath -Left $contractFullPath -Right $staging.contract) {
    throw "Prepare requires the external run contract"
}
if (
    (Test-Path -LiteralPath $staging.root) -or
    (Test-Path -LiteralPath $externalPaths.state) -or
    (Test-Path -LiteralPath $externalPaths.ready) -or
    (Test-Path -LiteralPath $externalPaths.rollback) -or
    (Test-Path -LiteralPath $externalPaths.post_status)
) {
    throw "Windows target lifecycle already exists for attempt $($contract.attempt_id)"
}

$targetAddress = @(
    Get-NetIPAddress `
        -AddressFamily IPv4 `
        -IPAddress ([string]$contract.topology.target_ip) `
        -ErrorAction SilentlyContinue
)
if ($targetAddress.Count -ne 1) {
    throw "Expected exactly one Windows target IP: $($contract.topology.target_ip)"
}
if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
    throw "Firewall rule already exists: $ruleName"
}
foreach ($taskName in @($taskNames.serve, $taskNames.rollback)) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw "Scheduled task already exists: $taskName"
    }
}

New-Item -ItemType Directory -Path $staging.root | Out-Null
Protect-StagingRoot -Path $staging.root
New-Item -ItemType Directory -Force -Path $localPaths.root | Out-Null
Copy-NewFile -Source $PSCommandPath -Destination $staging.script
Copy-NewFile -Source $contractFullPath -Destination $staging.contract
$scriptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $staging.script).Hash.ToLowerInvariant()
$contractHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $staging.contract).Hash.ToLowerInvariant()
$sourceScriptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
$sourceContractHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $contractFullPath).Hash.ToLowerInvariant()
if ($scriptHash -cne $sourceScriptHash -or $contractHash -cne $sourceContractHash) {
    throw "Staged artifacts failed SHA-256 verification"
}

$prepareLock = Acquire-LifecycleLock -Path $localPaths.lock
$prepareError = $null
try {
    $ftpService = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
    $ftpServiceWasRunning = $null -ne $ftpService -and $ftpService.Status -eq "Running"
    $ttlSeconds = [int]$contract.bounds.windows_ttl_seconds
    $preparedAt = [DateTimeOffset]::UtcNow
    $expiresAt = $preparedAt.AddSeconds($ttlSeconds)

    Write-NewJson -Path $localPaths.state -Document ([ordered]@{
        schema_version = "1.0.0"
        task = "T9.1"
        kind = "windows_target_state"
        status = "preparing"
        attempt_id = $contract.attempt_id
        run_token = $contract.run_token
        source_ip = $contract.topology.source_ip
        target_ip = $contract.topology.target_ip
        firewall_rule = $ruleName
        firewall_remote_address = $contract.topology.source_ip
        firewall_local_ports = $contract.target.firewall_tcp_ports
        ftp_service_was_running = $ftpServiceWasRunning
        responder_task = $taskNames.serve
        rollback_task = $taskNames.rollback
        script_sha256 = $scriptHash
        contract_sha256 = $contractHash
        ttl_seconds = $ttlSeconds
        prepared_at_utc = $preparedAt.ToString("o")
        expires_at_utc = $expiresAt.ToString("o")
    })

    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $rollbackArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
        "-File `"$($staging.script)`" -Action Rollback " +
        "-ContractPath `"$($staging.contract)`""
    $rollbackAction = New-ScheduledTaskAction `
        -Execute $PowerShellPath `
        -Argument $rollbackArguments `
        -WorkingDirectory $staging.root
    $rollbackTriggers = @(
        New-ScheduledTaskTrigger -Once -At $expiresAt.LocalDateTime
        New-ScheduledTaskTrigger -AtStartup
    )
    $rollbackSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    $rollbackDefinition = New-ScheduledTask `
        -Action $rollbackAction `
        -Trigger $rollbackTriggers `
        -Principal $principal `
        -Settings $rollbackSettings
    Register-ScheduledTask `
        -TaskName $taskNames.rollback `
        -InputObject $rollbackDefinition |
        Out-Null

    if ($ftpServiceWasRunning) {
        Stop-Service -Name FTPSVC -Force
        $ftpService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(15))
    }
    $existingFtpListeners = @(
        Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue
    )
    if ($existingFtpListeners.Count -ne 0) {
        throw "TCP/21 is already occupied"
    }
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName `
        -Direction Inbound -Action Allow -Protocol TCP `
        -LocalPort ([string]$contract.target.firewall_tcp_ports) `
        -RemoteAddress ([string]$contract.topology.source_ip) `
        -Profile Any |
        Out-Null

    $serveArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
        "-File `"$($staging.script)`" -Action Serve " +
        "-ContractPath `"$($staging.contract)`""
    $serveAction = New-ScheduledTaskAction `
        -Execute $PowerShellPath `
        -Argument $serveArguments `
        -WorkingDirectory $staging.root
    $serveSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Seconds ($ttlSeconds + 60))
    $serveDefinition = New-ScheduledTask `
        -Action $serveAction `
        -Principal $principal `
        -Settings $serveSettings
    Register-ScheduledTask `
        -TaskName $taskNames.serve `
        -InputObject $serveDefinition |
        Out-Null
    Start-ScheduledTask -TaskName $taskNames.serve

    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(
        [int]$contract.bounds.ready_timeout_seconds
    )
    $readiness = $null
    while ([DateTimeOffset]::UtcNow -lt $readyDeadline) {
        $state = Read-JsonIfPresent -Path $localPaths.state
        $responder = Get-ResponderFacts `
            -Contract $contract `
            -State $state `
            -Staging $staging `
            -LocalPaths $localPaths `
            -TaskNames $taskNames
        $rollbackTask = Get-TaskIdentityFacts `
            -TaskName $taskNames.rollback `
            -ExpectedAction "Rollback" `
            -Staging $staging
        $firewall = Get-FirewallFacts -Contract $contract -RuleName $ruleName
        $service = Get-FtpServiceFacts
        $probe = if ($responder.healthy) {
            Test-FtpProbe -Address ([string]$contract.topology.target_ip)
        } else {
            [ordered]@{ success = $false; observed_banner = $null }
        }
        $servicePrepared = -not $ftpServiceWasRunning -or $service.status -eq "Stopped"
        if (
            $responder.healthy -and
            $rollbackTask.healthy -and
            $firewall.exact -and
            $servicePrepared -and
            $probe.success
        ) {
            $readiness = [ordered]@{
                responder = $responder
                rollback_task = $rollbackTask
                firewall = $firewall
                ftp_service = $service
                ftp_probe = $probe
            }
            break
        }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq $readiness) {
        throw "FTP responder failed exact readiness checks"
    }

    Write-NewJson -Path $localPaths.ready -Document ([ordered]@{
        schema_version = "1.0.0"
        task = "T9.1"
        kind = "windows_target_ready"
        status = "ready"
        attempt_id = $contract.attempt_id
        run_token = $contract.run_token
        source_ip = $contract.topology.source_ip
        target_ip = $contract.topology.target_ip
        firewall_rule = $ruleName
        firewall_remote_address = $contract.topology.source_ip
        firewall_local_ports = $contract.target.firewall_tcp_ports
        responder_task = $taskNames.serve
        rollback_task = $taskNames.rollback
        listener_process_id = $readiness.responder.process_id
        listener_start_time_filetime_utc = $readiness.responder.start_time_filetime_utc
        observed_banner = $readiness.ftp_probe.observed_banner
        script_sha256 = $scriptHash
        contract_sha256 = $contractHash
        expires_at_utc = $expiresAt.ToString("o")
        ready_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    })
    Publish-LocalEvidence -LocalPaths $localPaths -ExternalPaths $externalPaths
}
catch {
    $prepareError = $_
}
finally {
    $prepareLock.Dispose()
}

if ($null -ne $prepareError) {
    $rollbackError = $null
    try {
        Invoke-Rollback `
            -Contract $contract `
            -Staging $staging `
            -LocalPaths $localPaths `
            -ExternalPaths $externalPaths `
            -TaskNames $taskNames `
            -RuleName $ruleName |
            Out-Null
    }
    catch {
        $rollbackError = $_
    }
    if ($null -ne $rollbackError) {
        throw "Prepare failed: $($prepareError.Exception.Message); rollback failed: $($rollbackError.Exception.Message)"
    }
    throw "Prepare failed and was rolled back: $($prepareError.Exception.Message)"
}

[ordered]@{
    schema_version = "1.0.0"
    operation = "prepare"
    status = "ready"
    attempt_id = $contract.attempt_id
    ready = $externalPaths.ready
    local_root = $staging.root
} | ConvertTo-Json -Depth 8
