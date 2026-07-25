[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop")]
    [string]$Action = "Start",
    [string]$ListenAddress = "192.168.252.20",
    [string]$LabSubnet = "192.168.252.0/24",
    [string]$Username = "nidslab",
    [string]$Password = "Nids-Lab-2026!",
    [string]$OpenSshSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$firewallRule = "NIDS-T85-All-Services"
$certificateSubject = "CN=NIDS-T85-Lab"
$sslAppId = "{8c9f207e-f61f-4d8f-90eb-9135b38db352}"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator"
    }
}

function Remove-LabConfiguration {
    Get-Job -Name "NIDS-T85-*" -ErrorAction SilentlyContinue |
        Stop-Job -ErrorAction SilentlyContinue
    Get-Job -Name "NIDS-T85-*" -ErrorAction SilentlyContinue |
        Remove-Job -Force -ErrorAction SilentlyContinue

    Remove-NetFirewallRule -Name $firewallRule -ErrorAction SilentlyContinue
    Stop-Service -Name sshd -ErrorAction SilentlyContinue
    & netsh.exe http delete urlacl "url=http://$ListenAddress`:80/" | Out-Null
    & netsh.exe http delete urlacl "url=https://$ListenAddress`:443/" | Out-Null
    & netsh.exe http delete sslcert "ipport=$ListenAddress`:443" | Out-Null

    Get-ChildItem Cert:\LocalMachine\My |
        Where-Object Subject -eq $certificateSubject |
        Remove-Item -Force -ErrorAction SilentlyContinue

    if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $Username
    }
}

function Install-OpenSsh {
    $capability = Get-WindowsCapability -Online |
        Where-Object Name -like "OpenSSH.Server*"
    if (-not $capability) {
        Write-Warning "OpenSSH.Server capability is not exposed by this Windows image"
        return $false
    }
    if ($capability.State -ne "Installed") {
        Write-Host "Installing Windows OpenSSH Server..."
        try {
            if ($OpenSshSource) {
                Add-WindowsCapability -Online -Name $capability.Name `
                    -Source $OpenSshSource -LimitAccess | Out-Null
            } else {
                Add-WindowsCapability -Online -Name $capability.Name | Out-Null
            }
        }
        catch {
            Write-Warning "OpenSSH unavailable: $($_.Exception.Message)"
            Write-Warning "HTTP, HTTPS and FTP will still start. Use -OpenSshSource with a Windows Features-on-Demand source to enable SSH."
            return $false
        }
    }
    Set-Service -Name sshd -StartupType Manual
    Start-Service -Name sshd
    return $true
}

function Start-FtpResponder {
    Start-Job -Name "NIDS-T85-FTP" -ArgumentList $ListenAddress, $Username, $Password -ScriptBlock {
        param($Address, $ExpectedUser, $ExpectedPassword)
        $listener = [Net.Sockets.TcpListener]::new(
            [Net.IPAddress]::Parse($Address),
            21
        )
        $listener.Start()
        try {
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII)
                    $writer = [IO.StreamWriter]::new($stream, [Text.Encoding]::ASCII)
                    $writer.NewLine = "`r`n"
                    $writer.AutoFlush = $true
                    $writer.WriteLine("220 NIDS T8.5 disposable FTP")
                    $userAccepted = $false
                    while ($client.Connected) {
                        $line = $reader.ReadLine()
                        if ($null -eq $line) { break }
                        $parts = $line.Split(" ", 2)
                        $command = $parts[0].ToUpperInvariant()
                        $argument = if ($parts.Count -eq 2) { $parts[1] } else { "" }
                        switch ($command) {
                            "USER" {
                                $userAccepted = $argument -eq $ExpectedUser
                                $writer.WriteLine("331 Password required")
                            }
                            "PASS" {
                                if ($userAccepted -and $argument -eq $ExpectedPassword) {
                                    $writer.WriteLine("230 Login successful")
                                } else {
                                    $writer.WriteLine("530 Login incorrect")
                                }
                            }
                            "SYST" { $writer.WriteLine("215 Windows_NT") }
                            "TYPE" { $writer.WriteLine("200 Type set") }
                            "PWD"  { $writer.WriteLine('257 "/"') }
                            "QUIT" {
                                $writer.WriteLine("221 Goodbye")
                                break
                            }
                            default { $writer.WriteLine("502 Command not implemented") }
                        }
                        if ($command -eq "QUIT") { break }
                    }
                }
                finally {
                    $client.Dispose()
                }
            }
        }
        finally {
            $listener.Stop()
        }
    } | Out-Null
}

function Start-WebServer([bool]$SshReady) {
    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add("http://$ListenAddress`:80/")
    $listener.Prefixes.Add("https://$ListenAddress`:443/")
    $listener.Start()
    try {
        Write-Host "READY HTTP  : http://$ListenAddress/"
        Write-Host "READY HTTPS : https://$ListenAddress/"
        Write-Host "READY FTP   : ftp://$ListenAddress/"
        if ($SshReady) {
            Write-Host "READY SSH   : ssh $Username@$ListenAddress"
        } else {
            Write-Warning "SSH SKIPPED: OpenSSH Server is not installed"
        }
        Write-Host "Credentials : $Username / $Password"
        Write-Host "Press Ctrl+C to stop and clean up."

        while ($listener.IsListening) {
            $context = $listener.GetContext()
            try {
                $request = $context.Request
                $body = switch -Regex ($request.Url.AbsolutePath) {
                    "^/login" { "Invalid username or password"; break }
                    "^/search" { "No matching records"; break }
                    "^/upload" { "Upload accepted for diagnostic lab"; break }
                    default { "NIDS T8.5 disposable Windows target" }
                }
                $bytes = [Text.Encoding]::UTF8.GetBytes($body)
                $context.Response.StatusCode = 200
                $context.Response.ContentType = "text/plain; charset=utf-8"
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            }
            finally {
                $context.Response.Close()
            }
        }
    }
    finally {
        $listener.Close()
    }
}

Assert-Administrator

if ($Action -eq "Stop") {
    Remove-LabConfiguration
    Write-Host "Windows lab services removed."
    exit 0
}

$address = @(Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object IPAddress -eq $ListenAddress)
if ($address.Count -ne 1) {
    throw "Expected exactly one Windows lab address: $ListenAddress"
}

Remove-LabConfiguration

$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
New-LocalUser -Name $Username -Password $securePassword `
    -Description "Disposable NIDS T8.5 lab account" `
    -PasswordNeverExpires | Out-Null
$usersGroup = Get-LocalGroup -SID "S-1-5-32-545"
Add-LocalGroupMember -Group $usersGroup -Member $Username

$sshReady = Install-OpenSsh

if ($sshReady) {
    $labPorts = @(21, 22, 80, 443)
} else {
    $labPorts = @(21, 80, 443)
}
New-NetFirewallRule -Name $firewallRule -DisplayName $firewallRule `
    -Direction Inbound -Action Allow -Protocol TCP `
    -LocalPort $labPorts -RemoteAddress $LabSubnet -Profile Any | Out-Null

$certificate = New-SelfSignedCertificate -Subject $certificateSubject `
    -DnsName $ListenAddress -CertStoreLocation Cert:\LocalMachine\My `
    -NotAfter ([DateTime]::UtcNow.AddDays(7))
& netsh.exe http add urlacl "url=http://$ListenAddress`:80/" `
    "sddl=D:(A;;GX;;;WD)" | Out-Null
& netsh.exe http add urlacl "url=https://$ListenAddress`:443/" `
    "sddl=D:(A;;GX;;;WD)" | Out-Null
& netsh.exe http add sslcert "ipport=$ListenAddress`:443" `
    "certhash=$($certificate.Thumbprint)" "appid=$sslAppId" | Out-Null

Start-FtpResponder
try {
    Start-WebServer -SshReady $sshReady
}
finally {
    Remove-LabConfiguration
}
