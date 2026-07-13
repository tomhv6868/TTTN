<#
.SYNOPSIS
  One-time SSH bootstrap for the NIDS lab VMs (kali/ubuntu/windows), so that
  tools/labctl.py (key-only, BatchMode=yes, never prompts) can take over
  afterwards.

.WHY THIS EXISTS
  labctl.py intentionally never does password auth or interactive host-key
  prompts. That means it cannot install its own SSH key on a guest that
  doesn't have one yet - something else has to do that first. This script
  is that "something else". It uses VMware's own guest-automation channel
  (vmrun runProgramInGuest / copyFileFromHostToGuest), authenticated with
  the guest OS credentials you type directly into this PowerShell prompt.

.SECURITY NOTES
  - Credentials are read with Get-Credential (masked prompt) and used only
    in-memory for the duration of this script. They are never written to
    disk, never logged, and never sent anywhere outside vmrun talking to
    your own local VMs.
  - This script does not touch tools/labctl.py or config/lab-hosts.json's
    schema - it only reads lab-hosts.json for paths/aliases and writes to
    your personal ~/.ssh/config and the guest's authorized_keys.
  - Re-running this script is safe: each step is idempotent (skips work
    that is already done).

.NOTES ON RELIABILITY (learned from the first live run)
  - vmrun's own exit code for runProgramInGuest does not reliably reflect
    whether the *guest* command succeeded - only whether vmrun could talk
    to VMware Tools. So per-step [ok]/[fail] during setup is best-effort
    diagnostic noise, not proof. The actual source of truth is step 5: a
    real SSH connect using the freshly-installed key. If that succeeds,
    everything upstream worked, full stop.
  - Native stderr from vmrun/ssh must NOT be merged with 2>&1 under
    $ErrorActionPreference = "Stop" - PowerShell 5.1 wraps merged stderr
    lines as terminating NativeCommandError objects, which aborted the
    whole script mid-run the first time this was used. Fixed by never
    setting ErrorActionPreference to Stop and never redirecting native
    stderr with 2>&1.

.USAGE
  powershell -ExecutionPolicy Bypass -File tools\labctl_bootstrap_ssh.ps1
  powershell -ExecutionPolicy Bypass -File tools\labctl_bootstrap_ssh.ps1 -Roles windows
#>

param(
    [ValidateSet("kali", "ubuntu", "windows")]
    [string[]]$Roles = @("kali", "ubuntu", "windows"),
    [string]$ConfigPath = "$PSScriptRoot\..\config\lab-hosts.json",
    [string]$PublicKeyPath = "$env:USERPROFILE\.ssh\id_ed25519_nidslab.pub"
)

function Write-Step($msg) { Write-Host "`n== $msg ==" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "  [ok] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [fail] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "  [i] $msg" -ForegroundColor DarkGray }

if (-not (Test-Path $ConfigPath)) {
    Write-Fail "Khong tim thay $ConfigPath. Chay lai sau khi tao config/lab-hosts.json."
    exit 1
}
if (-not (Test-Path $PublicKeyPath)) {
    Write-Fail "Khong tim thay public key $PublicKeyPath. Tao truoc bang: ssh-keygen -t ed25519 -f `"$env:USERPROFILE\.ssh\id_ed25519_nidslab`" -N '""'"
    exit 1
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$vmrun = $config.vmrun
$sshExe = $config.ssh
$pubKeyContent = (Get-Content $PublicKeyPath -Raw).Trim()
$privateKeyPath = $PublicKeyPath -replace '\.pub$', ''
$sshConfigPath = "$env:USERPROFILE\.ssh\config"

if (-not (Test-Path $vmrun)) { Write-Fail "vmrun khong ton tai o $vmrun"; exit 1 }
if (-not (Test-Path $sshExe)) { Write-Fail "ssh.exe khong ton tai o $sshExe"; exit 1 }
if (-not (Test-Path "$env:USERPROFILE\.ssh")) { New-Item -ItemType Directory -Path "$env:USERPROFILE\.ssh" | Out-Null }
if (-not (Test-Path $sshConfigPath)) { New-Item -ItemType File -Path $sshConfigPath | Out-Null }

$isLinux = @{ kali = $true; ubuntu = $true; windows = $false }

foreach ($role in $Roles) {
    $hostCfg = $config.hosts.$role
    $vmx = $hostCfg.vmx
    $alias = $hostCfg.alias
    Write-Step "$role ($alias)"

    if (-not (Test-Path $vmx)) { Write-Fail "VMX khong ton tai: $vmx"; continue }

    # 1. Discover current guest IP via VMware Tools (no guest credentials needed).
    #    No stderr redirection here - let vmrun print its own diagnostics if any.
    $ip = (& $vmrun getGuestIPAddress $vmx -wait | Select-Object -Last 1).Trim()
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        Write-Fail "Khong lay duoc IP that (vmrun tra ve: '$ip'). VM co dang bat va co VMware Tools khong?"
        continue
    }
    Write-Ok "IP hien tai: $ip"

    # 2. Guest OS credentials, typed directly here - never stored, never logged.
    $cred = Get-Credential -Message "Tai khoan guest OS cho $role ($alias) - dung 1 lan de cai SSH key"
    $guestUser = $cred.UserName
    $guestPassPlain = $cred.GetNetworkCredential().Password

    if ($isLinux[$role]) {
        # 3a. Build a real script file on the host (avoids fragile quoting across
        #     PowerShell -> vmrun -> bash -c) and copy + run it in the guest.
        $localScript = New-TemporaryFile
        $remoteScript = "/tmp/nidslab_bootstrap.sh"
        $remoteKey = "/tmp/nidslab_bootstrap_key.pub"
        @"
#!/bin/bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
grep -qxF "`$(cat $remoteKey)" ~/.ssh/authorized_keys || cat $remoteKey >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
rm -f $remoteKey
sudo -n systemctl enable --now ssh 2>/dev/null || sudo -n systemctl enable --now sshd 2>/dev/null
exit 0
"@ | Set-Content -Path $localScript -NoNewline -Encoding ascii

        & $vmrun -gu $guestUser -gp $guestPassPlain copyFileFromHostToGuest $vmx $PublicKeyPath $remoteKey
        if ($LASTEXITCODE -ne 0) { Write-Fail "copyFileFromHostToGuest (key) that bai - sai user/password, hoac VMware Tools chua san sang."; Remove-Item $localScript; continue }

        & $vmrun -gu $guestUser -gp $guestPassPlain copyFileFromHostToGuest $vmx $localScript.FullName $remoteScript
        if ($LASTEXITCODE -ne 0) { Write-Fail "copyFileFromHostToGuest (script) that bai."; Remove-Item $localScript; continue }
        Remove-Item $localScript

        & $vmrun -gu $guestUser -gp $guestPassPlain runProgramInGuest $vmx /bin/bash $remoteScript
        Write-Info "Da chay script cai dat tren guest (xac nhan that o buoc 5 ben duoi, khong dua vao exit code cua vmrun o day)."
    } else {
        # 3b. Windows guest: OpenSSH Server feature + administrators_authorized_keys,
        #     driven from a real .ps1 file copied into the guest (same reasoning).
        $localScript = New-TemporaryFile
        $localScriptPs1 = "$localScript.ps1"
        Rename-Item $localScript $localScriptPs1
        $remoteKey = "C:\Windows\Temp\nidslab_bootstrap_key.pub"
        $remoteScript = "C:\Windows\Temp\nidslab_bootstrap.ps1"
        @"
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue | Out-Null
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\ssh' | Out-Null
Add-Content -Path 'C:\ProgramData\ssh\administrators_authorized_keys' -Value (Get-Content '$remoteKey')
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Remove-Item '$remoteKey' -Force
"@ | Set-Content -Path $localScriptPs1 -Encoding utf8

        & $vmrun -gu $guestUser -gp $guestPassPlain copyFileFromHostToGuest $vmx $PublicKeyPath $remoteKey
        if ($LASTEXITCODE -ne 0) { Write-Fail "copyFileFromHostToGuest (key) that bai - sai user/password, hoac VMware Tools chua san sang."; Remove-Item $localScriptPs1; continue }

        & $vmrun -gu $guestUser -gp $guestPassPlain copyFileFromHostToGuest $vmx $localScriptPs1 $remoteScript
        if ($LASTEXITCODE -ne 0) { Write-Fail "copyFileFromHostToGuest (script) that bai."; Remove-Item $localScriptPs1; continue }
        Remove-Item $localScriptPs1

        & $vmrun -gu $guestUser -gp $guestPassPlain runProgramInGuest $vmx "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File $remoteScript
        Write-Info "Da chay script cai dat tren guest (xac nhan that o buoc 5 ben duoi, khong dua vao exit code cua vmrun o day). Yeu cau user nay la Administrator tren guest."
    }

    $guestPassPlain = $null  # drop the plaintext password reference as soon as we're done with it

    # 4. Write/refresh this host's ~/.ssh/config block (idempotent).
    $marker = "Host $alias"
    $existing = Get-Content $sshConfigPath -Raw -ErrorAction SilentlyContinue
    if ($existing -notmatch [regex]::Escape($marker)) {
        Add-Content -Path $sshConfigPath -Value "`nHost $alias`n    User $guestUser`n    IdentityFile $($privateKeyPath -replace '\\','/')`n"
        Write-Ok "Da them block '$marker' vao $sshConfigPath (User=$guestUser)"
    } else {
        Write-Ok "Block '$marker' da co san trong $sshConfigPath, khong ghi de"
    }

    # 5. Enroll the host key by connecting once with auto-accept, and treat this
    #    as the ONLY authoritative pass/fail signal for the whole role.
    & $sshExe -T -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ConnectionAttempts=1 -o "HostName=$ip" -o "HostKeyAlias=$alias" -- $alias hostname
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "SSH round-trip thanh cong qua alias $alias - key + sshd + host key deu on."
    } else {
        Write-Fail "SSH that bai that su (exit $LASTEXITCODE) - xem stderr ngay o tren de biet ly do that (permission denied / connection refused / timeout)."
    }
}

Write-Host "`nXong. Chay: `".venv\Scripts\python.exe tools\labctl.py status`" hoac bam Refresh trong tab Lab Topology de kiem tra that." -ForegroundColor Cyan
