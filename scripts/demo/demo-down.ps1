<#
demo-down.ps1 — tat dashboard va may ao ma demo-up.ps1 da bat.

Dung khi da thoat demo-up bang 'b' hoac 'k' (giu nguyen tien trinh) va gio muon tat.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-down.ps1

Tham so:
    -Session <ten>               Session can tat. Mac dinh: session dang active.
    -Stop suspend|poweroff|leave Cach xu ly may ao. Mac dinh suspend.
    -KeepVm                      Chi tat dashboard, giu nguyen may ao.

Doc danh sach PID va may ao tu <session>/session.json do demo-up ghi lai.
#>

[CmdletBinding()]
param(
    [string]$Session = "",
    [ValidateSet("suspend", "poweroff", "leave")][string]$Stop = "suspend",
    [switch]$KeepVm
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$sessionDir = Resolve-SessionArg -Session $Session
$m = Get-SessionManifest -SessionDir $sessionDir
if ($null -eq $m) { throw "Khong doc duoc session.json trong $sessionDir" }
Write-Ok "Session: $sessionDir"

# ------------------------------------------------------------- Tien trinh
$procs = @()
if ($m.PSObject.Properties.Name -contains "processes") { $procs = @($m.processes) }

if ($procs.Count -eq 0) {
    Write-Warn2 "session.json khong ghi tien trinh nao."
} else {
    Write-Step "Tat tien trinh dashboard"
    foreach ($p in $procs) {
        if ($null -eq $p) { continue }
        try {
            $proc = Get-Process -Id $p.id -ErrorAction Stop
            Stop-Process -Id $p.id -Force -ErrorAction Stop
            Write-Ok "da tat $($p.name) (pid $($p.id))"
        } catch {
            Write-Warn2 "$($p.name) pid $($p.id) khong con chay"
        }
    }
}

# Vite chay qua cmd.exe nen sinh tien trinh node con, phai don rieng.
Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*vite*" -or $_.CommandLine -like "*dashboard*web*" } |
    ForEach-Object {
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Ok "da tat node pid $($_.ProcessId)" } catch { }
    }

# Backend co the con song neu bi khoi dong lai ngoai script
Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*uvicorn*dashboard.server.app*" } |
    ForEach-Object {
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Ok "da tat uvicorn pid $($_.ProcessId)" } catch { }
    }

# ---------------------------------------------------------------- May ao
$vms = @()
if ($m.PSObject.Properties.Name -contains "vms_started") { $vms = @($m.vms_started | Where-Object { $null -ne $_ }) }

if ($KeepVm -or $Stop -eq "leave") {
    Write-Warn2 "Giu nguyen may ao."
} elseif ($vms.Count -eq 0) {
    Write-Warn2 "session.json khong ghi may ao nao do script bat."
} else {
    $cfg = Get-LabConfig
    $op = "suspend"
    if ($Stop -ne "suspend") { $op = "stop" }
    foreach ($h in $vms) {
        if (-not ($cfg.hosts.PSObject.Properties.Name -contains $h)) { continue }
        Write-Step "$op may ao: $h"
        $out = & $cfg.vmrun $op $cfg.hosts.$h.vmx "soft" 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Ok "$h da $op" }
        else {
            $lines = @($out -split "`n" | Where-Object { $_.Trim() -ne "" })
            $first = "(khong co thong bao)"
            if ($lines.Count -gt 0) { $first = $lines[0] }
            Write-Warn2 "$h $op that bai: $first"
        }
    }
}

Write-Host ""
Write-Ok "Xong. Log cua session van con o: $sessionDir"
Write-Host "    Xoa khi khong can nua: scripts\demo\demo-clean.ps1" -ForegroundColor DarkGray
