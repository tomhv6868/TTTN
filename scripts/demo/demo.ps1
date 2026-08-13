<#
demo.ps1 — menu tong, goi cac script demo khac.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo.ps1

Menu lap lai tan khi chon 0. Moi muc goi mot script rieng, xong lai ve menu.
Cac script van chay doc lap duoc, menu chi la vo boc cho tien.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$ps = "powershell"
$here = $PSScriptRoot

function Invoke-Sub {
    param([string]$Script, [string[]]$Extra = @())
    $target = Join-Path $here $Script
    if (-not (Test-Path $target)) { Write-Err2 "Khong thay $Script"; return }
    Write-Host ""
    $callArgs = @("-ExecutionPolicy", "Bypass", "-File", $target) + $Extra
    & $ps @callArgs
    Write-Host ""
    Write-Host "  ---- xong: $Script ----" -ForegroundColor DarkGray
    Read-Host "  Enter de ve menu" | Out-Null
}

function Show-Status {
    $active = Get-ActiveSession
    Write-Host ""
    Write-Host "=============================================================" -ForegroundColor DarkGray
    Write-Host "  DEMO NIDS - menu" -ForegroundColor White
    Write-Host "=============================================================" -ForegroundColor DarkGray

    if ($null -eq $active) {
        Write-Host "  Session : (chua co)" -ForegroundColor Yellow
    } else {
        $f9 = Get-JsonlLineCount -Path (Join-Path $active "live-detection-f9.jsonl")
        $tm = Get-JsonlLineCount -Path (Join-Path $active "live-detection-terminal.jsonl")
        Write-Host ("  Session : {0}" -f (Split-Path $active -Leaf)) -ForegroundColor Green
        Write-Host ("  Stream  : f9={0}  terminal={1}" -f $f9, $tm) -ForegroundColor Green
    }

    # Dashboard con song khong
    $be = @(Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like "*uvicorn*dashboard.server.app*" })
    $fe = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like "*vite*" })
    $beTxt = "tat"; if ($be.Count -gt 0) { $beTxt = "dang chay (pid $($be[0].ProcessId))" }
    $feTxt = "tat"; if ($fe.Count -gt 0) { $feTxt = "dang chay (pid $($fe[0].ProcessId))" }
    Write-Host ("  Backend : {0}" -f $beTxt)
    Write-Host ("  Web     : {0}   http://localhost:5173" -f $feTxt)

    # May ao
    try {
        $cfg = Get-LabConfig
        $out = & $cfg.vmrun "list" 2>&1
        $n = 0
        $m = [regex]::Match(($out -join "`n"), "Total running VMs:\s*(\d+)")
        if ($m.Success) { $n = [int]$m.Groups[1].Value }
        Write-Host ("  May ao  : {0} dang chay" -f $n)
    } catch { Write-Host "  May ao  : (khong doc duoc vmrun)" -ForegroundColor Yellow }

    Write-Host "-------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  1  Bat may ao + dashboard        (demo-up)"
    Write-Host "  2  Tao luong demo theo model     (demo-stream)"
    Write-Host "  3  Gui canh bao qua thu          (demo-mail)"
    Write-Host "  4  Chon session dashboard doc    (demo-log -Pick)"
    Write-Host "  5  Xem log / duoi stream         (demo-log)"
    Write-Host "  6  Tat dashboard + may ao        (demo-down)"
    Write-Host "  7  Don log da tao                (demo-clean)"
    Write-Host "  0  Thoat menu"
    Write-Host "-------------------------------------------------------------" -ForegroundColor DarkGray
}

function Menu-Stream {
    Write-Host ""
    Write-Host "  1  slide20-dashboard   28.937 ban ghi   (terminal)"
    Write-Host "  2  slide23-ftp         209/209 alert    (f9)"
    Write-Host "  3  slide23-goldeneye   4.127 alert      (f9)"
    Write-Host "  4  slide19-latency     7.509 alert      (f9)"
    Write-Host "  5  hulk                6.086 alert      (f9)"
    Write-Host "  6  Tu chon file        (script se hoi)"
    Write-Host ""
    $p = (Read-Host "Chon [1-6]").Trim()
    $map = @{ "1" = "slide20-dashboard"; "2" = "slide23-ftp"; "3" = "slide23-goldeneye";
              "4" = "slide19-latency"; "5" = "hulk" }
    if ($map.ContainsKey($p)) {
        $follow = (Read-Host "Bam duoi file de day tung su kien? [k/c]").Trim().ToLower()
        $extra = @("-Preset", $map[$p])
        if ($follow -eq "c" -or $follow -eq "y") { $extra += "-Follow" }
        Invoke-Sub -Script "demo-stream.ps1" -Extra $extra
    } elseif ($p -eq "6") {
        Invoke-Sub -Script "demo-stream.ps1"
    } else {
        Write-Warn2 "Bo qua."
    }
}

function Menu-Mail {
    Write-Host ""
    Write-Host "  1  Chay thu (khong gui)"
    Write-Host "  2  Gui that"
    Write-Host "  3  Xem cau hinh SMTP"
    Write-Host "  4  Chay thu voi nguong + loc theo ho"
    Write-Host ""
    $p = (Read-Host "Chon [1-4]").Trim()
    $model = (Read-Host "Model [f9/terminal, Enter = f9]").Trim().ToLower()
    if ($model -ne "terminal") { $model = "f9" }
    if     ($p -eq "1") { Invoke-Sub -Script "demo-mail.ps1" -Extra @("-Model", $model) }
    elseif ($p -eq "2") { Invoke-Sub -Script "demo-mail.ps1" -Extra @("-Model", $model, "-Send") }
    elseif ($p -eq "3") { Invoke-Sub -Script "demo-mail.ps1" -Extra @("-Model", $model, "-ShowConfig") }
    elseif ($p -eq "4") {
        $min = (Read-Host "Nguong toi thieu [Enter = 20]").Trim()
        if ($min -eq "" -or $min -notmatch "^[0-9]+$") { $min = "20" }
        $fam = (Read-Host "Toi da moi ho [Enter = 5, 0 = khong gioi han]").Trim()
        if ($fam -eq "" -or $fam -notmatch "^[0-9]+$") { $fam = "5" }
        Invoke-Sub -Script "demo-mail.ps1" -Extra @(
            "-Model", $model, "-FromStart",
            "-MinAlerts", $min, "-PerFamilyLimit", $fam)
    }
    else { Write-Warn2 "Bo qua." }
}

# ------------------------------------------------------------------ Vong lap
while ($true) {
    Show-Status
    $choice = (Read-Host "Chon").Trim()
    switch ($choice) {
        "1" { Invoke-Sub -Script "demo-up.ps1" }
        "2" { Menu-Stream }
        "3" { Menu-Mail }
        "4" { Invoke-Sub -Script "demo-log.ps1" -Extra @("-Pick") }
        "5" {
            $mm = (Read-Host "Xem duoi stream nao? [f9/terminal, Enter = chi liet ke]").Trim().ToLower()
            if ($mm -eq "f9" -or $mm -eq "terminal") {
                Invoke-Sub -Script "demo-log.ps1" -Extra @("-Tail", $mm)
            } else {
                Invoke-Sub -Script "demo-log.ps1" -Extra @("-Evidence")
            }
        }
        "6" { Invoke-Sub -Script "demo-down.ps1" }
        "7" { Invoke-Sub -Script "demo-clean.ps1" }
        "0" { Write-Host ""; Write-Ok "Thoat menu. Dashboard va may ao van giu nguyen neu dang chay."; return }
        default { Write-Warn2 "Khong hieu: $choice" }
    }
}
