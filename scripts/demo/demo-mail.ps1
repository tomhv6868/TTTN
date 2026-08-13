<#
demo-mail.ps1 — gui canh bao qua thu dien tu tu stream cua session demo.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-mail.ps1            # chay thu
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-mail.ps1 -Send      # gui that

Tham so:
    -Model f9|terminal   Stream nguon. Mac dinh f9.
    -Send                Gui that. MAC DINH LA CHAY THU (dry run).
    -Limit 20            So canh bao toi da trong mot ban tin. Mac dinh 20.
    -MinAlerts 1         Chi gui khi gom du bay nhieu canh bao. Chua du thi giu
                         con tro lai de lan chay sau gom tiep. Mac dinh 1.
    -PerFamilyLimit 5    So dong toi da moi ho tan cong trong mot ban tin, de mot
                         ho on ao khong lap het cho cua cac ho khac. 0 = bo gioi
                         han. Mac dinh 5.
    -DedupeHours 24      Khong bao lai cung mot luong trong bay nhieu gio. 0 = tat.
                         Chi ghi nho khi gui that, chay thu khong lam ban bo nho.
                         Mac dinh 24.
    -FromStart           Bo qua con tro, doc lai tu dau file.
    -Session <ten>       Session dich. Mac dinh: session dang active.
    -ShowConfig          In cau hinh SMTP dang dung (che mat khau).

AN TOAN:
    - Mac dinh la chay thu. Khong co -Send thi khong gui di dau ca.
    - Con tro va bien nhan ghi vao  <session>/alert-email/  chu KHONG ghi vao
      run_log/full-flow-v1/alert-email/. Bon bien nhan cua bao cao (2 dry_run +
      2 sent, tong 25 canh bao) giu nguyen, demo khong lam lech con so do.
    - Thong tin dang nhap doc tu .env, khong bao gio in ra man hinh.
#>

[CmdletBinding()]
param(
    [ValidateSet("f9", "terminal")][string]$Model = "f9",
    [switch]$Send,
    [int]$Limit = 20,
    [int]$MinAlerts = 1,
    [int]$PerFamilyLimit = 5,
    [double]$DedupeHours = 24,
    [switch]$FromStart,
    [string]$Session = "",
    [switch]$ShowConfig
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$repo = Get-RepoRoot
$sessionDir = Resolve-SessionArg -Session $Session
Assert-InsideDemoRoot $sessionDir | Out-Null
Write-Ok "Session: $sessionDir"

# ------------------------------------------------------------------ .env
$envFile = Join-Path $repo ".env"
if (-not (Test-Path $envFile)) {
    throw "Thieu .env. Xem docs/alert-email-setup.vi.md de tao."
}
$needed = @("NIDS_SMTP_HOST", "NIDS_SMTP_PORT", "NIDS_SMTP_USER",
            "NIDS_SMTP_PASSWORD", "NIDS_ALERT_SENDER", "NIDS_ALERT_RECIPIENTS")
$found = @{}
foreach ($line in (Get-Content $envFile -Encoding UTF8)) {
    $t = $line.Trim()
    if ($t -eq "" -or $t.StartsWith("#") -or -not $t.Contains("=")) { continue }
    $k = $t.Split("=", 2)[0].Trim()
    $v = $t.Split("=", 2)[1].Trim()
    if ($needed -contains $k) { $found[$k] = $v }
}
$missing = @($needed | Where-Object { -not $found.ContainsKey($_) -or $found[$_] -eq "" })
if ($missing.Count -gt 0) { throw "Thieu bien trong .env: $($missing -join ', ')" }
Write-Ok "SMTP: du 6 bien trong .env"

if ($ShowConfig) {
    Write-Host ""
    Write-Host ("   host       : {0}:{1}" -f $found["NIDS_SMTP_HOST"], $found["NIDS_SMTP_PORT"]) -ForegroundColor White
    Write-Host ("   nguoi gui  : {0}" -f $found["NIDS_ALERT_SENDER"]) -ForegroundColor White
    Write-Host ("   nguoi nhan : {0}" -f $found["NIDS_ALERT_RECIPIENTS"]) -ForegroundColor White
    Write-Host  "   mat khau   : (khong in ra)" -ForegroundColor DarkGray
    Write-Host ""
}

# ----------------------------------------------------------------- Stream
$stream = Join-Path $sessionDir "live-detection-$Model.jsonl"
if (-not (Test-Path $stream)) { throw "Chua co stream $Model. Chay demo-stream.ps1 truoc." }
$lines = Get-JsonlLineCount -Path $stream
if ($lines -eq 0) { throw "Stream $Model dang trong. Chay demo-stream.ps1 truoc." }
Write-Ok "Stream: $stream ($lines dong)"

# Con tro va bien nhan RIENG cua session — khong dung vao thu muc bang chung.
$mailDir = Join-Path $sessionDir "alert-email"
Assert-InsideDemoRoot $mailDir | Out-Null
if (-not (Test-Path $mailDir)) { New-Item -ItemType Directory -Path $mailDir | Out-Null }
$cursor = Join-Path $mailDir "cursor.json"

# ------------------------------------------------------------------ Chay
$argsList = @(
    (Join-Path $repo "scripts\alert_email_notifier.py"),
    "--stream", $stream,
    "--state", $cursor,
    "--receipt-dir", $mailDir,
    "--limit", "$Limit",
    "--min-alerts", "$MinAlerts",
    "--per-family-limit", "$PerFamilyLimit",
    "--dedupe-window-hours", "$DedupeHours"
)
if ($FromStart) { $argsList += "--from-start" }
if ($Send) { $argsList += "--send" }

$before = @(Get-ChildItem -Path $mailDir -Filter "receipt-*.json" -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Name })

if ($Send) {
    Write-Host ""
    Write-Warn2 "SAP GUI THAT toi: $($found['NIDS_ALERT_RECIPIENTS'])"
    $ans = Read-Host "Go 'gui' de xac nhan"
    if ($ans.Trim().ToLower() -ne "gui") { Write-Warn2 "Da huy."; exit 1 }
} else {
    Write-Warn2 "CHAY THU (dry run). Them -Send de gui that."
}

Write-Step "Chay alert_email_notifier.py"
Write-Host ""
& $script:VenvPython @argsList
$code = $LASTEXITCODE
Write-Host ""

# --------------------------------------------------------------- Ket qua
$receipts = @(Get-ChildItem -Path $mailDir -Filter "receipt-*.json" -ErrorAction SilentlyContinue |
              Where-Object { $before -notcontains $_.Name } |
              Sort-Object LastWriteTime)
$held = $false
if ($receipts.Count -eq 0) {
    # Notifier thoat 0 ma khong sinh bien nhan = chua du nguong, dang gom tiep.
    $held = $true
    Write-Warn2 "Chua sinh bien nhan lan nay: chua dat nguong -MinAlerts $MinAlerts."
    Write-Host "    Con tro giu nguyen, khong canh bao nao bi mat." -ForegroundColor DarkGray
} else {
    $last = $receipts[-1]
    try {
        $r = Get-Content $last.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $names = $r.PSObject.Properties.Name
        Write-Ok "Bien nhan: $($last.Name)"
        Write-Host ("     mode      : {0}" -f $r.mode) -ForegroundColor White
        Write-Host ("     subject   : {0}" -f $r.subject) -ForegroundColor White
        if ($names -contains "recipients") {
            Write-Host ("     nguoi nhan: {0}" -f (@($r.recipients) -join ", ")) -ForegroundColor White
        }
        if ($names -contains "family_totals") {
            $fam = @($r.family_totals.PSObject.Properties.Name)
            Write-Host ("     ho tan cong: {0} ho co mat trong ban tin" -f $fam.Count) -ForegroundColor White
        }
        if ($names -contains "skipped_recent" -and $r.skipped_recent -gt 0) {
            Write-Host ("     bo qua da bao trong {0}h: {1}" -f $DedupeHours, $r.skipped_recent) -ForegroundColor White
        }
        if ($names -contains "family_suppressed") {
            $sup = @($r.family_suppressed.PSObject.Properties)
            if ($sup.Count -gt 0) {
                $tong = ($sup | Measure-Object -Property Value -Sum).Sum
                Write-Host ("     da gop bot : {0} su kien cung loai" -f $tong) -ForegroundColor White
            }
        }
    } catch { Write-Warn2 "Khong doc duoc bien nhan $($last.Name)" }
}

Write-Host ""
if ($code -eq 0) {
    if ($held) { Write-Ok "Chua den nguong nen chua gui. Chay lai sau khi stream co them canh bao." }
    elseif ($Send) { Write-Ok "Da gui. Mo hom thu nguoi nhan de doi chieu." }
    else { Write-Ok "Chay thu xong, chua gui gi. Them -Send de gui that." }
    Write-Host "    Bien nhan cua session: $mailDir" -ForegroundColor DarkGray
    Write-Host "    Bien nhan cua bao cao van nguyen: run_log/full-flow-v1/alert-email/" -ForegroundColor Green
} else {
    Write-Err2 "Notifier thoat voi ma $code."
    Write-Host "    Gmail bao 535 thi xem docs/alert-email-setup.vi.md — can App Password." -ForegroundColor DarkGray
}
exit $code
