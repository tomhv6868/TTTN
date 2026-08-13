<#
demo-clean.ps1 — xoa log do bo script demo tao ra, de chay lai tu dau.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-clean.ps1

Tham so:
    -Session <ten>   Xoa dung mot session. Mac dinh: session dang active.
    -All             Xoa MOI session trong run_log/demo.
    -StreamsOnly     Chi lam rong hai file .jsonl, giu thu muc va log dashboard.
    -Yes             Khong hoi lai (dung khi chay tu script khac).
    -List            Chi liet ke, khong xoa.

AN TOAN:
    Script chi dong den  run_log/demo/**.
    Hai file bang chung  run_log/full-flow-v1/live-detection-f9.jsonl  va
    live-detection-terminal.jsonl  nam ngoai pham vi nay va KHONG bao gio bi
    dung toi. Ham Assert-InsideDemoRoot chan moi duong dan ra ngoai.
#>

[CmdletBinding()]
param(
    [string]$Session = "",
    [switch]$All,
    [switch]$StreamsOnly,
    [switch]$Yes,
    [switch]$List
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$demoRoot = Get-DemoRoot

if (-not (Test-Path $demoRoot)) {
    Write-Ok "Chua co run_log/demo — khong co gi de xoa."
    exit 0
}

# ------------------------------------------------------------- Chon target
$targets = @()
if ($All) {
    $targets = @(Get-AllSessions | Where-Object { $null -ne $_ } | ForEach-Object { $_.FullName })
    if ($targets.Count -eq 0) { Write-Ok "Khong co session nao."; exit 0 }
} else {
    $targets = @((Resolve-SessionArg -Session $Session))
}

# ------------------------------------------------------------- Liet ke
Write-Step "Se xoa trong pham vi run_log/demo"
Write-Host ""
$totalFiles = 0
$totalBytes = 0
foreach ($t in $targets) {
    Assert-InsideDemoRoot $t | Out-Null
    $files = @(Get-ChildItem -Path $t -Recurse -File -ErrorAction SilentlyContinue)
    $bytes = 0
    foreach ($f in $files) { $bytes += $f.Length }
    $totalFiles += $files.Count
    $totalBytes += $bytes
    $name = Split-Path $t -Leaf
    Write-Host ("  {0}   {1} file, {2:N0} KB" -f $name, $files.Count, ($bytes / 1KB)) -ForegroundColor White
    foreach ($f in ($files | Sort-Object Name)) {
        $lines = ""
        if ($f.Extension -eq ".jsonl") { $lines = " ({0} dong)" -f (Get-JsonlLineCount -Path $f.FullName) }
        Write-Host ("      - {0}{1}" -f $f.Name, $lines) -ForegroundColor DarkGray
    }
}
Write-Host ""
Write-Host ("  Tong: {0} file, {1:N0} KB" -f $totalFiles, ($totalBytes / 1KB)) -ForegroundColor White
Write-Host ""

Write-Host "  KHONG dung toi (bang chung bao cao):" -ForegroundColor Green
foreach ($e in @("live-detection-f9.jsonl", "live-detection-terminal.jsonl", "live-detection.jsonl")) {
    $p = Join-Path $script:EvidenceDir $e
    if (Test-Path $p) {
        $kb = [math]::Round((Get-Item $p).Length / 1KB)
        Write-Host ("      - run_log/full-flow-v1/{0}  [{1:N0} KB]  giu nguyen" -f $e, $kb) -ForegroundColor Green
    }
}
Write-Host ""

if ($List) { exit 0 }
if ($totalFiles -eq 0) { Write-Ok "Khong co file nao de xoa."; exit 0 }

# ------------------------------------------------------------- Xac nhan
if (-not $Yes) {
    $mode = "xoa ca thu muc session"
    if ($StreamsOnly) { $mode = "lam rong hai file .jsonl, giu nguyen thu muc" }
    $ans = Read-Host "Xac nhan $mode ? go 'xoa' de tiep tuc"
    if ($ans.Trim().ToLower() -ne "xoa") { Write-Warn2 "Da huy."; exit 1 }
}

# ------------------------------------------------------------- Thuc hien
foreach ($t in $targets) {
    $safe = Assert-InsideDemoRoot $t
    if ($StreamsOnly) {
        foreach ($f in @("live-detection-f9.jsonl", "live-detection-terminal.jsonl")) {
            $p = Join-Path $safe $f
            if (Test-Path $p) {
                Assert-InsideDemoRoot $p | Out-Null
                Set-Content -Path $p -Value "" -NoNewline -Encoding utf8
                Write-Ok "da lam rong $f"
            }
        }
        # Xoa vet cac lan chay bridge trong manifest
        $m = Get-SessionManifest -SessionDir $safe
        if ($null -ne $m) {
            $m | Add-Member -NotePropertyName streams_run -NotePropertyValue @() -Force
            Save-SessionManifest -SessionDir $safe -Manifest $m
        }
    } else {
        try {
            Remove-Item -Path $safe -Recurse -Force -ErrorAction Stop
            Write-Ok "da xoa $(Split-Path $safe -Leaf)"
        } catch {
            # Thuong la dashboard-backend.err con bi uvicorn giu. Xoa tung file,
            # bo qua cai nao dang khoa, roi bao lai cho nguoi dung biet.
            Write-Warn2 "Khong xoa duoc ca thu muc, thu xoa tung file"
            $locked = @()
            foreach ($file in @(Get-ChildItem -Path $safe -Recurse -File -ErrorAction SilentlyContinue)) {
                try { Remove-Item -Path $file.FullName -Force -ErrorAction Stop }
                catch { $locked += $file.Name }
            }
            if ($locked.Count -eq 0) {
                Remove-Item -Path $safe -Recurse -Force -ErrorAction SilentlyContinue
                Write-Ok "da xoa $(Split-Path $safe -Leaf)"
            } else {
                Write-Warn2 "Con file dang bi process giu: $($locked -join ', ')"
                Write-Host "        Tat backend/vite roi chay lai, hoac xoa tay thu muc:" -ForegroundColor DarkGray
                Write-Host "        $safe" -ForegroundColor DarkGray
            }
        }
    }
}

# Neu session active vua bi xoa thi bo con tro
$active = Get-ActiveSession
if ($null -eq $active) {
    $activeFile = Join-Path $demoRoot ".active-session"
    if (Test-Path $activeFile) { Remove-Item $activeFile -Force }
    Write-Warn2 "Da bo con tro session active."
}

Write-Host ""
Write-Ok "Xong. Chay lai demo-up.ps1 de tao session moi."
