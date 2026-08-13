<#
demo-log.ps1 — xem va chon thu cong file log nao dang duoc dashboard doc.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-log.ps1

Tham so:
    (khong co)            Liet ke moi session, file, so dong, va danh dau
                          session dashboard dang doc.
    -Pick                 Chon session ngay trong terminal: liet ke co danh so,
                          go so thu tu la doi luon.
    -Use <ten|duong dan>  Tro dashboard sang session khac. Chi doi con tro,
                          KHONG tu khoi dong lai backend — script se in dung
                          lenh can chay.
    -Tail <model>         Xem 20 dong cuoi cua stream (f9 hoac terminal).
    -Lines N              So dong khi -Tail. Mac dinh 20.
    -Session <ten>        Session ap dung cho -Tail. Mac dinh: dang active.
    -Evidence             Liet ke ca hai file bang chung o run_log/full-flow-v1
                          (chi doc, khong bao gio ghi).

Nen nho: dashboard chon file theo bien moi truong NIDS_LIVE_DIR luc khoi dong
backend. Doi con tro xong phai khoi dong lai backend thi moi co hieu luc.
#>

[CmdletBinding()]
param(
    [switch]$Pick,
    [string]$Use = "",
    [ValidateSet("", "f9", "terminal")][string]$Tail = "",
    [int]$Lines = 20,
    [string]$Session = "",
    [switch]$Evidence
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$repo = Get-RepoRoot
$demoRoot = Get-DemoRoot
$active = Get-ActiveSession

# --------------------------------------------------------------- -Pick
if ($Pick) {
    $list = @(Get-AllSessions | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { throw "Chua co session nao. Chay demo-up.ps1 truoc." }
    Write-Step "Chon session"
    Write-Host ""
    for ($i = 0; $i -lt $list.Count; $i++) {
        $d = $list[$i].FullName
        $mark = " "
        if ($null -ne $active -and $d -eq $active) { $mark = "*" }
        $f9 = Get-JsonlLineCount -Path (Join-Path $d "live-detection-f9.jsonl")
        $tm = Get-JsonlLineCount -Path (Join-Path $d "live-detection-terminal.jsonl")
        Write-Host ("  {0} {1,2}) {2,-28} f9={3,-7} terminal={4}" -f $mark, ($i + 1), $list[$i].Name, $f9, $tm) -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  (* = dashboard dang doc)" -ForegroundColor DarkGray
    $ans = Read-Host "So thu tu (Enter de bo qua)"
    $ans = $ans.Trim()
    if ($ans -eq "") { Write-Warn2 "Khong doi gi."; exit 0 }
    $idx = 0
    if (-not [int]::TryParse($ans, [ref]$idx) -or $idx -lt 1 -or $idx -gt $list.Count) {
        throw "So khong hop le: $ans"
    }
    $Use = $list[$idx - 1].FullName
}

# --------------------------------------------------------------- -Use
if ($Use -ne "") {
    $target = Resolve-SessionArg -Session $Use
    Assert-InsideDemoRoot $target | Out-Null
    foreach ($f in @("live-detection-f9.jsonl", "live-detection-terminal.jsonl")) {
        $p = Join-Path $target $f
        if (-not (Test-Path $p)) { New-Item -ItemType File -Path $p | Out-Null }
    }
    Set-ActiveSession -SessionDir $target
    Write-Ok "Con tro session -> $target"
    Write-Host ""
    Write-Ok "KHONG can khoi dong lai backend."
    Write-Host "    dashboard/server/app.py doc lai con tro nay o moi request," -ForegroundColor DarkGray
    Write-Host "    dashboard tu doi nguon o lan poll ke tiep (~2 giay)." -ForegroundColor DarkGray
    Write-Host ""
    foreach ($mm in @("f9", "terminal")) {
        $pp = Join-Path $target "live-detection-$mm.jsonl"
        $nn = Get-JsonlLineCount -Path $pp
        Write-Host ("    {0,-9} {1} dong" -f $mm, $nn) -ForegroundColor White
    }
    Write-Host ""
    exit 0
}

# --------------------------------------------------------------- -Tail
if ($Tail -ne "") {
    $sessionDir = Resolve-SessionArg -Session $Session
    $p = Join-Path $sessionDir "live-detection-$Tail.jsonl"
    if (-not (Test-Path $p)) { throw "Khong thay $p" }
    $n = Get-JsonlLineCount -Path $p
    Write-Ok "$p  ($n dong)"
    Write-Host ""
    Get-Content -Path $p -Tail $Lines -Encoding UTF8 | ForEach-Object {
        try {
            $e = $_ | ConvertFrom-Json
            $ts = ""
            if ($e.PSObject.Properties.Name -contains "ts") { $ts = $e.ts }
            Write-Host ("  {0,-10} {1,-18} {2,-22} -> {3,-22} {4}" -f `
                $e.model, $e.decision, $e.source, $e.destination, $e.candidate)
        } catch {
            Write-Host ("  {0}" -f $_) -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    exit 0
}

# --------------------------------------------------------------- Liet ke
Write-Step "Cac session demo trong run_log/demo"
Write-Host ""

$sessions = @(Get-AllSessions | Where-Object { $null -ne $_ })
if ($sessions.Count -eq 0) {
    Write-Warn2 "Chua co session nao. Chay scripts\demo\demo-up.ps1 truoc."
} else {
    foreach ($s in $sessions) {
        $mark = "  "
        if ($null -ne $active -and $s.FullName -eq $active) { $mark = "->" }
        $m = Get-SessionManifest -SessionDir $s.FullName
        $created = ""
        if ($null -ne $m) { $created = $m.created_utc }
        Write-Host ("{0} {1}" -f $mark, $s.Name) -ForegroundColor White
        foreach ($model in @("f9", "terminal")) {
            $p = Join-Path $s.FullName "live-detection-$model.jsonl"
            if (Test-Path $p) {
                $n = Get-JsonlLineCount -Path $p
                $kb = [math]::Round((Get-Item $p).Length / 1KB)
                $tag = "trong"
                if ($n -gt 0) { $tag = "$n dong" }
                Write-Host ("       live-detection-{0,-9} {1,-12} {2,6:N0} KB" -f $model, $tag, $kb) -ForegroundColor DarkGray
            }
        }
        if ($null -ne $m -and ($m.PSObject.Properties.Name -contains "streams_run")) {
            foreach ($r in @($m.streams_run)) {
                Write-Host ("       run: {0}  model={1}  +{2} su kien" -f $r.run_label, $r.model, $r.added) -ForegroundColor DarkGray
            }
        }
    }
}

Write-Host ""
if ($null -ne $active) {
    Write-Ok "Dashboard doc: $active"
} else {
    Write-Warn2 "Chua tro session nao. Dashboard se doc mac dinh run_log/full-flow-v1."
}

# --------------------------------------------------------------- Evidence
if ($Evidence) {
    Write-Host ""
    Write-Step "File bang chung (chi doc, script demo khong bao gio ghi)"
    foreach ($e in @("live-detection-f9.jsonl", "live-detection-terminal.jsonl", "live-detection.jsonl")) {
        $p = Join-Path $script:EvidenceDir $e
        if (Test-Path $p) {
            $item = Get-Item $p
            $n = Get-JsonlLineCount -Path $p
            Write-Host ("   run_log/full-flow-v1/{0,-32} {1,8} dong  {2,8:N0} KB  {3}" -f `
                $e, $n, ($item.Length / 1KB), $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")) -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "  Doi session : scripts\demo\demo-log.ps1 -Use <ten>" -ForegroundColor White
Write-Host "  Xem cuoi    : scripts\demo\demo-log.ps1 -Tail f9" -ForegroundColor White
Write-Host "  Xoa log     : scripts\demo\demo-clean.ps1" -ForegroundColor White
