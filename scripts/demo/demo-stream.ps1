<#
demo-stream.ps1 — tao luong cho dashboard theo model tu chon.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-stream.ps1
    ... -Model f9 -Sensor run_log\t8.5\...\sensor.jsonl -Follow

Tham so:
    -Preset <ten>        Chon nhanh bo du lieu khop voi so lieu tren slide.
                         Xem danh sach:  demo-stream.ps1 -ListPresets
    -Model f9|terminal   Nhanh mo hinh. Bo trong thi script hoi.
    -Sensor <path>       File sensor.jsonl nguon. Co the lap lai nhieu lan.
                         Bo trong thi script liet ke cac file tim duoc de chon.
    -RunLabel <ten>      Nhan hien tren dashboard. Mac dinh lay ten thu muc cha.
    -Follow              Bam duoi file nguon, day tung su kien moi ra dashboard.
    -FollowSeconds 300   Thoi gian bam duoi.
    -Session <ten>       Session dich. Mac dinh: session dang active.
    -Reset               Xoa sach stream cua model do truoc khi ghi.

Ghi vao:  <session>/live-detection-<model>.jsonl
Do dashboard doc  NIDS_LIVE_DIR = <session>  nen no thay ngay, khong can doi code.
File bang chung run_log/full-flow-v1/live-detection-*.jsonl KHONG bi ghi de.
#>

[CmdletBinding()]
param(
    [string]$Preset = "",
    [switch]$ListPresets,
    [ValidateSet("f9", "terminal")][string]$Model = "",
    [string[]]$Sensor = @(),
    [string]$RunLabel = "",
    [switch]$Follow,
    [double]$FollowSeconds = 300,
    [string]$Session = "",
    [switch]$Reset
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$repo = Get-RepoRoot

# ---------------------------------------------------------------- Preset
# Moi preset tro toi dung bo du lieu sinh ra con so dang in tren slide.
# Duong dan dung wildcard vi ten thu muc co dau thoi gian.
$Presets = [ordered]@{
    "slide20-dashboard" = @{
        model = "terminal"
        label = "portscan-replay-r3"
        desc  = "28.860 tan cong + 77 lanh tinh = 28.937 ban ghi (slide 20)"
        globs = @(
            "run_log\full-flow-v1\live\portscan-replay\t91-portscan-pcap-r3-*\ubuntu\sensor.jsonl",
            "run_log\full-flow-v1\live\portscan\t91-portscan-20260809061438-*\ubuntu\sensor.jsonl"
        )
    }
    "slide23-ftp" = @{
        model = "f9"
        label = "f9-ftp-patator"
        desc  = "209/209 alert dung nhan tuyet doi (slide 23, the A)"
        globs = @("run_log\t8.5\scenarios\rebuild-20260808\ubuntu\f9-ftp-patator\sensor.jsonl")
    }
    "slide23-goldeneye" = @{
        model = "f9"
        label = "f9-dos-goldeneye"
        desc  = "4.127 alert, 3.175 bi nhan thanh DoS Hulk (slide 23, the B)"
        globs = @("run_log\t8.5\scenarios\rebuild-20260808\ubuntu\f9-dos-goldeneye\sensor.jsonl")
    }
    "slide19-latency" = @{
        model = "f9"
        label = "latency-f9-r3"
        desc  = "7.509 alert, luot dung do p99 ba chang (slide 19)"
        globs = @("run_log\full-flow-v1\latency-live\20260809-latency-f9-r3\f9-dos-hulk\sensor.jsonl")
    }
    "hulk" = @{
        model = "f9"
        label = "f9-dos-hulk"
        desc  = "6.086 alert DoS Hulk, luong day nhat cho demo truc quan"
        globs = @("run_log\t8.5\scenarios\rebuild-20260808\ubuntu\fh-hulk\sensor.jsonl")
    }
}

if ($ListPresets) {
    Write-Step "Cac preset co san"
    Write-Host ""
    foreach ($k in $Presets.Keys) {
        $p = $Presets[$k]
        Write-Host ("  {0,-20} model={1,-9} {2}" -f $k, $p.model, $p.desc) -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  Dung:  scripts\demo\demo-stream.ps1 -Preset slide23-ftp" -ForegroundColor White
    exit 0
}

if ($Preset -ne "") {
    if (-not $Presets.Contains($Preset)) {
        throw "Preset khong ton tai: $Preset. Xem: demo-stream.ps1 -ListPresets"
    }
    $pr = $Presets[$Preset]
    $Model = $pr.model
    if ($RunLabel -eq "") { $RunLabel = $pr.label }
    $Sensor = @()
    foreach ($g in $pr.globs) {
        $hits = @(Get-ChildItem -Path (Join-Path $repo $g) -ErrorAction SilentlyContinue)
        if ($hits.Count -eq 0) { throw "Preset '$Preset': khong tim thay file khop $g" }
        foreach ($h in $hits) { $Sensor += $h.FullName }
    }
    Write-Ok "Preset: $Preset - $($pr.desc)"
}

$sessionDir = Resolve-SessionArg -Session $Session
Assert-InsideDemoRoot $sessionDir | Out-Null
Write-Ok "Session: $sessionDir"

# ------------------------------------------------------------------ Model
if ($Model -eq "") {
    Write-Host ""
    Write-Host "  1) f9        — nhanh moc kiem tra F9, cau 9 goi (Random Forest hai tang)"
    Write-Host "  2) terminal  — nhanh Full flow toan luong (LightGBM sau lop)"
    Write-Host ""
    $pick = Read-Host "Chon model [1/2]"
    if ($pick.Trim() -eq "2") { $Model = "terminal" } else { $Model = "f9" }
}
Write-Ok "Model: $Model"

$bridge = "bridge_sensor_to_dashboard.py"
if ($Model -eq "terminal") { $bridge = "bridge_terminal_to_dashboard.py" }
$bridgePath = Join-Path $repo "scripts\$bridge"
if (-not (Test-Path $bridgePath)) { throw "Khong thay bridge: $bridgePath" }

# ----------------------------------------------------------------- Sensor
if ($Sensor.Count -eq 0) {
    Write-Step "Tim file sensor.jsonl trong run_log"
    $found = @(Get-ChildItem -Path (Join-Path $repo "run_log") -Filter "sensor.jsonl" -Recurse -File -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 20)
    if ($found.Count -eq 0) { throw "Khong tim thay sensor.jsonl nao. Truyen -Sensor <path>." }
    Write-Host ""
    for ($i = 0; $i -lt $found.Count; $i++) {
        $rel = $found[$i].FullName.Substring($repo.Length + 1)
        $kb = [math]::Round($found[$i].Length / 1KB)
        Write-Host ("  {0,2}) {1}  [{2} KB, {3}]" -f ($i + 1), $rel, $kb, $found[$i].LastWriteTime.ToString("MM-dd HH:mm"))
    }
    Write-Host ""
    $pick = Read-Host "Chon so thu tu (cach nhau dau phay neu nhieu file)"
    $Sensor = @()
    foreach ($p in $pick.Split(",")) {
        $idx = 0
        if ([int]::TryParse($p.Trim(), [ref]$idx) -and $idx -ge 1 -and $idx -le $found.Count) {
            $Sensor += $found[$idx - 1].FullName
        }
    }
    if ($Sensor.Count -eq 0) { throw "Khong chon duoc file nao." }
}

foreach ($s in $Sensor) {
    if (-not (Test-Path $s)) { throw "Khong thay file sensor: $s" }
    Write-Ok "Nguon: $s"
}

if ($RunLabel -eq "") {
    $RunLabel = Split-Path (Split-Path $Sensor[0] -Parent) -Leaf
}
Write-Ok "Run label: $RunLabel"

# ----------------------------------------------------------------- Output
$outFile = Join-Path $sessionDir "live-detection-$Model.jsonl"
Assert-InsideDemoRoot $outFile | Out-Null

if ($Reset) {
    Write-Warn2 "Xoa sach stream cu: $outFile"
    Set-Content -Path $outFile -Value "" -NoNewline -Encoding utf8
}
if (-not (Test-Path $outFile)) { New-Item -ItemType File -Path $outFile | Out-Null }

$before = Get-JsonlLineCount -Path $outFile

# ----------------------------------------------------------------- Chay
$argsList = @($bridgePath)
foreach ($s in $Sensor) { $argsList += @("--sensor", $s) }
$argsList += @("--run-label", $RunLabel, "--output", $outFile, "--append")
if ($Follow) { $argsList += @("--follow", "--follow-seconds", "$FollowSeconds") }

Write-Step "Chay bridge: $bridge"
Write-Host "    $($script:VenvPython) $($argsList -join ' ')" -ForegroundColor DarkGray
Write-Host ""
& $script:VenvPython @argsList
$code = $LASTEXITCODE

$after = Get-JsonlLineCount -Path $outFile
$added = $after - $before

Write-Host ""
if ($code -eq 0) {
    Write-Ok "Bridge xong. Them $added su kien (tong $after)."
} else {
    Write-Err2 "Bridge thoat voi ma $code. Them $added su kien."
}

# Ghi vet vao manifest de demo-clean va demo-log biet
$m = Get-SessionManifest -SessionDir $sessionDir
if ($null -ne $m) {
    $entry = [ordered]@{
        at         = (Get-Date).ToUniversalTime().ToString("o")
        model      = $Model
        bridge     = $bridge
        sensors    = $Sensor
        run_label  = $RunLabel
        output     = $outFile
        added      = $added
        total      = $after
        exit_code  = $code
    }
    $list = @()
    if ($m.PSObject.Properties.Name -contains "streams_run") { $list = @($m.streams_run) }
    $list += $entry
    $m | Add-Member -NotePropertyName streams_run -NotePropertyValue $list -Force
    Save-SessionManifest -SessionDir $sessionDir -Manifest $m
}

Write-Host "    Mo dashboard, chon model '$Model' o o toggle de xem." -ForegroundColor White
exit $code
