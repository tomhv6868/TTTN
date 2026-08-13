# demo-common.ps1 — hàm dùng chung cho bộ script demo.
#
# Không chạy trực tiếp file này. Các script khác dot-source nó:
#   . "$PSScriptRoot\demo-common.ps1"
#
# Quy ước quan trọng:
#   - Mọi thứ script demo tạo ra đều nằm trong  run_log/demo/<session>/
#   - KHÔNG bao giờ ghi hay xoá  run_log/full-flow-v1/live-detection-*.jsonl
#     Đó là bằng chứng của các lượt chạy trong báo cáo.

# Strict mode duoc dat trong tung script goi, khong dat o day —
# dot-source file nay se lam ro strict mode sang shell cua nguoi dung.

$script:RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$script:DemoRoot   = Join-Path $script:RepoRoot "run_log\demo"
$script:ActiveFile = Join-Path $script:DemoRoot ".active-session"
$script:LabHosts   = Join-Path $script:RepoRoot "config\lab-hosts.json"
$script:VenvPython = Join-Path $script:RepoRoot ".venv\Scripts\python.exe"

# Thư mục bằng chứng — chỉ đọc, tuyệt đối không ghi/xoá.
$script:EvidenceDir = Join-Path $script:RepoRoot "run_log\full-flow-v1"

function Write-Step  { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Text) Write-Host "    OK  $Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "    !   $Text" -ForegroundColor Yellow }
function Write-Err2  { param([string]$Text) Write-Host "    X   $Text" -ForegroundColor Red }

function Get-RepoRoot { return $script:RepoRoot }
function Get-DemoRoot { return $script:DemoRoot }

function Assert-InsideDemoRoot {
    <#  Chốt an toàn. Mọi thao tác ghi/xoá phải đi qua hàm này.
        Ném lỗi nếu đường dẫn nằm ngoài run_log/demo — chặn việc lỡ tay
        xoá vào thư mục bằng chứng. #>
    param([Parameter(Mandatory=$true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetFullPath($script:DemoRoot)
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "TU CHOI: '$full' nam ngoai '$root'. Script demo chi duoc dung trong run_log/demo."
    }
    return $full
}

function Get-LabConfig {
    if (-not (Test-Path $script:LabHosts)) { throw "Thieu $($script:LabHosts)" }
    return (Get-Content $script:LabHosts -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function New-DemoSession {
    param([string]$Label = "")
    if (-not (Test-Path $script:DemoRoot)) { New-Item -ItemType Directory -Path $script:DemoRoot | Out-Null }
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $name = $stamp
    if ($Label -ne "") { $name = "$stamp-$Label" }
    $dir = Join-Path $script:DemoRoot $name
    Assert-InsideDemoRoot $dir | Out-Null
    New-Item -ItemType Directory -Path $dir | Out-Null

    # Hai stream rong. Dashboard doc dung ten file nay.
    foreach ($f in @("live-detection-f9.jsonl", "live-detection-terminal.jsonl")) {
        New-Item -ItemType File -Path (Join-Path $dir $f) | Out-Null
    }

    $manifest = [ordered]@{
        schema_version = "1.0.0"
        session        = $name
        created_utc    = (Get-Date).ToUniversalTime().ToString("o")
        created_by     = "scripts/demo/demo-up.ps1"
        live_dir       = $dir
        streams        = [ordered]@{
            f9       = Join-Path $dir "live-detection-f9.jsonl"
            terminal = Join-Path $dir "live-detection-terminal.jsonl"
        }
        processes      = @()
        vms_started    = @()
        note           = "Moi file trong thu muc nay do script demo tao ra va co the xoa bang demo-clean.ps1"
    }
    Save-SessionManifest -SessionDir $dir -Manifest $manifest
    Set-ActiveSession -SessionDir $dir
    return $dir
}

function Save-SessionManifest {
    param([Parameter(Mandatory=$true)][string]$SessionDir, [Parameter(Mandatory=$true)]$Manifest)
    Assert-InsideDemoRoot $SessionDir | Out-Null
    $path = Join-Path $SessionDir "session.json"
    $Manifest | ConvertTo-Json -Depth 8 | Out-File -FilePath $path -Encoding utf8
}

function Get-SessionManifest {
    param([Parameter(Mandatory=$true)][string]$SessionDir)
    $path = Join-Path $SessionDir "session.json"
    if (-not (Test-Path $path)) { return $null }
    return (Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Set-ActiveSession {
    param([Parameter(Mandatory=$true)][string]$SessionDir)
    Assert-InsideDemoRoot $SessionDir | Out-Null
    # Ghi KHONG BOM: Out-File -Encoding utf8 cua PowerShell 5.1 them BOM,
    # phia Python doc ra "﻿E:\..." nen khong nhan ra duong dan.
    [System.IO.File]::WriteAllText($script:ActiveFile, $SessionDir, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-ActiveSession {
    <# Tra ve thu muc session dang duoc dung, hoac $null. #>
    if (Test-Path $script:ActiveFile) {
        $p = (Get-Content $script:ActiveFile -Raw -Encoding UTF8).Trim()
        if ($p -ne "" -and (Test-Path $p)) { return $p }
    }
    return $null
}

function Get-AllSessions {
    if (-not (Test-Path $script:DemoRoot)) { return @() }
    return @(Get-ChildItem -Path $script:DemoRoot -Directory | Sort-Object Name)
}

function Resolve-SessionArg {
    <# Nhan ten session, duong dan, hoac rong (= session dang active). #>
    param([string]$Session = "")
    if ($Session -eq "") {
        $a = Get-ActiveSession
        if ($null -eq $a) { throw "Chua co session nao. Chay demo-up.ps1 truoc, hoac truyen -Session <ten>." }
        return $a
    }
    if (Test-Path $Session) { return (Resolve-Path $Session).Path }
    $candidate = Join-Path $script:DemoRoot $Session
    if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
    throw "Khong tim thay session: $Session"
}

function Get-JsonlLineCount {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $n = 0
    $reader = [System.IO.File]::OpenText($Path)
    try { while ($null -ne $reader.ReadLine()) { $n++ } } finally { $reader.Close() }
    return $n
}
