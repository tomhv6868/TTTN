<#
demo-up.ps1 — bat may ao + dashboard cho buoi demo, cho lenh thoat roi tu tat.

Chay:
    powershell -ExecutionPolicy Bypass -File scripts\demo\demo-up.ps1

Tham so:
    -Hosts kali,ubuntu,windows   May ao can bat. Mac dinh: ca ba.
    -SkipVm                      Bo qua buoc bat may ao (may ao da chay san).
    -SkipDashboard               Chi bat may ao, khong bat dashboard.
    -BackendPort <so>            Cong FastAPI. Mac dinh: doc tu proxy trong
                                 dashboard/web/vite.config.js (hien la 8080).
    -WebPort 5173                Cong Vite.
    -Stop suspend|poweroff|leave Cach tat may ao luc ket thuc. Mac dinh suspend.
    -Label ten                   Hau to cho ten thu muc session.
    -Gui                         Bat may ao co cua so (mac dinh nogui).
    -NoPause                     Bat xong thi thoat ngay, GIU NGUYEN moi thu dang
                                 chay. Dung khi goi tu script khac hoac khi khong
                                 co ban phim. Tat sau bang demo-down.ps1.
    -DryRun                      Chi in ra se lam gi: khong bat may ao, khong bat
                                 dashboard, khong cho nhap. Kiem truoc buoi demo.

Script tao thu muc  run_log/demo/<yyyyMMdd-HHmmss>/  va tro dashboard vao do
bang bien moi truong NIDS_LIVE_DIR. Hai file bang chung
run_log/full-flow-v1/live-detection-*.jsonl KHONG bi dung toi.

Ket thuc: go  q  roi Enter. Script tu tat dashboard va xu ly may ao theo -Stop.
#>

[CmdletBinding()]
param(
    [string[]]$Hosts = @("kali", "ubuntu", "windows"),
    [switch]$SkipVm,
    [switch]$SkipDashboard,
    [int]$BackendPort = 0,
    [int]$WebPort = 5173,
    [ValidateSet("suspend", "poweroff", "leave")][string]$Stop = "suspend",
    [string]$Label = "",
    [switch]$Gui,
    [switch]$DryRun,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
. "$PSScriptRoot\demo-common.ps1"

$repo = Get-RepoRoot
$script:SkipTeardown = $false
$startedVms = @()
$procs = @()
$session = $null

function Invoke-VmRun {
    # KHONG dat ten tham so la $Args — do la bien tu dong cua PowerShell,
    # splat @Args se lay bien tu dong (rong) chu khong lay tham so, va vmrun
    # se chay khong co doi so roi in nguyen trang usage.
    param([string]$VmRun, [string[]]$VmArgs)
    $out = & $VmRun @VmArgs 2>&1
    return @{ code = $LASTEXITCODE; out = ($out -join "`n") }
}

function Format-VmRunError {
    # vmrun in ca trang usage khi that bai. Chi giu vai dong dau cho de doc.
    param([string]$Text)
    $lines = @($Text -split "`n" | Where-Object { $_.Trim() -ne "" })
    if ($lines.Count -eq 0) { return "(khong co thong bao)" }
    $keep = $lines | Select-Object -First 3
    $suffix = ""
    if ($lines.Count -gt 3) { $suffix = " ... (+$($lines.Count - 3) dong)" }
    return (($keep -join " | ") + $suffix)
}

function Get-RunningVmx {
    param([string]$VmRun)
    $r = Invoke-VmRun -VmRun $VmRun -VmArgs @("list")
    return $r.out
}

try {
    # Cong backend PHAI trung voi proxy trong vite.config.js, neu khong frontend
    # goi /api la truot het va trang trang. Doc thang tu file thay vi doan.
    $viteConfig = Join-Path $repo "dashboard\web\vite.config.js"
    $proxyPort = 0
    if (Test-Path $viteConfig) {
        $m = [regex]::Match((Get-Content $viteConfig -Raw), '"/api"\s*:\s*"http://127\.0\.0\.1:(\d+)"')
        if ($m.Success) { $proxyPort = [int]$m.Groups[1].Value }
    }
    if ($BackendPort -eq 0) {
        if ($proxyPort -eq 0) { $BackendPort = 8080 } else { $BackendPort = $proxyPort }
    }
    if ($proxyPort -ne 0 -and $BackendPort -ne $proxyPort) {
        Write-Err2 "Cong backend $BackendPort KHAC proxy cua vite ($proxyPort)."
        Write-Err2 "Frontend se trang trang vi moi loi goi /api deu truot."
        Write-Err2 "Sua vite.config.js hoac bo -BackendPort de dung $proxyPort."
        throw "Cong backend va proxy vite khong khop"
    }

    Write-Step "Chuan bi session"
    $session = New-DemoSession -Label $Label
    Write-Ok "Session: $session"

    # ------------------------------------------------------------------ VM
    if (-not $SkipVm) {
        $cfg = Get-LabConfig
        $vmrun = $cfg.vmrun
        if (-not (Test-Path $vmrun)) { throw "Khong thay vmrun: $vmrun" }

        $running = Get-RunningVmx -VmRun $vmrun
        $mode = "nogui"
        if ($Gui) { $mode = "gui" }

        foreach ($h in $Hosts) {
            if (-not ($cfg.hosts.PSObject.Properties.Name -contains $h)) {
                Write-Warn2 "Bo qua '$h' — khong co trong config/lab-hosts.json"
                continue
            }
            $vmx = $cfg.hosts.$h.vmx
            if (-not (Test-Path $vmx)) { Write-Err2 "$h : khong thay vmx $vmx"; continue }

            if ($running -like "*$([System.IO.Path]::GetFileName($vmx))*") {
                Write-Ok "$h da chay san"
                continue
            }
            Write-Step "Bat may ao: $h"
            if ($DryRun) { Write-Warn2 "[DryRun] bo qua: vmrun start `"$vmx`" $mode"; continue }
            $r = Invoke-VmRun -VmRun $vmrun -VmArgs @("start", $vmx, $mode)
            if ($r.code -eq 0) {
                Write-Ok "$h da bat ($mode)"
                $startedVms += $h
            } else {
                Write-Err2 "$h bat that bai: $(Format-VmRunError $r.out)"
            }
        }

        if ($startedVms.Count -gt 0) {
            Write-Step "Cho may ao san sang (labctl status)"
            $deadline = (Get-Date).AddMinutes(4)
            $ready = $false
            while ((Get-Date) -lt $deadline) {
                $raw = & $script:VenvPython (Join-Path $repo "tools\labctl.py") "status" 2>&1
                if ($?) {
                    try {
                        $doc = ($raw -join "`n") | ConvertFrom-Json
                        if ($doc.status -eq "ok") { $ready = $true; break }
                    } catch { }
                }
                Start-Sleep -Seconds 10
                Write-Host "    ... dang cho" -ForegroundColor DarkGray
            }
            if ($ready) { Write-Ok "Ba may ao tra loi labctl status = ok" }
            else { Write-Warn2 "Het 4 phut ma labctl status chua ok. Kiem tra thu cong roi tiep tuc." }
        }
    } else {
        Write-Warn2 "Bo qua buoc bat may ao (-SkipVm)"
    }

    # ----------------------------------------------------------- Dashboard
    if (-not $SkipDashboard) {
        if ($DryRun) {
            Write-Warn2 "[DryRun] bo qua backend: uvicorn cong $BackendPort, NIDS_LIVE_DIR=$session"
            Write-Warn2 "[DryRun] bo qua vite: npm run dev cong $WebPort"
        } else {
        Write-Step "Bat dashboard backend (NIDS_LIVE_DIR = session)"
        $env:NIDS_LIVE_DIR = $session
        $beOut = Join-Path $session "dashboard-backend.out"
        $beErr = Join-Path $session "dashboard-backend.err"
        $be = Start-Process -FilePath $script:VenvPython `
            -ArgumentList @("-m", "uvicorn", "dashboard.server.app:app", "--app-dir", ".",
                            "--host", "127.0.0.1", "--port", "$BackendPort") `
            -WorkingDirectory $repo -PassThru -NoNewWindow `
            -RedirectStandardOutput $beOut -RedirectStandardError $beErr
        $procs += @{ name = "backend"; id = $be.Id }
        Write-Ok "backend pid $($be.Id) — http://127.0.0.1:$BackendPort (khop proxy vite)"

        Write-Step "Bat dashboard web (Vite)"
        $feOut = Join-Path $session "dashboard-vite.out"
        $feErr = Join-Path $session "dashboard-vite.err"
        # Vite dev server doc stdin de nhan phim tat (r/u/o/q). Neu de no dung
        # chung stdin voi script thi no NUOT mat cai Read-Host o diem dung ben
        # duoi. Cho no doc mot file rong de khong cuop duoc ban phim.
        $nullIn = Join-Path $session ".vite-stdin"
        New-Item -ItemType File -Path $nullIn -Force | Out-Null
        $fe = Start-Process -FilePath "cmd.exe" `
            -ArgumentList @("/c", "npm", "run", "dev", "--", "--port", "$WebPort") `
            -WorkingDirectory (Join-Path $repo "dashboard\web") -PassThru -NoNewWindow `
            -RedirectStandardInput $nullIn `
            -RedirectStandardOutput $feOut -RedirectStandardError $feErr
        $procs += @{ name = "vite"; id = $fe.Id }
        Write-Ok "vite pid $($fe.Id) — http://localhost:$WebPort"

        Start-Sleep -Seconds 4
        try {
            $ping = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/api/overview" -TimeoutSec 8 -UseBasicParsing
            if ($ping.StatusCode -eq 200) { Write-Ok "backend tra loi /api/overview" }
        } catch { Write-Warn2 "backend chua tra loi — xem $beErr" }
        }
    }

    # Ghi lai vao manifest de cac script khac biet
    $m = Get-SessionManifest -SessionDir $session
    $m.processes = $procs
    $m.vms_started = $startedVms
    $m | Add-Member -NotePropertyName backend_port -NotePropertyValue $BackendPort -Force
    $m | Add-Member -NotePropertyName web_port -NotePropertyValue $WebPort -Force
    Save-SessionManifest -SessionDir $session -Manifest $m

    Write-Host ""
    Write-Host "-------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " SAN SANG DEMO" -ForegroundColor White
    Write-Host "   Dashboard : http://localhost:$WebPort" -ForegroundColor White
    Write-Host "   Session   : $session" -ForegroundColor White
    Write-Host "   Tao luong : scripts\demo\demo-stream.ps1 -Model f9" -ForegroundColor White
    Write-Host "   Xem log   : scripts\demo\demo-log.ps1" -ForegroundColor White
    Write-Host "-------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    # ----------------------------------------------------------- Diem dung
    if ($DryRun) {
        Write-Warn2 "[DryRun] khong cho nhap. Session thu da tao o: $session"
        Write-Host "    Xoa session thu: scripts\demo\demo-clean.ps1 -Session $(Split-Path $session -Leaf) -Yes"
        exit 0
    }
    Write-Host "  q  tat toan bo (dashboard + may ao)" -ForegroundColor White
    Write-Host "  b  quay lai menu, GIU NGUYEN moi thu dang chay" -ForegroundColor White
    Write-Host "  k  thoat script, giu nguyen moi thu dang chay" -ForegroundColor White
    Write-Host ""
    if ($NoPause) {
        $script:SkipTeardown = $true
        Write-Ok "-NoPause: giu nguyen dashboard va may ao, thoat ngay."
        Write-Host "    Tat sau bang: scripts\demo\demo-down.ps1" -ForegroundColor White
        exit 0
    }

    # Khi chay khong co ban phim that (CI, pipe, -NonInteractive) thi Read-Host
    # tra ve rong lien tuc. Khong chan thi vong lap quay mai. Qua 3 lan rong thi
    # coi nhu khong hoi duoc, va chon phuong an AN TOAN: giu nguyen moi thu.
    $empty = 0
    do {
        $answer = Read-Host "Chon [q/b/k]"
        if ($null -eq $answer) { $answer = "" }
        $answer = $answer.Trim().ToLower()
        if ($answer -eq "") {
            $empty++
            if ($empty -ge 3) {
                Write-Warn2 "Khong doc duoc ban phim. Giu nguyen moi thu dang chay."
                $answer = "k"
            }
        }
    } until ($answer -eq "q" -or $answer -eq "b" -or $answer -eq "k" -or $answer -eq "quit" -or $answer -eq "exit")

    if ($answer -eq "b" -or $answer -eq "k") {
        # exit trong try VAN chay khoi finally -> phai co co nay, khong thi tat het.
        $script:SkipTeardown = $true
        Write-Warn2 "Giu nguyen dashboard va may ao."
        Write-Host "    Tat sau bang: scripts\demo\demo-down.ps1" -ForegroundColor White
        exit 0
    }
}
finally {
    if ($script:SkipTeardown) {
        Write-Ok "Session giu nguyen: $session"
    }
    elseif ($null -ne $session) {
        Write-Step "Dang tat"
        foreach ($p in $procs) {
            try {
                Stop-Process -Id $p.id -Force -ErrorAction Stop
                Write-Ok "da tat $($p.name) (pid $($p.id))"
            } catch { Write-Warn2 "$($p.name) pid $($p.id) khong tat duoc hoac da dung" }
        }
        # Vite spawn tien trinh node con qua cmd.exe -> don not
        Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like "*dashboard*web*" -or $_.CommandLine -like "*vite*" } |
            ForEach-Object {
                try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Ok "da tat node pid $($_.ProcessId)" } catch { }
            }

        if ($startedVms.Count -gt 0 -and $Stop -ne "leave") {
            $cfg = Get-LabConfig
            foreach ($h in $startedVms) {
                $vmx = $cfg.hosts.$h.vmx
                Write-Step "$Stop may ao: $h"
                $op = "suspend"
                if ($Stop -ne "suspend") { $op = "stop" }
                $r = Invoke-VmRun -VmRun $cfg.vmrun -VmArgs @($op, $vmx, "soft")
                if ($r.code -eq 0) { Write-Ok "$h da $op" }
                else { Write-Warn2 "$h $op that bai: $(Format-VmRunError $r.out)" }
            }
        } elseif ($Stop -eq "leave") {
            Write-Warn2 "Giu nguyen may ao (-Stop leave)"
        }

        Write-Host ""
        Write-Ok "Xong. Log cua session van con o: $session"
        Write-Host "    Xoa khi khong can nua: scripts\demo\demo-clean.ps1"
    }
}
