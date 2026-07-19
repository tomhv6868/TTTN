param(
    [ValidateSet('Status', 'Next', 'All', 'Finalize')]
    [string]$Mode = 'Status'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Script = Join-Path $ProjectRoot 'scripts\run_t33_join_windows.py'
$FinalizeScript = Join-Path $ProjectRoot 'scripts\finalize_t33_checkpointed.py'
$Contract = Join-Path $ProjectRoot 'config\cicids2017-label-join-contract.json'
$ArtifactRoot = Join-Path $ProjectRoot 'run_log\t3.3'
$Python = Get-Command python -ErrorAction Stop

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    throw 'T3.3 portable join must run in native Windows PowerShell.'
}

$Stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
$AttemptRoot = Join-Path $ArtifactRoot "attempts\windows-join-$Stamp"
New-Item -ItemType Directory -Path $AttemptRoot -Force | Out-Null
$Log = Join-Path $AttemptRoot 'windows-join.log'
$Common = @(
    '--project-root', $ProjectRoot,
    '--contract', $Contract
)

switch ($Mode) {
    'Status' {
        & $Python.Source -B $Script status @Common --enforce-host 2>&1 |
            Tee-Object -FilePath $Log
    }
    'Next' {
        & $Python.Source -B $Script run @Common --max-stages 1 2>&1 |
            Tee-Object -FilePath $Log
    }
    'All' {
        & $Python.Source -B $Script run @Common --max-stages 999 2>&1 |
            Tee-Object -FilePath $Log
    }
    'Finalize' {
        & $Python.Source -B $FinalizeScript @Common 2>&1 |
            Tee-Object -FilePath $Log
    }
}

if ($LASTEXITCODE -ne 0) {
    throw "T3.3 Windows pipeline failed with exit code $LASTEXITCODE. Log: $Log"
}

Write-Host "[T3.3 windows-join] mode=$Mode log=$Log"
if ($Mode -eq 'Next') {
    Write-Host '[T3.3 windows-join] next: powershell -ExecutionPolicy Bypass -File scripts\run_t33_join_windows.ps1 -Mode Next'
}
