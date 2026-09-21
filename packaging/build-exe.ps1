<#
    Build a single-file riff.exe for dropping on a network share.

    Machines running it need no Python and no pip install — the interpreter,
    `cryptography` and the web UI are all inside the one file.

        .\packaging\build-exe.ps1
        copy .\dist\riff.exe <wherever you hand it out>

    Each user still gets their OWN certificate authority under
    %USERPROFILE%\.riff. Do not put RIFF_HOME anywhere others can read: a shared CA private
    key means every reader of that share can impersonate any HTTPS site to
    everyone who trusts it.
#>

[CmdletBinding()]
param(
    [string]$Python = ".\.venv\Scripts\python.exe",
    [string]$OutDir = ".\dist"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path $Python)) {
    throw "Python not found at $Python. Create a venv first, or pass -Python."
}

Write-Host "installing build dependencies..." -ForegroundColor Cyan
& $Python -m pip install --quiet --upgrade pyinstaller
if ($LASTEXITCODE -ne 0) { throw "could not install pyinstaller" }

Write-Host "building riff.exe..." -ForegroundColor Cyan
& $Python -m PyInstaller `
    --clean `
    --onefile `
    --paths "$PSScriptRoot\.." `
    --name riff `
    --distpath $OutDir `
    --workpath .\build `
    --specpath .\build `
    --add-data "$PSScriptRoot\..\riff\ui;riff/ui" `
    --collect-submodules cryptography `
    --console `
    --noconfirm `
    .\packaging\riff_main.py
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }

$exe = Join-Path $OutDir "riff.exe"
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host ""
Write-Host "built $exe ($size MB)" -ForegroundColor Green
Write-Host "smoke test:" -ForegroundColor Cyan
& $exe --version
Write-Host ""
Write-Host "attach it to a release, then from any machine:" -ForegroundColor Cyan
Write-Host "  .\dist\riff.exe run -s .\examples\starter.riff"
