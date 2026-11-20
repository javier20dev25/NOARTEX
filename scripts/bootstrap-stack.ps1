# Bootstrap NOARTEX natural stack repositories (git submodules)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path (Join-Path $root ".git"))) {
  Write-Error "This script must run inside a git clone of NOARTEX."
}

git submodule update --init --recursive
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Stack repositories initialized under .\stack (sentinel-cli, sentinel-audit, sentinel-oracle, sentinel-runtime)."
Write-Host "Review each component README/LICENSE and install prerequisites before use."
