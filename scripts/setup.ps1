# Windows equivalent of scripts/setup.sh (PowerShell)
param([switch]$Full)
python -m venv .venv
.\.venv\Scripts\python -m pip install --quiet -r requirements-dev.txt
if ($Full) { .\.venv\Scripts\python -m pip install --quiet -r requirements-optional.txt }
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
$env:PYTHONPATH = (Get-Location).Path
.\.venv\Scripts\python -m aegis.training
Write-Host "setup complete -> .\scripts\run.ps1"
