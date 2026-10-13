$b = Join-Path (Split-Path -Parent $PSScriptRoot) "backend"; Set-Location $b
if (-not (Test-Path .venv)) { Write-Error "Run .\scripts\setup.ps1 first."; exit 1 }
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
