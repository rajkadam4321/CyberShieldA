# Run from the cybershield-app folder:  .\scripts\setup.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
foreach ($t in "python","node","npm") { if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { Write-Error "$t not found. Install it first (see README)."; exit 1 } }
Set-Location "$root\backend"
if (-not (Test-Path .venv)) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) {
  $secret = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
  (Get-Content .env.example) -replace "SECRET_KEY=change-me","SECRET_KEY=$secret" | Set-Content .env
  Write-Host "Created backend\.env with a new random SECRET_KEY."
}
Set-Location "$root\frontend"; npm install
Write-Host "Setup done. Next: .\scripts\start_backend.ps1 (terminal 1) and .\scripts\start_frontend.ps1 (terminal 2)."
