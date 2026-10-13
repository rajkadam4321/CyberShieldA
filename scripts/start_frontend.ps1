Set-Location (Join-Path (Split-Path -Parent $PSScriptRoot) "frontend")
if (-not (Test-Path node_modules)) { Write-Error "Run .\scripts\setup.ps1 first."; exit 1 }
npm run dev
