$b = Join-Path (Split-Path -Parent $PSScriptRoot) "backend"; Set-Location $b
$py = if (Test-Path .\.venv\Scripts\python.exe) { ".\.venv\Scripts\python.exe" } else { "python" }
& $py -m uvicorn app.main:app --reload --port 8000
