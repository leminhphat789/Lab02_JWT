$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create Python virtual environment' }
}
& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Cannot install dependencies' }
Write-Host 'Swagger UI: http://127.0.0.1:5001/docs'
Write-Host 'Demo account: phat / Phat@123'
& '.\.venv\Scripts\python.exe' -m flask --app app:create_app run --host 127.0.0.1 --port 5001
