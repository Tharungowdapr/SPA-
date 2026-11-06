# Start the platform.
# `scripts/run_dualstack.py` binds one IPv6 socket with IPV6_V6ONLY=0 so both
# `localhost` (::1) and `127.0.0.1` reach the app on Windows.
# Env: HOST, PORT. Workers stay at 1 (in-process state).
$env:PYTHONPATH = (Get-Location).Path
$port = if ($env:PORT) { $env:PORT } else { 8000 }
Write-Host "AegisClick -> http://localhost:${port}   simulator: /sim   api docs: /docs"
Write-Host "demo logins: admin@aegis.local/admin123  analyst@aegis.local/analyst123  viewer@aegis.local/viewer123"
.\.venv\Scripts\python scripts\run_dualstack.py
