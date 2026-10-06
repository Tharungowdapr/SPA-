$env:PYTHONPATH = (Get-Location).Path
.\.venv\Scripts\python -m uvicorn aegis.api.app:app_factory --factory --host 0.0.0.0 --port 8000
