# Backend

FastAPI service for Indicator of Compromise (IOC) enrichment and authorized
Python port scans. API keys are read from environment variables only and must
never be exposed to the frontend.

## Local setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8080
```

## Tests

```bash
cd backend
python -m unittest discover -s app/tests
```

## Useful endpoints

- `GET /api/health`
- `POST /api/analyze`
- `POST /api/analyze/file`
- `POST /api/active-scan/ports`
- `GET /api/results/{analysis_id}` for current-session results
- `GET /api/results/{analysis_id}/report.pdf` for executive PDF reports
- `GET /api/sources/status`

The active scanner uses Python TCP connect checks by default. The SYN preset
uses Scapy when raw socket support is available and falls back to TCP connect
checks otherwise.
