# Backend

FastAPI service for passive IOC enrichment. API keys are read from environment
variables only and must never be exposed to the frontend.

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
- `GET /api/results/{analysis_id}` for current-session results
- `GET /api/sources/status`
