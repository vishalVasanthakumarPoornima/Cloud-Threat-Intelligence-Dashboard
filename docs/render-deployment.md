# Render Deployment

This project deploys cleanly on Render as two services:

- a FastAPI Web Service for `backend/`
- a Vite Static Site for `frontend/`

The repo includes `render.yaml` for a Blueprint deployment. It configures the
backend as a Docker service and the frontend as a static site with its API URL
pointed at the backend service.

Render can also provide PostgreSQL. The current app only uses current-process
result storage, but keeping a database attached is useful for a future persistent
history upgrade.

## 1. Backend Web Service

In Render, create a new **Web Service** from this GitHub repo.

Use these settings:

```text
Name: cloud-threat-intelligence-api
Root Directory: backend
Runtime: Python 3
Build Command: pip install -r requirements.txt
Start Command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

The backend can run as Docker or as Render's Python runtime:

```text
Name: cloud-threat-intelligence-api
Root Directory: backend
Runtime: Docker
```

Active port scans use Python TCP connect checks by default. The Scapy SYN
preset may require raw socket support from the host runtime; when that is not
available, the backend falls back to TCP connect checks.

Set these environment variables:

```text
APP_ENV=production
API_PREFIX=/api
ALLOW_PRIVATE_IOCS=false
MAX_REQUEST_BYTES=8192
MAX_UPLOAD_FILE_BYTES=33554432
ANALYZE_RATE_LIMIT_PER_MINUTE=30
CONNECTOR_TIMEOUT_SECONDS=12
AI_PROVIDER=disabled
```

Add provider API keys as backend-only secrets:

```text
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
SHODAN_API_KEY=
URLSCAN_API_KEY=
IPINFO_TOKEN=
GEMINI_API_KEY=
GROQ_API_KEY=
XAI_API_KEY=
```

If you create a Render PostgreSQL database, copy its internal connection string
into:

```text
DATABASE_URL=<Render internal database URL>
```

After the backend deploys, verify:

```text
https://<backend-service>.onrender.com/
https://<backend-service>.onrender.com/api/health
```

Both endpoints should return JSON with `"status": "ok"`.

## 2. Frontend Static Site

Create a new **Static Site** from the same GitHub repo.

Use these settings:

```text
Name: cloud-threat-intelligence-dashboard
Root Directory: frontend
Build Command: npm install && npm run build
Publish Directory: dist
```

Set this environment variable:

```text
Key: VITE_API_BASE_URL
Value: https://<backend-service>.onrender.com/api
```

Set `VITE_API_BASE_URL` before the frontend build runs. Vite bakes this value
into the static JavaScript bundle, so changing it later requires redeploying the
frontend static site. Do not point it at the frontend URL; it must point at the
FastAPI backend URL and end with `/api`.

In Render's environment variable UI, do not paste
`VITE_API_BASE_URL=https://...` into the value field. The key field should be
`VITE_API_BASE_URL`, and the value field should be only the URL.

Deploy the frontend. After it finishes, copy the frontend URL and go back to the
backend service environment variables.

Set:

```text
ALLOWED_ORIGINS=https://<frontend-static-site>.onrender.com
```

Redeploy the backend after changing `ALLOWED_ORIGINS`.

## 3. Common Render Issues

- If the backend says no open ports were detected, confirm the start command
  uses `--host 0.0.0.0 --port $PORT`.
- If the frontend loads but analyses fail, check `VITE_API_BASE_URL` and redeploy
  the frontend after changing it.
- If the browser blocks requests, check backend `ALLOWED_ORIGINS`.
- If a provider card says `not_configured`, the corresponding API key is empty.
- If Shodan says `restricted`, the key exists but the account plan does not
  allow that endpoint.

## 4. Sharing The Project

For classmates or reviewers, Docker is useful after the Render setup because it
lets someone run the same backend/frontend/Postgres stack locally with one
command instead of installing Python, Node, and PostgreSQL manually.
