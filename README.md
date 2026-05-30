# Threat Intelligence Dashboard

A secure Indicator of Compromise (IOC) enrichment and investigation dashboard
built with FastAPI, React, TypeScript, Tailwind, SQLAlchemy, and PostgreSQL.

The project accepts an IP address, domain, URL, or file hash, classifies and
validates the input, orchestrates server-side threat intelligence connectors,
calculates a transparent risk score, and renders analyst-readable evidence in a
dashboard.

## Current Status

This repo now contains the foundation from the Codex build plan:

- FastAPI backend with `/api/health`, `/api/analyze`, `/api/active-scan/nmap`, `/api/sources/status`, and result routes.
- Strict Indicator of Compromise (IOC) classifier covering IPs, domains, URLs,
  and hashes.
- Default blocking for private/internal, loopback, link-local, multicast, and cloud metadata IPs.
- SQLAlchemy data models for analysis requests, tool results, risk reports, cache entries, and audit logs.
- Request size limits, basic rate limiting, safe CORS defaults, and security headers.
- React TypeScript dashboard with light/dark mode, risk card, source status cards, evidence table, and API client.
- Dockerfile, Docker Compose PostgreSQL service, environment examples, and architecture documentation.
- Live passive connectors for VirusTotal, AbuseIPDB, AlienVault OTX, Shodan,
  URLScan, and IPinfo.
- Active Nmap presets for authorized IP/domain targets only, including quick
  port checks, service detection, OS fingerprint attempts, and SYN scan mode.
  Privileged presets can use passwordless `sudo -n nmap` when explicitly
  enabled for a local demo.
- Safe VirusTotal file checks that hash uploaded files first and treat samples
  as opaque bytes without local execution, extraction, or unpacking.
- Current-session result lookup through `/api/results/{analysis_id}`.
- Finished visual dashboard polish with animated scroll effects, loading
  feedback, result completion feedback, dark/light mode, and responsive cards.

## Project Readiness

The project is ready to run locally and demo end to end. The remaining work is
deployment/input setup rather than missing core code:

- Add real provider API keys in `backend/.env` for live intelligence results.
- Run `./start.sh` from the repo root and open `http://127.0.0.1:5173`.
- Use `backend/scripts/check_api_keys.py` after adding keys to confirm provider access.
- For Render hosting, follow `docs/render-deployment.md`.
- For production, set a non-local `ALLOWED_ORIGINS`, provide `DATABASE_URL`
  through secrets, and deploy the frontend with `VITE_API_BASE_URL` pointed at
  the backend API.
- Optional future upgrade: persist completed reports to PostgreSQL instead of
  keeping result lookups in the current backend process memory.

## Repository Structure

```text
backend/
  app/
    api/routes/
    connectors/
    core/
    db/
    schemas/
    services/
    tests/
frontend/
  src/
    api/
    components/
    types/
docs/
  architecture.md
  screenshots/
```

## Backend Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8080
```

Health check:

```bash
curl http://localhost:8080/api/health
```

## Start Everything

From the project root:

```bash
./start.sh
```

The script creates missing local dependencies, starts FastAPI on
`http://127.0.0.1:8080`, starts Vite on `http://127.0.0.1:5173`, and shuts both
down when you press `Ctrl+C`. If either port is already in use, the script exits
with a clear message instead of silently switching ports.

Analyze request:

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc":"8.8.8.8"}'
```

Fetch a current-session result:

```bash
curl http://localhost:8080/api/results/<analysis_id>
```

VirusTotal file check:

```bash
curl -X POST http://localhost:8080/api/analyze/file \
  -F "file=@/path/to/sample"
```

## Frontend Setup

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

The dashboard expects the backend at `http://localhost:8080/api` unless
`VITE_API_BASE_URL` is changed. The backend's local CORS default allows both
`http://localhost:5173` and `http://127.0.0.1:5173`.

## API Keys

Store keys only in backend environment variables or a deployment secret manager:

- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `OTX_API_KEY`
- `SHODAN_API_KEY`
- `URLSCAN_API_KEY`
- `IPINFO_TOKEN`

File upload guardrail:

- `MAX_UPLOAD_FILE_BYTES` defaults to `33554432` bytes. Uploaded files are
  hashed locally, queried by SHA-256 in VirusTotal first, and only submitted to
  VirusTotal when no existing report is available.

Privileged Nmap setup:

- `NMAP_USE_SUDO=false` by default.
- Set `NMAP_USE_SUDO=true` only in a local or locked-down backend environment.
- Follow `docs/nmap-privileged-mode.md` before demoing OS detection or SYN scan
  presets on systems that require root privileges.

Optional AI summaries:

- `AI_PROVIDER=groq` with `GROQ_API_KEY` and `GROQ_MODEL` for Groq Cloud.
- `AI_PROVIDER=xai` with `XAI_API_KEY` and `XAI_MODEL` for xAI/Grok.
- `AI_PROVIDER=gemini` with `GEMINI_API_KEY` and `GEMINI_MODEL` for Gemini.

Do not put API keys in frontend `.env` files, source code, screenshots, or logs.

You can run a redacted provider smoke test after adding keys:

```bash
cd backend
.venv/bin/python scripts/check_api_keys.py
```

The script prints provider status codes and short health messages only. It does
not print API key values.

## Tests

The classifier tests use the Python standard library so they can run before the
full backend dependency install:

```bash
cd backend
PYTHONPATH=. python -m unittest discover -s app/tests
```

## Ethical Use

This project performs enrichment through approved third-party APIs and includes
active Nmap scans only when the user confirms authorization. It does not
exploit, brute force, fuzz, or attack targets. Only analyze indicators and scan
hosts you are authorized to investigate.
