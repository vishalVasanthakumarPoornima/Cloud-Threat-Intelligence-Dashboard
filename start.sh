#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PORT="${BACKEND_PORT:-8080}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}"
FRONTEND_URL="http://127.0.0.1:${FRONTEND_PORT}"

ensure_port_available() {
  local port="$1"
  local label="$2"
  local env_name="$3"
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "${label} port ${port} is already in use."
    echo "Stop that process or run with ${env_name} set to another port."
    exit 1
  fi
}

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then
    kill "${BACKEND_PID}" 2>/dev/null || true
  fi
  if [[ -n "${FRONTEND_PID:-}" ]]; then
    kill "${FRONTEND_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

ensure_port_available "${BACKEND_PORT}" "backend" "BACKEND_PORT"
ensure_port_available "${FRONTEND_PORT}" "frontend" "FRONTEND_PORT"

if [[ ! -f "${ROOT}/backend/.env" ]]; then
  cp "${ROOT}/backend/.env.example" "${ROOT}/backend/.env"
  echo "Created backend/.env from backend/.env.example. Add API keys there before expecting live provider data."
fi

if [[ ! -x "${ROOT}/backend/.venv/bin/python" ]]; then
  echo "Creating backend virtual environment..."
  python3 -m venv "${ROOT}/backend/.venv"
fi

if "${ROOT}/backend/.venv/bin/python" -c "import fastapi, httpx, sqlalchemy, dotenv, multipart, scapy" >/dev/null 2>&1; then
  cp "${ROOT}/backend/requirements.txt" "${ROOT}/backend/.venv/.requirements-installed"
elif [[ ! -f "${ROOT}/backend/.venv/.requirements-installed" ]] || ! cmp -s "${ROOT}/backend/requirements.txt" "${ROOT}/backend/.venv/.requirements-installed"; then
  echo "Installing backend dependencies..."
  if ! "${ROOT}/backend/.venv/bin/python" -m pip install -r "${ROOT}/backend/requirements.txt"; then
    if [[ -d "/opt/homebrew/opt/expat/lib" ]]; then
      DYLD_LIBRARY_PATH="/opt/homebrew/opt/expat/lib" "${ROOT}/backend/.venv/bin/python" -m pip install -r "${ROOT}/backend/requirements.txt"
    else
      exit 1
    fi
  fi
  cp "${ROOT}/backend/requirements.txt" "${ROOT}/backend/.venv/.requirements-installed"
fi

if [[ ! -d "${ROOT}/frontend/node_modules" ]]; then
  echo "Installing frontend dependencies..."
  (cd "${ROOT}/frontend" && npm install)
fi

echo "Starting backend at ${BACKEND_URL}"
(cd "${ROOT}/backend" && "${ROOT}/backend/.venv/bin/uvicorn" app.main:app --host 127.0.0.1 --port "${BACKEND_PORT}") &
BACKEND_PID=$!

echo "Starting frontend at ${FRONTEND_URL}"
(cd "${ROOT}/frontend" && VITE_API_BASE_URL="${BACKEND_URL}/api" npm run dev -- --host 127.0.0.1 --port "${FRONTEND_PORT}" --strictPort) &
FRONTEND_PID=$!

cat <<EOF

Cloud Threat Intelligence Dashboard is starting.
Frontend: ${FRONTEND_URL}
Backend:  ${BACKEND_URL}/api/health

Press Ctrl+C in this terminal to stop both servers.
EOF

wait "${BACKEND_PID}" "${FRONTEND_PID}"
