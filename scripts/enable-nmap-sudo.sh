#!/usr/bin/env bash
set -euo pipefail

NMAP_BIN="${NMAP_PATH:-$(command -v nmap || true)}"
if [[ -z "${NMAP_BIN}" ]]; then
  echo "Nmap was not found on PATH. Install Nmap first or run with NMAP_PATH=/path/to/nmap."
  exit 1
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  SUDOERS_DIR="/private/etc/sudoers.d"
else
  SUDOERS_DIR="/etc/sudoers.d"
fi

SUDOERS_FILE="${SUDOERS_DIR}/cloud-threat-intel-nmap"
CURRENT_USER="$(id -un)"
TMP_RULE="$(mktemp)"
trap 'rm -f "${TMP_RULE}"' EXIT

printf "%s ALL=(root) NOPASSWD: %s\n" "${CURRENT_USER}" "${NMAP_BIN}" > "${TMP_RULE}"
chmod 0440 "${TMP_RULE}"

sudo mkdir -p "${SUDOERS_DIR}"
sudo visudo -cf "${TMP_RULE}"
sudo cp "${TMP_RULE}" "${SUDOERS_FILE}"
sudo chmod 0440 "${SUDOERS_FILE}"
sudo visudo -cf "${SUDOERS_FILE}"

echo "Installed ${SUDOERS_FILE}"
echo "The backend can now run: sudo -n ${NMAP_BIN}"
