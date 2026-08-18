#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo: sudo ./setup.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SCRIPT_DIR/install-ssh-ws.sh"
REPO_RAW_BASE="${SSHWS_REPO_RAW_BASE:-https://raw.githubusercontent.com/Kris69445578/vpntony/main}"

# The VPS command may download only setup.sh. If the complete project is
# already present locally, keep those bundled files authoritative. This never
# downloads or executes a third-party repository.
required_files=(
  install-ssh-ws.sh
  sshws_server.py
  sshws_cli.py
  sshws-dashboard.sh
  sshws-traffic-collector.py
  sshws-session-scanner.py
  ssh-ws-traffic-collector.service
  sshws-auth-proxy.py
  ssh-ws-auth-proxy.service
  banner.html
  ssh-banner.txt
  README.md
  ssh-ws.service
  ssh-ws-cleanup.service
  ssh-ws-cleanup.timer
)

download_file() {
  local name="$1"
  local destination="$SCRIPT_DIR/$name"
  local url="$REPO_RAW_BASE/$name"
  local temporary="$destination.tmp.$$"

  echo "Downloading $name..."
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 15 --max-time 120 \
      -o "$temporary" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 --timeout=30 -O "$temporary" "$url"
  else
    echo "Neither curl nor wget is installed; cannot download $name." >&2
    exit 1
  fi
  [[ -s "$temporary" ]] || {
    rm -f "$temporary"
    echo "Downloaded $name is empty." >&2
    exit 1
  }
  mv -f "$temporary" "$destination"
}

all_present=1
for file in "${required_files[@]}"; do
  if [[ ! -s "$SCRIPT_DIR/$file" ]]; then
    all_present=0
    break
  fi
done

if [[ "${SSHWS_REFRESH_REMOTE:-0}" == "1" || "$all_present" -eq 0 ]]; then
  for file in "${required_files[@]}"; do
    download_file "$file"
  done
else
  echo "Using the bundled local installer files."
fi

if [[ ! -f "$INSTALLER" ]]; then
  echo "install-ssh-ws.sh was not found beside setup.sh." >&2
  echo "Check that the files exist in $REPO_RAW_BASE." >&2
  exit 1
fi

chmod 0755 "$INSTALLER" "$SCRIPT_DIR/sshws_server.py" \
  "$SCRIPT_DIR/sshws_cli.py" "$SCRIPT_DIR/sshws-dashboard.sh" \
  "$SCRIPT_DIR/sshws-traffic-collector.py" "$SCRIPT_DIR/sshws-session-scanner.py"
exec "$INSTALLER"