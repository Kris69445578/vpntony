#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/ssh-ws"
ETC_DIR="/etc/ssh-ws"
STATE_DIR="/var/lib/ssh-ws"
SERVICE_USER="sshws"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }
trap 'echo "ERROR: installation failed at line $LINENO" >&2' ERR

[[ "${EUID}" -eq 0 ]] || die "Run this installer as root: sudo ./install-ssh-ws.sh"
[[ -r /etc/os-release ]] || die "Cannot detect the Linux distribution."
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" &&
      "${ID_LIKE:-}" != *debian* ]]; then
  die "This installer supports Ubuntu and Debian only (detected: ${PRETTY_NAME:-unknown})."
fi
command -v apt-get >/dev/null || die "This installer requires Ubuntu/Debian apt-get."
command -v systemctl >/dev/null || die "systemd/systemctl is required on the VPS."

INTERNAL_PORT="80"
TRANSPORT_LISTEN_HOST="0.0.0.0"
PUBLIC_HTTP_PORT="80"
PUBLIC_TLS_PORT="443"

HOSTNAME_VALUE="${SSHWS_HOSTNAME:-}"
if [[ -z "$HOSTNAME_VALUE" ]]; then
  read -r -p "Public hostname (for example ssh.example.com): " HOSTNAME_VALUE
fi
[[ "$HOSTNAME_VALUE" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid hostname."

# This installer intentionally asks for only the public hostname. The public
# hostname is retained for payload examples and account/operator messages; it
# is never used as an outbound destination.
BACKEND_PORT="22"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2

# The Python transport owns the public HTTP listener directly. Stop and
# disable nginx when it is present so it cannot reclaim port 80 on reboot.
# Do not purge the package or touch unrelated nginx configuration; operators
# may still use it for another application later.
systemctl stop nginx.service 2>/dev/null || true
systemctl disable nginx.service 2>/dev/null || true

listener_details() {
  ss -H -ltnp "sport = :$1" 2>/dev/null || true
}

assert_port_available() {
  local port="$1"
  local allowed_processes="$2"
  local details
  details="$(listener_details "$port")"
  [[ -z "$details" ]] && return 0
  if grep -Eiq "$allowed_processes" <<<"$details"; then
    return 0
  fi
  echo "ERROR: port $port/tcp is already in use:" >&2
  echo "$details" >&2
  echo "Stop the conflicting service or choose a different deployment before retrying." >&2
  exit 1
}

# The old ssh-ws service is allowed here so an existing installation can
# migrate from its former listeners without being mistaken for a conflict.
assert_port_available "$PUBLIC_HTTP_PORT" 'ssh-ws|sshws_server'
assert_port_available "$PUBLIC_TLS_PORT" 'ssh-ws|sshws_server'

DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 openssh-server ca-certificates sqlite3 openssl nethogs

install -d -m 0750 "$APP_DIR" "$ETC_DIR" "$STATE_DIR"
if ! getent group sshws-users >/dev/null 2>&1; then
  groupadd --system sshws-users
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -o root -g root -m 0755 "$SCRIPT_DIR/sshws_server.py" "$APP_DIR/sshws_server.py"
install -o root -g root -m 0755 "$SCRIPT_DIR/sshws_cli.py" "$APP_DIR/sshws_cli.py"
install -o root -g root -m 0755 "$SCRIPT_DIR/sshws-dashboard.sh" "$APP_DIR/sshws-dashboard.sh"
install -o root -g root -m 0755 "$SCRIPT_DIR/sshws-traffic-collector.py" "$APP_DIR/sshws-traffic-collector.py"
install -o root -g root -m 0755 "$SCRIPT_DIR/sshws-session-scanner.py" "$APP_DIR/sshws-session-scanner.py"
install -o root -g root -m 0755 "$SCRIPT_DIR/sshws-auth-proxy.py" "$APP_DIR/sshws-auth-proxy.py"
install -o root -g root -m 0644 "$SCRIPT_DIR/banner.html" "$APP_DIR/banner.html"
install -o root -g root -m 0644 "$SCRIPT_DIR/README.md" "$APP_DIR/README.md"
install -o root -g root -m 0644 "$SCRIPT_DIR/ssh-banner.txt" "$ETC_DIR/ssh-banner.txt"

TLS_CERT_PATH="$ETC_DIR/tls.crt"
TLS_KEY_PATH="$ETC_DIR/tls.key"

if [[ ! -f "$ETC_DIR/config.env" ]]; then
  cat > "$ETC_DIR/config.env" <<EOF
SSHWS_HOSTNAME=$HOSTNAME_VALUE
SSHWS_LISTEN_HOST=$TRANSPORT_LISTEN_HOST
SSHWS_BACKEND_HOST=127.0.0.1
SSHWS_BACKEND_PORT=$BACKEND_PORT
SSHWS_UPSTREAM_HOST=
SSHWS_UPSTREAM_PORT=80
SSHWS_UPSTREAM_TLS=0
SSHWS_ENABLE_HTTP=1
SSHWS_ENABLE_TLS=1
SSHWS_HTTP_PORTS=$INTERNAL_PORT
SSHWS_TLS_PORTS=$PUBLIC_TLS_PORT
SSHWS_TLS_CERT=$TLS_CERT_PATH
SSHWS_TLS_KEY=$TLS_KEY_PATH
SSHWS_MAX_CONNECTIONS=500
SSHWS_MAX_HEADER_BYTES=16384
SSHWS_HANDSHAKE_TIMEOUT=10
SSHWS_SECOND_BLOCK_GRACE=0.2
SSHWS_IDLE_TIMEOUT=3600
SSHWS_FORCE_101=1
SSHWS_CONNECT_TARGETS=wifipay.co.ke:80
SSHWS_CONNECT_BACKEND_HOST=127.0.0.1
SSHWS_CONNECT_BACKEND_PORT=22
SSHWS_CONNECT_USE_WEBSOCKET=1
SSHWS_DAILY_ACCOUNT_LIMIT=500
SSHWS_DEFAULT_DAYS=7
SSHWS_DEFAULT_MAX_SESSIONS=2
EOF
else
  # Keep reruns predictable: update values owned by this installer while
  # preserving operator-tuned limits.
  tmp_config="$(mktemp)"
  awk -v hostname="$HOSTNAME_VALUE" \
      -v listen_host="$TRANSPORT_LISTEN_HOST" -v backend_host="127.0.0.1" \
      -v backend_port="$BACKEND_PORT" \
      -v enable_http="1" -v enable_tls="1" \
      -v http_ports="$INTERNAL_PORT" -v tls_ports="$PUBLIC_TLS_PORT" \
      -v cert="$TLS_CERT_PATH" -v key="$TLS_KEY_PATH" '
    BEGIN {
       seen_host=seen_listen=seen_backend_host=seen_port=0
       seen_upstream_host=seen_upstream_port=seen_upstream_tls=0
       seen_http=seen_tls=0
             seen_http_ports=seen_tls_ports=seen_cert=seen_key=0
      seen_force=0
      seen_connect_targets=seen_connect_backend_host=0
      seen_connect_backend_port=seen_connect_websocket=0

    }
    /^SSHWS_HOSTNAME=/ { print "SSHWS_HOSTNAME=" hostname; seen_host=1; next }
    /^SSHWS_LISTEN_HOST=/ { print "SSHWS_LISTEN_HOST=" listen_host; seen_listen=1; next }
    /^SSHWS_BACKEND_HOST=/ { print "SSHWS_BACKEND_HOST=" backend_host; seen_backend_host=1; next }
    /^SSHWS_BACKEND_PORT=/ { print "SSHWS_BACKEND_PORT=" backend_port; seen_port=1; next }
    /^SSHWS_UPSTREAM_HOST=/ { print; seen_upstream_host=1; next }
    /^SSHWS_UPSTREAM_PORT=/ { print; seen_upstream_port=1; next }
    /^SSHWS_UPSTREAM_TLS=/ { print; seen_upstream_tls=1; next }
    /^SSHWS_ENABLE_HTTP=/ { print "SSHWS_ENABLE_HTTP=" enable_http; seen_http=1; next }
    /^SSHWS_ENABLE_TLS=/ { print "SSHWS_ENABLE_TLS=" enable_tls; seen_tls=1; next }
    /^SSHWS_HTTP_PORTS=/ { print "SSHWS_HTTP_PORTS=" http_ports; seen_http_ports=1; next }
    /^SSHWS_TLS_PORTS=/ { print "SSHWS_TLS_PORTS=" tls_ports; seen_tls_ports=1; next }
    /^SSHWS_TLS_CERT=/ { print "SSHWS_TLS_CERT=" cert; seen_cert=1; next }
    /^SSHWS_TLS_KEY=/ { print "SSHWS_TLS_KEY=" key; seen_key=1; next }
    /^SSHWS_PUBLIC_IP=/ { next }
    /^SSHWS_FORCE_101=/ { print "SSHWS_FORCE_101=1"; seen_force=1; next }
    /^SSHWS_CONNECT_TARGETS=/ { print; seen_connect_targets=1; next }
    /^SSHWS_CONNECT_BACKEND_HOST=/ { print; seen_connect_backend_host=1; next }
    /^SSHWS_CONNECT_BACKEND_PORT=/ { print "SSHWS_CONNECT_BACKEND_PORT=22"; seen_connect_backend_port=1; next }
    /^SSHWS_CONNECT_USE_WEBSOCKET=/ { print; seen_connect_websocket=1; next }
    { print }
    END {
      if (!seen_host) print "SSHWS_HOSTNAME=" hostname
      if (!seen_listen) print "SSHWS_LISTEN_HOST=" listen_host
      if (!seen_backend_host) print "SSHWS_BACKEND_HOST=" backend_host
      if (!seen_port) print "SSHWS_BACKEND_PORT=" backend_port
      if (!seen_upstream_host) print "SSHWS_UPSTREAM_HOST="
      if (!seen_upstream_port) print "SSHWS_UPSTREAM_PORT=80"
      if (!seen_upstream_tls) print "SSHWS_UPSTREAM_TLS=0"
      if (!seen_http) print "SSHWS_ENABLE_HTTP=" enable_http
      if (!seen_tls) print "SSHWS_ENABLE_TLS=" enable_tls
      if (!seen_http_ports) print "SSHWS_HTTP_PORTS=" http_ports
      if (!seen_tls_ports) print "SSHWS_TLS_PORTS=" tls_ports
      if (!seen_cert) print "SSHWS_TLS_CERT=" cert
      if (!seen_key) print "SSHWS_TLS_KEY=" key
      if (!seen_force) print "SSHWS_FORCE_101=1"
      if (!seen_connect_targets) print "SSHWS_CONNECT_TARGETS=wifipay.co.ke:80"
      if (!seen_connect_backend_host) print "SSHWS_CONNECT_BACKEND_HOST=127.0.0.1"
      if (!seen_connect_backend_port) print "SSHWS_CONNECT_BACKEND_PORT=22"
      if (!seen_connect_websocket) print "SSHWS_CONNECT_USE_WEBSOCKET=1"
    }
  ' "$ETC_DIR/config.env" > "$tmp_config"
  install -o root -g root -m 0600 "$tmp_config" "$ETC_DIR/config.env"
  rm -f "$tmp_config"
fi
chown root:root "$ETC_DIR/config.env"
chmod 0600 "$ETC_DIR/config.env"

# With nginx removed, Python terminates TLS directly on port 443. A
# self-signed certificate keeps the listener usable for HTTP Custom clients;
# users who require browser-trusted TLS can replace these files with a
# certificate whose SAN matches the configured hostname.
if [[ ! -s "$TLS_CERT_PATH" || ! -s "$TLS_KEY_PATH" ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$TLS_KEY_PATH" -out "$TLS_CERT_PATH" \
    -subj "/CN=$HOSTNAME_VALUE" \
    -addext "subjectAltName=DNS:$HOSTNAME_VALUE" \
    >/dev/null 2>&1
fi
chmod 0600 "$TLS_KEY_PATH"
chmod 0644 "$TLS_CERT_PATH"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_MARKER="# Managed by ssh-ws-autoscript"
SSHD_AUTH_DROPIN="/etc/ssh/sshd_config.d/00-ssh-ws-auth.conf"

# Ensure drop-ins are loaded at all (must be near the top of the file).
if [[ -f "$SSHD_CONFIG" ]] && ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
  sshd -t
fi

# Clean up the old inline block from earlier installer versions, if present;
# its job is now done by the drop-in below (superset of what it did).
if [[ -f "$SSHD_CONFIG" ]] && grep -Fq "$SSHD_MARKER" "$SSHD_CONFIG"; then
  cp -a "$SSHD_CONFIG" "$SSHD_CONFIG.ssh-ws-backup.$(date +%Y%m%d%H%M%S)"
  awk -v marker="$SSHD_MARKER" '
    $0==marker {skip=2; next}
    skip>0 {skip--; next}
    {print}
  ' "$SSHD_CONFIG" > "$SSHD_CONFIG.tmp" && mv "$SSHD_CONFIG.tmp" "$SSHD_CONFIG"
fi

# Managed drop-in: banner, password auth, and authenticated client-side
# forwarding for the managed tunnel accounts ONLY. The WebSocket/CONNECT
# bridge still connects only to loopback SSH; arbitrary egress is available
# only after OpenSSH has authenticated the account.
# Ubuntu cloud images commonly ship a cloud-init drop-in (e.g.
# 50-cloud-init.conf) that sets PasswordAuthentication no server-wide;
# OpenSSH uses the FIRST value it encounters for a given keyword, so this
# file is named to sort (and load) before that one.
cat > "$SSHD_AUTH_DROPIN" <<EOF
# Managed by ssh-ws-autoscript. Do not edit manually.
# Scoped to the managed tunnel accounts only.
Match Group sshws-users
    Banner $ETC_DIR/ssh-banner.txt
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    # Allow client-initiated forwarding (including dynamic/SOCKS routing)
    # only after this managed SSH account has authenticated. Remote reverse
    # forwarding is intentionally disabled.
    AllowTcpForwarding local
    PermitOpen any
    GatewayPorts no
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
Match all
EOF
chmod 0644 "$SSHD_AUTH_DROPIN"
sshd -t || {
  echo "ERROR: sshd rejected the new config; removing $SSHD_AUTH_DROPIN" >&2
  rm -f "$SSHD_AUTH_DROPIN"
  exit 1
}

# Enable password authentication globally as requested. This is deliberately
# written as a separate drop-in so the exact setting is present on the VPS
# after installation and on every installer rerun.
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/99-password-auth.conf
chmod 0644 /etc/ssh/sshd_config.d/99-password-auth.conf
sshd -t
systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null || true

install -o root -g root -m 0644 "$SCRIPT_DIR/ssh-ws.service" /etc/systemd/system/ssh-ws.service
install -o root -g root -m 0644 "$SCRIPT_DIR/ssh-ws-cleanup.service" /etc/systemd/system/ssh-ws-cleanup.service
install -o root -g root -m 0644 "$SCRIPT_DIR/ssh-ws-cleanup.timer" /etc/systemd/system/ssh-ws-cleanup.timer
install -o root -g root -m 0644 "$SCRIPT_DIR/ssh-ws-traffic-collector.service" /etc/systemd/system/ssh-ws-traffic-collector.service
install -o root -g root -m 0644 "$SCRIPT_DIR/ssh-ws-auth-proxy.service" /etc/systemd/system/ssh-ws-auth-proxy.service
if [[ ! -f "$ETC_DIR/proxy-users.json" ]]; then
  printf '{"users": {}}\n' > "$ETC_DIR/proxy-users.json"
fi
chown root:root "$ETC_DIR/proxy-users.json"
chmod 0600 "$ETC_DIR/proxy-users.json"

install -d -m 0755 /usr/local/libexec
cat > /usr/local/libexec/sshws-menu <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/ssh-ws/sshws_cli.py "$@"
EOF
chmod 0755 /usr/local/libexec/sshws-menu
ln -sfn /usr/local/libexec/sshws-menu /usr/local/bin/menu
ln -sfn /usr/local/libexec/sshws-menu /usr/local/bin/sshws

# Auto-open the control center for interactive root shells only. The marker
# keeps installer reruns idempotent, and SSHWS_SKIP_MENU provides a documented
# escape hatch for recovery and automation.
ROOT_BASHRC="/root/.bashrc"
install -o root -g root -m 0644 /dev/null "$ROOT_BASHRC" 2>/dev/null || true
if ! grep -Fq '# >>> SSHWS AUTO MENU >>>' "$ROOT_BASHRC"; then
  cat >> "$ROOT_BASHRC" <<'EOF'

# >>> SSHWS AUTO MENU >>>
# Opens the SSHWS control center only for interactive root shells.
# Bypass with: SSHWS_SKIP_MENU=1 bash, or use bash --noprofile --norc.
if [[ $- == *i* && -z "${SSHWS_SKIP_MENU:-}" && -z "${SSHWS_MENU_ACTIVE:-}" && -x /usr/local/bin/menu ]]; then
  export SSHWS_MENU_ACTIVE=1
  /usr/local/bin/menu
  unset SSHWS_MENU_ACTIVE
fi
# <<< SSHWS AUTO MENU <<<
EOF
fi
chmod 0644 "$ROOT_BASHRC"

if command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH >/dev/null 2>&1 || true
  ufw allow "$PUBLIC_HTTP_PORT/tcp"
  ufw allow "$PUBLIC_TLS_PORT/tcp"
  ufw allow 1080/tcp
fi

systemctl daemon-reload
# Stop the previous transport before starting the direct public listener.
systemctl stop ssh-ws.service 2>/dev/null || true
if [[ -n "$(listener_details "$PUBLIC_HTTP_PORT")" ]]; then
  die "Port $PUBLIC_HTTP_PORT is still occupied; the direct HTTP Custom listener cannot start."
fi
if [[ -n "$(listener_details "$PUBLIC_TLS_PORT")" ]]; then
  die "Port $PUBLIC_TLS_PORT is still occupied; the direct TLS listener cannot start."
fi
systemctl enable ssh-ws.service
systemctl restart ssh-ws.service
systemctl enable --now ssh-ws-cleanup.timer
systemctl enable --now ssh-ws-traffic-collector.service
systemctl enable --now ssh-ws-auth-proxy.service

sleep 1
if systemctl is-active --quiet ssh-ws.service; then
  python3 "$APP_DIR/sshws_cli.py" doctor || true
  python3 "$APP_DIR/sshws_cli.py" test-payload || true
else
  echo "ERROR: ssh-ws.service did not start."
  echo "Run: journalctl -u ssh-ws.service -n 100 --no-pager"
  exit 1
fi

echo
echo "SSH WebSocket service installed."
echo "HTTP Custom CONNECT endpoint: http://$HOSTNAME_VALUE:$PUBLIC_HTTP_PORT"
echo "Direct listener: $TRANSPORT_LISTEN_HOST:$PUBLIC_HTTP_PORT (no Nginx)"
echo "Run 'menu' to manage accounts."
echo "Per-account GB traffic collector: enabled (ssh-ws-traffic-collector.service)."
echo "Root auto-menu: enabled for interactive root logins."
echo "Bypass: SSHWS_SKIP_MENU=1 bash  (or: bash --noprofile --norc)"
echo "Exact HTTP Custom CONNECT check:"
echo "Remote proxy: $HOSTNAME_VALUE:$PUBLIC_HTTP_PORT"
echo "Payload: CONNECT wifipay.co.ke:80 HTTP/1.1[crlf]Host: https://$HOSTNAME_VALUE[crlf]Connection: keep-alive[crlf]X-Online-Host: $HOSTNAME_VALUE[crlf]X-Forward-Host: $HOSTNAME_VALUE[crlf][crlf]"
echo "Expected response: HTTP/1.1 101 Switching Protocols"
echo "Restricted CONNECT route: wifipay.co.ke:80 -> 127.0.0.1:22"
echo "Direct TLS CONNECT endpoint: $HOSTNAME_VALUE:$PUBLIC_TLS_PORT"
echo
echo "CF-RAY payload (decoy probe + real upgrade block; decoy Host can be any Cloudflare domain):"
echo "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: any-cloudflare-domain[crlf][crlf]CF-RAY / HTTP/1.1[crlf]Host: $HOSTNAME_VALUE[crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf][crlf]"
echo
echo "WebSocket transports bridge to 127.0.0.1:$BACKEND_PORT."
echo "CONNECT wifipay.co.ke:80 is handed to 127.0.0.1:22 after the 101 response; other CONNECT targets are rejected."
if [[ -t 0 && -t 1 && -z "${SSHWS_SKIP_MENU:-}" && -z "${SSHWS_MENU_ACTIVE:-}" ]]; then
  echo
  echo "Opening SSHWS Control Center..."
  SSHWS_MENU_ACTIVE=1 /usr/local/bin/menu || true
fi
