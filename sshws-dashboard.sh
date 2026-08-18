#!/usr/bin/env bash
# sshws-dashboard.sh — root-run status and usage dashboard for ssh-ws.
#
# This script reads service/account/session state and writes only the local
# per-account usage-limit policy file when an operator changes a limit.
# Account creation/expiry/deletion still goes through sshws_cli.py
# ("menu" / "sshws").
#
# Install:
#   install -o root -g root -m 0755 sshws-dashboard.sh /opt/ssh-ws/sshws-dashboard.sh
#   ln -sfn /opt/ssh-ws/sshws-dashboard.sh /usr/local/bin/sshws-dashboard
#
# Run as root (needed to read /etc/ssh-ws/config.env and the accounts db).

set -uo pipefail

CONFIG="${SSHWS_CONFIG:-/etc/ssh-ws/config.env}"
DB="${SSHWS_DB:-/var/lib/ssh-ws/accounts.sqlite3}"
LIMITS_FILE="${SSHWS_LIMITS:-/var/lib/ssh-ws/bandwidth-limits.conf}"
USAGE_FILE="${SSHWS_USAGE:-/var/lib/ssh-ws/traffic/usage.json}"
WIDTH=108

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m';  C_BOLD=$'\033[1m'
  C_CYAN=$'\033[36m';  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m';   C_MAGENTA=$'\033[35m'; C_DIM=$'\033[2m'
  C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_CYAN=""; C_GREEN=""; C_YELLOW=""
  C_RED=""; C_MAGENTA=""; C_DIM=""; C_BLUE=""
fi

ICON_OK="${C_GREEN}●${C_RESET}"
ICON_BAD="${C_RED}●${C_RESET}"
ICON_WARN="${C_YELLOW}●${C_RESET}"

hr() { printf '%s\n' "${C_DIM}$(printf '─%.0s' $(seq 1 "$WIDTH"))${C_RESET}"; }
box_top()    { printf '%s\n' "${C_CYAN}╔$(printf '═%.0s' $(seq 1 $((WIDTH-2))))╗${C_RESET}"; }
box_bottom() { printf '%s\n' "${C_CYAN}╚$(printf '═%.0s' $(seq 1 $((WIDTH-2))))╝${C_RESET}"; }
box_title() {
  local text="$1"
  local pad=$(( (WIDTH - 2 - ${#text}) / 2 ))
  printf '%s║%*s%s%s%s%*s║%s\n' "$C_CYAN" "$pad" "" "$C_BOLD$C_MAGENTA" "$text" "$C_RESET$C_CYAN" \
    "$((WIDTH - 2 - pad - ${#text}))" "" "$C_RESET"
}
section() {
  echo
  printf '%s┌─ %s%s%s ' "$C_BLUE" "$C_BOLD$C_YELLOW" "$1" "$C_RESET$C_BLUE"
  printf '%.0s─' $(seq 1 $((WIDTH - 5 - ${#1})))
  printf '%s\n' "$C_RESET"
}
row() { printf '  %-22s %s\n' "$1" "$2"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

db_query() {
  python3 - "$DB" "$1" <<'PY'
import sqlite3, sys
path, query = sys.argv[1], sys.argv[2]
try:
    with sqlite3.connect(path) as conn:
        for row in conn.execute(query):
            print('|'.join('' if value is None else str(value) for value in row))
except Exception:
    pass
PY
}

# Parse config.env by hand (no `source`) so a tampered/odd file can't run code.
declare -A CFG
load_config() {
  [[ -r "$CONFIG" ]] || { echo "Cannot read $CONFIG (run as root)." >&2; exit 1; }
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
    CFG["$key"]="$value"
  done < "$CONFIG"
}

bar_of() {
  local pct="${1:-0}" w="${2:-20}"
  (( pct < 0 )) && pct=0; (( pct > 100 )) && pct=100
  local filled=$(( pct * w / 100 ))
  local empty=$(( w - filled ))
  local color="$C_GREEN"
  (( pct >= 90 )) && color="$C_RED" || { (( pct >= 70 )) && color="$C_YELLOW"; }
  printf '%s%s%s%s %3d%%' "$color" "$(printf '█%.0s' $(seq 1 "$filled") 2>/dev/null)" \
    "$C_DIM" "$(printf '░%.0s' $(seq 1 "$empty") 2>/dev/null)" "$pct"
  printf '%s' "$C_RESET"
}

print_banner() {
  box_top
  box_title "SSH-WS  DASHBOARD"
  box_bottom
  local now hostname_display
  now="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  hostname_display="${CFG[SSHWS_HOSTNAME]:-unknown}"
  printf '  %sHost:%s %-30s %sTime:%s %s\n' "$C_DIM" "$C_RESET" "$hostname_display" "$C_DIM" "$C_RESET" "$now"
}

print_service_status() {
  section "Service"
  if systemctl is-active --quiet ssh-ws.service; then
    row "ssh-ws.service" "$ICON_OK active"
  else
    row "ssh-ws.service" "$ICON_BAD inactive"
  fi
  local backend_host="${CFG[SSHWS_BACKEND_HOST]:-127.0.0.1}"
  local backend_port="${CFG[SSHWS_BACKEND_PORT]:-22}"
  if (exec 3<>"/dev/tcp/$backend_host/$backend_port") 2>/dev/null; then
    exec 3<&- 3>&-
    row "SSH backend ($backend_host:$backend_port)" "$ICON_OK reachable"
  else
    row "SSH backend ($backend_host:$backend_port)" "$ICON_BAD unreachable"
  fi
  local uptime_str
  uptime_str="$(uptime -p 2>/dev/null || uptime)"
  row "System uptime" "$uptime_str"
}

print_resources() {
  section "System Resources"
  local load
  load="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo "n/a")"
  row "Load average (1/5/15m)" "$load"

  if has_cmd free; then
    local mem_line mem_total mem_used mem_pct
    mem_line="$(free -m | awk '/^Mem:/{print $2, $3}')"
    mem_total="$(awk '{print $1}' <<<"$mem_line")"
    mem_used="$(awk '{print $2}' <<<"$mem_line")"
    if [[ -n "$mem_total" && "$mem_total" -gt 0 ]]; then
      mem_pct=$(( mem_used * 100 / mem_total ))
      row "RAM (${mem_used}MB/${mem_total}MB)" "$(bar_of "$mem_pct")"
    fi
  fi

  if has_cmd df; then
    local disk_pct
    disk_pct="$(df -P / | awk 'NR==2{gsub("%","",$5); print $5}')"
    row "Disk (/)" "$(bar_of "${disk_pct:-0}")"
  fi
}

print_account_stats() {
  section "Managed Accounts"
  if ! command -v python3 >/dev/null 2>&1; then
    row "database reader" "$ICON_WARN python3 not installed, skipping"
    return
  fi
  if [[ ! -r "$DB" ]]; then
    row "accounts db" "$ICON_WARN not found at $DB"
    return
  fi
  local total active expired soon
  total="$(db_query "SELECT COUNT(*) FROM accounts;" | head -1)"; total="${total:-0}"
  active="$(db_query "SELECT COUNT(*) FROM accounts WHERE status='active';" | head -1)"; active="${active:-0}"
  expired="$(db_query "SELECT COUNT(*) FROM accounts WHERE status='expired';" | head -1)"; expired="${expired:-0}"
  soon="$(db_query "SELECT COUNT(*) FROM accounts WHERE status='active' AND expires_at <= datetime('now','+3 day');" | head -1)"; soon="${soon:-0}"

  row "Total accounts" "$total"
  row "Active" "${C_GREEN}${active}${C_RESET}"
  row "Expired" "${C_RED}${expired}${C_RESET}"
  if [[ "$soon" -gt 0 ]]; then
    row "Expiring within 3 days" "${ICON_WARN} ${C_YELLOW}${soon}${C_RESET}"
  else
    row "Expiring within 3 days" "0"
  fi

  echo
  printf '  %s%-16s %-22s %-6s %s%s\n' "$C_DIM" "USERNAME" "EXPIRES" "MAX" "STATUS" "$C_RESET"
  db_query "SELECT username, expires_at, max_sessions, status FROM accounts WHERE status='active' ORDER BY expires_at LIMIT 15;" |
  while IFS='|' read -r uname expires maxs status; do
    local badge="$ICON_OK"
    local expires_epoch now_epoch
    expires_epoch="$(date -d "$expires" +%s 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    if [[ "$expires_epoch" -gt 0 && $((expires_epoch - now_epoch)) -lt 259200 ]]; then
      badge="$ICON_WARN"
    fi
    printf '  %-16s %-22s %-6s %s %s\n' "$uname" "${expires:0:19}" "$maxs" "$badge" "$status"
  done
  if [[ "$total" -gt 0 && "$active" -eq 0 ]]; then
    row "" "${C_DIM}(no active accounts)${C_RESET}"
  fi
}

device_name() {
  local ip="$1" name
  name="$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')"
  [[ -n "$name" ]] && echo "$name" || echo "Client-${ip//./-}"
}

ping_ms() {
  local ip="$1" result
  result="$(ping -n -c 1 -W 1 "$ip" 2>/dev/null | awk -F'time=' '/time=/{print $2}' | awk '{print $1}')"
  [[ -n "$result" ]] && echo "${result} ms" || echo "n/a"
}

uptime_since() {
  local login="$1" epoch now seconds
  epoch="$(date -d "$login" +%s 2>/dev/null || echo 0)"; now="$(date +%s)"
  seconds=$(( now - epoch )); (( seconds < 0 )) && seconds=0
  printf '%dd %02dh %02dm' $((seconds/86400)) $(((seconds%86400)/3600)) $(((seconds%3600)/60))
}

limit_for() { awk -F= -v u="$1" '$1==u{print $2; found=1} END{if(!found) print "Unlimited"}' "$LIMITS_FILE" 2>/dev/null; }

usage_for() {
  local user="$1" ip="$2"
  python3 - "$USAGE_FILE" "$user" "$ip" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    account = data.get('accounts', {}).get(sys.argv[2], {})
    if sys.argv[3] != 'unknown':
        for device in account.get('devices', {}).values():
            if device.get('ip') == sys.argv[3]:
                print(f"{float(device.get('gb_used', 0.0)):.2f} GB")
                raise SystemExit
    print(f"{float(account.get('total_gb', 0.0)):.2f} GB")
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    print('0.00 GB')
PY
}

collector_status() {
  local state
  state="$(systemctl is-active ssh-ws-traffic-collector.service 2>/dev/null || true)"
  [[ "$state" == "active" ]] && printf 'active' || printf 'inactive'
}

usage_total() {
  python3 - "$USAGE_FILE" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    print(f"{float(data.get('total_gb', 0.0)):.2f} GB")
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    print('0.00 GB')
PY
}

ssh_sessions() {
  local members="$1" scanner
  scanner="$(dirname "$0")/sshws-session-scanner.py"
  [[ -r "$scanner" ]] || scanner="/opt/ssh-ws/sshws-session-scanner.py"
  [[ -r "$scanner" ]] && python3 "$scanner" "$members"
}

print_online_users() {
  section "Online Accounts & Devices"
  printf '  %s%-15s %-24s %-18s %-12s %-12s %-10s %-9s %s%s\n' "$C_DIM" "ACCOUNT" "DEVICE" "IP ADDRESS" "GB USED" "UPTIME" "PING" "DEVICES" "LIMIT" "$C_RESET"
  local found=0 members session uname ip start device ordinal total pid usage limit
  members="$(db_query "SELECT username FROM accounts WHERE status='active' ORDER BY username;" | paste -sd, -)"
  while IFS='|' read -r uname ip start device ordinal total pid; do
    [[ -z "$uname" ]] && continue
    found=1
    [[ "$ip" == "" ]] && ip="unknown"
    usage="$(usage_for "$uname" "$ip") used"; limit="$(limit_for "$uname")"
    if [[ "$start" -gt 0 ]]; then
      login_at="$(date -d "@$start" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo now)"
      online_uptime="$(uptime_since "$login_at")"
    else
      online_uptime="n/a"
    fi
    printf '  %s%-15s%s %-24s %-18s %-12s %-12s %-10s %-9s %s\n' "$C_GREEN" "$uname" "$C_RESET" "$device" "$ip" "$usage" "$online_uptime" "$( [[ "$ip" == unknown ]] && echo n/a || ping_ms "$ip" )" "$ordinal/$total" "$limit"
  done < <(ssh_sessions "$members")
  [[ "$found" -eq 0 ]] && row "" "${C_DIM}(no managed SSH sessions detected; forwarding sessions are checked without requiring a TTY)${C_RESET}"
  row "Connected devices" "${C_DIM}Each row is one unique device; DEVICES shows that device's number / total for the account.${C_RESET}"
  row "Session detection" "${C_DIM}Reads authenticated sshd child processes and established sockets, including no-TTY forwarding sessions.${C_RESET}"
}

print_bandwidth() {
  section "GB Used Overview"
  local iface today rx tx
  iface="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  row "Collector" "$(collector_status)"
  row "Collected GB used" "$(usage_total)"
  if has_cmd vnstat && [[ -n "$iface" ]]; then
    today="$(vnstat -i "$iface" --oneline 2>/dev/null)"; rx="$(cut -d';' -f9 <<<"$today")"; tx="$(cut -d';' -f10 <<<"$today")"
    row "Interface" "${iface:-n/a}"; row "Today GB used (RX / TX)" "${rx:-n/a} / ${tx:-n/a}"
  else
    row "Interface" "${iface:-n/a}"; row "Today GB used" "${ICON_WARN} vnstat unavailable or no data yet"
  fi
}

bandwidth_controls() {
  section "Account Bandwidth Controls"
  mkdir -p "$(dirname "$LIMITS_FILE")" 2>/dev/null || true
  touch "$LIMITS_FILE" 2>/dev/null || true
  row "Policy file" "$LIMITS_FILE"
  if command -v python3 >/dev/null 2>&1; then
    printf '  %s%-18s %-18s%s\n' "$C_DIM" "ACCOUNT" "CURRENT LIMIT" "$C_RESET"
    db_query "SELECT username FROM accounts WHERE status='active' ORDER BY username;" | while IFS='|' read -r user; do
      printf '  %-18s %-18s\n' "$user" "$(limit_for "$user")"
    done
  fi
  echo
  printf '  %sSet a limit in Mbps (0 = Unlimited), or press Enter to leave unchanged.%s\n' "$C_DIM" "$C_RESET"
  read -r -p "  Account: " target
  [[ -z "$target" ]] && return
  if [[ ! "$target" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ ]]; then row "Result" "${ICON_BAD} invalid account name"; return; fi
  read -r -p "  Limit Mbps [0 = Unlimited]: " value
  [[ ! "$value" =~ ^[0-9]+$ ]] && { row "Result" "${ICON_BAD} enter a whole number"; return; }
  grep -v -E "^${target}=" "$LIMITS_FILE" > "${LIMITS_FILE}.tmp" 2>/dev/null || true
  printf '%s=%s\n' "$target" "$([[ "$value" == 0 ]] && echo Unlimited || echo "${value} Mbps")" >> "${LIMITS_FILE}.tmp"
  mv -f "${LIMITS_FILE}.tmp" "$LIMITS_FILE"
  row "Updated" "${ICON_OK} $target → $([[ "$value" == 0 ]] && echo Unlimited || echo "${value} Mbps")"
}

main() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
  fi
  load_config
  clear 2>/dev/null || true
  print_banner
  print_service_status
  print_resources
  print_account_stats
  print_online_users
  print_bandwidth
  bandwidth_controls
  echo
  hr
  printf '  %sTip:%s run %ssshws%s / %smenu%s to create, disable, or delete accounts.\n' \
    "$C_DIM" "$C_RESET" "$C_CYAN" "$C_RESET" "$C_CYAN" "$C_RESET"
  echo
}

main "$@"