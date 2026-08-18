#!/usr/bin/env python3
"""Root-only account and service management CLI."""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import shutil
import sqlite3
import ssl
import string
import subprocess
import sys
import socket
import time
from pathlib import Path

CONFIG = Path("/etc/ssh-ws/config.env")
DB = Path("/var/lib/ssh-ws/accounts.sqlite3")
SSHD_LIMITS = Path("/etc/ssh/sshd_config.d/ssh-ws-users.conf")
DASHBOARD = Path("/opt/ssh-ws/sshws-dashboard.sh")
PROXY_CREDENTIALS = Path("/etc/ssh-ws/proxy-users.json")
PROXY_PORT = 1080
if not DASHBOARD.is_file():
    DASHBOARD = Path(__file__).resolve().with_name("sshws-dashboard.sh")

# Colors / symbols. Disabled automatically when stdout isn't a terminal or
# NO_COLOR is set, so redirecting output to a file/log stays clean text.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


class C:
    RESET = "\033[0m" if _COLOR else ""
    BOLD = "\033[1m" if _COLOR else ""
    DIM = "\033[2m" if _COLOR else ""
    CYAN = "\033[36m" if _COLOR else ""
    GREEN = "\033[32m" if _COLOR else ""
    YELLOW = "\033[33m" if _COLOR else ""
    RED = "\033[31m" if _COLOR else ""
    MAGENTA = "\033[35m" if _COLOR else ""
    BLUE = "\033[34m" if _COLOR else ""


WIDTH = 68
APP_VERSION = "2.1"
DOT_OK = f"{C.GREEN}●{C.RESET}"
DOT_BAD = f"{C.RED}●{C.RESET}"
DOT_WARN = f"{C.YELLOW}●{C.RESET}"
ARROW = f"{C.CYAN}►{C.RESET}"
SPARK = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]


def clear_screen() -> None:
    """Refresh the interactive dashboard without affecting redirected output."""
    if _COLOR:
        print("\033[2J\033[H", end="")


def hr(char: str = "─") -> None:
    print(f"{C.DIM}{char * WIDTH}{C.RESET}")


def progress_bar(percent: float, width: int = 20) -> str:
    value = max(0.0, min(100.0, float(percent)))
    filled = int(round(value / 100 * width))
    color = C.GREEN if value < 70 else C.YELLOW if value < 90 else C.RED
    return f"{color}{'█' * filled}{C.DIM}{'░' * (width - filled)}{C.RESET} {value:5.1f}%"


def status_badge(active: bool, label: str | None = None) -> str:
    text = label or ("ONLINE" if active else "OFFLINE")
    color = C.GREEN if active else C.RED
    return f"{color}{text}{C.RESET}"


def sparkline(values: list[float]) -> str:
    if not values:
        return f"{C.DIM}n/a{C.RESET}"
    low, high = min(values), max(values)
    span = high - low or 1.0
    return "".join(SPARK[int((value - low) / span * (len(SPARK) - 1))] for value in values)


def panel_title(title: str, accent: str | None = None) -> None:
    color = accent or C.CYAN
    print(f"{color}┌{'─' * (WIDTH - 2)}┐{C.RESET}")
    label = f"  {title.upper()}"
    print(f"{color}│{C.RESET}{C.BOLD}{label:<{WIDTH - 2}}{C.RESET}{color}│{C.RESET}")
    print(f"{color}├{'─' * (WIDTH - 2)}┤{C.RESET}")


def panel_end(accent: str | None = None) -> None:
    color = accent or C.CYAN
    print(f"{color}└{'─' * (WIDTH - 2)}┘{C.RESET}")


def panel_line(text: str = "", accent: str | None = None) -> None:
    color = accent or C.CYAN
    print(f"{color}│{C.RESET} {text:<{WIDTH - 3}}")


def banner() -> None:
    print(f"{C.BLUE}╔{'═' * (WIDTH - 2)}╗{C.RESET}")
    title = "SSHWS  •  CONTROL CENTER"
    subtitle = "Secure access, account operations, and live server health"
    for text, color in ((title, C.MAGENTA), (subtitle, C.CYAN)):
        pad = max(0, (WIDTH - 2 - len(text)) // 2)
        right = max(0, WIDTH - 2 - pad - len(text))
        print(
            f"{C.BLUE}║{C.RESET}{' ' * pad}{C.BOLD}{color}{text}{C.RESET}"
            f"{' ' * right}{C.BLUE}║{C.RESET}"
        )
    meta = f"release {APP_VERSION}  •  {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    print(f"{C.BLUE}║{C.RESET}{C.DIM}{meta:^{WIDTH - 2}}{C.RESET}{C.BLUE}║{C.RESET}")
    print(f"{C.BLUE}╚{'═' * (WIDTH - 2)}╝{C.RESET}")


def status_dot(status: str) -> str:
    return {"active": DOT_OK, "expired": DOT_BAD, "disabled": DOT_WARN}.get(
        status, DOT_WARN
    )


def cfg() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in CONFIG.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v.strip().strip('"').strip("'")
    return out


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("This command must be run as root.")


def db() -> sqlite3.Connection:
    DB.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    connection = sqlite3.connect(DB)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS accounts (
           username TEXT PRIMARY KEY, created_at TEXT NOT NULL,
           expires_at TEXT NOT NULL, max_sessions INTEGER NOT NULL,
           status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
           last_login TEXT)"""
    )
    connection.commit()
    os.chmod(DB, 0o600)
    return connection


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, check=check, text=True, capture_output=True)
    except FileNotFoundError as exc:
        if check:
            raise
        return subprocess.CompletedProcess(args, 127, stdout="", stderr=str(exc))


def sync_session_limits(conn: sqlite3.Connection) -> None:
    """Write per-user OpenSSH session limits from the account database."""
    rows = conn.execute(
        "SELECT username, max_sessions FROM accounts "
        "WHERE status='active' ORDER BY username"
    ).fetchall()
    SSHD_LIMITS.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    content = [
        "# Managed by ssh-ws-autoscript. Do not edit manually.",
        "# Each rule applies only to the named managed SSH account.",
    ]
    for username, max_sessions in rows:
        if safe_username(username):
            content.extend(
                [
                    "",
                    f"Match User {username}",
                    f"    MaxSessions {int(max_sessions)}",
                ]
            )
    content.extend(["", "Match all", ""])
    temporary = SSHD_LIMITS.with_suffix(".tmp")
    temporary.write_text("\n".join(content), encoding="utf-8")
    os.chmod(temporary, 0o644)
    existing = SSHD_LIMITS.read_bytes() if SSHD_LIMITS.exists() else None
    temporary.replace(SSHD_LIMITS)
    check = run("sshd", "-t", check=False)
    if check.returncode != 0:
        if existing is None:
            SSHD_LIMITS.unlink(missing_ok=True)
        else:
            SSHD_LIMITS.write_bytes(existing)
        raise RuntimeError(f"OpenSSH configuration rejected: {check.stderr.strip()}")
    run("systemctl", "reload", "ssh.service", check=False)


def password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(secrets.choice(alphabet) for _ in range(18))


def safe_username(value: str) -> bool:
    return bool(value) and len(value) <= 32 and value[0].isalnum() and all(
        c.isalnum() or c in "._-" for c in value
    )


def proxy_users() -> dict[str, str]:
    try:
        data = json.loads(PROXY_CREDENTIALS.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.get("users", {}).items()}
    except (OSError, ValueError, TypeError):
        return {}


def save_proxy_users(users: dict[str, str]) -> None:
    PROXY_CREDENTIALS.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    temporary = PROXY_CREDENTIALS.with_suffix(".tmp")
    temporary.write_text(json.dumps({"users": users}, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(PROXY_CREDENTIALS)


def manage_proxy() -> None:
    users = proxy_users()
    print(f"\n{C.BOLD}{C.CYAN}Authenticated proxy manager{C.RESET}")
    print(f"  {C.DIM}Endpoint:{C.RESET} 0.0.0.0:{PROXY_PORT}")
    print(f"  {C.DIM}Protocols:{C.RESET} HTTP, SOCKS5, SOCKS4/SOCKS4a")
    print(f"  {C.DIM}Credentials:{C.RESET} {PROXY_CREDENTIALS}")
    print(f"  {C.DIM}Security:{C.RESET} authentication is required; traffic is not disguised or concealed.{C.RESET}")
    if users:
        print(f"\n{C.BOLD}Configured users{C.RESET}")
        for username in sorted(users):
            print(f"  {DOT_OK} {username}")
    else:
        print(f"\n{C.DIM}No proxy users configured yet.{C.RESET}")
    username = input("\nProxy username (blank = return): ").strip()
    if not username:
        return
    if not safe_username(username):
        print(f"{DOT_BAD} Invalid username. Use letters, numbers, dot, underscore, or hyphen.")
        return
    generated = password()
    supplied = input("Proxy password (blank = generate): ")
    secret = supplied if supplied else generated
    if len(secret) < 8:
        print(f"{DOT_BAD} Password must contain at least 8 characters.")
        return
    users[username] = secret
    save_proxy_users(users)
    run("systemctl", "restart", "ssh-ws-auth-proxy.service", check=False)
    print(f"\n{DOT_OK} Proxy user saved. The service was restarted.")
    print(f"  {C.DIM}Host:{C.RESET}     {cfg().get('SSHWS_HOSTNAME', socket.gethostname())}")
    print(f"  {C.DIM}Port:{C.RESET}     {PROXY_PORT}")
    print(f"  {C.DIM}Username:{C.RESET} {username}")
    print(f"  {C.DIM}Password:{C.RESET} {secret}")
    print(f"  {C.DIM}HTTP:{C.RESET}     Basic proxy authentication")
    print(f"  {C.DIM}SOCKS5:{C.RESET}   username/password authentication")
    print(f"  {C.DIM}SOCKS4:{C.RESET}   username in the SOCKS4 user-id field; SOCKS4 has no standard password field")


def create_account() -> None:
    conf = cfg()
    username = input("Username (blank = generate): ").strip()
    if not username:
        username = "ws" + secrets.token_hex(4)
    if not safe_username(username):
        print("Invalid username.")
        return
    days_raw = input(f"Validity days [{conf.get('SSHWS_DEFAULT_DAYS', '7')}]: ").strip()
    days = int(days_raw or conf.get("SSHWS_DEFAULT_DAYS", "7"))
    max_raw = input(
        f"Maximum sessions [{conf.get('SSHWS_DEFAULT_MAX_SESSIONS', '2')}]: "
    ).strip()
    max_sessions = int(max_raw or conf.get("SSHWS_DEFAULT_MAX_SESSIONS", "2"))
    if not 1 <= days <= 3650 or not 1 <= max_sessions <= 50:
        print("Values are outside the safe range.")
        return
    if run("id", username, check=False).returncode == 0:
        print("That Linux username already exists. Choose another username.")
        return
    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(days=days)
    conn = db()
    try:
        with conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE created_at >= date('now')"
            ).fetchone()[0]
            if count >= int(conf.get("SSHWS_DAILY_ACCOUNT_LIMIT", "500")):
                print("Daily account limit reached.")
                return
            if conn.execute(
                "SELECT 1 FROM accounts WHERE username=?", (username,)
            ).fetchone():
                print("Username already exists.")
                return
            run(
                "useradd",
                "--create-home",
                "--shell",
                "/bin/bash",
                "--groups",
                "sshws-users",
                username,
            )
            generated = password()
            subprocess.run(
                ["chpasswd"],
                input=f"{username}:{generated}\n",
                text=True,
                check=True,
            )
            run("chage", "--expiredate", expires.strftime("%Y-%m-%d"), username)
            conn.execute(
                "INSERT INTO accounts VALUES (?, ?, ?, ?, 'active', '', NULL)",
                (username, now.isoformat(), expires.isoformat(), max_sessions),
            )
            sync_session_limits(conn)
    except Exception as exc:
        run("userdel", "--remove", username, check=False)
        print(f"Account creation failed: {exc}")
        return
    print(f"\n{DOT_OK} {C.BOLD}Account created.{C.RESET} The password is shown once:\n")
    print(f"  {C.DIM}Host:{C.RESET}     {conf.get('SSHWS_HOSTNAME')}")
    print(f"  {C.DIM}Username:{C.RESET} {C.GREEN}{username}{C.RESET}")
    print(f"  {C.DIM}Password:{C.RESET} {C.GREEN}{generated}{C.RESET}")
    print(f"  {C.DIM}SSH port:{C.RESET} {conf.get('SSHWS_BACKEND_PORT', '22')}")
    print(f"  {C.DIM}Expires:{C.RESET}  {expires.date()}")
    print(f"  {C.DIM}Max sessions:{C.RESET} {max_sessions}")
    print(
        f"\n  {C.YELLOW}In the app's SSH tab: SSH Host must be 127.0.0.1{C.RESET}"
        f" — the payload/proxy target stays as your hostname above."
    )
    print(
        f"  {C.DIM}Client-controlled routing:{C.RESET} authenticated SSH local"
        " forwarding and dynamic/SOCKS forwarding are enabled; reverse"
        " forwarding is disabled."
    )


def list_accounts(all_accounts: bool = False) -> None:
    rows = db().execute(
        "SELECT username, expires_at, max_sessions, status FROM accounts "
        + ("" if all_accounts else "WHERE status='active' ")
        + "ORDER BY expires_at"
    ).fetchall()
    if not rows:
        print(f"{C.DIM}No accounts found.{C.RESET}")
        return
    print(f"{C.DIM}{'USERNAME':<22} {'EXPIRES':<21} {'MAX':<5} STATUS{C.RESET}")
    now = dt.datetime.now(dt.timezone.utc)
    for username, expires_at, max_sessions, status in rows:
        dot = status_dot(status)
        try:
            expires_dt = dt.datetime.fromisoformat(expires_at)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=dt.timezone.utc)
            soon = status == "active" and (expires_dt - now) < dt.timedelta(days=3)
        except (ValueError, TypeError):
            soon = False
        expires_display = f"{expires_at[:19]:<21}"
        if soon:
            expires_display = f"{C.YELLOW}{expires_display}{C.RESET}"
        print(f"{username:<22} {expires_display} {max_sessions:<5} {dot} {status}")


def expire_accounts() -> None:
    conn = db()
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    rows = conn.execute(
        "SELECT username FROM accounts WHERE status='active' AND expires_at <= ?",
        (now,),
    ).fetchall()
    for (username,) in rows:
        run("usermod", "--lock", username, check=False)
        conn.execute("UPDATE accounts SET status='expired' WHERE username=?", (username,))
    conn.commit()
    sync_session_limits(conn)
    if rows:
        print(f"Expired {len(rows)} account(s).")


def service_info() -> None:
    conf = cfg()
    print(f"{C.DIM}Hostname:{C.RESET} {conf.get('SSHWS_HOSTNAME')}")
    print(
        f"{C.DIM}Backend:{C.RESET}  "
        f"{conf.get('SSHWS_BACKEND_HOST', '127.0.0.1')}:"
        f"{conf.get('SSHWS_BACKEND_PORT', '22')}"
    )
    print(
        f"{C.DIM}CONNECT:{C.RESET}  "
        f"{conf.get('SSHWS_CONNECT_TARGETS', 'wifipay.co.ke:80')} -> "
        f"{conf.get('SSHWS_CONNECT_BACKEND_HOST', '127.0.0.1')}:"
        f"{conf.get('SSHWS_CONNECT_BACKEND_PORT', '22')}"
    )
    print(f"\n{C.BOLD}{C.YELLOW}WebSocket payload:{C.RESET}")
    print(
        f"{C.GREEN}GET / HTTP/1.1[crlf]Host: {conf.get('SSHWS_HOSTNAME')}[crlf]"
        f"Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]{C.RESET}"
    )
    print(f"\n{C.BOLD}{C.YELLOW}Allowlisted HTTP CONNECT payload:{C.RESET}")
    print(
        f"{C.GREEN}CONNECT wifipay.co.ke:80 HTTP/1.1[crlf]Host: "
        f"https://{conf.get('SSHWS_HOSTNAME')}[crlf]Connection: keep-alive[crlf]"
        f"X-Online-Host: {conf.get('SSHWS_HOSTNAME')}[crlf]"
        f"X-Forward-Host: {conf.get('SSHWS_HOSTNAME')}[crlf][crlf]{C.RESET}"
    )
    print("CONNECT response: HTTP/1.1 101 Switching Protocols")
    print(
        f"\n{C.YELLOW}Reminder:{C.RESET} app's SSH tab Host = 127.0.0.1, "
        "not this hostname."
    )
    print(
        f"{C.YELLOW}Routing:{C.RESET} use authenticated SSH local or dynamic/SOCKS "
        "forwarding for client-selected destinations; the HTTP CONNECT target "
        "is not an outbound route selector."
    )


def doctor() -> None:
    """Run local, non-destructive checks for the full tunnel path."""
    conf = cfg()
    banner()
    print(f"{C.DIM}Hostname:{C.RESET} {conf.get('SSHWS_HOSTNAME', '(missing)')}")
    print(
        f"{C.DIM}Backend:{C.RESET}  "
        f"{conf.get('SSHWS_BACKEND_HOST', '127.0.0.1')}:"
        f"{conf.get('SSHWS_BACKEND_PORT', '22')}"
    )
    print()

    def line(ok: bool, label: str) -> None:
        print(f"{DOT_OK if ok else DOT_BAD} {label}")

    sshd = run("sshd", "-t", check=False)
    line(sshd.returncode == 0, "sshd configuration")
    if sshd.returncode:
        print(f"  {C.RED}{sshd.stderr.strip()}{C.RESET}")

    service = run("systemctl", "is-active", "ssh-ws.service", check=False)
    line(service.returncode == 0, "ssh-ws.service active")
    if service.returncode:
        print(f"  {C.DIM}Run: journalctl -u ssh-ws.service -n 100 --no-pager{C.RESET}")

    backend_host = conf.get("SSHWS_BACKEND_HOST", "127.0.0.1")
    backend_port = int(conf.get("SSHWS_BACKEND_PORT", "22"))
    try:
        with socket.create_connection((backend_host, backend_port), timeout=3) as sock:
            sock.settimeout(3)
            ssh_banner = sock.recv(256)
        line(True, f"SSH backend reachable; banner={ssh_banner[:80]!r}")
    except OSError as exc:
        line(False, f"SSH backend is not reachable: {exc}")

    connect_backend_host = conf.get("SSHWS_CONNECT_BACKEND_HOST", "127.0.0.1")
    connect_backend_port = int(conf.get("SSHWS_CONNECT_BACKEND_PORT", "22"))
    try:
        with socket.create_connection(
            (connect_backend_host, connect_backend_port), timeout=3
        ) as sock:
            sock.settimeout(3)
            backend_banner = sock.recv(128)
        line(
            True,
            f"CONNECT/SSH backend reachable at {connect_backend_host}:{connect_backend_port}; "
            f"initial bytes={backend_banner[:40]!r}",
        )
    except OSError as exc:
        line(
            False,
            f"CONNECT/SSH backend is not reachable at "
            f"{connect_backend_host}:{connect_backend_port}: {exc}",
        )

    ports: list[int] = []
    if conf.get("SSHWS_ENABLE_HTTP", "1") == "1":
        ports += [
            int(x)
            for x in conf.get("SSHWS_HTTP_PORTS", "80").split(",")
            if x
        ]
    if conf.get("SSHWS_ENABLE_TLS", "0") == "1":
        ports += [
            int(x)
            for x in conf.get("SSHWS_TLS_PORTS", "").split(",")
            if x
        ]
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                line(True, f"listener 127.0.0.1:{port} accepts TCP")
        except OSError as exc:
            line(False, f"listener 127.0.0.1:{port}: {exc}")

    accounts_active = 0
    sample_user = None
    try:
        conn = db()
        accounts_active = conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE status='active'"
        ).fetchone()[0]
        row = conn.execute(
            "SELECT username FROM accounts WHERE status='active' LIMIT 1"
        ).fetchone()
        sample_user = row[0] if row else None
    except Exception:
        pass
    if accounts_active == 0:
        print(
            f"\n{DOT_WARN} {C.YELLOW}No active accounts exist yet.{C.RESET}"
            " Run option 1 (Create account) before testing from the app —"
            " every login will fail until one exists."
        )
    elif sample_user:
        effective = run(
            "sshd",
            "-T",
            "-C",
            f"user={sample_user},host=127.0.0.1,addr=127.0.0.1",
            check=False,
        )
        pw_line = next(
            (
                l
                for l in effective.stdout.splitlines()
                if l.lower().startswith("passwordauthentication")
            ),
            None,
        )
        if pw_line and pw_line.split()[-1].lower() == "yes":
            line(
                True,
                f"password auth enabled for '{sample_user}' (effective config)",
            )
        else:
            line(
                False,
                f"password auth is DISABLED for '{sample_user}' (effective config)",
            )
            print(
                f"  {C.YELLOW}This is almost always a cloud-init drop-in that sets"
                f" PasswordAuthentication no server-wide.{C.RESET}"
            )
            print(
                f"  {C.DIM}Check: sshd -T -C user={sample_user},host=127.0.0.1,"
                f"addr=127.0.0.1 | grep -i passwordauth{C.RESET}"
            )
            print(
                f"  {C.DIM}Fix: re-run install-ssh-ws.sh (writes "
                f"/etc/ssh/sshd_config.d/00-ssh-ws-auth.conf){C.RESET}"
            )

    print()
    print(f"{C.DIM}If local checks pass but the phone still fails, compare:{C.RESET}")
    print("  DNS record -> VPS public IP")
    print("  Cloudflare WebSocket support enabled")
    print("  HTTP Custom remote proxy uses the VPS hostname on direct port 80")
    print("  The Python bridge owns port 80; no reverse proxy is required")
    print(f"  {C.YELLOW}App's SSH tab Host = 127.0.0.1{C.RESET} (not the public hostname)")

def raw_payload_test() -> None:
    """Exercise direct HTTP Custom handshakes locally without credentials."""
    conf = cfg()
    port = int(conf.get("SSHWS_HTTP_PORTS", "80").split(",")[0])
    host = conf.get("SSHWS_HOSTNAME", "localhost")

    def probe(payload: bytes, label: str, tls: bool = False) -> None:
        raw_sock = None
        try:
            target_port = port
            raw_sock = socket.create_connection(("127.0.0.1", target_port), timeout=3)
            if tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(
                    raw_sock,
                    server_hostname=host or "localhost",
                )
                raw_sock = None
            else:
                sock = raw_sock
                raw_sock = None
            with sock:
                sock.sendall(payload)
                sock.settimeout(3)
                response = sock.recv(512)
            first_line = response.split(b"\r\n", 1)[0]
            if first_line == b"HTTP/1.1 101 Switching Protocols":
                print(f"{DOT_OK} PASS: {label} on 127.0.0.1:{port} for {host}")
            else:
                print(f"{DOT_BAD} FAIL: {label} received {first_line!r}")
                print(response[:512].decode("ascii", errors="replace"))
        except OSError as exc:
            print(f"{DOT_BAD} FAIL: {label} could not connect to local listener: {exc}")
        finally:
            if raw_sock is not None:
                raw_sock.close()

    connect_payload = (
        "CONNECT wifipay.co.ke:80 HTTP/1.1\r\n"
        f"Host: https://{host}\r\n"
        "Connection: keep-alive\r\n"
        f"X-Online-Host: {host}\r\n"
        f"X-Forward-Host: {host}\r\n\r\n"
    ).encode()
    probe(connect_payload, "allowlisted HTTPS CONNECT 101 handshake")
    if conf.get("SSHWS_ENABLE_TLS", "0") == "1":
        tls_port = int(conf.get("SSHWS_TLS_PORTS", "443").split(",")[0])
        old_port = port
        port = tls_port
        probe(connect_payload, "allowlisted TLS CONNECT 101 handshake", tls=True)
        port = old_port

    symbolic_payload = (
        "CONNECT wifipay.co.ke:80 HTTP/1.1\r\n"
        f"Host: https://{host}:UC19O866GH\r\n"
        "Connection: keep-alive\r\n"
        f"X-Online-Host: {host}:UC19O866GH\r\n"
        f"X-Forward-Host: {host}:UC19O866GH\r\n\r\n"
    ).encode()
    probe(symbolic_payload, "symbolic-port CONNECT 101 handshake")

    gx_payload = (
        "CONNECT wifipay.co.ke:80 HTTP/1.1\r\n"
        f"Host: https://{host}:GX\r\n"
        "Connection: keep-alive\r\n"
        f"X-Online-Host: {host}:GX\r\n"
        f"X-Forward-Host: {host}:GX\r\n\r\n"
    ).encode()
    probe(gx_payload, "GX symbolic-port CONNECT 101 handshake")

    get_symbolic_payload = (
        "GET https://wifipay.co.ke:GX HTTP/1.1\r\n"
        f"Host: https://{host}:UC19O866GH\r\n"
        "Connection: keep-alive\r\n"
        f"X-Online-Host: {host}:UC19O866GH\r\n"
        f"X-Forward-Host: {host}:UC19O866GH\r\n\r\n"
    ).encode()
    probe(get_symbolic_payload, "GET symbolic-port raw 101 handshake")

    legacy_payload = (
        "CONNECT wifipay.co.ke:80 HTTP/1.1\r\n"
        f"Host: https://netpap.co.ke:UC19O866GH\r\n"
        "Connection: keep-alive\r\n"
        "X-Online-Host: m.netpap.co.ke:UC19O866GH\r\n"
        "X-Forward-Host: m.netpap.co.ke:UC19O866GH\r\n\r\n"
    ).encode()
    probe(legacy_payload, "legacy 101 handshake")

    cfray_payload = (
        "GET /cdn-cgi/trace HTTP/1.1\r\n"
        "Host: any-cloudflare-domain\r\n\r\n"
        "CF-RAY / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: Websocket\r\n"
        "Connection: Keep-Alive\r\n\r\n"
    ).encode()
    probe(cfray_payload, "CF-RAY compound handshake")


def box(title: str) -> None:
    """Draw a titled box matching the banner() style, for menu sections."""
    print(f"{C.CYAN}╔{'═' * (WIDTH - 2)}╗{C.RESET}")
    pad = (WIDTH - 2 - len(title)) // 2
    print(
        f"{C.CYAN}║{C.RESET}{' ' * pad}{C.BOLD}{title}{C.RESET}"
        f"{' ' * (WIDTH - 2 - pad - len(title))}{C.CYAN}║{C.RESET}"
    )
    print(f"{C.CYAN}╚{'═' * (WIDTH - 2)}╝{C.RESET}")


def kv(label: str, value: str) -> None:
    print(f"  {C.DIM}{label:<15}{C.RESET}: {value}")


def human_bytes(n: float) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{value:.0f} {unit}"
        value /= 1024
    return f"{value:.2f} PB"


def read_os_pretty_name() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Unknown"


def read_cpu_info() -> tuple[str, int]:
    model = "Unknown CPU"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return model, (os.cpu_count() or 1)


def cpu_usage_percent() -> float:
    """Instantaneous CPU usage via two /proc/stat samples."""
    def read_stat() -> tuple[int, int]:
        with open("/proc/stat") as fh:
            nums = [int(x) for x in fh.readline().split()[1:]]
        idle = nums[3] + nums[4]
        return idle, sum(nums)

    try:
        idle1, total1 = read_stat()
        time.sleep(0.15)
        idle2, total2 = read_stat()
        delta_total = total2 - total1
        if delta_total <= 0:
            return 0.0
        return max(0.0, min(100.0, (1 - (idle2 - idle1) / delta_total) * 100))
    except OSError:
        return 0.0


def ram_info() -> tuple[str, str, float]:
    try:
        meminfo: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            meminfo[key] = int(rest.strip().split()[0])  # kB
        total_kb = meminfo.get("MemTotal", 0)
        avail_kb = meminfo.get("MemAvailable", 0)
        used_kb = max(0, total_kb - avail_kb)
        pct = (used_kb / total_kb * 100) if total_kb else 0.0
        return human_bytes(used_kb * 1024), human_bytes(total_kb * 1024), pct
    except OSError:
        return "n/a", "n/a", 0.0


def disk_info() -> tuple[str, str, float]:
    try:
        total, used, _free = shutil.disk_usage("/")
        pct = (used / total * 100) if total else 0.0
        return human_bytes(used), human_bytes(total), pct
    except OSError:
        return "n/a", "n/a", 0.0


def uptime_display() -> str:
    try:
        with open("/proc/uptime") as fh:
            seconds = float(fh.readline().split()[0])
        days, rem = divmod(int(seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        parts = [f"{days}d"] if days else []
        if hours or days:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return " ".join(parts)
    except OSError:
        return "n/a"


def detect_public_ip(conf: dict[str, str]) -> str:
    configured = conf.get("SSHWS_PUBLIC_IP", "").strip()
    if configured:
        return configured
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "n/a"


def print_system_information(conf: dict[str, str]) -> None:
    cpu_model, cores = read_cpu_info()
    ram_used, ram_total, ram_pct = ram_info()
    disk_used, disk_total, disk_pct = disk_info()
    now = dt.datetime.now()
    panel_title("System overview", C.BLUE)
    panel_line(f"{C.BOLD}Host{C.RESET}     {socket.gethostname()}  {C.DIM}•{C.RESET}  {read_os_pretty_name()}", C.BLUE)
    panel_line(f"{C.BOLD}Domain{C.RESET}   {conf.get('SSHWS_HOSTNAME', 'n/a')}  {C.DIM}•{C.RESET}  {detect_public_ip(conf)}", C.BLUE)
    panel_line(f"{C.BOLD}CPU{C.RESET}      {cpu_model[:38]}  {C.DIM}({cores} cores){C.RESET}", C.BLUE)
    panel_line(f"{C.BOLD}RAM{C.RESET}      {progress_bar(ram_pct)}  {C.DIM}{ram_used} / {ram_total}{C.RESET}", C.BLUE)
    panel_line(f"{C.BOLD}Disk{C.RESET}     {progress_bar(disk_pct)}  {C.DIM}{disk_used} / {disk_total}{C.RESET}", C.BLUE)
    panel_line(f"{C.BOLD}Uptime{C.RESET}   {uptime_display()}  {C.DIM}•  {now.strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}", C.BLUE)
    panel_end(C.BLUE)


def print_service_status() -> None:
    """Render only real service states and listener information."""
    conf = cfg()
    ssh_active = (
        run("systemctl", "is-active", "ssh.service", check=False).returncode == 0
        or run("systemctl", "is-active", "sshd.service", check=False).returncode == 0
    )
    ws_active = run("systemctl", "is-active", "ssh-ws.service", check=False).returncode == 0
    http_ports = conf.get("SSHWS_HTTP_PORTS", "80")
    tls_ports = conf.get("SSHWS_TLS_PORTS", "443") if conf.get("SSHWS_ENABLE_TLS", "0") == "1" else "off"
    panel_title("Service health", C.GREEN)
    panel_line(f"{C.BOLD}SSH daemon{C.RESET}     {status_badge(ssh_active)}", C.GREEN)
    panel_line(f"{C.BOLD}SSHWS bridge{C.RESET}   {status_badge(ws_active)}", C.GREEN)
    panel_line(f"{C.BOLD}Listeners{C.RESET}      HTTP {http_ports}  {C.DIM}•{C.RESET}  TLS {tls_ports}", C.GREEN)
    panel_line(f"{C.BOLD}CONNECT route{C.RESET}  {conf.get('SSHWS_CONNECT_TARGETS', 'wifipay.co.ke:80')} {C.DIM}→{C.RESET} {conf.get('SSHWS_CONNECT_BACKEND_HOST', '127.0.0.1')}:{conf.get('SSHWS_CONNECT_BACKEND_PORT', '22')}", C.GREEN)
    panel_end(C.GREEN)


def print_account_summary() -> None:
    active = expired = disabled = total = 0
    try:
        conn = db()
        total = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM accounts WHERE status='active'").fetchone()[0]
        expired = conn.execute("SELECT COUNT(*) FROM accounts WHERE status='expired'").fetchone()[0]
        disabled = conn.execute("SELECT COUNT(*) FROM accounts WHERE status='disabled'").fetchone()[0]
    except Exception:
        pass
    panel_title("Account center", C.MAGENTA)
    panel_line(f"{C.BOLD}Total{C.RESET}     {total:<5}  {C.BOLD}Active{C.RESET}   {C.GREEN}{active}{C.RESET}  {C.BOLD}Disabled{C.RESET} {C.YELLOW}{disabled}{C.RESET}  {C.BOLD}Expired{C.RESET} {C.RED}{expired}{C.RESET}", C.MAGENTA)
    ratio = (active / total * 100) if total else 0
    panel_line(f"{C.BOLD}Ready ratio{C.RESET} {progress_bar(ratio, 18)}  {C.DIM}accounts are ready for login{C.RESET}", C.MAGENTA)
    panel_end(C.MAGENTA)


MENU_ITEMS = [
    ("1", "Create account", " "),
    ("2", "Active accounts", "  "),
    ("3", "All accounts", " "),
    ("4", "Disable account", "  "),
    ("5", "Enable account", " "),
    ("6", "Delete account", "  "),
    ("7", "Expire old accounts", " "),
    ("8", "Service status", " "),
    ("9", "Server information", " "),
    ("10", "Diagnostics", " "),
    ("11", "Test transport", ""),
    ("12", "Stats dashboard", ""),
    ("13", "Recent service logs", ""),
    ("14", "Authenticated proxy", "HTTP / SOCKS4 / SOCKS5 on :1080"),
    ("0", "Exit", " "),
]


def help_screen() -> None:
    clear_screen()
    banner()
    panel_title("Quick help", C.YELLOW)
    panel_line(f"{C.BOLD}Numbers{C.RESET}    Select an operation from the command cards below.", C.YELLOW)
    panel_line(f"{C.BOLD}R / refresh{C.RESET} Redraw the dashboard and refresh live metrics.", C.YELLOW)
    panel_line(f"{C.BOLD}H / help{C.RESET}    Open this guide from the main menu.", C.YELLOW)
    panel_line(f"{C.BOLD}0 / quit{C.RESET}    Leave the control center safely.", C.YELLOW)
    panel_line(f"{C.BOLD}Safety{C.RESET}     Account deletion requires an explicit DELETE confirmation.", C.YELLOW)
    panel_line(f"{C.BOLD}Routing{C.RESET}    CONNECT is allowlisted; SSH forwarding remains authenticated.", C.YELLOW)
    panel_end(C.YELLOW)


def recent_logs() -> None:
    print()
    panel_title("Recent SSHWS logs", C.CYAN)
    subprocess.run(
        ["journalctl", "-u", "ssh-ws.service", "-n", "40", "--no-pager", "-o", "short-iso"],
        check=False,
    )
    panel_end(C.CYAN)


def print_menu() -> None:
    conf = cfg()
    clear_screen()
    banner()
    print()
    print_system_information(conf)
    print()
    print_service_status()
    print()
    print_account_summary()
    print()
    panel_title("Operations", C.CYAN)
    for key, label, description in MENU_ITEMS:
        color = C.RED if key == "0" else C.CYAN
        panel_line(
            f"{color}{C.BOLD}[{key:>2}]{C.RESET} {C.BOLD}{label:<22}{C.RESET}"
            f" {C.DIM}{description}{C.RESET}",
            C.CYAN,
        )
    panel_end(C.CYAN)
    print(f"{C.DIM}  Shortcuts: [R] refresh  [H] help  [0] exit  •  Choose an action below.{C.RESET}")


def menu() -> None:
    while True:
        print_menu()
        choice = input(f"\n{C.BOLD}{C.GREEN}sshws{C.RESET} {C.DIM}select ›{C.RESET} ").strip().lower()
        if choice in {"r", "refresh"}:
            continue
        if choice in {"h", "help", "?"}:
            help_screen()
            input(f"\n{C.DIM}Press Enter to return to the dashboard...{C.RESET}")
            continue
        if choice == "1":
            create_account()
        elif choice == "2":
            list_accounts()
        elif choice == "3":
            list_accounts(True)
        elif choice in {"4", "5"}:
            username = input("Username: ").strip()
            if safe_username(username):
                action = "--lock" if choice == "4" else "--unlock"
                status = "disabled" if choice == "4" else "active"
                run("usermod", action, username, check=False)
                connection = db()
                connection.execute(
                    "UPDATE accounts SET status=? WHERE username=?",
                    (status, username),
                )
                connection.commit()
                sync_session_limits(connection)
        elif choice == "6":
            username = input("Username to delete: ").strip()
            if safe_username(username) and input("Type DELETE to confirm: ") == "DELETE":
                run("userdel", "--remove", username, check=False)
                connection = db()
                connection.execute("DELETE FROM accounts WHERE username=?", (username,))
                connection.commit()
                sync_session_limits(connection)
        elif choice == "7":
            expire_accounts()
        elif choice == "8":
            subprocess.run(["systemctl", "--no-pager", "status", "ssh-ws.service"], check=False)
        elif choice == "9":
            service_info()
        elif choice == "10":
            doctor()
        elif choice == "11":
            raw_payload_test()
        elif choice == "12":
            if DASHBOARD.is_file():
                subprocess.run(["bash", str(DASHBOARD)], check=False)
            else:
                print(f"{DOT_WARN} Dashboard script not found at {DASHBOARD}.")
        elif choice == "13":
            recent_logs()
        elif choice == "14":
            manage_proxy()
        elif choice == "0":
            return
        else:
            print(f"\n{DOT_WARN} Unknown option. Press H for help or choose a number from the cards.")
        if choice not in {"0", "r", "refresh"}:
            input(f"\n{C.DIM}Press Enter to continue...{C.RESET}")


if __name__ == "__main__":
    require_root()
    if len(sys.argv) > 1:
        if sys.argv[1] == "create":
            create_account()
        elif sys.argv[1] == "list":
            list_accounts()
        elif sys.argv[1] == "expire":
            expire_accounts()
        elif sys.argv[1] == "info":
            service_info()
        elif sys.argv[1] == "doctor":
            doctor()
        elif sys.argv[1] == "test-payload":
            raw_payload_test()
        elif sys.argv[1] == "dashboard":
            if DASHBOARD.is_file():
                subprocess.run(["bash", str(DASHBOARD)], check=False)
            else:
                print(f"{DOT_WARN} Dashboard script not found at {DASHBOARD}.")
        else:
            menu()
    else:
        menu()