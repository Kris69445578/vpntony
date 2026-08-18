#!/usr/bin/env python3
"""Root traffic collector for ssh-ws managed accounts.

The collector uses nethogs' terminal output to sample process traffic and
attributes SSH child-process traffic to Linux usernames. It stores cumulative
per-account/per-device GB counters in a small JSON file for the root dashboard.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

DB = Path("/var/lib/ssh-ws/accounts.sqlite3")
STATE_DIR = Path("/var/lib/ssh-ws/traffic")
STATE_FILE = STATE_DIR / "usage.json"
INTERVAL = int(os.environ.get("SSHWS_TRAFFIC_INTERVAL", "60"))
SSH_GROUP = "sshws-users"


def managed_users() -> set[str]:
    try:
        line = subprocess.check_output(["getent", "group", SSH_GROUP], text=True).strip()
        members = line.split(":")[-1]
        return {item for item in members.split(",") if item}
    except (OSError, subprocess.CalledProcessError):
        return set()


def process_user(pid: int) -> str | None:
    try:
        return subprocess.check_output(["ps", "-o", "user=", "-p", str(pid)], text=True).strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def remote_for_pid(pid: int) -> tuple[str, str]:
    """Return (ip, friendly device name) from established sockets for a PID."""
    try:
        output = subprocess.check_output(["ss", "-tnp"], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return "unknown", "Unknown device"
    marker = f"pid={pid},"
    for line in output.splitlines():
        if marker not in line:
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        peer = fields[4].rsplit(":", 1)[0].strip("[]")
        if peer in {"127.0.0.1", "::1", "0.0.0.0", "*"}:
            continue
        name = "Client-" + re.sub(r"[^A-Za-z0-9]+", "-", peer).strip("-")
        try:
            reverse = socket.gethostbyaddr(peer)[0]
            if reverse:
                name = reverse[:48]
        except (OSError, socket.herror):
            pass
        return peer, name
    return "unknown", "Unknown device"


def read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "updated_at": None, "total_gb": 0.0, "accounts": {}}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, 0o640)
    os.replace(temp, STATE_FILE)


def sample_nethogs() -> list[tuple[int, float]]:
    """Read one text-mode nethogs sample as (pid, bytes_per_second)."""
    try:
        output = subprocess.check_output(
            ["timeout", "8", "nethogs", "-t", "-c", "1", "-d", "1"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    rows: list[tuple[int, float]] = []
    for line in output.splitlines():
        fields = line.split()
        pid = next((int(value) for value in fields if value.isdigit() and int(value) > 1), None)
        if pid is None or len(fields) < 3:
            continue
        numeric = []
        for value in reversed(fields):
            try:
                numeric.append(float(value.replace(",", ".")))
            except ValueError:
                if len(numeric) >= 2:
                    break
        if len(numeric) >= 2:
            # nethogs reports sent/received in KB/s in text mode.
            rows.append((pid, sum(numeric[:2]) * 1024.0))
    return rows


def collect_once(state: dict, users: set[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    total_bytes = 0.0
    for pid, bytes_per_second in sample_nethogs():
        user = process_user(pid)
        if user not in users:
            continue
        ip, device = remote_for_pid(pid)
        used_gb = bytes_per_second * max(INTERVAL, 1) / (1024 ** 3)
        account = state.setdefault("accounts", {}).setdefault(user, {"total_gb": 0.0, "devices": {}})
        account["total_gb"] = float(account.get("total_gb", 0.0)) + used_gb
        device_key = f"{device}|{ip}"
        device_data = account.setdefault("devices", {}).setdefault(device_key, {"name": device, "ip": ip, "gb_used": 0.0, "last_seen": None})
        device_data["gb_used"] = float(device_data.get("gb_used", 0.0)) + used_gb
        device_data["last_seen"] = now
        total_bytes += bytes_per_second * max(INTERVAL, 1)
    state["total_gb"] = float(state.get("total_gb", 0.0)) + total_bytes / (1024 ** 3)
    state["updated_at"] = now
    save_state(state)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Run as root.")
    state = read_state()
    while True:
        collect_once(state, managed_users())
        time.sleep(max(INTERVAL, 10))


if __name__ == "__main__":
    main()
