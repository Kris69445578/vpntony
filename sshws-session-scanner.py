#!/usr/bin/env python3
"""Print unique active managed SSH devices as pipe-delimited rows."""
from __future__ import annotations

import datetime as dt
import re
import socket
import subprocess
import sys

managed = {item for item in sys.argv[1].split(",") if item}
if not managed:
    raise SystemExit
try:
    ps = subprocess.check_output(["ps", "-eo", "pid=,lstart=,args="], text=True, stderr=subprocess.DEVNULL)
    ss = subprocess.check_output(["ss", "-tnpH"], text=True, stderr=subprocess.DEVNULL)
except (OSError, subprocess.CalledProcessError):
    raise SystemExit

sockets: dict[int, str] = {}
for line in ss.splitlines():
    match = re.search(r"pid=(\d+),", line)
    fields = line.split()
    if not match or len(fields) < 5:
        continue
    peer = fields[4].rsplit(":", 1)[0].strip("[]")
    if peer in {"127.0.0.1", "::1", "0.0.0.0", "*"}:
        continue
    sockets.setdefault(int(match.group(1)), peer)

# Keying by account + remote IP prevents multiple SSH channels from one device
# being counted as multiple devices. Unknown-IP sessions remain distinct by PID.
devices: dict[tuple[str, str], dict[str, object]] = {}
for line in ps.splitlines():
    match = re.match(r"\s*(\d+)\s+(.{24})\s+(.*)$", line)
    if not match:
        continue
    pid = int(match.group(1))
    started = match.group(2).strip()
    args = match.group(3).strip()
    user_match = re.search(r"^sshd:\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,31})(?:@|\s|$)", args)
    if not user_match:
        continue
    user = user_match.group(1)
    if user not in managed or "[priv]" in args or "listener" in args:
        continue
    ip = sockets.get(pid, "unknown")
    key = (user, ip if ip != "unknown" else f"unknown-{pid}")
    try:
        start = int(dt.datetime.strptime(started, "%a %b %d %H:%M:%S %Y").timestamp())
    except ValueError:
        start = 0
    current = devices.get(key)
    if current is not None and int(current["start"]) <= start:
        continue
    device = "Client-" + re.sub(r"[^A-Za-z0-9]+", "-", ip).strip("-") if ip != "unknown" else "SSH forwarding client"
    if ip != "unknown":
        try:
            device = socket.gethostbyaddr(ip)[0][:48]
        except (OSError, socket.herror):
            pass
    devices[key] = {"user": user, "ip": ip, "start": start, "device": device, "pid": pid}

by_user: dict[str, list[dict[str, object]]] = {}
for device in devices.values():
    by_user.setdefault(str(device["user"]), []).append(device)
for user in sorted(by_user):
    rows = sorted(by_user[user], key=lambda item: (str(item["device"]), str(item["ip"])))
    total = len(rows)
    for ordinal, device in enumerate(rows, 1):
        print(f"{user}|{device['ip']}|{device['start']}|{device['device']}|{ordinal}|{total}|{device['pid']}")
