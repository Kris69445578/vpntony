from __future__ import annotations

import asyncio
from pathlib import Path
import ssl
from urllib.parse import urlsplit


CONFIG_PATH = Path("/etc/ssh-ws/config.env")

# Defaults are also useful when the server is run manually. The installer
# writes /etc/ssh-ws/config.env and the service loads those values at startup.
# HTTP Custom CONNECT traffic reaches this process directly on public port 80.
# There is no reverse-proxy dependency; this process owns the public listener.
LISTEN_HOST = "0.0.0.0"
HTTP_PORTS = [80]
TLS_PORTS: list[int] = []
ENABLE_HTTP = True
ENABLE_TLS = False

FALLBACK_BACKEND_HOST = "127.0.0.1"
FALLBACK_BACKEND_PORT = 22
UPSTREAM_HOST = ""
UPSTREAM_PORT = 80
UPSTREAM_TLS = False
MAX_CONNECTIONS = 500
MAX_HEADER_BYTES = 16384
HANDSHAKE_TIMEOUT = 10.0
SECOND_BLOCK_GRACE = 0.2
IDLE_TIMEOUT = 3600.0
FORCE_101 = True
ACCEPT_RAW_BINARY_ON_HTTP = True
RAW_BINARY_PROBE_TIMEOUT = 0.25

SYMBOLIC_PORT_DEFAULT = 80
PORT_ALIASES_TEXT = ""
CONNECT_TARGETS_TEXT = "0.0.0.0:80"
CONNECT_BACKEND_HOST = "127.0.0.1"
CONNECT_BACKEND_PORT = 22
CONNECT_USE_WEBSOCKET_RESPONSE = True

TLS_CERT = "/etc/ssh-ws/tls.crt"
TLS_KEY = "/etc/ssh-ws/tls.key"


def read_config() -> dict[str, str]:
    """Read simple KEY=value settings without executing the file."""
    values: dict[str, str] = {}
    try:
        lines = CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'").strip()
    return values


def bool_value(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def int_value(raw: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw or default)
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default


def float_value(
    raw: str | None,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(raw or default)
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default


def port_list(
    raw: str | None, default: list[int], *, allow_empty: bool = False
) -> list[int]:
    if raw is not None and not raw.strip():
        return [] if allow_empty else default
    result: list[int] = []
    for item in (raw or "").split(","):
        try:
            port = int(item.strip())
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in result:
            result.append(port)
    return result or default


def load_runtime_config() -> None:
    """Apply the installer's config.env to the existing runtime settings."""
    global LISTEN_HOST, HTTP_PORTS, TLS_PORTS, ENABLE_HTTP, ENABLE_TLS
    global FALLBACK_BACKEND_HOST, FALLBACK_BACKEND_PORT
    global UPSTREAM_HOST, UPSTREAM_PORT, UPSTREAM_TLS
    global MAX_CONNECTIONS, MAX_HEADER_BYTES, HANDSHAKE_TIMEOUT
    global SECOND_BLOCK_GRACE, IDLE_TIMEOUT, FORCE_101
    global ACCEPT_RAW_BINARY_ON_HTTP, RAW_BINARY_PROBE_TIMEOUT
    global SYMBOLIC_PORT_DEFAULT, PORT_ALIASES_TEXT, PORT_ALIASES
    global CONNECT_TARGETS_TEXT, CONNECT_TARGETS
    global CONNECT_BACKEND_HOST, CONNECT_BACKEND_PORT
    global CONNECT_USE_WEBSOCKET_RESPONSE
    global TLS_CERT, TLS_KEY

    values = read_config()
    LISTEN_HOST = values.get("SSHWS_LISTEN_HOST", LISTEN_HOST) or LISTEN_HOST
    if LISTEN_HOST not in {"127.0.0.1", "::1", "0.0.0.0"}:
        raise RuntimeError(
            "SSHWS_LISTEN_HOST must be 127.0.0.1, ::1, or 0.0.0.0."
        )
    HTTP_PORTS = port_list(values.get("SSHWS_HTTP_PORTS"), HTTP_PORTS)
    TLS_PORTS = port_list(
        values.get("SSHWS_TLS_PORTS"), TLS_PORTS, allow_empty=True
    )
    ENABLE_HTTP = bool_value(values.get("SSHWS_ENABLE_HTTP"), ENABLE_HTTP)
    ENABLE_TLS = bool_value(values.get("SSHWS_ENABLE_TLS"), ENABLE_TLS)

    # The bridge is intentionally an SSH transport, not an open proxy. Never
    # use a client-supplied destination or a non-loopback configured host.
    configured_backend_host = (
        values.get("SSHWS_BACKEND_HOST", FALLBACK_BACKEND_HOST)
        or FALLBACK_BACKEND_HOST
    )
    if configured_backend_host not in {"127.0.0.1", "::1"}:
        raise RuntimeError(
            "SSHWS_BACKEND_HOST must be a loopback address; refusing open-proxy routing."
        )
    FALLBACK_BACKEND_HOST = configured_backend_host
    FALLBACK_BACKEND_PORT = int_value(
        values.get("SSHWS_BACKEND_PORT"),
        FALLBACK_BACKEND_PORT,
        1,
        65535,
    )
    configured_upstream_host = values.get("SSHWS_UPSTREAM_HOST", UPSTREAM_HOST).strip()
    if any(character.isspace() for character in configured_upstream_host):
        raise RuntimeError("SSHWS_UPSTREAM_HOST must be a hostname or IP address.")
    UPSTREAM_HOST = configured_upstream_host
    UPSTREAM_PORT = int_value(
        values.get("SSHWS_UPSTREAM_PORT"),
        UPSTREAM_PORT,
        1,
        65535,
    )
    UPSTREAM_TLS = bool_value(values.get("SSHWS_UPSTREAM_TLS"), UPSTREAM_TLS)
    MAX_CONNECTIONS = int_value(
        values.get("SSHWS_MAX_CONNECTIONS"), MAX_CONNECTIONS, 1, 100_000
    )
    MAX_HEADER_BYTES = int_value(
        values.get("SSHWS_MAX_HEADER_BYTES"), MAX_HEADER_BYTES, 256, 1_048_576
    )
    HANDSHAKE_TIMEOUT = float_value(
        values.get("SSHWS_HANDSHAKE_TIMEOUT"), HANDSHAKE_TIMEOUT, 0.1, 300.0
    )
    SECOND_BLOCK_GRACE = float_value(
        values.get("SSHWS_SECOND_BLOCK_GRACE"), SECOND_BLOCK_GRACE, 0.0, 30.0
    )
    IDLE_TIMEOUT = float_value(
        values.get("SSHWS_IDLE_TIMEOUT"), IDLE_TIMEOUT, 1.0, 86_400.0
    )
    FORCE_101 = bool_value(values.get("SSHWS_FORCE_101"), FORCE_101)
    ACCEPT_RAW_BINARY_ON_HTTP = bool_value(
        values.get("SSHWS_ACCEPT_RAW_BINARY"),
        ACCEPT_RAW_BINARY_ON_HTTP,
    )
    RAW_BINARY_PROBE_TIMEOUT = float_value(
        values.get("SSHWS_RAW_BINARY_PROBE_TIMEOUT"),
        RAW_BINARY_PROBE_TIMEOUT,
        0.05,
        5.0,
    )
    SYMBOLIC_PORT_DEFAULT = int_value(
        values.get("SSHWS_SYMBOLIC_PORT_DEFAULT"),
        SYMBOLIC_PORT_DEFAULT,
        1,
        65535,
    )
    PORT_ALIASES_TEXT = values.get("SSHWS_PORT_ALIASES", PORT_ALIASES_TEXT)
    PORT_ALIASES = load_port_aliases(PORT_ALIASES_TEXT)
    CONNECT_TARGETS_TEXT = values.get(
        "SSHWS_CONNECT_TARGETS", CONNECT_TARGETS_TEXT
    )
    CONNECT_TARGETS = load_connect_targets(CONNECT_TARGETS_TEXT)
    configured_connect_backend_host = (
        values.get("SSHWS_CONNECT_BACKEND_HOST", CONNECT_BACKEND_HOST)
        or CONNECT_BACKEND_HOST
    )
    if configured_connect_backend_host not in {"127.0.0.1", "::1"}:
        raise RuntimeError(
            "SSHWS_CONNECT_BACKEND_HOST must be a loopback address."
        )
    CONNECT_BACKEND_HOST = configured_connect_backend_host
    CONNECT_BACKEND_PORT = int_value(
        values.get("SSHWS_CONNECT_BACKEND_PORT"),
        CONNECT_BACKEND_PORT,
        1,
        65535,
    )
    CONNECT_USE_WEBSOCKET_RESPONSE = bool_value(
        values.get("SSHWS_CONNECT_USE_WEBSOCKET"),
        CONNECT_USE_WEBSOCKET_RESPONSE,
    )
    TLS_CERT = values.get("SSHWS_TLS_CERT", TLS_CERT)
    TLS_KEY = values.get("SSHWS_TLS_KEY", TLS_KEY)


def normalize_connect_target(value: str) -> str | None:
    """Return a canonical host:port form without making any network request."""
    candidate = value.strip()
    if not candidate or any(character.isspace() for character in candidate):
        return None
    try:
        if "://" in candidate:
            parsed = urlsplit(candidate)
            host = parsed.hostname
            port = parsed.port or 80
        else:
            candidate = candidate.split("/", 1)[0].split("@", 1)[-1]
            if candidate.startswith("["):
                closing = candidate.find("]")
                if closing < 0:
                    return None
                host = candidate[1:closing]
                port_text = candidate[closing + 1 :]
                port = int(port_text[1:]) if port_text.startswith(":") else 80
            elif ":" in candidate:
                host, port_text = candidate.rsplit(":", 1)
                port = int(port_text)
            else:
                host, port = candidate, 80
    except (ValueError, UnicodeError):
        return None
    host = (host or "").strip().strip("[]").rstrip(".").casefold()
    if not host or not 1 <= port <= 65535:
        return None
    return f"{host}:{port}"


def load_connect_targets(raw: str) -> set[str]:
    """Load exact host:port CONNECT targets; blank means no special routes."""
    targets: set[str] = set()
    for item in raw.split(","):
        normalized = normalize_connect_target(item.strip())
        if normalized:
            targets.add(normalized)
    return targets


def load_port_aliases(raw: str) -> dict[str, int]:
    """Load symbolic port aliases such as UC19O866GH=443,8443."""
    aliases: dict[str, int] = {}
    for item in raw.split(","):
        name, separator, port_text = item.partition("=")
        if not separator:
            continue
        try:
            port = int(port_text.strip())
        except ValueError:
            continue
        if name.strip() and 1 <= port <= 65535:
            aliases[name.strip().casefold()] = port
    return aliases


PORT_ALIASES = load_port_aliases(PORT_ALIASES_TEXT)
CONNECT_TARGETS = load_connect_targets(CONNECT_TARGETS_TEXT)
if not 1 <= SYMBOLIC_PORT_DEFAULT <= 65535:
    SYMBOLIC_PORT_DEFAULT = FALLBACK_BACKEND_PORT

active_connections = 0
connection_lock = asyncio.Lock()

BANNER_HEADER = (
    "Premium Autoscript Combine | NO HACKING | NO PORN | ONE TERM | By jahim"
)
SWITCHING_PROTOCOLS_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n\r\n"
)
RAW_STREAM_SWITCHING_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Connection: keep-alive\r\n\r\n"
)


async def write_and_close(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    try:
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass


async def open_target(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=HANDSHAKE_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError):
        return None


async def bridge(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_reader: asyncio.StreamReader,
    target_writer: asyncio.StreamWriter,
    initial_client_data: bytes = b"",
    initial_target_data: bytes = b"",
) -> None:
    if initial_client_data:
        target_writer.write(initial_client_data)
        await target_writer.drain()
    if initial_target_data:
        client_writer.write(initial_target_data)
        await client_writer.drain()
    await asyncio.gather(
        relay(client_reader, target_writer),
        relay(target_reader, client_writer),
        return_exceptions=True,
    )


def parse_header_block(head: str) -> tuple[str, dict[str, str]] | None:
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines or len(lines[0].split()) != 3:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        separator = line.find(":", 1) if line.startswith(":") else line.find(":")
        if separator < 0:
            return None
        key, value = line[:separator], line[separator + 1 :]
        key = key.strip().lower()
        if not key or key in headers:
            return None
        headers[key] = value.strip()
    return lines[0].strip(), headers


def header_end(data: bytearray) -> tuple[int, int] | None:
    crlf = data.find(b"\r\n\r\n")
    lf = data.find(b"\n\n")
    candidates = [(idx, 4) for idx in (crlf,) if idx >= 0]
    candidates += [(idx, 2) for idx in (lf,) if idx >= 0]
    return min(candidates) if candidates else None


def has_binary_request_prefix(data: bytes) -> bool:
    """Detect bytes that cannot belong to an HTTP request line.

    The raw fallback is deliberately decided before any text decoding. CR, LF,
    and horizontal tab are valid HTTP framing bytes; other control bytes and
    non-ASCII bytes are a strong signal that the client is speaking a binary
    protocol directly.
    """
    first_line = data.split(b"\n", 1)[0]
    return any(
        byte not in {0x09, 0x0D}
        and (byte < 0x20 or byte > 0x7E)
        for byte in first_line
    )


def has_http_request_line(data: bytearray) -> bool:
    """Return whether the first complete line has HTTP request-line shape."""
    line_end = data.find(b"\n")
    if line_end < 0:
        return False
    line = bytes(data[:line_end]).rstrip(b"\r")
    parts = line.split()
    return len(parts) == 3 and parts[2].startswith(b"HTTP/")


def looks_like_http_prefix(data: bytes) -> bool:
    """Return whether an incomplete first line could still be an HTTP request."""
    line = data.split(b"\n", 1)[0].rstrip(b"\r")
    token = line.split(None, 1)[0] if line.split(None, 1) else line
    if not token or len(token) > 32:
        return False
    return all(0x21 <= byte <= 0x7E for byte in token)


def serialize_request(request_line: str, headers: dict[str, str]) -> bytes:
    lines = [request_line]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


async def read_upstream_response(
    reader: asyncio.StreamReader,
) -> tuple[int, bytes] | None:
    data = bytearray()
    deadline = asyncio.get_event_loop().time() + HANDSHAKE_TIMEOUT
    while header_end(data) is None:
        if len(data) >= MAX_HEADER_BYTES:
            return None
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return None
        try:
            part = await asyncio.wait_for(reader.read(2048), timeout=remaining)
        except asyncio.TimeoutError:
            return None
        if not part:
            return None
        data.extend(part)

    end = header_end(data)
    if end is None:
        return None
    index, delimiter_length = end
    status_line = bytes(data[:index]).decode("iso-8859-1", errors="replace").split(
        "\n", 1
    )[0].strip()
    status_parts = status_line.split()
    if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
        return None
    try:
        status_code = int(status_parts[1])
    except ValueError:
        return None
    return status_code, bytes(data[index + delimiter_length :])


async def open_upstream(
    request_line: str, headers: dict[str, str]
) -> tuple[
    asyncio.StreamReader, asyncio.StreamWriter, bytes
] | None:
    if not UPSTREAM_HOST:
        return None
    tls = ssl.create_default_context() if UPSTREAM_TLS else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                UPSTREAM_HOST,
                UPSTREAM_PORT,
                ssl=tls,
                server_hostname=UPSTREAM_HOST if tls else None,
            ),
            timeout=HANDSHAKE_TIMEOUT,
        )
        writer.write(serialize_request(request_line, headers))
        await asyncio.wait_for(writer.drain(), timeout=HANDSHAKE_TIMEOUT)
        upstream_response = await read_upstream_response(reader)
        if upstream_response is None:
            writer.close()
            await writer.wait_closed()
            return None
        status_code, initial_upstream_data = upstream_response
        if not 200 <= status_code < 300:
            writer.close()
            await writer.wait_closed()
            return None
        return reader, writer, initial_upstream_data
    except (OSError, asyncio.TimeoutError):
        return None


def is_handshake_block(request_line: str, headers: dict[str, str]) -> bool:
    parts = request_line.split()
    if len(parts) != 3:
        return False
    if parts[0].upper() == "CONNECT":
        return True
    return headers.get("upgrade", "").lower() == "websocket"


async def read_request(
    reader: asyncio.StreamReader,
    *,
    allow_raw_binary: bool = False,
) -> tuple[str, dict[str, str], bytes, bool] | None:
    data = bytearray()
    deadline = asyncio.get_event_loop().time() + HANDSHAKE_TIMEOUT

    async def fill_until(is_ready, until: float) -> bool:
        while not is_ready():
            if len(data) >= MAX_HEADER_BYTES:
                return False
            remaining = until - asyncio.get_event_loop().time()
            if remaining <= 0:
                return False
            try:
                part = await asyncio.wait_for(reader.read(2048), timeout=remaining)
            except asyncio.TimeoutError:
                return False
            if not part:
                return False
            data.extend(part)
        return True

    # Port 80 also supports clients that begin with a binary protocol rather
    # than an HTTP request. Read the first available bytes without decoding;
    # probe briefly only when they could still be an incomplete HTTP line.
    # This preserves normal HTTP parsing while avoiding a long wait for a
    # binary client that never sends an HTTP header terminator.
    if allow_raw_binary:
        try:
            part = await asyncio.wait_for(
                reader.read(2048),
                timeout=max(0.0, deadline - asyncio.get_event_loop().time()),
            )
        except asyncio.TimeoutError:
            return None
        if not part:
            return None
        data.extend(part)
        if has_binary_request_prefix(bytes(data)):
            return "", {}, bytes(data), True
        if not header_end(data) and not looks_like_http_prefix(bytes(data)):
            return "", {}, bytes(data), True

    header_deadline = deadline
    if allow_raw_binary:
        header_deadline = min(
            deadline,
            asyncio.get_event_loop().time() + RAW_BINARY_PROBE_TIMEOUT,
        )
    if not await fill_until(lambda: header_end(data) is not None, header_deadline):
        if allow_raw_binary and not has_http_request_line(data):
            return "", {}, bytes(data), True
        return None

    first_end = header_end(data)
    if first_end is None:
        return None
    idx1, delimiter1_len = first_end
    head1 = bytes(data[:idx1]).decode("iso-8859-1", errors="replace")
    parsed1 = parse_header_block(head1)
    if parsed1 is None:
        if allow_raw_binary and not has_http_request_line(data):
            return "", {}, bytes(data), True
        return None
    request_line1, headers1 = parsed1
    rest_start = idx1 + delimiter1_len

    if is_handshake_block(request_line1, headers1):
        return request_line1, headers1, bytes(data[rest_start:]), False

    grace_deadline = min(
        deadline,
        asyncio.get_event_loop().time() + SECOND_BLOCK_GRACE,
    )
    if not await fill_until(lambda: header_end(data[rest_start:]) is not None, grace_deadline):
        return request_line1, headers1, bytes(data[rest_start:]), False

    second_end = header_end(data[rest_start:])
    if second_end is None:
        return request_line1, headers1, bytes(data[rest_start:]), False
    relative_idx2, delimiter2_len = second_end
    idx2 = rest_start + relative_idx2
    head2 = bytes(data[rest_start:idx2]).decode("iso-8859-1", errors="replace")
    parsed2 = parse_header_block(head2)
    if parsed2 is None:
        return request_line1, headers1, bytes(data[rest_start:]), False

    request_line2, headers2 = parsed2
    return request_line2, headers2, bytes(data[idx2 + delimiter2_len :]), False


def request_path(target: str) -> str:
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        return parsed.path or "/"
    return target.split("?", 1)[0] or "/"


def error_response(status: str, detail: str = "") -> bytes:
    body = f"{status}\n".encode()
    if detail:
        body += f"{detail}\n".encode()
    return (
        f"HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )


def parse_authority(
    value: str, default_port: int
) -> tuple[str, int, bool] | None:
    """Parse a CONNECT authority without making any outbound connection."""
    value = value.strip()
    if not value or any(character.isspace() for character in value):
        return None
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("@", 1)[-1]

    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            return None
        host = value[1:closing]
        if not host:
            return None
        port_text = value[closing + 1 :]
        if port_text.startswith(":"):
            port_token = port_text[1:].strip()
            try:
                port = int(port_token)
            except ValueError:
                port = PORT_ALIASES.get(
                    port_token.casefold(), SYMBOLIC_PORT_DEFAULT
                )
            if not 1 <= port <= 65535:
                return None
            return host, port, True
        return host, default_port, False

    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            port = PORT_ALIASES.get(
                port_text.strip().casefold(), SYMBOLIC_PORT_DEFAULT
            )
        if not host.strip("[]") or not 1 <= port <= 65535:
            return None
        return host.strip("[]"), port, True
    host = value.strip("[]")
    return (host, default_port, False) if host else None


def valid_connect_request(request_line: str, headers: dict[str, str]) -> bool:
    """Accept HTTP Custom CONNECT targets while keeping the upstream fixed to local SSH.

    HTTP Custom clients use both authority-form (``CONNECT host:port``) and
    origin-form (``CONNECT /`` with a Host header). Some clients also send
    bracketed or placeholder targets such as ``[0.0.0.0]:80``. The target is
    never used for routing, so any non-empty, whitespace-free target is
    accepted after the request line itself has been validated.
    """
    parts = request_line.split()
    if len(parts) != 3 or parts[0].upper() != "CONNECT":
        return False
    target = parts[1]
    if not target or any(ord(character) < 0x20 for character in target):
        return False
    return True


def connection_response(
    method: str, headers: dict[str, str]
) -> bytes:
    """Return the protocol response sent before starting the raw bridge.

    CONNECT receives a WebSocket-style 101 response when
    CONNECT_USE_WEBSOCKET_RESPONSE is enabled, or a bare 101 handoff when it is
    disabled. Legacy GET/POST/CF-RAY profiles that do not request WebSocket
    receive a bare 101 handoff instead,
    because advertising an unsolicited WebSocket upgrade can make some mobile
    clients keep the HTTP layer open rather than handing the socket to SSH.
    FORCE_101 still controls the legacy non-CONNECT compatibility profiles.
    """
    requested_upgrade = headers.get("upgrade", "").strip().lower()
    if method == "CONNECT":
        return (
            SWITCHING_PROTOCOLS_RESPONSE
            if CONNECT_USE_WEBSOCKET_RESPONSE
            else RAW_STREAM_SWITCHING_RESPONSE
        )
    if (
        FORCE_101
        and method in {"GET", "POST", "CF-RAY"}
        and requested_upgrade != "websocket"
    ):
        return RAW_STREAM_SWITCHING_RESPONSE
    return SWITCHING_PROTOCOLS_RESPONSE


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    global active_connections
    peer = writer.get_extra_info("peername")
    async with connection_lock:
        if active_connections >= MAX_CONNECTIONS:
            await write_and_close(
                writer,
                b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n",
            )
            return
        active_connections += 1
    try:
        sockname = writer.get_extra_info("sockname")
        local_port = sockname[1] if isinstance(sockname, tuple) and len(sockname) > 1 else None
        request = await read_request(
            reader,
            allow_raw_binary=(
                ACCEPT_RAW_BINARY_ON_HTTP and local_port == 80
            ),
        )
        if request is None:
            print(f"invalid HTTP headers from {peer!r}", flush=True)
            await write_and_close(
                writer,
                error_response("400 Bad Request", "invalid HTTP headers"),
            )
            return
        request_line, headers, initial_client_data, is_raw_binary = request
        if is_raw_binary and local_port != 80:
            await write_and_close(
                writer,
                error_response("400 Bad Request", "invalid HTTP headers"),
            )
            return
        if is_raw_binary:
            target_conn = await open_target(
                FALLBACK_BACKEND_HOST,
                FALLBACK_BACKEND_PORT,
            )
            if target_conn is None:
                # A raw protocol has no HTTP response framing. Closing the
                # socket avoids injecting text bytes into the binary stream.
                return
            target_reader, target_writer = target_conn
            await bridge(
                reader,
                writer,
                target_reader,
                target_writer,
                initial_client_data,
            )
            return
        method, target, version = request_line.split()
        if not version.startswith("HTTP/"):
            await write_and_close(writer, error_response("405 Method Not Allowed"))
            return

        method = method.upper()
        is_websocket = (
            method == "GET" and headers.get("upgrade", "").lower() == "websocket"
        )
        # CF-RAY payloads use a second synthetic request line after a decoy
        # probe; keep accepting that legacy shape when compatibility mode is on.
        is_compatibility_upgrade = FORCE_101 and method in {"GET", "POST", "CF-RAY"}
        if method == "CONNECT":
            if not valid_connect_request(request_line, headers):
                await write_and_close(
                    writer,
                    error_response(
                        "400 Bad Request",
                        "CONNECT must include a valid authority or Host header",
                    ),
                )
                return
            normalized_target = normalize_connect_target(target)
            if normalized_target not in CONNECT_TARGETS:
                await write_and_close(
                    writer,
                    error_response(
                        "403 Forbidden",
                        "CONNECT target is not allowlisted",
                    ),
                )
                return
        elif not is_websocket and not is_compatibility_upgrade:
            await write_and_close(
                writer,
                error_response("426 Upgrade Required", "WebSocket upgrade required"),
            )
            return

        initial_upstream_data = b""
        if method == "CONNECT":
            # The allowlisted CONNECT route is a local reverse-proxy handoff.
            # The client-supplied authority is checked above but is never used
            # as an outbound host; this route always reaches the local SSH service.
            target_conn = await open_target(
                CONNECT_BACKEND_HOST, CONNECT_BACKEND_PORT
            )
            if target_conn is None:
                await write_and_close(
                    writer,
                    error_response(
                        "502 Bad Gateway",
                        "local CONNECT backend unavailable",
                    ),
                )
                return
            target_reader, target_writer = target_conn
        else:
            # WebSocket and legacy compatibility transports continue to reach
            # the authenticated local SSH daemon.
            target_conn = await open_target(
                FALLBACK_BACKEND_HOST, FALLBACK_BACKEND_PORT
            )
            if target_conn is None:
                await write_and_close(
                    writer,
                    error_response("502 Bad Gateway", "local SSH backend unavailable"),
                )
                return
            target_reader, target_writer = target_conn

        # The local backend or upstream handshake is completed before the
        # success response, so 101 means a live byte bridge is ready.
        writer.write(connection_response(method, headers))
        await writer.drain()

        await bridge(
            reader,
            writer,
            target_reader,
            target_writer,
            initial_client_data,
            initial_upstream_data,
        )
    except (ConnectionError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        async with connection_lock:
            active_connections -= 1
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass


def tls_context() -> ssl.SSLContext | None:
    if not ENABLE_TLS:
        return None
    cert = TLS_CERT
    key = TLS_KEY
    if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
        raise RuntimeError(
            "TLS is enabled, but the certificate or private key is missing. "
            f"Expected certificate={cert!r}, key={key!r}."
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


async def main() -> None:
    load_runtime_config()
    servers: list[asyncio.AbstractServer] = []
    if ENABLE_HTTP:
        for port in HTTP_PORTS:
            servers.append(await asyncio.start_server(handle_client, LISTEN_HOST, port))
    context = tls_context()
    if context:
        for port in TLS_PORTS:
            servers.append(
                await asyncio.start_server(
                    handle_client,
                    LISTEN_HOST,
                    port,
                    ssl=context,
                )
            )
    if not servers:
        raise RuntimeError(
            "No listeners configured. Check HTTP_PORTS, TLS_PORTS, "
            "ENABLE_HTTP, and ENABLE_TLS in /etc/ssh-ws/config.env."
        )

    sockets = [
        [sock.getsockname() for sock in (server.sockets or [])]
        for server in servers
    ]
    print(
        f"ssh-ws listening on {sockets}; SSH backend "
        f"{FALLBACK_BACKEND_HOST}:{FALLBACK_BACKEND_PORT}; CONNECT targets "
        f"{sorted(CONNECT_TARGETS)} -> "
        f"{CONNECT_BACKEND_HOST}:{CONNECT_BACKEND_PORT}",
        flush=True,
    )

    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass