"""--port spec parsing + parallel-safe socket binding.

Pure helpers with no IDA/FastMCP dependency, shared by headless.py and
mcpserver.py so both bind the first actually-free port in a configured range.
Mirrors MCPyGhidra's portspec.py for cross-repo parity (IDA base port 6150).
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
import socket
import struct

# Default --port: a parallel-safe range. A bare single port is strict.
DEFAULT_PORT_RANGE = '6150-6159'


def parse_port_spec(spec: str | int) -> list[int]:
    """Parse a --port spec into an ordered candidate list.

    "6150-6159" -> [6150, ..., 6159]   (inclusive range)
    "6150"/6150 -> [6150]               (strict single)
    "0"/0       -> [0]                  (OS auto-assign sentinel)

    Raises ValueError on malformed input, M < N, or out-of-range ports
    (1..65535; 0 only as the lone auto-assign sentinel).
    """
    text = str(spec).strip()
    if not text:
        raise ValueError('empty --port spec')

    if '-' in text:
        start_s, _, end_s = text.partition('-')
        try:
            start, end = int(start_s), int(end_s)
        except ValueError:
            raise ValueError(f'invalid --port range: {spec!r}')
        if not (1 <= start <= 65535) or not (1 <= end <= 65535):
            raise ValueError(f'--port range out of bounds (1-65535): {spec!r}')
        if end < start:
            raise ValueError(f'--port range end < start: {spec!r}')
        return list(range(start, end + 1))

    try:
        port = int(text)
    except ValueError:
        raise ValueError(f'invalid --port: {spec!r}')
    if port == 0:
        return [0]
    if not (1 <= port <= 65535):
        raise ValueError(f'--port out of bounds (1-65535 or 0): {spec!r}')
    return [port]


def resolve_port_spec(
    explicit: int | str | None,
    configured: int | str | None,
) -> int | str:
    """Resolve the effective --port spec for a server start.

    Precedence: an explicit spec passed to start() wins; otherwise the
    server's previously-configured port; otherwise the default parallel-safe
    range. This is the single source of the default so GUI and headless agree:
    the GUI constructs ``McpServer()`` with no port and starts with none, so it
    lands on ``DEFAULT_PORT_RANGE`` exactly like ``mcpyida-headless``.
    """
    if explicit is not None:
        return explicit
    if configured is not None:
        return configured
    return DEFAULT_PORT_RANGE


def bind_listen_socket(
    host: str,
    candidates: list[int],
    *,
    exclude: AbstractSet[int] = frozenset(),
) -> tuple[socket.socket, int]:
    """Create a listening server socket bound to the first candidate that binds.

    - Sets SO_REUSEADDR + SO_LINGER(1, 0) for immediate reuse (no TIME_WAIT).
    - Skips any port in ``exclude``.
    - candidates == [0] -> OS auto-assign (single bind to port 0).
    - On OSError for a candidate, closes that socket and tries the next.
    - Does bind + listen(100) + setblocking(False); returns (socket, actual_port).

    Raises OSError if no candidate binds.
    """
    last_err: OSError | None = None
    for port in candidates:
        # Never skip the OS-auto-assign sentinel (0), even if it lands in
        # `exclude` (defensive; matches MCPyGhidra).
        if port != 0 and port in exclude:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_LINGER with 0 timeout forces immediate close (no TIME_WAIT).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        try:
            sock.bind((host, port))
        except OSError as e:
            last_err = e
            sock.close()
            continue
        sock.listen(100)
        sock.setblocking(False)
        return sock, sock.getsockname()[1]

    detail = f' (excluding {sorted(exclude)})' if exclude else ''
    raise OSError(
        f'no bindable port in {list(candidates)!r} on {host}{detail}'
    ) from last_err
