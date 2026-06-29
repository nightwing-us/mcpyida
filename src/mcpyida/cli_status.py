"""Structured stdout status/error contract for the headless launcher.

Pure (no IDA): a background/polling launcher reads ONE JSON line from stdout to
diagnose the outcome, instead of scraping a stderr traceback. Mirrors
MCPyGhidra's cli_status for cross-repo parity.
"""

from __future__ import annotations

import json
import sys

# reason -> process exit code. The JSON `reason` is the primary contract; the
# codes are secondary (a launcher can branch on either).
EXIT_CODES = {
    'binary_not_found': 3,
    'missing_install_dir': 4,
    'bad_port': 5,
    'port_unavailable': 6,
    'open_failed': 7,
    # Reserved for cross-repo parity with MCPyGhidra (JVM/JDK launch failure).
    # IDA is native, so this reason is never emitted here — but the taxonomy is
    # shared so a launcher sees one reason->code map across both tools.
    'jvm_not_found': 8,
    'internal': 1,
}


def emit_ready(host: str, port: int, binary: str) -> None:
    """Print the readiness JSON to stdout (flushed)."""
    print(
        json.dumps({'status': 'ready', 'host': host, 'port': port, 'binary': binary}),
        flush=True,
    )


def emit_error(reason: str, detail: str, *, remediation: str | None = None) -> int:
    """Print an error JSON to stdout, a human remediation line to stderr, and
    return the mapped exit code. The caller does ``sys.exit(...)`` with it."""
    print(
        json.dumps({'status': 'error', 'reason': reason, 'detail': detail}),
        flush=True,
    )
    if remediation is not None:
        print(remediation, file=sys.stderr, flush=True)
    return EXIT_CODES.get(reason, 1)
