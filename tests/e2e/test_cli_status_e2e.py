# tests/e2e/test_cli_status_e2e.py
"""E2E: a bare busy --port yields a structured port_unavailable error on stdout.

Live-IDA only (needs idalib); runs in CI (test:full).
"""
import json
import socket
import subprocess
import sys

import pytest

from tests.conftest import CRACKME_ELF


def _can_import(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


requires_ida = pytest.mark.skipif(
    not _can_import('idapro'),
    reason='idalib not available (install idapro pip package)',
)


@requires_ida
def test_bare_busy_port_emits_port_unavailable(tmp_path):
    # Occupy a single port, then ask headless for exactly that one (strict).
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    occupied.bind(('127.0.0.1', 0))
    occupied.listen(1)
    busy = occupied.getsockname()[1]
    try:
        proc = subprocess.run(
            [
                sys.executable, '-m', 'mcpyida.headless',
                CRACKME_ELF,
                '--port', str(busy),
                '--idb-path', str(tmp_path / 'db.i64'),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
    finally:
        occupied.close()

    # The LAST stdout JSON line is the structured error.
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    payload = json.loads(lines[-1])
    assert payload['status'] == 'error'
    assert payload['reason'] == 'port_unavailable'
    assert proc.returncode == 6
