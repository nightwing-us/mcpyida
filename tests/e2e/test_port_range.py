"""E2E: parallel headless instances land on distinct ports in the range.

Proves the --port range default (6150-6159) lets multiple mcpyida-headless
servers launch at once without a port clash. Each instance gets its own
--idb-path so they don't contend on the database file — the only shared resource
under test is the port range.

Live-IDA only (needs idalib); runs in CI (test:full).
"""
import subprocess
import sys
import tempfile

import pytest

from tests.conftest import CRACKME_ELF
from tests.e2e.conftest import LAUNCH_TIMEOUT, _wait_for_ready


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


def _launch(idb_path: str) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            '-m',
            'mcpyida.headless',
            CRACKME_ELF,
            '--port',
            '6150-6159',
            '--idb-path',
            idb_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _terminate(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@requires_ida
def test_two_parallel_instances_get_distinct_ports():
    d1 = tempfile.mkdtemp()
    d2 = tempfile.mkdtemp()
    proc1 = _launch(f'{d1}/db.i64')
    proc2 = _launch(f'{d2}/db.i64')
    try:
        status1 = _wait_for_ready(proc1, LAUNCH_TIMEOUT)
        status2 = _wait_for_ready(proc2, LAUNCH_TIMEOUT)

        assert status1['status'] == 'ready'
        assert status2['status'] == 'ready'

        p1, p2 = status1['port'], status2['port']
        assert p1 != p2, f'parallel instances must get distinct ports, both got {p1}'
        for p in (p1, p2):
            assert 6150 <= p <= 6159, f'port {p} outside the requested range 6150-6159'
    finally:
        _terminate(proc1)
        _terminate(proc2)
