"""E2E: --idb-path output control + persist-on-SIGTERM.

Proves two contracts of the headless launcher:

  1. ``--idb-path`` writes the IDA database at the chosen path and NOT beside
     the binary (idalib otherwise drops the .i64 next to the input file).
  2. A default ``SIGTERM`` (``proc.terminate()``) triggers a graceful save, so
     an edit made over MCP survives a reopen of the saved database. Without the
     SIGTERM -> KeyboardInterrupt conversion, the ``finally: close_database()``
     shutdown path is skipped and the edit is lost.
"""
import glob
import os
import subprocess
import sys

import pytest

from tests.conftest import CRACKME_ELF
from tests.e2e.conftest import LAUNCH_TIMEOUT, _wait_for_ready
from tests.e2e.test_headless_launch import mcp_call


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

# Working/packed database extensions IDA may emit.
_DB_EXTS = ('id0', 'id1', 'id2', 'nam', 'til', 'i64')


def _clean_db_files(directory: str) -> None:
    """Remove any stale IDA database files in *directory*."""
    for ext in _DB_EXTS:
        for f in glob.glob(os.path.join(directory, f'*.{ext}')):
            try:
                os.remove(f)
            except OSError:
                pass


def _launch(extra_args: list[str], binary: str = CRACKME_ELF) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            '-m',
            'mcpyida.headless',
            binary,
            '--port',
            '0',
            *extra_args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _terminate_and_wait(proc: subprocess.Popen, timeout: int = 30) -> None:
    """Send SIGTERM and wait for graceful shutdown (kill as a backstop)."""
    proc.terminate()  # SIGTERM
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise


@requires_ida
def test_idb_path_controls_location_and_persists_on_sigterm(tmp_path):
    """--idb-path lands the .i64 at the chosen path, nothing beside the binary."""
    binary_dir = os.path.dirname(CRACKME_ELF)
    _clean_db_files(binary_dir)  # ensure nothing stale is sitting beside the binary

    idb_path = tmp_path / 'controlled.i64'

    proc = _launch(['--idb-path', str(idb_path)])
    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        assert status['status'] == 'ready'
    finally:
        _terminate_and_wait(proc)

    # The SIGTERM shutdown path must have saved the database to the chosen path.
    assert idb_path.exists(), f'expected database at --idb-path {idb_path}'

    # And nothing should have been written beside the binary.
    beside = glob.glob(os.path.join(binary_dir, '*.i64'))
    assert not beside, f'unexpected database beside the binary: {beside}'


@requires_ida
def test_edit_survives_sigterm(tmp_path):
    """A rename made over MCP survives a default SIGTERM and a reopen."""
    binary_dir = os.path.dirname(CRACKME_ELF)
    _clean_db_files(binary_dir)

    idb_path = tmp_path / 'edit.i64'
    marker = 'survived_sigterm_marker'

    # First session: rename a known function, confirm it took effect live,
    # then stop the server with a default SIGTERM.
    proc = _launch(['--idb-path', str(idb_path)])
    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        mcp_call(
            status,
            'rename',
            {'items': [{'name': 'check_password', 'new_name': marker}]},
        )
        live = mcp_call(
            status,
            'list',
            {'entry_type': 'function', 'offset': 0, 'limit': 1000},
        )
        assert marker in live, f'rename did not take effect live; got: {live[:500]}'
    finally:
        _terminate_and_wait(proc)

    assert idb_path.exists(), 'SIGTERM did not persist the database'

    # Second session: reopen the SAVED database (pass the .i64 as the binary)
    # and confirm the rename persisted across the SIGTERM shutdown.
    proc2 = _launch([], binary=str(idb_path))
    try:
        status2 = _wait_for_ready(proc2, LAUNCH_TIMEOUT)
        reopened = mcp_call(
            status2,
            'list',
            {'entry_type': 'function', 'offset': 0, 'limit': 1000},
        )
        assert marker in reopened, (
            f'rename did not survive SIGTERM/reopen; got: {reopened[:500]}'
        )
    finally:
        _terminate_and_wait(proc2)
