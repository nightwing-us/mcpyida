"""E2E test fixtures — launches headless IDA server as subprocess."""
import json
import subprocess
import sys
import threading
import time

import pytest

from tests.conftest import CRACKME_ELF, STRUCT_TEST_ELF

LAUNCH_TIMEOUT = 120  # seconds — IDA analysis is typically faster than Ghidra


def _wait_for_ready(proc: subprocess.Popen, timeout: float) -> dict:
    """Read stdout lines until we get the JSON ready signal."""
    deadline = time.monotonic() + timeout
    watchdog = threading.Timer(timeout + 5, proc.kill)
    watchdog.daemon = True
    watchdog.start()

    try:
        for line in proc.stdout:
            if time.monotonic() > deadline:
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get('status') == 'ready':
                    return data
            except json.JSONDecodeError:
                continue

        exit_code = proc.poll()
        pytest.fail(
            f'Server did not become ready within {timeout}s. '
            f'Process exit code: {exit_code}'
        )
    finally:
        watchdog.cancel()


@pytest.fixture(scope='module')
def headless_server(request):
    """Launch mcpyida-headless as subprocess, wait for ready signal."""
    import os

    def _can_import(module: str) -> bool:
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    if not _can_import('idapro'):
        pytest.skip('idalib not available (install idapro pip package)')

    # Clean stale IDA database files (prevents reusing empty analysis)
    import glob
    for ext in ['*.id0', '*.id1', '*.id2', '*.nam', '*.til', '*.i64']:
        for f in glob.glob(os.path.join(os.path.dirname(CRACKME_ELF), ext)):
            os.remove(f)

    proc = subprocess.Popen(
        [
            sys.executable, '-m', 'mcpyida.headless',
            CRACKME_ELF,
            '--port', '0',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        yield status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope='class')
def fresh_headless_server(request):
    """Launch a FRESH headless server per test class — clean database.

    Use this for mutation tests (rename, set_comments, patch, etc.) that
    modify the binary and might not restore cleanly.

    The existing 'headless_server' (module-scoped) is shared by read-only tests.
    """
    import os

    def _can_import(module: str) -> bool:
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    if not _can_import('idapro'):
        pytest.skip('idalib not available (install idapro pip package)')

    # Clean stale IDA database files
    import glob
    for ext in ['*.id0', '*.id1', '*.id2', '*.nam', '*.til', '*.i64']:
        for f in glob.glob(os.path.join(os.path.dirname(CRACKME_ELF), ext)):
            os.remove(f)

    proc = subprocess.Popen(
        [sys.executable, '-m', 'mcpyida.headless', CRACKME_ELF, '--port', '0'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        yield status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope='class')
def struct_test_server(request):
    """Launch a FRESH headless server loaded with struct_test.elf.

    struct_test.elf has debug info with Config/Point structs and known
    local variables in process_config (total: int, p: Point on stack).

    Use this for tests that change local variable types to user-defined
    struct pointers — the binary already has the struct definitions.
    """
    import os

    def _can_import(module: str) -> bool:
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    if not _can_import('idapro'):
        pytest.skip('idalib not available (install idapro pip package)')

    # Clean stale IDA database files for struct_test.elf
    import glob
    for ext in ['*.id0', '*.id1', '*.id2', '*.nam', '*.til', '*.i64']:
        for f in glob.glob(os.path.join(os.path.dirname(STRUCT_TEST_ELF), ext)):
            os.remove(f)

    proc = subprocess.Popen(
        [sys.executable, '-m', 'mcpyida.headless', STRUCT_TEST_ELF, '--port', '0'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        yield status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        # Clean up IDA database files for struct_test.elf
        for ext in ['*.id0', '*.id1', '*.id2', '*.nam', '*.til', '*.i64']:
            for f in glob.glob(os.path.join(os.path.dirname(STRUCT_TEST_ELF), ext)):
                try:
                    os.remove(f)
                except OSError:
                    pass
