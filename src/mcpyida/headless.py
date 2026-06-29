"""MCPyIDA headless MCP server.

Launch IDA headless via idalib, open a binary, run auto-analysis,
and start the MCP server. Blocks until interrupted.

Usage:
    mcpyida-headless /path/to/elf [--host 127.0.0.1] [--port 6150-6159] [--ida-dir DIR]
    python -m mcpyida.headless /path/to/elf

Prints JSON readiness signal to stdout when the server is ready:
    {"status": "ready", "host": "127.0.0.1", "port": 6150, "binary": "/path/to/elf"}

This is the contract that test harnesses and MCP client CLI rely on.

Requires idapro pip package (idalib).
"""

from __future__ import annotations

import argparse
import os
import platform
import queue
import sys
import threading
from pathlib import Path


def run_on_main_thread(func, *args, **kwargs):
    """Submit *func* to the main thread and block until the result is ready.

    Called from uvicorn worker threads via the sync @run_in_ida_main decorator.
    Raises any exception that func raises.
    """
    from mcpyida.mcpserver import get_ida_work_queue

    result_event = threading.Event()
    result_holder: list = [None, None]  # [result, exception]

    def work_item() -> None:
        try:
            result_holder[0] = func(*args, **kwargs)
        except Exception as exc:
            result_holder[1] = exc
        finally:
            result_event.set()

    get_ida_work_queue().put(work_item)
    result_event.wait()  # Block until the main thread completes the call

    if result_holder[1] is not None:
        raise result_holder[1]
    return result_holder[0]


def _idalib_filename() -> str:
    """Platform name of the idalib shared library (per idapro/__init__.py)."""
    system = platform.system()
    if system == 'Windows':
        return 'idalib.dll'
    if system == 'Darwin':
        return 'libidalib.dylib'
    return 'libidalib.so'


def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCPyIDA headless MCP server',
    )
    parser.add_argument(
        'binary',
        help='Path to the binary file to analyze.',
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind MCP server (default: 127.0.0.1)',
    )
    parser.add_argument(
        '--port',
        type=str,
        default='6150-6159',
        help='Port for the MCP server. A range "N-M" (default 6150-6159) binds '
        'the first free port in the range — safe for launching multiple '
        'instances in parallel. A bare "N" is strict (only that port; fails if '
        'busy). "0" lets the OS auto-assign. The actual bound port is reported '
        'in the JSON ready signal.',
    )
    parser.add_argument(
        '--idb-path',
        default=None,
        help='Output path (extension optional) for the IDA database. Passes IDA '
        "'-o' so the .i64/.idb is written here instead of beside the binary "
        '(idalib has no db-path arg otherwise). Default: beside the binary.',
    )
    parser.add_argument(
        '--ida-dir',
        default=None,
        help='Path to the IDA Pro install directory (the one containing '
        'libidalib.so). Precedence: --ida-dir > $IDADIR > '
        '~/.idapro/ida-config.json (py-activate-idalib). If unset and idalib is '
        'not configured, the server exits with a clear structured error.',
    )
    args = parser.parse_args()

    from mcpyida import cli_status
    from mcpyida.portspec import parse_port_spec

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        sys.exit(
            cli_status.emit_error(
                'binary_not_found',
                f'binary not found: {binary_path}',
                remediation=f'Check the path. Given: {args.binary!r}',
            )
        )

    # Validate --port now (before the expensive idalib import) so bad input
    # fails fast. The actual bind happens in McpServer.start.
    try:
        parse_port_spec(args.port)
    except ValueError as e:
        sys.exit(
            cli_status.emit_error(
                'bad_port',
                f'invalid --port {args.port!r}: {e}',
                remediation='Use a single port "N", a range "N-M", or "0".',
            )
        )

    # Resolve --idb-path now (before the idalib import). IDA splits the '-o'
    # argument on whitespace, so a path with spaces is mis-parsed — reject it.
    # (Pure usage error: keep argparse's exit 2.)
    idb_path = None
    if args.idb_path:
        idb_path = str(Path(args.idb_path).expanduser())
        if any(c.isspace() for c in idb_path):
            parser.error(
                f'--idb-path must not contain whitespace (IDA splits the -o '
                f'argument on spaces): {idb_path!r}'
            )

    # Pin the IDA install if requested. idalib reads $IDADIR at `import idapro`
    # time (it overrides the JSON config), so set it before importing idapro.
    if args.ida_dir:
        ida_dir = Path(args.ida_dir).expanduser()
        libname = _idalib_filename()
        if not ida_dir.is_dir() or not any(ida_dir.rglob(libname)):
            sys.exit(
                cli_status.emit_error(
                    'missing_install_dir',
                    f'--ida-dir does not contain {libname}: {ida_dir}',
                    remediation=(
                        f'Pass the IDA install dir that contains {libname}, or '
                        f'set IDADIR. Searched: {ida_dir}'
                    ),
                )
            )
        os.environ['IDADIR'] = str(ida_dir)

    # Check prerequisites before expensive imports. Headless mode is built on
    # idalib (IDA Pro 9.0+); the `idapro` module does NOT exist in IDA 7.x/8.x.
    try:
        import idapro
    except ImportError as e:
        searched = os.environ.get('IDADIR') or '~/.idapro/ida-config.json'
        sys.exit(
            cli_status.emit_error(
                'missing_install_dir',
                f'could not import idapro (idalib): {e}',
                remediation=(
                    'Headless mode requires IDA Pro 9.0+ with idalib activated. '
                    'Pass --ida-dir <dir>, set IDADIR, or run '
                    'py-activate-idalib.py in this venv. '
                    f'Searched: {searched}. See docs/installation.md.'
                ),
            )
        )

    # Signal headless mode before importing mcpserver so that is_headless()
    # returns True immediately, even if idalib doesn't set the batch flag.
    os.environ['MCPYIDA_HEADLESS'] = '1'

    # idalib must be imported first — initializes the IDA environment.
    # --idb-path threads IDA's '-o' switch so the database lands at a controlled
    # location (idalib follows symlinks to the real binary, so a symlink trick
    # does NOT work; '-o' is the only clean lever — validated on IDA 9.2).
    open_args = f'-o{idb_path}' if idb_path else None
    print('Starting IDA headless (idalib)...', file=sys.stderr)
    try:
        idapro.open_database(str(binary_path), run_auto_analysis=True, args=open_args)
    except Exception as e:
        sys.exit(cli_status.emit_error('open_failed', f'failed to open binary: {e}'))

    # Echo the resolved install/version/binary (item 4). The bound port is not
    # known until the server binds (after analysis); it is in the ready JSON.
    try:
        # idapro re-exports get_ida_install_dir from idapro.config in its
        # __init__, so reach it via the package (no submodule import — keeps
        # mypy happy: `idapro` is ignore_missing_imports, `idapro.config` isn't).
        _ver = idapro.get_library_version()  # (major, minor, build) or None
        _ver_s = '.'.join(str(x) for x in _ver) if _ver else 'unknown'
        _install = idapro.get_ida_install_dir() or 'unknown'
    except Exception:
        _ver_s, _install = 'unknown', 'unknown'
    print(
        f'Using IDA {_ver_s} ({_install}) · binary {binary_path.name}',
        file=sys.stderr,
    )

    # Persist the database on SIGTERM. The `finally: close_database()` below saves
    # on graceful exit (KeyboardInterrupt/normal), but a default SIGTERM terminates
    # the process and skips it — losing analysis/edits. Convert SIGTERM into
    # KeyboardInterrupt so the shutdown path (finally -> close_database) runs.
    # Registered here, right after the database is open, so it also covers
    # auto-analysis and server startup — not just the work-queue pump loop.
    # IDA is native (no JVM), so no '-Xrs' is needed here. Validated on IDA 9.2:
    # a rename survives SIGTERM with this; without it it is lost.
    import signal as _signal

    def _on_sigterm(_signum, _frame):
        raise KeyboardInterrupt

    _signal.signal(_signal.SIGTERM, _on_sigterm)

    # Everything past open_database runs under a finally that closes (and saves)
    # the database, so a SIGTERM (now a KeyboardInterrupt) anywhere below persists.
    server = None
    try:
        import ida_auto

        print('Waiting for auto-analysis to complete...', file=sys.stderr)
        ida_auto.auto_wait()
        print('Analysis complete.', file=sys.stderr)

        print(f'Starting MCP server on {args.host}:{args.port}...', file=sys.stderr)
        from mcpyida.mcpserver import (
            McpServer,
            set_headless_dispatcher,
            get_ida_work_queue,
        )

        # Register the work-queue dispatcher so that run_in_ida_main routes IDA
        # API calls through the main-thread queue instead of calling directly from
        # the uvicorn thread (which IDA 9 rejects with RuntimeError).
        set_headless_dispatcher(run_on_main_thread)

        # Use McpServer for lifecycle management (threading, sockets, ports).
        # McpServer.start() calls server.create_mcp_app() internally.
        server = McpServer()
        try:
            server.start(args.host, args.port)
        except OSError as e:
            sys.exit(
                cli_status.emit_error(
                    'port_unavailable',
                    f'could not bind a port for --port {args.port!r}: {e}',
                    remediation='Pass a --port range (e.g. 6150-6159) or omit --port.',
                )
            )

        actual_port = server.port
        if actual_port is None or actual_port <= 0:
            sys.exit(
                cli_status.emit_error(
                    'internal', f'server port not assigned (got {actual_port!r})'
                )
            )

        cli_status.emit_ready(args.host, actual_port, str(binary_path))

        # Pump the IDA main-thread work queue.
        #
        # Both async tool handlers (via run_on_ida_main_async) and sync tool
        # handlers (via run_in_ida_main / run_on_main_thread) submit work items
        # here.  We execute them on the main thread and return results via
        # asyncio Future callbacks or threading.Event signals respectively.
        _work_queue = get_ida_work_queue()
        while True:
            try:
                work_item = _work_queue.get(timeout=0.1)
                work_item()
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print('Shutting down...', file=sys.stderr)
    finally:
        if server is not None:
            server.stop()
        idapro.close_database()


if __name__ == '__main__':
    main()
