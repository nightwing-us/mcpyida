"""MCPyIDA headless MCP server.

Launch IDA headless via idalib, open a binary, run auto-analysis,
and start the MCP server. Blocks until interrupted.

Usage:
    mcpyida-headless --binary /path/to/elf [--host 127.0.0.1] [--port 6150]
    python -m mcpyida.headless --binary /path/to/elf

Prints JSON readiness signal to stdout when the server is ready:
    {"status": "ready", "host": "127.0.0.1", "port": 6150, "binary": "/path/to/elf"}

This is the contract that test harnesses and wingman CLI rely on.

Requires idapro pip package (idalib).
"""

from __future__ import annotations

import argparse
import json
import os
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCPyIDA headless MCP server',
    )
    parser.add_argument(
        '--binary',
        required=True,
        help='Path to binary file to analyze',
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind MCP server (default: 127.0.0.1)',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=6150,
        help='Port for MCP server (default: 6150, 0 for auto-assign)',
    )
    args = parser.parse_args()

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        print(f'Error: binary not found: {binary_path}', file=sys.stderr)
        sys.exit(1)

    # Check prerequisites before expensive imports.
    #
    # Headless mode is built on idalib, which was introduced in IDA Pro 9.0.
    # The `idapro` module does NOT exist in IDA 7.x/8.x — on older IDA, use the
    # GUI plugin (`mcpyida_install`) instead of headless mode.
    try:
        import idapro
    except ImportError as e:
        error_msg = str(e)
        if 'libidalib' in error_msg or 'py-activate-idalib' in error_msg:
            # idapro is importable but idalib has not been activated yet.
            print(
                'Error: idalib is not configured.\n'
                '\n'
                'Headless mode requires IDA Pro 9.0 or later (idalib). The idapro\n'
                'module is present but idalib has not been activated in this\n'
                'environment. Activate it by running the script shipped with IDA,\n'
                'in the SAME virtual environment used to run mcpyida-headless:\n'
                '  python /path/to/ida-pro-9/idalib/python/py-activate-idalib.py\n'
                '\n'
                'Full setup:\n'
                '  1. Install IDA Pro 9.0+ (https://hex-rays.com). idalib does not\n'
                '     exist in IDA 7.x/8.x — use the GUI plugin there instead.\n'
                '  2. Run py-activate-idalib.py (writes ~/.idapro/ida-config.json)\n'
                '     in the same venv as mcpyida-headless.\n'
                '  3. pip install mcpyida\n'
                '  4. mcpyida-headless --binary /path/to/elf',
                file=sys.stderr,
            )
        else:
            # The idapro module itself is missing — typically IDA older than 9.0,
            # or idalib not installed/activated in this environment.
            print(
                f'Error: could not import idapro (idalib): {e}\n'
                '\n'
                'Headless mode requires IDA Pro 9.0 or later. idalib and its\n'
                'idapro module were introduced in IDA 9.0 and do NOT exist in\n'
                'IDA 7.x or 8.x. On older IDA, use the GUI plugin (mcpyida_install)\n'
                'instead of headless mode.\n'
                '\n'
                'If you do have IDA Pro 9.0+, activate idalib in this environment:\n'
                '  python /path/to/ida-pro-9/idalib/python/py-activate-idalib.py\n'
                '\n'
                'See docs/installation.md for full setup.',
                file=sys.stderr,
            )
        sys.exit(1)

    # Signal headless mode before importing mcpserver so that is_headless()
    # returns True immediately, even if idalib doesn't set the batch flag.
    os.environ['MCPYIDA_HEADLESS'] = '1'

    # idalib must be imported first — initializes the IDA environment
    print('Starting IDA headless (idalib)...', file=sys.stderr)
    try:
        idapro.open_database(str(binary_path), run_auto_analysis=True)
    except Exception as e:
        print(f'Error: Failed to open binary: {e}', file=sys.stderr)
        sys.exit(1)

    import ida_auto

    print('Waiting for auto-analysis to complete...', file=sys.stderr)
    ida_auto.auto_wait()
    print('Analysis complete.', file=sys.stderr)

    print(f'Starting MCP server on {args.host}:{args.port}...', file=sys.stderr)
    from mcpyida.mcpserver import McpServer, set_headless_dispatcher, get_ida_work_queue

    # Register the work-queue dispatcher so that run_in_ida_main routes IDA
    # API calls through the main-thread queue instead of calling directly from
    # the uvicorn thread (which IDA 9 rejects with RuntimeError).
    set_headless_dispatcher(run_on_main_thread)

    # Use McpServer for lifecycle management (threading, sockets, port assignment).
    # McpServer.start() calls server.create_mcp_app() internally.
    server = McpServer()
    server.start(args.host, args.port)

    actual_port = server.port
    if actual_port is None or actual_port <= 0:
        print(f'Error: server port not assigned (got {actual_port!r})', file=sys.stderr)
        sys.exit(1)

    status = {
        'status': 'ready',
        'host': args.host,
        'port': actual_port,
        'binary': str(binary_path),
    }
    print(json.dumps(status), flush=True)

    # Pump the IDA main-thread work queue.
    #
    # Both async tool handlers (via run_on_ida_main_async) and sync tool
    # handlers (via run_in_ida_main / run_on_main_thread) submit work items
    # here.  We execute them on the main thread and return results via
    # asyncio Future callbacks or threading.Event signals respectively.
    _work_queue = get_ida_work_queue()
    try:
        while True:
            try:
                work_item = _work_queue.get(timeout=0.1)
                work_item()
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print('Shutting down...', file=sys.stderr)
        server.stop()
    finally:
        idapro.close_database()


if __name__ == '__main__':
    main()
