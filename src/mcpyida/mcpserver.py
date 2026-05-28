# Standard Libraries
import asyncio
from datetime import (
    datetime,
    timedelta,
)
from enum import Enum
import functools
import logging
import queue as _queue_module
import socket
import struct
import sys
from threading import (
    RLock,
    Thread,
)
import time
import traceback
from typing import (
    Any,
    Callable,
    List,
)

# Third Party Libraries
from fastapi import FastAPI

# IDA Pro: per the idalib README, `idapro` MUST be imported before any
# ida_* / idaapi modules so libidalib.so loads and ${IDADIR}/python is
# put on sys.path.
try:
    import idapro  # noqa: F401  # type: ignore[import-not-found]
except ImportError:
    # idalib's `idapro` exists only in IDA 9.0+ and is only needed for the
    # external-process headless bootstrap.  In the GUI plugin, on IDA 7/8, and
    # in IDA-free environments the kernel is already up (or unused), so its
    # absence is expected and harmless.
    pass
import ida_pro  # type: ignore[import-not-found]
import idaapi  # type: ignore[import-not-found]
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from sse_starlette.sse import AppStatus
import uvicorn

from .util import (
    find_next_available_port,
    is_headless,
)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Main-thread work queue (for async headless dispatch)
#
# Lives here in mcpserver.py (not headless.py) so that run_on_ida_main_async
# and the headless main() pump loop both reference the same object.
# When headless.py runs as __main__, importing mcpyida.headless gives a
# different module instance than __main__, so any queue defined there would
# be duplicated.  Keeping the queue here avoids that problem.
# ---------------------------------------------------------------------------
_ida_work_queue: _queue_module.Queue = _queue_module.Queue()


def get_ida_work_queue() -> _queue_module.Queue:
    """Return the IDA main-thread work queue (used by headless pump loop)."""
    return _ida_work_queue


# Set by headless.py to dispatch IDA API calls to the main thread via the
# work queue.  None when running inside the IDA GUI (execute_sync is used
# instead).
_headless_dispatcher: Callable[..., Any] | None = None


def set_headless_dispatcher(dispatcher: Callable[..., Any]) -> None:
    """Register the main-thread work-queue dispatcher (called by headless.py)."""
    global _headless_dispatcher
    _headless_dispatcher = dispatcher


class ThreadedServer(uvicorn.Server):
    def __init__(self, config: uvicorn.Config, sockets: list | None = None):
        super().__init__(config)
        self._sockets = sockets

    def install_signal_handlers(self) -> None:
        # disable signal handlers
        ...

    def run(self, sockets: list | None = None) -> None:
        # Use pre-bound sockets if provided
        return super().run(sockets=self._sockets or sockets)


class MCPyIdaError(Exception): ...


def run_in_ida_main(_func=None, *, mode=idaapi.MFF_READ):
    """
    Decorator to run a function in IDA's main thread via execute_sync.
    Avoids dispatching if already in main thread.

    Usage:
        @run_in_ida_main
        @run_in_ida_main()
        @run_in_ida_main(mode=idaapi.MFF_WRITE)
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # In headless/idalib mode there is no GUI event loop so
            # execute_sync would deadlock.  IDA 9 idalib enforces that all
            # ida_* API calls happen on the main thread even in headless mode,
            # so we must dispatch to it via the work queue rather than calling
            # directly from the uvicorn thread.
            if is_headless():
                if ida_pro.is_main_thread():
                    # Already on the main thread (e.g. during startup) —
                    # execute directly.
                    try:
                        return func(*args, **kwargs)
                    except Exception as ex:
                        logger.exception('Exception in headless main-thread call')
                        raise ToolError(f'{ex}\n{traceback.format_exc()}')
                if _headless_dispatcher is not None:
                    # Dispatch to the main thread via the work queue.
                    return _headless_dispatcher(func, *args, **kwargs)
                # Dispatcher not yet registered (shouldn't happen in normal
                # operation) — attempt a direct call and let IDA reject it.
                try:
                    return func(*args, **kwargs)
                except Exception as ex:
                    logger.exception(
                        'Exception in headless direct call (no dispatcher)'
                    )
                    raise ToolError(f'{ex}\n{traceback.format_exc()}')
            if ida_pro.is_main_thread():
                # Already in main thread — execute directly
                try:
                    return func(*args, **kwargs)
                except Exception as ex:
                    logger.exception('Exception in main-thread call')
                    raise ToolError(f'{ex}\n{traceback.format_exc()}')
            else:
                # Not in main thread — dispatch via execute_sync
                result_container = []

                def inner():
                    try:
                        result_container.append(('result', func(*args, **kwargs)))
                    except Exception as ex:
                        full_traceback = traceback.format_exc()
                        logger.error(
                            'Exception in IDA main thread: %s\n%s', ex, full_traceback
                        )
                        result_container.append(('error', ex, full_traceback))
                    return 1  # must return 1 to indicate success

                idaapi.execute_sync(inner, mode)
                if not result_container:
                    return None
                item = result_container[0]
                if item[0] == 'error':
                    raise ToolError(f'{item[1]}\n{item[2]}')
                return item[1]

        return wrapper

    if _func is None:
        # Called with parentheses: @run_in_ida_main(...)
        return decorator
    else:
        # Called without parentheses: @run_in_ida_main
        return decorator(_func)


async def run_on_ida_main_async(func, *args, **kwargs):
    """Async dispatch to IDA main thread.

    In headless mode: submits work to the main-thread queue and awaits the result
    via an asyncio Future.  In GUI mode: offloads to a thread pool and uses
    idaapi.execute_sync inside that thread.
    """
    if is_headless():
        if ida_pro.is_main_thread():
            # Already on the main thread (e.g. during startup) — execute directly.
            return func(*args, **kwargs)
        # Headless: use work queue + asyncio future.
        # _ida_work_queue lives in this module (mcpserver) to avoid the
        # __main__ vs mcpyida.headless duplicate-module problem.
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()

        def work_item() -> None:
            try:
                result = func(*args, **kwargs)
                loop.call_soon_threadsafe(future.set_result, result)
            except Exception as exc:
                loop.call_soon_threadsafe(future.set_exception, exc)

        _ida_work_queue.put(work_item)
        return await future
    else:
        # GUI mode: dispatch via anyio thread pool + execute_sync inside thread.
        import anyio

        def _run_sync() -> Any:
            if ida_pro.is_main_thread():
                return func(*args, **kwargs)
            result_container: list = []

            def inner() -> int:
                try:
                    result_container.append(('ok', func(*args, **kwargs)))
                except Exception as exc:
                    result_container.append(('err', exc))
                return 1  # must return 1

            idaapi.execute_sync(inner, idaapi.MFF_READ)
            if result_container and result_container[0][0] == 'err':
                raise result_container[0][1]
            return result_container[0][1] if result_container else None

        return await anyio.to_thread.run_sync(_run_sync)


class _Skip(Exception): ...


class McpServerState(Enum):
    STOPPED = 0
    STARTING = 1
    RUNNING = 2
    STOPPING = 3
    ERROR = sys.maxsize


# Helper functions used by tools/core.py
def _normalize_processor(proc_name: str) -> str:
    """Normalize IDA processor name to standard form."""
    mapping = {
        'metapc': 'x86',
        'ARM': 'ARM',
        'MIPS': 'MIPS',
        'PPC': 'PowerPC',
        'pc': 'x86',
    }
    return mapping.get(proc_name, proc_name)


def _normalize_format(format_str: str) -> str:
    """Normalize file format to short form."""
    if 'PE' in format_str or 'Portable Executable' in format_str:
        return 'PE'
    elif 'ELF' in format_str:
        return 'ELF'
    elif 'Mach-O' in format_str:
        return 'Mach-O'
    elif 'COFF' in format_str:
        return 'COFF'
    return format_str


class McpServer:
    StartStopHandler = Callable[['McpServer', McpServerState], None]

    def __init__(
        self,
        host: str = '',
        port: int = 0,
    ) -> None:
        logger.info('McpServer init Started')

        self.host = host
        self.port: int | None = port
        self.state = McpServerState.STOPPED
        self._watchers: List[McpServer.StartStopHandler] = []
        self._lock = RLock()

        self._app: FastAPI | None = None
        self._mcp: FastMCP | None = None
        self._server_thread: Thread | None = None
        self._server: ThreadedServer | None = None
        self._socket: socket.socket | None = None
        logger.info('McpServer init done')

    def _update_state(self, state: McpServerState) -> None:
        with self._lock:
            self.state = state

            for handler in self._watchers:
                handler(self, self.state)

    def start(self, host: str | None = None, port: int | None = None) -> None:
        if self._server_thread is None:
            self._update_state(McpServerState.STARTING)

            # Pass get_port as a lambda so server://info always reflects the live port.
            # self.port is updated a few lines below after socket bind.
            from mcpyida.server import create_mcp_app

            self._app, self._mcp = create_mcp_app(get_port=lambda: self.port)

            host = host or self.host
            port = (
                port or self.port or find_next_available_port(port or self.port or 6150)
            )

            logger.info(f'Starting MCP Server on {host}:{port}')
            self.host = host
            self.port = port

            # Create socket with SO_REUSEADDR and SO_LINGER to allow immediate port reuse
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # SO_LINGER with 0 timeout forces immediate socket close (no TIME_WAIT)
            self._socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)
            )
            self._socket.bind((host, port))
            self.port = self._socket.getsockname()[
                1
            ]  # Read actual port (supports --port 0)
            self._socket.listen(100)
            self._socket.setblocking(False)

            # Don't pass host/port to config when providing pre-bound sockets
            config = uvicorn.Config(self._app, log_level='info', lifespan='on')
            self._server = ThreadedServer(config=config, sockets=[self._socket])

            self._server_thread = Thread(target=self._server.run, daemon=True)
            self._server_thread.start()
            req_time = datetime.now()
            while not self._server.started:
                time.sleep(1e-3)
                if datetime.now() - req_time > timedelta(seconds=1):
                    logger.error('Timed out waiting for server to start.')
                    self.stop()
                    return
            print(f'MCP Server started: http://{self.host}:{self.port}/mcp')
            self._update_state(McpServerState.RUNNING)
        else:
            logger.warning('MCP Server already started')

    def stop(self) -> None:
        if self._server_thread is not None and self._server is not None:
            self._update_state(McpServerState.STOPPING)
            self._server.should_exit = True
            self._server_thread.join(timeout=1.0)
            if self._server_thread.is_alive():
                self._server.force_exit = True
                self._server_thread.join(timeout=4.0)
            if self._server_thread.is_alive():
                logger.error('Could not stop MCP server.')

            # Explicitly close uvicorn server sockets to prevent defunct socket issues
            try:
                if hasattr(self._server, 'servers') and self._server.servers:
                    for server in self._server.servers:
                        if server and hasattr(server, 'close'):
                            server.close()
                            logger.debug(f'Closed server socket: {server}')
            except Exception as e:
                logger.warning(f'Error closing server sockets: {e}')

            # Explicitly close our socket to release the port
            if self._socket is not None:
                try:
                    self._socket.close()
                    logger.debug('Closed main server socket')
                except Exception as e:
                    logger.warning(f'Error closing main socket: {e}')
                finally:
                    self._socket = None

            self._server = None
            self._server_thread = None
            self._mcp = None
            # Clear the global event used internally by starlette.
            AppStatus.should_exit_event = None  # type: ignore[attr-defined]
            self._update_state(McpServerState.STOPPED)

    def add_watcher(self, watcher: StartStopHandler) -> None:
        self._watchers.append(watcher)

    def remove_watcher(self, watcher: StartStopHandler) -> None:
        try:
            self._watchers.remove(watcher)
        except ValueError:
            ...

    @property
    def running(self) -> bool:
        return (
            self._server_thread is not None
            and self._server is not None
            and self._server_thread.is_alive()
            and self._server.started
        )
