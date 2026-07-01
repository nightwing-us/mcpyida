"""MCP server lifecycle and tool/resource registration.

This module is the registration layer that connects the extracted tool functions
in tools/ to FastMCP. It uses a McpToolRegistration class to preserve type
annotations for FastMCP schema generation (bare closures lose annotations).

Usage::

    from mcpyida.server import create_mcp_app

    app, mcp = create_mcp_app()
"""

import asyncio
import contextvars
import functools
import importlib.util
import inspect
import logging
import os
import queue
import re
import sys
import time
import typing
from contextlib import asynccontextmanager
from typing import (
    Annotated,
    Any,
)

from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError
from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
)
from pydantic import Field
from starlette.middleware.cors import CORSMiddleware

import anyio

from mcpyida.rpc_callbacks import (
    CallbackScope,
    RPCDisconnectedError,
    RPCError,
    RPCNamespace,
    RPCTimeoutError,
    ToolNamespace,
    generate_callback_function,
    is_name_safe,
    map_exception,
    project_name,
)
from mcpyida.rpc_types import (
    CallFunctionException,
    CallFunctionResult,
    FunctionDefinition,
    ListFunctionsResult,
)
from mcpyida.tools import analysis, core, modify, scripting, search
from mcpyida.tools import types as type_tools
from mcpyida.dispatch import single_or_batch, unwrap


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Context threading via contextvars
# ---------------------------------------------------------------------------

_current_mcp_context: contextvars.ContextVar = contextvars.ContextVar(
    '_current_mcp_context', default=None
)

# Module-level batch state for IDA (cleared around each tool call batch).
# IDA tools dispatch sync work to the main thread; they cannot await directly.
# The async registration methods below clear this before each tool call and
# pass the reference down via _current_ida_batch_state.
_ida_batch_state: dict = {}


def get_current_context():
    """Return the MCP Context for the current request, or None."""
    return _current_mcp_context.get()


async def elicit_confirmation(description: str, batch_state: dict) -> bool:
    """Ask the MCP client for user confirmation via elicitation.

    Returns True to proceed, False to skip.
    Handles batch 'apply_to_all' state and falls back to auto-allow when
    elicitation is unsupported by the client or SDK.
    """
    # Check batch cache — if a previous item's 'apply_to_all' was set, use it.
    if batch_state.get('apply_to_all_decision') is not None:
        return batch_state['apply_to_all_decision']

    ctx = get_current_context()
    if ctx is None:
        return True  # No context — auto-allow

    from mcpyida.models import ConfirmAction

    try:
        result = await ctx.elicit(
            message=description,
            schema=ConfirmAction,
        )
    except Exception:
        # Client doesn't support elicitation or SDK version too old — auto-allow
        return True

    if result.action == 'accept':
        data = result.data
        if data is not None and data.apply_to_all:
            batch_state['apply_to_all_decision'] = data.confirm
        return data.confirm if data is not None else True

    # 'decline' or 'cancel' — skip this item
    return False


def elicit_confirmation_sync(description: str, batch_state: dict) -> bool:
    """Sync bridge for calling elicit_confirmation from IDA main thread.

    The IDA main thread is blocked waiting for the result of work dispatched
    via run_on_ida_main_async.  The asyncio event loop is running on the uvicorn
    thread, so we can use run_coroutine_threadsafe to call back into it.

    Falls back to True (auto-allow) if the event loop is not available.
    """
    # Fast path: batch decision already set
    if batch_state.get('apply_to_all_decision') is not None:
        return batch_state['apply_to_all_decision']

    ctx = get_current_context()
    if ctx is None:
        return True

    try:
        loop = asyncio.get_event_loop()
        if loop is None or not loop.is_running():
            return True
        future = asyncio.run_coroutine_threadsafe(
            elicit_confirmation(description, batch_state), loop
        )
        return future.result(timeout=60)
    except Exception:
        return True


# ---------------------------------------------------------------------------
# RPC Callbacks — state, low-level helpers, function discovery
# ---------------------------------------------------------------------------

# Module-level cache: set once per server process after the first successful
# mcpy/listFunctions round-trip.  None = not yet discovered; a populated
# RPCNamespace = discovery succeeded; empty RPCNamespace with is_available()==False
# but _rpc_functions_discovered==True = client does not support the capability.
#
# _rpc_session_id tracks the id() of the session that populated the cache.
# If a new session connects (different id), the cache is invalidated.
_rpc_namespace: RPCNamespace | None = None
_rpc_functions_discovered: bool = False
_rpc_session_id: int | None = None

# Snapshot isolation state: a script execution holds the function list snapshot.
# If the client sends notifications/mcpy/functions/list_changed mid-execution,
# the update is deferred until the script completes.
_rpc_update_deferred: bool = False
_script_executing: bool = False


def _reset_rpc_discovery() -> None:
    """Reset module-level discovery cache (used by tests and server restart)."""
    global _rpc_namespace, _rpc_functions_discovered, _rpc_session_id
    global _rpc_update_deferred, _script_executing
    _rpc_namespace = None
    _rpc_functions_discovered = False
    _rpc_session_id = None
    _rpc_update_deferred = False
    _script_executing = False


def _on_functions_changed() -> None:
    """Called when the client notifies that the function list has changed.

    If a script is currently executing, the update is deferred until the script
    completes (snapshot isolation — we do not mutate the function list mid-execution).
    If no script is running, the cache is invalidated immediately so that the next
    tool call re-discovers functions.
    """
    global _rpc_update_deferred, _rpc_functions_discovered
    if _script_executing:
        _rpc_update_deferred = True  # defer until script ends
    else:
        _rpc_functions_discovered = False  # invalidate cache immediately


async def _send_custom_request(
    session: Any,
    method: str,
    params: dict[str, Any],
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Send an arbitrary JSON-RPC request through the MCP session transport.

    The MCP SDK's session.send_request() only accepts typed ServerRequest
    objects (PingRequest, CreateMessageRequest, …).  Our custom methods
    (mcpy/listFunctions, mcpy/callFunction) are not in that union, so we
    bypass the typed path and construct a JSONRPCRequest directly, then
    register a response stream exactly as the SDK does internally.

    Args:
        session: A ServerSession (or any BaseSession with _write_stream /
                 _response_streams / _request_id attributes).
        method:  The JSON-RPC method name, e.g. 'mcpy/listFunctions'.
        params:  The params dict (will be embedded verbatim).
        timeout: How long to wait for the response, in seconds.

    Returns:
        The result dict from the JSON-RPC response.

    Raises:
        McpError:    If the peer returns a JSON-RPC error.
        TimeoutError: If the response is not received within *timeout* seconds.
    """
    # NOTE: Safe under single-threaded asyncio — no await between read and write.
    # Mirrors the SDK's own send_request() pattern.
    request_id: int = session._request_id
    session._request_id = request_id + 1

    response_stream, response_stream_reader = anyio.create_memory_object_stream(1)
    session._response_streams[request_id] = response_stream

    try:
        jsonrpc_request = JSONRPCRequest(
            jsonrpc='2.0',
            id=request_id,
            method=method,
            params=params,
        )
        await session._write_stream.send(
            SessionMessage(message=JSONRPCMessage(jsonrpc_request))
        )

        with anyio.fail_after(timeout):
            response_or_error = await response_stream_reader.receive()

        if isinstance(response_or_error, JSONRPCError):
            raise McpError(response_or_error.error)

        # response_or_error is a JSONRPCResponse; .result is the payload dict
        result = response_or_error.result
        if result is None:
            return {}
        if isinstance(result, dict):
            return result
        # Pydantic model or other — convert to dict
        return dict(result)

    finally:
        session._response_streams.pop(request_id, None)
        await response_stream.aclose()
        await response_stream_reader.aclose()


def _noop() -> None:
    """No-op sentinel pushed onto the IDA work queue to wake the RPC pump."""
    return None


def _make_sync_caller_ida(
    session: Any,
    scope: CallbackScope,
    event_loop: asyncio.AbstractEventLoop,
) -> Any:
    """Create a sync rpc_caller for IDA — pumps the work queue while waiting.

    IDA scripts run on the IDA main thread (dispatched by run_on_ida_main_async).
    We cannot use anyio.from_thread.run() here because the main thread is not
    inside an anyio thread pool.  Instead we:

    1. Submit the async _async_call coroutine to the event loop via
       asyncio.run_coroutine_threadsafe().
    2. Pump the IDA work queue while waiting so that other IDA-main-thread
       work items dispatched by the async layer can complete (avoids deadlock).
    3. Respect the per-call timeout.

    Args:
        session:    The live ServerSession for this tool call.
        scope:      The CallbackScope for this execution.
        event_loop: The running asyncio event loop (captured from the async context
                    before dispatching to the IDA main thread).

    Returns:
        A synchronous callable(name, arguments, timeout) -> Any that sends
        mcpy/callFunction and returns the result.content value.
    """

    async def _async_call(name: str, arguments: dict[str, Any], timeout: float) -> Any:
        scope.check()  # raises RuntimeError if expired
        try:
            raw = await _send_custom_request(
                session,
                'mcpy/callFunction',
                {'name': name, 'arguments': arguments or {}},
                timeout=timeout,
            )
        except TimeoutError:
            raise RPCTimeoutError(f'Callback {name!r} timed out after {timeout}s')
        except McpError as exc:
            raise RPCError(f'MCP error calling {name!r}: {exc}') from exc
        except (ConnectionError, OSError, EOFError) as exc:
            raise RPCDisconnectedError(
                f'Lost connection calling {name!r}: {exc}'
            ) from exc

        # Check for a server-side exception embedded in the response.
        if isinstance(raw, dict) and raw.get('exception'):
            exc_data = CallFunctionException.model_validate(raw['exception'])
            raise map_exception(exc_data.type, exc_data.message, exc_data.traceback)

        result = CallFunctionResult.model_validate(raw)
        return result.content

    def sync_call(name: str, arguments: dict[str, Any], timeout: float) -> Any:
        scope.check()  # fail fast before bridging to the event loop

        from mcpyida.mcpserver import _ida_work_queue

        future = asyncio.run_coroutine_threadsafe(
            _async_call(name, arguments, timeout), event_loop
        )

        # Wake the pump the instant the callback response lands instead of
        # waiting out the poll interval. The no-op sentinel is drained by this
        # loop's next get() (or a later sync_call / the headless pump) — harmless.
        future.add_done_callback(lambda _f: _ida_work_queue.put(_noop))

        deadline = time.monotonic() + timeout
        while not future.done():
            try:
                work = _ida_work_queue.get(timeout=0.1)
                work()
            except queue.Empty:
                pass
            if time.monotonic() > deadline:
                future.cancel()
                raise RPCTimeoutError(f'Callback {name!r} timed out after {timeout}s')

        return future.result()

    return sync_call


async def _discover_rpc_functions(session: Any) -> RPCNamespace | None:
    """Check client capability and discover callback functions.

    Sends mcpy/listFunctions on the first call and caches the result.
    Subsequent calls return the cached namespace immediately (unless the
    session identity has changed, in which case the cache is invalidated).

    Args:
        session: A live ServerSession obtained from the MCP Context.

    Returns:
        Populated RPCNamespace if the client supports mcpy/rpcCallbacks,
        otherwise None.
    """
    global _rpc_namespace, _rpc_functions_discovered, _rpc_session_id

    # Invalidate cache if a different session connected.
    current_id = id(session)
    if _rpc_session_id != current_id:
        _rpc_functions_discovered = False
        _rpc_namespace = None
        _rpc_session_id = current_id

    if _rpc_functions_discovered:
        return _rpc_namespace

    # Check whether the client declared mcpy/rpcCallbacks experimental capability.
    try:
        client_params = session.client_params
        caps = client_params.capabilities if client_params else None
        experimental = caps.experimental if caps else None
        if not experimental or 'mcpy/rpcCallbacks' not in experimental:
            _rpc_functions_discovered = True
            _rpc_namespace = None
            return None
    except Exception:
        _rpc_functions_discovered = True
        _rpc_namespace = None
        return None

    # Fetch the function list from the client, following pagination cursors.
    try:
        all_functions: list[FunctionDefinition] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {}
            if cursor:
                params['cursor'] = cursor
            raw = await _send_custom_request(session, 'mcpy/listFunctions', params)
            result = ListFunctionsResult.model_validate(raw)
            all_functions.extend(result.functions)
            if not result.nextCursor:
                break
            cursor = result.nextCursor
    except Exception as exc:
        logger.warning('mcpy/listFunctions failed: %s', exc)
        # Don't cache failure — allow retry on next tool call.
        return None

    namespace = RPCNamespace()
    functions: dict[str, Any] = {}
    definitions: dict[str, FunctionDefinition] = {}

    # Build generated callback wrappers.  We use a temporary scope; the real
    # per-execution scope will be created in idapython_eval and injected into
    # the script globals at that point.  The wrappers stored in the namespace
    # are regenerated per-execution — this discovery step only records which
    # functions exist so we know their definitions.
    for defn in all_functions:
        # Raw-name denylist check (flat names). Nested `__` names are projected and
        # escaped per-segment later in _build_rpc_globals via project_name().
        if not is_name_safe(defn.name):
            logger.warning('Skipping unsafe callback function name: %r', defn.name)
            continue
        definitions[defn.name] = defn

    namespace.update_functions(functions, definitions)
    _rpc_namespace = namespace
    _rpc_functions_discovered = True
    return namespace


def _install_rpc_path(
    roots: dict[str, Any],
    path: list[str],
    fn: Any,
) -> bool:
    """Insert callable *fn* into the nested namespace tree at *path*.

    All but the last segment are namespace levels (auto-created as
    ToolNamespace); the last segment is the callable leaf. Returns ``False``
    and installs nothing on a conflict:

    - a namespace segment is already bound to a callable (cannot nest under it)
    - the leaf slot is already occupied (by a namespace or another callable)

    Args:
        roots: Top-level mapping (name -> ToolNamespace | callable).
        path: Attribute path segments (length >= 1).
        fn: The callback wrapper to bind at the leaf.

    Returns:
        True if installed, False on conflict.
    """
    *ns_segs, leaf = path
    children = roots
    prefix: list[str] = []
    for seg in ns_segs:
        prefix.append(seg)
        node = children.get(seg)
        if node is None:
            node = ToolNamespace('.'.join(prefix))
            children[seg] = node
        elif not isinstance(node, ToolNamespace):
            return False  # a callable occupies this path — cannot nest under it
        children = node._children
    if leaf in children:
        return False  # leaf slot already taken (namespace or duplicate callable)
    children[leaf] = fn
    return True


def _shadows_real_module(name: str) -> bool:
    """True if *name* names an importable module/package.

    A projected faux top-level with such a name would shadow the real module in
    the script's import machinery (see the REPL ``__import__`` support in
    scripting.py), so it must be escaped. ``mcp`` is the one blessed exception:
    the real MCP SDK is never used inside the idapython REPL, so ``mcp.*`` is the
    intended faux import root.
    """
    if name == 'mcp':
        return False
    if name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _top_level_collides(name: str, existing_globals: dict[str, Any]) -> bool:
    """A projected top-level *name* is unsafe if it would shadow a Python
    builtin/keyword, an existing scripting global, or an importable module."""
    return not is_name_safe(name, existing_globals) or _shadows_real_module(name)


def _build_rpc_globals(
    namespace: RPCNamespace,
    session: Any,
    scope: CallbackScope,
    existing_globals: dict[str, Any],
    event_loop: asyncio.AbstractEventLoop | None = None,
    roots: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate per-execution callback globals from a discovered RPCNamespace.

    Projects ``__``-separated function names into nested ToolNamespace objects
    (``mcp__ghidra1__list`` -> ``mcp.ghidra1.list``). Names with no separator
    are injected as flat globals. The top-level segment is the only real
    global; if it would shadow an existing global / builtin / keyword it is
    escaped with a leading underscore (skipped only if the escaped name also
    collides). Functions are processed in sorted name order so leaf-vs-namespace
    conflicts resolve deterministically (first claim wins).

    Args:
        namespace:        The cached RPCNamespace populated by _discover_rpc_functions.
        session:          The ServerSession for this tool call.
        scope:            The CallbackScope for this execution.
        existing_globals: The current script globals (used for collision detection).
        event_loop:       The asyncio event loop for the IDA sync caller bridge.
        roots:            If provided, reverse-RPC entries are merged into it so that
                          mcp.self.* and mcp.<other>.* share one `mcp` root.

    Returns:
        A dict of top-level name -> object (ToolNamespace or callable) to merge
        into the script globals.  The caller removes these same keys when the
        tool execution ends.
    """
    if roots is None:
        roots = {}
    rpc_caller = _make_sync_caller_ida(session, scope, event_loop)  # type: ignore[arg-type]

    for name in sorted(namespace._definitions.keys()):
        defn = namespace._definitions[name]
        path = project_name(name)
        if path is None:
            logger.warning('Skipping RPC callback %r: no usable name segments', name)
            continue

        # The top-level segment is the only real global; escape it if it would
        # shadow an existing global, builtin, or keyword.
        top = path[0]
        if _top_level_collides(top, existing_globals):
            escaped = '_' + top
            if _top_level_collides(escaped, existing_globals):
                logger.warning(
                    'Skipping RPC callback %r: top-level name %r collides with an '
                    'existing global, builtin, or importable module',
                    name,
                    top,
                )
                continue
            top = escaped
        path = [top, *path[1:]]

        if path[:2] == ['mcp', 'self']:
            logger.warning(
                'Skipping RPC callback %r: mcp.self.* is reserved for in-process tools',
                name,
            )
            continue

        fn = generate_callback_function(defn, rpc_caller, scope, namespace)
        # help()/pydoc shows __name__; use the projected dotted path so
        # help(mcp.ghidra1.list) reads 'mcp.ghidra1.list(...)' rather than the
        # raw 'mcp__ghidra1__list'. The wire call still uses the original name
        # (captured in the wrapper's closure, unaffected by __name__).
        _dotted = '.'.join(path)
        fn.__name__ = _dotted
        fn.__qualname__ = _dotted
        if not _install_rpc_path(roots, path, fn):
            logger.warning(
                'Skipping RPC callback %r: path %r conflicts with an existing namespace or function',
                name,
                '.'.join(path),
            )

    return roots


# Tools NOT projected into mcp.self.* (the code-exec tool would just nest exec).
_SELF_EXCLUDED_TOOLS: frozenset[str] = frozenset({'idapython'})


def _drive_coro_sync(coro: Any) -> Any:
    """Run *coro* to completion on the current thread and return its result.

    Used to call an async tool coroutine from synchronous script code that runs
    on the IDA main thread. Safe because run_on_ida_main_async short-circuits to
    a direct synchronous call on the main thread, so the coroutine's awaits
    resolve in-line without needing the server's event loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass  # no running loop on this thread — safe to drive synchronously
    else:
        raise RuntimeError(
            '_drive_coro_sync must not be called while an event loop is running '
            'on this thread (expected: the IDA main thread, which has none)'
        )
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_self_tool_wrapper(bound_method: Any) -> Any:
    """Wrap an async McpToolRegistration method as a sync in-process callable."""

    def _wrapper(*args: Any, **kwargs: Any) -> Any:
        return _drive_coro_sync(bound_method(*args, **kwargs))

    _wrapper.__name__ = getattr(bound_method, '__name__', 'tool')
    _wrapper.__qualname__ = _wrapper.__name__
    _wrapper.__doc__ = getattr(bound_method, '__doc__', None)
    return _wrapper


# Always-injected by scripting._idapython_eval_sync (mcp.self.* is available
# regardless of whether the client supports reverse-RPC callbacks).
def _build_self_globals() -> dict[str, Any]:
    """Build {'mcp': ToolNamespace} exposing this server's own tools as
    mcp.self.<tool>(), dispatched in-process (no reverse-RPC).

    Enumerates McpToolRegistration.iter_tools(), skips _SELF_EXCLUDED_TOOLS,
    and binds each tool to an in-process sync wrapper.

    Tools are invoked without an MCP Context, so confirmation elicitation is bypassed
    (auto-allow) — acceptable because scripts already have full in-process IDA access.
    """
    registration = McpToolRegistration()
    self_ns = ToolNamespace('mcp.self')
    for method_name, tool_name, _annotations, _is_readonly in registration.iter_tools():
        if tool_name in _SELF_EXCLUDED_TOOLS:
            continue
        bound = getattr(registration, method_name)
        self_ns._children[tool_name] = _make_self_tool_wrapper(bound)

    mcp_root = ToolNamespace('mcp')
    mcp_root._children['self'] = self_ns
    return {'mcp': mcp_root}


def _declare_rpc_capability(mcp: FastMCP) -> None:
    """Patch the low-level MCP server to advertise mcpy/rpcCallbacks capability.

    FastMCP calls ``_mcp_server.create_initialization_options()`` internally
    each time it starts a new transport session.  We wrap that method to inject
    ``mcpy/rpcCallbacks: {}`` into the ``experimental_capabilities`` dict so
    that every client handshake includes the capability declaration.

    Args:
        mcp: The FastMCP instance created in create_mcp_app().
    """
    low_level = mcp._mcp_server
    original = low_level.create_initialization_options

    @functools.wraps(original)
    def _patched(notification_options=None, experimental_capabilities=None):
        caps = dict(experimental_capabilities) if experimental_capabilities else {}
        caps.setdefault('mcpy/rpcCallbacks', {})
        return original(
            notification_options=notification_options,
            experimental_capabilities=caps,
        )

    low_level.create_initialization_options = _patched  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# mcpy/ notification routing (receive side)
# ---------------------------------------------------------------------------
#
# The MCP SDK validates every inbound notification against ClientNotification
# (a closed discriminated union). ``notifications/mcpy/*`` is not in that union,
# so the SDK's _receive_loop raises a validation error, logs a warning, and
# DROPS the notification — _on_functions_changed() never fires. We intercept
# mcpy/ notifications BEFORE that validation by wrapping the ServerSession read
# stream: mcpy/ notifications are routed to our handler and never reach the
# validator; all other messages pass through untouched.


def _route_mcpy_notification(method: str, root: Any) -> None:
    """Dispatch an inbound ``notifications/mcpy/*`` notification."""
    if method == 'notifications/mcpy/functions/list_changed':
        logger.debug('[rpc] received mcpy functions/list_changed')
        _on_functions_changed()
    else:
        logger.debug('[rpc] ignoring unknown mcpy notification: %s', method)


class _McpyNotificationReadFilter:
    """Wraps a ServerSession read stream, extracting ``notifications/mcpy/*``.

    Matching notifications are routed via *on_mcpy* and NOT yielded (so they
    never reach the SDK's ClientNotification validator). Every other message is
    passed through unchanged. Non-iteration attributes delegate to the wrapped
    stream so the session can still close/manage it.
    """

    def __init__(
        self, inner: Any, on_mcpy: 'typing.Callable[[str, Any], None]'
    ) -> None:
        self._inner = inner
        self._on_mcpy = on_mcpy
        self._it = inner.__aiter__()

    def __aiter__(self) -> '_McpyNotificationReadFilter':
        return self

    async def __aenter__(self) -> '_McpyNotificationReadFilter':
        # BaseSession._receive_loop does `async with self._read_stream`. Async-CM
        # dunders are resolved on the type, bypassing __getattr__, so these MUST
        # live on the class — delegate to the wrapped stream and keep filtering.
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc_info: Any) -> Any:
        return await self._inner.__aexit__(*exc_info)

    async def __anext__(self) -> Any:
        while True:
            msg = await self._it.__anext__()  # raises StopAsyncIteration at end
            root = getattr(getattr(msg, 'message', None), 'root', None)
            method = getattr(root, 'method', None)
            if (
                isinstance(root, JSONRPCNotification)
                and isinstance(method, str)
                and method.startswith('notifications/mcpy/')
            ):
                try:
                    self._on_mcpy(method, root)
                except Exception:
                    logger.debug('mcpy notification handler error', exc_info=True)
                continue
            return msg

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _install_mcpy_notification_routing() -> None:
    """Patch ServerSession to route inbound mcpy/ notifications.

    Wraps each new ServerSession's read stream with _McpyNotificationReadFilter.
    Idempotent. Pinned SDK seam: mcp.server.session.ServerSession.__init__
    (read_stream is its first positional arg).
    """
    import mcp.server.session as _ss

    if getattr(_ss.ServerSession, '_mcpy_routing_installed', False):
        return

    _orig_init = _ss.ServerSession.__init__

    @functools.wraps(_orig_init)
    def _patched_init(self: Any, read_stream: Any, *args: Any, **kwargs: Any) -> None:
        read_stream = _McpyNotificationReadFilter(read_stream, _route_mcpy_notification)
        _orig_init(self, read_stream, *args, **kwargs)

    _ss.ServerSession.__init__ = _patched_init  # type: ignore[method-assign]
    _ss.ServerSession._mcpy_routing_installed = True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Resource wrapper helper
# ---------------------------------------------------------------------------


def _make_resource_wrapper(fn: Any, uri_params: set[str]) -> Any:
    """Create a wrapper that exposes only URI template parameters for resource registration.

    FastMCP >= 1.25.0 validates that resource function parameters match URI
    template parameters exactly. This wrapper strips extra params not in the URI
    and eagerly resolves string annotations so pydantic TypeAdapter can build the
    JSON schema without needing access to this module's namespace.
    """
    sig = inspect.signature(fn)
    new_params = [p for name, p in sig.parameters.items() if name in uri_params]
    new_sig = sig.replace(parameters=new_params)

    @functools.wraps(fn)
    def wrapper(**kwargs: Any) -> Any:
        return fn(**kwargs)

    wrapper.__signature__ = new_sig  # type: ignore[attr-defined]

    try:
        underlying = inspect.unwrap(fn)
        globalns = getattr(underlying, '__globals__', {})
        resolved = typing.get_type_hints(underlying, globalns=globalns)
        wrapper.__annotations__ = resolved
    except Exception:
        pass

    return wrapper


# ---------------------------------------------------------------------------
# McpToolRegistration class
# ---------------------------------------------------------------------------


class McpToolRegistration:
    """Registration class that preserves type annotations for FastMCP.

    Using a class instead of bare closures ensures that FastMCP can introspect
    method signatures to generate correct tool schemas. Bare closures lose their
    annotations, resulting in untyped schema parameters.

    The standalone tool functions in tools/ remain independently testable.
    This class is purely the wiring layer — it delegates all logic.
    """

    def iter_tools(self) -> list[tuple[str, str, dict[str, Any], bool]]:
        """Return (method_name, tool_name, annotations, is_readonly) tuples.

        is_readonly=True means the tool will be skipped when
        MCPY_DISABLE_READONLY_TOOLS=1 is set.
        """
        return [
            # Core read-only tools
            ('list_entries', 'list', {'readOnlyHint': True}, True),
            ('cursor', 'cursor', {'readOnlyHint': True}, True),
            ('context', 'context', {'readOnlyHint': True}, True),
            ('funcs', 'funcs', {'readOnlyHint': True}, True),
            # Analysis read-only tools
            ('decompile', 'decompile', {'readOnlyHint': True}, True),
            ('disasm', 'disasm', {'readOnlyHint': True}, True),
            ('symbols', 'symbols', {'readOnlyHint': True}, True),
            ('xrefs', 'xrefs', {'readOnlyHint': True}, True),
            # Modify tools (write)
            ('rename', 'rename', {}, False),
            ('update_vars', 'update_vars', {}, False),
            ('set_comments', 'set_comments', {}, False),
            ('get_comment', 'get_comment', {'readOnlyHint': True}, True),
            ('set_prototype', 'set_prototype', {}, False),
            ('patch', 'patch', {'destructiveHint': True}, False),
            # begin_trans/end_trans omitted — IDA has no explicit transactions
            # Type tools
            ('type_info', 'type_info', {'readOnlyHint': True}, True),
            ('create_struct', 'create_struct', {}, False),
            ('add_field', 'add_field', {}, False),
            # Scripting
            ('idapython_eval', 'idapython', {'executesCode': True}, False),
            # Search tools
            ('find_bytes', 'find_bytes', {'readOnlyHint': True}, True),
            ('find_insns', 'find_insns', {'readOnlyHint': True}, True),
            # CFG tools
            ('cfg', 'cfg', {'readOnlyHint': True}, True),
            ('callgraph', 'callgraph', {'readOnlyHint': True}, True),
        ]

    # --- Core tools ---

    async def list_entries(
        self,
        entry_type: Annotated[
            str,
            Field(
                description=(
                    'Type of entry to list. '
                    'Valid values: function, memory_segment, import, export, string, class, namespace, type'
                )
            ),
        ],
        offset: Annotated[
            int, Field(description='Pagination offset (default 0)', ge=0)
        ] = 0,
        limit: Annotated[
            int, Field(description='Max items to return (default 500)', ge=1, le=10000)
        ] = 500,
        match_filter: Annotated[
            str,
            Field(
                description=(
                    'Optional substring filter on the name (functions, strings, and types only)'
                )
            ),
        ] = '',
    ) -> Any:
        """Get a paginated list of binary entries by type.

        RETURNS: ListResult with items[], page_info (has_more, next_offset), total_count

        VALID entry_type VALUES: function, memory_segment, import, export, string, class, namespace, type

        EXAMPLES:
        - list(entry_type='function') -> first 500 functions
        - list(entry_type='function', limit=50) -> first 50 functions
        - list(entry_type='function', offset=100, limit=50) -> functions 100-149
        - list(entry_type='string', match_filter='error', limit=20) -> strings containing 'error'
        - list(entry_type='type', match_filter='stream') -> types matching 'stream'"""
        # entry_type is validated by FastMCP from the JSON-schema enum at
        # request time; cast here to match core.list_entries' Literal type.
        return await core.list_entries(
            entry_type=entry_type,  # type: ignore[arg-type]
            offset=offset,
            limit=limit,
            match_filter=match_filter,
        )

    async def cursor(self) -> Any:
        """Get the address and function info at the user's current cursor position in IDA.

        RETURNS: CurrentLocation with:
        - addr: Current hex address (e.g., "0x401000")
        - function: FunctionInfo if cursor is inside a function (name, entrypoint, signature), or null

        USE CASE: Find where the user is looking before taking contextual actions."""
        return await core.cursor()

    async def context(self) -> Any:
        """Get comprehensive context about the currently open binary.

        RETURNS: BinaryContext with complete information about:
        - current_location: Cursor position and current function
        - program: Binary file details (path, format, size, hash)
        - architecture: Processor, bitness, endianness
        - memory: Address space layout (base, entry point, min/max)
        - analysis: Database path, function count, symbols, analysis state
        - application: RE application name and version"""
        return await core.context()

    async def funcs(
        self,
        items: Annotated[
            list[str] | None,
            Field(
                description=(
                    'Batch mode: list of addresses or function names. For one function, '
                    'omit items and pass target directly.'
                )
            ),
        ] = None,
        *,
        target: Annotated[
            str | None, Field(description='Single mode: hex address or function name.')
        ] = None,
    ) -> Any:
        """Get function info by address or name.

        Single: pass target directly (returns one result).
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with name,
        entrypoint, signature (on success) or error (on failure)."""
        items, single = single_or_batch(
            items,
            {'target': target},
            kind='scalar',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await core.get_funcs(items), single)

    # --- Analysis tools ---

    async def decompile(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {addr?, name?}. For a single function, omit '
                    'items and pass addr/name directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: function address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(description='Single mode: function name.')
        ] = None,
    ) -> Any:
        """Decompile function(s). Returns C pseudocode with function comment prepended.

        Single: pass addr/name directly (returns one result).
        Batch: pass items=[{addr?, name?}, ...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - code: decompiled C pseudocode (on success)
        - name: resolved function name
        - entrypoint: function entry point (hex)
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items,
            {'addr': addr, 'name': name},
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.decompile(items), single)

    async def disasm(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {addr?, name?, count?}. For one target, omit '
                    'items and pass addr/name/count directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(description='Single mode: function name.')
        ] = None,
        count: Annotated[
            int | None,
            Field(description='Single mode: instruction count (address mode).'),
        ] = None,
    ) -> Any:
        """Disassemble function(s) or address ranges.

        Single: pass addr/name/count directly (returns one result).
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - asm: disassembly text (on success)
        - addr: resolved address
        - name: function name (if function mode)
        - mode: 'function' or 'address'
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items,
            {'addr': addr, 'name': name, 'count': count},
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.disasm(items), single)

    async def symbols(
        self,
        items: Annotated[
            list[str] | None,
            Field(
                description=(
                    'Batch mode: list of hex addresses. For one address, omit items and '
                    'pass addr directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: hex address.')
        ] = None,
    ) -> Any:
        """Get symbol info for address(es).

        Single: pass addr directly (returns one result).
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: input address
        - name: symbol name (on success)
        - symbol_type: one of function, code_label, global_variable, data_label, unknown
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items,
            {'addr': addr},
            kind='scalar',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.symbols(items), single)

    async def xrefs(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {addr|name, direction?, offset?, limit?}. For '
                    'one target, omit items and pass addr/name/direction/offset/limit '
                    'directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: hex address.')
        ] = None,
        name: Annotated[
            str | None, Field(description='Single mode: function name.')
        ] = None,
        target: Annotated[
            str | None,
            Field(
                description='Single mode: legacy alias for addr/name (auto-detected).'
            ),
        ] = None,
        direction: Annotated[
            str | None, Field(description='Single mode: "to" (default) or "from".')
        ] = None,
        offset: Annotated[
            int | None, Field(description='Single mode: pagination start.')
        ] = None,
        limit: Annotated[
            int | None, Field(description='Single mode: max results.')
        ] = None,
    ) -> Any:
        """Find cross-references to/from addresses or functions.

        Single: pass addr or name (and optional direction/offset/limit) directly.
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each a flat dict
        (no ['result'] wrapper) with:
        - addr: resolved address (hex); name: echoed when provided
        - direction: 'to' or 'from'
        - items: cross-reference rows (plus summary, entry_type, page_info)
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items,
            {
                'addr': addr,
                'name': name,
                'target': target,
                'direction': direction,
                'offset': offset,
                'limit': limit,
            },
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.xrefs(items), single)

    # --- Modify tools ---

    async def rename(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {new_name, addr?, name?}. For one symbol, omit '
                    'items and pass new_name plus addr/name directly.'
                )
            ),
        ] = None,
        *,
        new_name: Annotated[
            str | None, Field(description='Single mode: new symbol name.')
        ] = None,
        addr: Annotated[
            str | None, Field(description='Single mode: symbol address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(description='Single mode: current symbol name.')
        ] = None,
        ctx: Context | None = None,
    ) -> Any:
        """Rename symbol(s). THIS MODIFIES THE IDA DATABASE.

        Single: pass new_name plus addr/name directly (returns one result).
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: resolved hex address
        - old_name: previous symbol name
        - new_name: new name applied
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items, {'new_name': new_name, 'addr': addr, 'name': name}, kind='dict'
        )
        token = _current_mcp_context.set(ctx)
        _ida_batch_state.clear()
        try:
            return unwrap(await modify.rename(items), single)
        finally:
            _current_mcp_context.reset(token)
            _ida_batch_state.clear()

    async def update_vars(
        self,
        function_name: Annotated[
            str, Field(description='Name of the function containing the variables')
        ],
        variables_to_update: Annotated[
            dict[str, dict[str, str]],
            Field(
                description=(
                    'Mapping from current variable name to {new_name?, new_type?}'
                )
            ),
        ],
        ctx: Context | None = None,
    ) -> Any:
        """Rename and/or retype multiple variables in a function at once.

        THIS MODIFIES THE IDA DATABASE.

        EXAMPLE:
          update_vars(
            function_name="main",
            variables_to_update={
              "v1": {"new_name": "buffer", "new_type": "char*"},
              "a1": {"new_name": "argc"}
            }
          )

        RETURNS: a dict {function, addr, results, error}, where each item of
        `results` is {var, new_name, new_type, error} (error null on success).
        A function-level failure sets the top-level `error` with empty `results`."""
        token = _current_mcp_context.set(ctx)
        _ida_batch_state.clear()
        try:
            return await modify.update_vars(function_name, variables_to_update)
        finally:
            _current_mcp_context.reset(token)
            _ida_batch_state.clear()

    async def set_comments(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {comment, kind?, addr?, name?, line?}. For one '
                    'comment, omit items and pass the fields directly.'
                )
            ),
        ] = None,
        *,
        comment: Annotated[
            str | None, Field(description='Single mode: comment text.')
        ] = None,
        kind: Annotated[
            str | None,
            Field(description='Single mode: "disasm"|"decompiler"|"function"|"both".'),
        ] = None,
        addr: Annotated[
            str | None, Field(description='Single mode: address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(description='Single mode: function name.')
        ] = None,
        line: Annotated[
            int | None, Field(description='Single mode: decompiler line.')
        ] = None,
        ctx: Context | None = None,
    ) -> Any:
        """Set comment(s). THIS MODIFIES THE IDA DATABASE.

        Single: pass comment plus kind/addr/name/line directly (returns one result).
        Batch: pass items=[...] (returns a list).

        kind values:
        - 'disasm'     -> EOL comment at addr (requires addr)
        - 'decompiler' -> pre-comment at line in function (requires line and addr or name)
        - 'function'   -> plate comment on function (requires addr or name)
        - 'both'       (default) -> disasm comment at addr; ALSO decompiler comment if line provided

        RETURNS: a dict (single call) or list of dicts (batch), each with kind,
        addr, message (on success) or error (on failure)."""
        items, single = single_or_batch(
            items,
            {
                'comment': comment,
                'kind': kind,
                'addr': addr,
                'name': name,
                'line': line,
            },
            kind='dict',
        )
        token = _current_mcp_context.set(ctx)
        _ida_batch_state.clear()
        try:
            return unwrap(await modify.set_comments(items), single)
        finally:
            _current_mcp_context.reset(token)
            _ida_batch_state.clear()

    async def get_comment(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {addr?, name?}. For one function, omit items '
                    'and pass addr/name directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: function address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(description='Single mode: function name.')
        ] = None,
    ) -> Any:
        """Get function plate comment(s).

        Single: pass addr/name directly (returns one result).
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - name: function name
        - addr: function entry point address
        - comment: plate comment text (may be empty string)
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items,
            {'addr': addr, 'name': name},
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await modify.get_comment(items), single)

    async def set_prototype(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {addr, prototype}. For one function, omit items '
                    'and pass addr/prototype directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: function address (hex).')
        ] = None,
        prototype: Annotated[
            str | None, Field(description='Single mode: C-style signature.')
        ] = None,
        ctx: Context | None = None,
    ) -> Any:
        """Set function prototype(s). THIS MODIFIES THE IDA DATABASE.

        Single: pass addr/prototype directly (returns one result).
        Batch: pass items=[...] (returns a list).

        The old signature is saved in the function comment for reference.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: function address
        - name: function name
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items, {'addr': addr, 'prototype': prototype}, kind='dict'
        )
        token = _current_mcp_context.set(ctx)
        _ida_batch_state.clear()
        try:
            return unwrap(await modify.set_prototype(items), single)
        finally:
            _current_mcp_context.reset(token)
            _ida_batch_state.clear()

    async def patch(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {addr, hex_bytes}. For one patch, omit items '
                    'and pass addr/hex_bytes directly.'
                )
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(description='Single mode: address (hex).')
        ] = None,
        hex_bytes: Annotated[
            str | None, Field(description='Single mode: new bytes as hex.')
        ] = None,
    ) -> Any:
        """Overwrite bytes at address(es). THIS MODIFIES THE IDA DATABASE.

        Single: pass addr/hex_bytes directly (returns one result).
        Batch: pass items=[...] (returns a list).

        BEHAVIOR: Clears existing code unit, writes bytes, re-disassembles.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: patched address
        - error: null on success, error message on failure"""
        items, single = single_or_batch(
            items, {'addr': addr, 'hex_bytes': hex_bytes}, kind='dict'
        )
        return unwrap(await modify.patch(items), single)

    async def begin_trans(
        self,
        description: Annotated[
            str, Field(description='Human-readable transaction description')
        ],
    ) -> Any:
        """Start a manual transaction for multiple modifications.

        RETURNS: Transaction ID string needed to end the transaction.

        WHEN TO USE:
        - Most modification tools handle transactions internally
        - Only use manual transactions when making MULTIPLE modifications that should be atomic

        EXAMPLE:
          tx = begin_trans("Rename related functions")
          rename(...)
          end_trans(tx, commit=True)"""
        return modify.begin_trans(description)

    async def end_trans(
        self,
        transaction_id: Annotated[
            str, Field(description='Transaction ID returned by begin_trans')
        ],
        commit: Annotated[
            bool, Field(description='True to commit changes, False to rollback')
        ] = True,
    ) -> Any:
        """End a manual transaction started with begin_trans.

        PARAMETERS:
        - transaction_id: ID returned from begin_trans
        - commit: True to save changes, False to discard/rollback"""
        return modify.end_trans(int(transaction_id), commit)

    # --- Type tools ---

    async def type_info(
        self,
        items: Annotated[
            list[str] | None,
            Field(
                description=(
                    'Batch mode: list of type names. For one type, omit items and pass '
                    'type_name directly.'
                )
            ),
        ] = None,
        *,
        type_name: Annotated[
            str | None,
            Field(description='Single mode: type name (short or full path).'),
        ] = None,
    ) -> Any:
        """Get detailed type info.

        Single: pass type_name directly (returns one result).
        Batch: pass items=[...] (returns a list).

        RETURNS: a dict (single call) or list of dicts (batch), each with
        TypeDetails fields (on success) or {target, error} on failure."""
        items, single = single_or_batch(
            items,
            {'type_name': type_name},
            kind='scalar',
            empty_hint='list(entry_type="type")',
        )
        return unwrap(await type_tools.type_info(items), single)

    async def create_struct(
        self,
        name: Annotated[str, Field(description="Structure name (e.g., 'request_t')")],
        size: Annotated[
            int,
            Field(description='Total size in bytes. 0 = auto-size from fields', ge=0),
        ] = 0,
        fields: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Optional initial fields: [{name, type, offset, comment?}]'
                )
            ),
        ] = None,
        packed: Annotated[
            bool, Field(description='If True, no padding between fields')
        ] = False,
    ) -> Any:
        """Create a new structure type in the IDA type database.

        RETURNS: StructureCreationResult with name, size, created flag, and message.

        EXAMPLE:
          create_struct(
              name="NetworkPacket",
              fields=[
                  {"name": "header_ptr", "type": "void *", "offset": 0},
                  {"name": "length", "type": "int", "offset": 8},
              ]
          )"""
        return await type_tools.create_struct(
            name=name, size=size, fields=fields, packed=packed
        )

    async def add_field(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Batch mode: list of {struct_name, field_name, field_type, offset, '
                    'comment?}. For one field, omit items and pass the fields directly.'
                )
            ),
        ] = None,
        *,
        struct_name: Annotated[
            str | None, Field(description='Single mode: structure name.')
        ] = None,
        field_name: Annotated[
            str | None, Field(description='Single mode: field name.')
        ] = None,
        field_type: Annotated[
            str | None, Field(description='Single mode: field type.')
        ] = None,
        offset: Annotated[
            int | None, Field(description='Single mode: field offset.')
        ] = None,
        comment: Annotated[
            str | None, Field(description='Single mode: field comment.')
        ] = None,
    ) -> Any:
        """Add field(s) to struct(s). THIS MODIFIES THE IDA DATABASE.

        Single: pass struct_name/field_name/field_type/offset directly (returns one result).
        Batch: pass items=[...] (returns a list).

        If a field already exists at the specified offset, it will be replaced.
        If the structure is not large enough, it will be expanded automatically.

        RETURNS: a dict (single call) or list of dicts (batch) with
        FieldAdditionResult fields."""
        items, single = single_or_batch(
            items,
            {
                'struct_name': struct_name,
                'field_name': field_name,
                'field_type': field_type,
                'offset': offset,
                'comment': comment,
            },
            kind='dict',
        )
        return unwrap(await type_tools.add_field(items), single)

    # --- Scripting tools ---

    async def idapython_eval(
        self,
        code: Annotated[
            str,
            Field(
                description=(
                    'Python source code to execute in the IDA Pro context. '
                    'Has access to all ida_* modules (idaapi, idc, idautils, ida_bytes, ida_funcs, '
                    'ida_hexrays, ida_kernwin, ida_name, ida_nalt, etc.) and IdaFunction helper. '
                    'Jupyter-style: last expression value is returned as result. '
                    'Variables persist between calls for the MCP server lifetime.'
                )
            ),
        ],
        reset: Annotated[
            bool,
            Field(
                description=(
                    'If True, clear the persistent session state before executing code. '
                    'Resets globals to a fresh copy of __main__.__dict__. '
                    'Use to start a clean session. Default: False.'
                )
            ),
        ] = False,
        # NOTE: must be plain `Context`, NOT `Context | None`. FastMCP's
        # context-param detection (mcp/server/fastmcp/tools/base.py) skips any
        # parameter whose annotation has a typing origin (Union/Optional), so
        # `Context | None` is never injected and arrives as None — which
        # silently disabled RPC callback discovery. Plain `Context` is detected
        # and injected; the `= None` default only covers direct/test calls.
        ctx: Context = None,  # type: ignore[assignment]
    ) -> Any:
        """Execute arbitrary Python code in the IDA Pro context.

        Runs code with all IDA Python APIs pre-imported. Captures stdout/stderr.
        Jupyter-style: if the last statement is an expression, its value is returned.
        Variables persist between calls for the MCP server lifetime.

        PRE-IMPORTED: idaapi, idc, idautils, ida_bytes, ida_funcs, ida_hexrays,
        ida_kernwin, ida_name, ida_nalt, ida_segment, ida_typeinf, IdaFunction, and
        all other ida_* modules.

        RETURNS: ScriptResult with:
        - result: last expression value (Jupyter-style eval)
        - stdout: captured print() output
        - stderr: captured error output
        - output: interleaved stdout+stderr in execution order
        - success: False if an exception occurred
        - error: exception message if failed
        - error_traceback: full traceback if failed

        EXAMPLES:
        - idapython(code='idc.get_name(0x401000)') -> function name at address
        - idapython(code='list(idautils.Functions())[:5]') -> first 5 function addresses
        - idapython(code='print(idaapi.get_imagebase())') -> image base address
        - idapython(code='x = 42') then idapython(code='x') -> result='42' (persists)
        - idapython(code='', reset=True) -> clears session state"""
        # Discover RPC callback functions on first call (cached thereafter).
        mcp_session: Any = None
        rpc_ns: RPCNamespace | None = None
        event_loop: asyncio.AbstractEventLoop | None = None

        if ctx is not None:
            try:
                mcp_session = ctx.session
                # Capture the running event loop here (async context) before we
                # dispatch to the IDA main thread where get_running_loop() would fail.
                event_loop = asyncio.get_running_loop()
                rpc_ns = await _discover_rpc_functions(mcp_session)
            except Exception as exc:
                logger.debug('RPC discovery skipped: %s', exc)

        return await scripting.idapython_eval(
            code,
            reset,
            rpc_namespace=rpc_ns,
            session=mcp_session,
            event_loop=event_loop,
        )

    # --- Search tools ---

    async def find_bytes(
        self,
        patterns: Annotated[
            list[str],
            Field(
                description=(
                    'List of byte patterns to search for. '
                    'Each pattern: space-separated hex tokens, "??" for wildcard. '
                    'Example: ["48 8B ?? ??", "55 48 89 E5"]'
                )
            ),
        ],
        limit: Annotated[
            int,
            Field(
                description='Max matches per pattern (default 1000)', ge=1, le=100000
            ),
        ] = 1000,
        offset: Annotated[
            int, Field(description='Skip first N matches per pattern (default 0)', ge=0)
        ] = 0,
    ) -> Any:
        """Search for byte patterns in the binary with wildcard support.

        Each pattern is a space-separated sequence of hex bytes, where '??' matches any byte.

        RETURNS: list of dicts per pattern, each with:
        - pattern: the input pattern string
        - items: list of {addr, bytes} dicts
        - has_more: True if results were truncated at limit
        - error: null on success, error message on failure

        EXAMPLES:
        - find_bytes(patterns=['55 48 89 E5']) -> function prologues
        - find_bytes(patterns=['48 8B ?? ??']) -> MOV reg, [reg+disp8] variants
        - find_bytes(patterns=['FF 25 ?? ?? ?? ??']) -> indirect JMPs (import calls)"""
        return await search.find_bytes(patterns=patterns, limit=limit, offset=offset)

    async def find_insns(
        self,
        sequences: Annotated[
            list[list[dict]],
            Field(
                description=(
                    'List of instruction sequences to search for. '
                    'Each sequence is a list of {mnemonic, operands?} dicts. '
                    'mnemonic: exact or glob pattern (e.g. "MOV", "J*"). '
                    'operands: list of operand patterns (glob or /regex/). '
                    'Example: [[{"mnemonic": "PUSH", "operands": ["RBP"]}, '
                    '{"mnemonic": "MOV", "operands": ["RBP", "RSP"]}]]'
                )
            ),
        ],
        limit: Annotated[
            int,
            Field(
                description='Max matches per sequence (default 1000)', ge=1, le=100000
            ),
        ] = 1000,
        offset: Annotated[
            int,
            Field(description='Skip first N matches per sequence (default 0)', ge=0),
        ] = 0,
    ) -> Any:
        """Search for consecutive instruction sequences in executable code.

        Each sequence is a list of instruction patterns with mnemonic and optional operand matchers.
        Mnemonic supports glob patterns (MOV, J*, CALL). Operands support glob and /regex/ syntax.

        RETURNS: list of dicts per sequence, each with:
        - sequence: the input sequence spec
        - items: list of {addr, instructions} dicts
        - has_more: True if results were truncated at limit
        - error: null on success, error message on failure

        EXAMPLES:
        - find_insns(sequences=[[{"mnemonic": "PUSH"}, {"mnemonic": "MOV"}]]) -> push+mov pairs
        - find_insns(sequences=[[{"mnemonic": "MOV", "operands": ["RAX", "*"]}]]) -> MOV RAX, anything
        - find_insns(sequences=[[{"mnemonic": "J*"}]]) -> all conditional/unconditional jumps"""
        return await search.find_insns(sequences=sequences, limit=limit, offset=offset)

    # --- CFG tools ---

    async def cfg(
        self,
        address: Annotated[str, Field(description='Function address (hex) or name')],
        normalize: Annotated[
            bool, Field(description='Apply cross-tool normalization')
        ] = True,
        include_bytes: Annotated[
            bool, Field(description='Include base64 raw bytes per block')
        ] = False,
        include_disassembly: Annotated[
            bool, Field(description='Include instruction list per block')
        ] = False,
    ) -> dict:
        """Extract control flow graph for a function. Returns basic blocks with successors, called functions, and strings."""
        from mcpyida.tools.cfg import cfg as cfg_impl

        result = await cfg_impl(address, normalize, include_bytes, include_disassembly)
        return result.model_dump(by_alias=True)

    async def callgraph(
        self,
        address: Annotated[
            str, Field(description='Root function address (hex) or name')
        ],
        direction: Annotated[
            str, Field(description="'callees', 'callers', or 'both'")
        ] = 'callees',
        max_depth: Annotated[int, Field(description='Maximum traversal depth')] = 5,
        max_nodes: Annotated[int, Field(description='Maximum function nodes')] = 1000,
        max_edges: Annotated[int, Field(description='Maximum call edges')] = 5000,
    ) -> dict:
        """Build call graph from a root function. Traverses call relationships with configurable depth and limits."""
        from mcpyida.tools.cfg import callgraph as callgraph_impl

        result = await callgraph_impl(
            address, direction, max_depth, max_nodes, max_edges
        )
        return result.model_dump(by_alias=True)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_tools(mcp: FastMCP) -> None:
    """Register all MCP tools by instantiating McpToolRegistration.

    Checks MCPY_DISABLE_READONLY_TOOLS environment variable: if set to '1' or
    'true', read-only (readOnlyHint) tools are not registered.
    """
    disable_readonly = os.environ.get('MCPY_DISABLE_READONLY_TOOLS', '').lower() in (
        '1',
        'true',
    )

    registration = McpToolRegistration()

    for (
        method_name,
        tool_name,
        annotations_dict,
        is_readonly,
    ) in registration.iter_tools():
        if is_readonly and disable_readonly:
            continue
        method = getattr(registration, method_name)
        # FastMCP accepts a dict for `annotations` at runtime even though
        # the type is ToolAnnotations | None; the dict is normalized
        # internally. Suppress the strict-type mismatch here.
        mcp.tool(tool_name, annotations=annotations_dict)(method)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# MCP instructions builder
# ---------------------------------------------------------------------------


def build_instructions() -> str:
    """Build the MCP instructions string for MCPyIDA.

    IDA has no Backend class — reads global IDA state directly.
    Called at server startup from create_mcp_app(). Kept under 2 KB
    (Claude Code limit).
    """
    import idaapi
    import ida_nalt

    tool_line = 'MCPyIDA MCP Server'
    try:
        ver = idaapi.get_kernel_version()
        tool_line = f'MCPyIDA (IDA {ver})'
    except Exception:
        pass

    mode = 'headless' if os.environ.get('MCPYIDA_HEADLESS') else 'gui'

    try:
        binary_name = ida_nalt.get_root_filename() or 'unknown'
        binary_path = ida_nalt.get_input_file_path() or 'unknown'
        binary_line = f'Binary: {binary_name} ({binary_path})'
    except Exception:
        binary_line = 'Binary: unknown'

    try:
        inf = idaapi.get_inf_structure()
        proc = inf.procname if hasattr(inf, 'procname') else 'unknown'
        arch_line = f'Architecture: {proc}'
    except Exception:
        arch_line = 'Architecture: unknown'

    tools = (
        'list, cursor, context, funcs, decompile, disasm, symbols, xrefs, '
        'rename, update_vars, set_comments, get_comment, set_prototype, patch, '
        'type_info, create_struct, add_field, '
        'idapython, find_bytes, find_insns, cfg, callgraph'
    )

    lines = [
        tool_line,
        f'Mode: {mode}',
        binary_line,
        arch_line,
        'Port: see server://info',
        '',
        f'Available tools: {tools}',
        '',
        'Workflow: Use cfg/callgraph for control flow. Use decompile for C pseudocode.',
        'Check server://info for live server state including port.',
    ]
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Resource registration
# ---------------------------------------------------------------------------


def register_resources(
    mcp: FastMCP,
    get_port: 'typing.Callable[[], int | None] | None' = None,
) -> None:
    """Register all MCP resources.

    Resources expose the same data as tools but are accessible via URI.
    They call the same tool functions in tools/. Resources are always
    registered regardless of MCPY_DISABLE_READONLY_TOOLS.

    Args:
        mcp: The FastMCP instance to register resources on.
        get_port: Optional callable that returns the current server port.
                  Called at request time so the port is always up-to-date.
    """

    def _register(
        uri: str,
        fn: Any,
        *,
        name: str,
        description: str,
        mime_type: str = 'application/json',
        ann: dict[str, Any] | None = None,
    ) -> None:
        uri_params = set(re.findall(r'\{(\w+)\}', uri))
        wrapped = _make_resource_wrapper(fn, uri_params)
        resource_kwargs: dict[str, Any] = {
            'name': name,
            'description': description,
            'mime_type': mime_type,
        }
        if ann is not None:
            from mcp.types import Annotations

            mcp_ann = Annotations(**ann)
            try:
                mcp.resource(uri, **resource_kwargs, annotations=mcp_ann)(wrapped)
                return
            except TypeError:
                pass
        mcp.resource(uri, **resource_kwargs)(wrapped)

    # --- Server info ---

    def _res_server_info() -> Any:
        import idaapi
        import ida_nalt

        try:
            binary_name = ida_nalt.get_root_filename() or None
            binary_path = ida_nalt.get_input_file_path() or None
        except Exception:
            binary_name = None
            binary_path = None

        try:
            inf = idaapi.get_inf_structure()
            arch = inf.procname if hasattr(inf, 'procname') else None
        except Exception:
            arch = None

        try:
            version = idaapi.get_kernel_version()
        except Exception:
            version = 'unknown'

        mode = 'headless' if os.environ.get('MCPYIDA_HEADLESS') else 'gui'
        port = get_port() if get_port is not None else None
        analysis_status = 'complete' if binary_name else 'no_binary'

        return {
            'tool': 'ida',
            'version': version,
            'mode': mode,
            'binary': binary_name,
            'binary_path': binary_path,
            'architecture': arch,
            'analysis_status': analysis_status,
            'port': port,
        }

    _register(
        'server://info',
        _res_server_info,
        name='server_info',
        description='Live server metadata: tool, version, mode, binary, architecture, port',
        ann={'audience': ['assistant'], 'priority': 1.0},
    )

    # --- Cursor ---

    async def _res_cursor() -> Any:
        return await core.cursor()

    _register(
        'ida://cursor',
        _res_cursor,
        name='cursor',
        description='Current cursor position and function info',
        ann={'audience': ['assistant'], 'priority': 1.0},
    )

    # --- Program metadata ---

    async def _res_program_metadata() -> Any:
        return await core.context()

    _register(
        'ida://program/metadata',
        _res_program_metadata,
        name='program_metadata',
        description='Binary file info, architecture, base address, hashes',
        ann={'audience': ['assistant'], 'priority': 1.0},
    )

    # --- Paginated list resources ---

    async def _res_functions(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(
            entry_type='function', offset=offset, limit=limit
        )

    _register(
        'ida://functions/{offset}/{limit}',
        _res_functions,
        name='functions',
        description='Paginated list of functions',
    )

    async def _res_segments(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(
            entry_type='memory_segment', offset=offset, limit=limit
        )

    _register(
        'ida://program/segments/{offset}/{limit}',
        _res_segments,
        name='segments',
        description='Memory segments with permissions',
    )

    async def _res_imports(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(entry_type='import', offset=offset, limit=limit)

    _register(
        'ida://imports/{offset}/{limit}',
        _res_imports,
        name='imports',
        description='Imported functions and data',
    )

    async def _res_exports(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(entry_type='export', offset=offset, limit=limit)

    _register(
        'ida://exports/{offset}/{limit}',
        _res_exports,
        name='exports',
        description='Exported symbols',
    )

    async def _res_strings(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(entry_type='string', offset=offset, limit=limit)

    _register(
        'ida://strings/{offset}/{limit}',
        _res_strings,
        name='strings',
        description='String literals found in binary',
    )

    async def _res_classes(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(entry_type='class', offset=offset, limit=limit)

    _register(
        'ida://classes/{offset}/{limit}',
        _res_classes,
        name='classes',
        description='C++ classes',
    )

    async def _res_namespaces(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(
            entry_type='namespace', offset=offset, limit=limit
        )

    _register(
        'ida://namespaces/{offset}/{limit}',
        _res_namespaces,
        name='namespaces',
        description='C++ namespaces',
    )

    # --- Search resources ---

    async def _res_search_functions(pattern: str) -> Any:
        return await core.list_entries(
            entry_type='function', offset=0, limit=500, match_filter=pattern
        )

    _register(
        'ida://search/functions/{pattern}',
        _res_search_functions,
        name='search_functions',
        description='Search functions by name substring',
    )

    async def _res_search_strings(pattern: str) -> Any:
        return await core.list_entries(
            entry_type='string', offset=0, limit=500, match_filter=pattern
        )

    _register(
        'ida://search/strings/{pattern}',
        _res_search_strings,
        name='search_strings',
        description='Search strings by content substring',
    )

    # --- Program entry points ---

    def _res_entrypoints() -> Any:
        import ida_entry

        entries: list[dict[str, Any]] = []
        try:
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or f'entry_{ordinal}'
                entries.append({
                    'ordinal': ordinal,
                    'addr': f'{ea:#x}',
                    'name': name,
                })
        except Exception:
            pass
        return entries

    _register(
        'ida://program/entrypoints',
        _res_entrypoints,
        name='entrypoints',
        description='Program entry points',
    )

    # --- Current selection ---

    def _res_selection() -> Any:
        import idc
        from mcpyida.mcpserver import is_headless

        if is_headless():
            return {'selected': False}
        sel_start = idc.read_selection_start()
        sel_end = idc.read_selection_end()
        if sel_start == idc.BADADDR:
            return {'selected': False}
        return {
            'selected': True,
            'start': f'{sel_start:#x}',
            'end': f'{sel_end:#x}',
            'size': sel_end - sel_start,
        }

    _register(
        'ida://selection',
        _res_selection,
        name='selection',
        description='Current selection range in IDA',
    )

    # --- Disasm at address (N instructions) ---

    async def _res_disasm(addr: str, count: int = 10) -> Any:
        results = await analysis.disasm([{'addr': addr, 'count': count}])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r.get('asm', '')

    _register(
        'ida://disasm/{addr}/{count}',
        _res_disasm,
        name='disasm',
        description='Disassembly starting at address for count instructions',
        mime_type='text/plain',
    )

    # --- Bytes at address ---

    async def _res_bytes(addr: str, size: int = 64) -> Any:
        """Read raw bytes from memory at addr, return as hex dump."""
        import idaapi
        import ida_bytes

        try:
            ea = int(addr, 16)
        except ValueError:
            raise ToolError(f'Invalid address: {addr}')

        hard_cap = 1 * 1024 * 1024

        def _hexdump(buf: bytes, base: int) -> str:
            width = 16 if base >= (1 << 32) else 8
            lines = []
            for i in range(0, len(buf), 16):
                chunk = buf[i : i + 16]
                left = ' '.join(f'{b:02X}' for b in chunk[:8])
                right = ' '.join(f'{b:02X}' for b in chunk[8:])
                hexcol = f'{left:<23}  {right:<23}'
                ascii_ = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                lines.append(f'{base + i:0{width}X}  {hexcol}  |{ascii_}|')
            return '\n'.join(lines)

        want = min(size, hard_cap)
        buf = bytearray()
        cur = ea
        remaining = want

        while remaining > 0:
            if not ida_bytes.is_mapped(cur):
                break
            seg = idaapi.getseg(cur)
            if not seg:
                break
            max_here = max(0, seg.end_ea - cur)
            if max_here == 0:
                break
            chunk = min(remaining, max_here)
            data = ida_bytes.get_bytes(cur, chunk)
            if data is None:
                break
            buf.extend(data)
            cur += chunk
            remaining -= chunk

        if not buf:
            raise ToolError(f'No readable bytes at {addr}')
        return _hexdump(bytes(buf), ea)

    _register(
        'ida://bytes/{addr}/{size}',
        _res_bytes,
        name='bytes',
        description='Raw bytes at address as hex dump',
        mime_type='text/plain',
    )

    # --- Xrefs to function by name or address ---

    async def _res_xrefs_to_func(identifier: str) -> Any:
        results = await analysis.xrefs([
            {'target': identifier, 'direction': 'to', 'offset': 0, 'limit': 500}
        ])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        r.pop('error', None)
        return r

    _register(
        'ida://xrefs/to-func/{identifier}',
        _res_xrefs_to_func,
        name='xrefs_to_func',
        description='Cross-references to function by name or address',
    )

    # --- Types (paginated) ---

    async def _res_types(offset: int = 0, limit: int = 500) -> Any:
        return await core.list_entries(entry_type='type', offset=offset, limit=limit)

    _register(
        'ida://types/{offset}/{limit}',
        _res_types,
        name='types',
        description='Paginated list of all types (structs, enums, typedefs)',
    )

    # --- Type info by name ---

    async def _res_type_info(type_name: str) -> Any:
        results = await type_tools.type_info([type_name])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r

    _register(
        'ida://type/{type_name}',
        _res_type_info,
        name='type_info',
        description='Detailed type info (members, values, etc.)',
    )

    # --- Function containing address ---

    async def _res_function_containing(addr: str) -> Any:
        results = await core.get_funcs([addr])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r

    _register(
        'ida://function/containing/{addr}',
        _res_function_containing,
        name='function_containing',
        description='Function containing the given address',
    )

    # --- Decompile at address ---

    async def _res_decompile(addr: str) -> Any:
        results = await analysis.decompile([{'addr': addr}])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r.get('code', '')

    _register(
        'ida://decompile/{addr}',
        _res_decompile,
        name='decompile',
        description='Decompiled pseudocode for function at address',
        mime_type='text/plain',
    )

    # --- Symbol at address ---

    async def _res_symbol(addr: str) -> Any:
        results = await analysis.symbols([addr])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r

    _register(
        'ida://symbol/{addr}',
        _res_symbol,
        name='symbol',
        description='Symbol information at address',
    )

    # --- Function disassembly at address ---

    async def _res_disasm_function(addr: str) -> Any:
        results = await analysis.disasm([{'addr': addr}])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r.get('asm', '')

    _register(
        'ida://disasm/function/{addr}',
        _res_disasm_function,
        name='disasm_function',
        description='Disassembly of entire function at address',
        mime_type='text/plain',
    )

    # --- Xrefs to/from address ---

    async def _res_xrefs_to(addr: str) -> Any:
        results = await analysis.xrefs([
            {'target': addr, 'direction': 'to', 'offset': 0, 'limit': 500}
        ])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        r.pop('error', None)
        return r

    _register(
        'ida://xrefs/to/{addr}',
        _res_xrefs_to,
        name='xrefs_to',
        description='Cross-references to address',
    )

    async def _res_xrefs_from(addr: str) -> Any:
        results = await analysis.xrefs([
            {'target': addr, 'direction': 'from', 'offset': 0, 'limit': 500}
        ])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        r.pop('error', None)
        return r

    _register(
        'ida://xrefs/from/{addr}',
        _res_xrefs_from,
        name='xrefs_from',
        description='Cross-references from address',
    )

    # --- Function comment ---

    async def _res_function_comment(addr: str) -> Any:
        results = await modify.get_comment([{'addr': addr}])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r.get('comment', '')

    _register(
        'ida://function/{addr}/comment',
        _res_function_comment,
        name='function_comment',
        description='Comment for function at address',
        mime_type='text/plain',
    )

    # ida://type/{type_name} is already registered above as 'type_info' — no duplicate needed.


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_mcp_app(
    name: str = 'ida-mcp',
    get_port: 'typing.Callable[[], int | None] | None' = None,
) -> tuple[FastAPI, FastMCP]:
    """Create FastAPI + FastMCP app with all tools and resources registered.

    Args:
        name: MCP server name exposed to clients (default 'ida-mcp').
        get_port: Optional callable that returns the current server port at
                  request time.  Passed through to register_resources() so
                  that the server://info resource can report the live port.

    Returns:
        (app, mcp) tuple where app is the FastAPI ASGI app and mcp is the
        FastMCP instance. The caller is responsible for serving app with
        uvicorn or similar.
    """
    instructions = build_instructions()
    mcp = FastMCP(name, instructions=instructions)
    _declare_rpc_capability(mcp)
    _install_mcpy_notification_routing()

    @asynccontextmanager
    async def parent_lifespan(app: FastAPI) -> Any:  # type: ignore[misc]
        mcp_app = mcp.streamable_http_app()
        async with LifespanManager(mcp_app):
            yield

    app = FastAPI(title='IDA MCP', lifespan=parent_lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=['GET', 'POST', 'OPTIONS'],
        allow_headers=['*'],
        expose_headers=['*'],
        max_age=600,
    )

    # Resources are always registered (not affected by MCPY_DISABLE_READONLY_TOOLS)
    register_resources(mcp, get_port=get_port)

    # Tools are conditionally registered
    register_tools(mcp)

    mcp_app = mcp.streamable_http_app()
    app.mount('/', mcp_app)

    return app, mcp
