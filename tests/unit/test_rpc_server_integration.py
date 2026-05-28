"""Unit tests for RPC callback integration in server.py and tools/scripting.py.

These tests do NOT require IDA Pro or a live MCP server.  All session
and transport interactions are mocked at the Python level.

Test classes:
- TestSendCustomRequest    — low-level JSON-RPC helper constructs valid request
- TestDiscoverRpcFunctions — caching, no-capability path, listFunctions parsing
- TestBuildRpcGlobals      — namespace injection, name collision, rpc key
- TestScriptingIntegration — scope created/invalidated, globals injected per exec
- TestDeclareRpcCapability — experimental capabilities patched on low-level server
- TestMakeSyncCallerIda    — IDA-specific: work queue pump, timeout, scope checks
"""
from __future__ import annotations

import asyncio
import queue
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import pytest

# Restrict async tests to asyncio — trio is not installed in this environment.
pytestmark = pytest.mark.anyio(backends=['asyncio'])


@pytest.fixture
def anyio_backend():
    """Override anyio backend — restrict to asyncio only."""
    return 'asyncio'


from mcpyida.rpc_callbacks import (
    CallbackScope,
    RPCDisconnectedError,
    RPCError,
    RPCNamespace,
    RPCTimeoutError,
    generate_callback_function,
)
from mcpyida.rpc_types import (
    CallFunctionException,
    CallFunctionResult,
    FunctionDefinition,
    ListFunctionsResult,
)
from mcpyida.server import (
    _build_rpc_globals,
    _declare_rpc_capability,
    _discover_rpc_functions,
    _make_sync_caller_ida,
    _on_functions_changed,
    _reset_rpc_discovery,
    _send_custom_request,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_defn(
    name: str = 'search_web',
    param_order: list[str] | None = None,
    required: list[str] | None = None,
) -> FunctionDefinition:
    if param_order is None:
        param_order = ['query']
    if required is None:
        required = ['query']
    return FunctionDefinition(
        name=name,
        description=f'Description of {name}',
        parameterOrder=param_order,
        inputSchema={
            'type': 'object',
            'properties': {p: {'type': 'string'} for p in param_order},
            'required': required,
        },
    )


def _make_session(
    *,
    has_capability: bool = True,
    list_functions_result: dict | None = None,
) -> MagicMock:
    """Build a minimal mock ServerSession."""
    session = MagicMock()
    session._request_id = 0
    session._response_streams = {}
    session._write_stream = AsyncMock()

    # Build client_params with or without the experimental capability.
    client_params = MagicMock()
    caps = MagicMock()
    if has_capability:
        caps.experimental = {'mcpy/rpcCallbacks': {}}
    else:
        caps.experimental = {}
    client_params.capabilities = caps
    session.client_params = client_params

    return session


def _noop_rpc_caller(name: str, arguments: dict[str, Any], timeout: float) -> Any:
    """No-op rpc_caller used in tests that only check structure, not RPC behaviour."""
    return None


def _make_populated_namespace(
    names: list[str] | None = None,
) -> RPCNamespace:
    """Build an RPCNamespace with generated callback functions."""
    if names is None:
        names = ['search_web', 'ask_llm']
    ns = RPCNamespace()
    scope = CallbackScope()
    functions: dict[str, Any] = {}
    definitions: dict[str, FunctionDefinition] = {}
    for name in names:
        defn = _make_defn(name)
        fn = generate_callback_function(defn, _noop_rpc_caller, scope, ns)
        functions[name] = fn
        definitions[name] = defn
    ns.update_functions(functions, definitions)
    return ns


def _get_async_call(sync_call: Any) -> Any:
    """Extract the _async_call coroutine function from a sync_call_ida closure.

    _make_sync_caller_ida produces:
        def sync_call(...):   # closes over _async_call, scope, event_loop
            ...
            future = asyncio.run_coroutine_threadsafe(_async_call(...), event_loop)

    We extract _async_call from the closure cells by matching co_freevars.
    """
    freevars = sync_call.__code__.co_freevars
    cells = sync_call.__closure__ or ()
    cell_map = dict(zip(freevars, cells))
    if '_async_call' not in cell_map:
        raise KeyError(f'_async_call not found in closure; freevars={freevars!r}')
    return cell_map['_async_call'].cell_contents


# ---------------------------------------------------------------------------
# TestSendCustomRequest
# ---------------------------------------------------------------------------

class TestSendCustomRequest:
    """Tests for the low-level _send_custom_request helper."""

    @pytest.mark.anyio
    async def test_constructs_jsonrpc_request_with_correct_method(self):
        """Helper sends a JSONRPCRequest with the specified method."""
        from mcp.types import JSONRPCResponse

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={'functions': []})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        result = await _send_custom_request(session, 'mcpy/listFunctions', {})
        assert result == {'functions': []}

    @pytest.mark.anyio
    async def test_request_id_incremented(self):
        """Each call increments the session request ID."""
        from mcp.types import JSONRPCResponse

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        assert session._request_id == 0
        await _send_custom_request(session, 'mcpy/testMethod', {})
        assert session._request_id == 1
        await _send_custom_request(session, 'mcpy/testMethod', {})
        assert session._request_id == 2

    @pytest.mark.anyio
    async def test_raises_on_jsonrpc_error(self):
        """Helper raises McpError when the peer returns a JSON-RPC error."""
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData, JSONRPCError

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            err_data = ErrorData(code=-32601, message='Method not found')
            error = JSONRPCError(jsonrpc='2.0', id=req_id, error=err_data)
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(error)

        session._write_stream.send.side_effect = _fake_send

        with pytest.raises(McpError):
            await _send_custom_request(session, 'mcpy/unknown', {})

    @pytest.mark.anyio
    async def test_timeout_raises(self):
        """Helper raises TimeoutError when no response arrives within timeout."""
        session = _make_session()
        session._write_stream.send = AsyncMock()

        request_id = session._request_id
        with pytest.raises(TimeoutError):
            await _send_custom_request(session, 'mcpy/slow', {}, timeout=0.05)

        # Response stream must be cleaned up even on timeout.
        assert request_id not in session._response_streams

    @pytest.mark.anyio
    async def test_response_stream_cleaned_up_on_success(self):
        """_response_streams entry is removed after successful response."""
        from mcp.types import JSONRPCResponse

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        await _send_custom_request(session, 'mcpy/listFunctions', {})
        assert 0 not in session._response_streams

    @pytest.mark.anyio
    async def test_response_stream_cleaned_up_on_error(self):
        """_response_streams entry is removed even when an error response arrives."""
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData, JSONRPCError

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            err = JSONRPCError(
                jsonrpc='2.0', id=req_id,
                error=ErrorData(code=-32600, message='Invalid request'),
            )
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(err)

        session._write_stream.send.side_effect = _fake_send

        with pytest.raises(McpError):
            await _send_custom_request(session, 'mcpy/fail', {})
        assert 0 not in session._response_streams

    @pytest.mark.anyio
    async def test_params_embedded_in_request(self):
        """Params dict is sent as-is in the JSON-RPC request."""
        from mcp.types import JSONRPCResponse, JSONRPCMessage, JSONRPCRequest

        session = _make_session()
        sent_messages: list = []

        async def _fake_send(msg):
            sent_messages.append(msg)
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        params = {'cursor': 'abc123'}
        await _send_custom_request(session, 'mcpy/listFunctions', params)

        assert len(sent_messages) == 1
        # The message wraps a JSONRPCRequest
        msg = sent_messages[0]
        jsonrpc_req = msg.message.root
        assert isinstance(jsonrpc_req, JSONRPCRequest)
        assert jsonrpc_req.method == 'mcpy/listFunctions'
        assert jsonrpc_req.params == params


# ---------------------------------------------------------------------------
# TestDiscoverRpcFunctions
# ---------------------------------------------------------------------------

class TestDiscoverRpcFunctions:
    """Tests for _discover_rpc_functions caching and capability detection."""

    def setup_method(self):
        """Reset module-level discovery state before each test."""
        _reset_rpc_discovery()

    @pytest.mark.anyio
    async def test_returns_none_when_client_has_no_experimental(self):
        """Returns None if client capabilities.experimental is None."""
        session = _make_session(has_capability=False)
        session.client_params.capabilities.experimental = None

        result = await _discover_rpc_functions(session)
        assert result is None

    @pytest.mark.anyio
    async def test_returns_none_when_capability_absent(self):
        """Returns None if mcpy/rpcCallbacks is not in experimental dict."""
        session = _make_session(has_capability=False)

        result = await _discover_rpc_functions(session)
        assert result is None

    @pytest.mark.anyio
    async def test_returns_none_caches_false_result(self):
        """Second call with no-capability client uses cache (no extra requests)."""
        session = _make_session(has_capability=False)

        result1 = await _discover_rpc_functions(session)
        result2 = await _discover_rpc_functions(session)

        assert result1 is None
        assert result2 is None
        # _write_stream was never touched
        session._write_stream.send.assert_not_called()

    @pytest.mark.anyio
    async def test_discovers_functions_from_list_functions_response(self):
        """Builds RPCNamespace from mcpy/listFunctions response."""
        session = _make_session(has_capability=True)

        defn_data = {
            'functions': [
                {
                    'name': 'search_web',
                    'description': 'Search the web',
                    'parameterOrder': ['query'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': {'query': {'type': 'string'}},
                        'required': ['query'],
                    },
                }
            ]
        }

        with patch('mcpyida.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = defn_data
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert isinstance(result, RPCNamespace)
        assert 'search_web' in result._definitions

    @pytest.mark.anyio
    async def test_second_call_returns_cached_namespace(self):
        """_discover_rpc_functions returns cached result on second call."""
        session = _make_session(has_capability=True)

        defn_data = {
            'functions': [
                {
                    'name': 'fn_one',
                    'parameterOrder': ['x'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': {'x': {'type': 'string'}},
                        'required': ['x'],
                    },
                }
            ]
        }

        with patch('mcpyida.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = defn_data
            result1 = await _discover_rpc_functions(session)
            result2 = await _discover_rpc_functions(session)

        # Only one RPC call made
        assert mock_send.call_count == 1
        assert result1 is result2

    @pytest.mark.anyio
    async def test_returns_none_when_list_functions_raises(self):
        """Returns None gracefully when mcpy/listFunctions fails."""
        import mcpyida.server as srv

        session = _make_session(has_capability=True)

        with patch('mcpyida.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = RuntimeError('connection error')
            result = await _discover_rpc_functions(session)

        assert result is None
        # Transient failure must not be cached — allow retry on next call.
        assert srv._rpc_functions_discovered is False

    @pytest.mark.anyio
    async def test_skips_unsafe_function_names(self):
        """Functions whose names collide with Python builtins are skipped."""
        session = _make_session(has_capability=True)

        defn_data = {
            'functions': [
                {
                    'name': 'print',  # builtin — must be skipped
                    'parameterOrder': [],
                    'inputSchema': {'type': 'object', 'properties': {}},
                },
                {
                    'name': 'safe_fn',
                    'parameterOrder': ['x'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': {'x': {'type': 'string'}},
                        'required': ['x'],
                    },
                },
            ]
        }

        with patch('mcpyida.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = defn_data
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert 'print' not in result._definitions
        assert 'safe_fn' in result._definitions

    @pytest.mark.anyio
    async def test_returns_none_when_client_params_none(self):
        """Returns None gracefully when session.client_params is None."""
        session = _make_session(has_capability=False)
        session.client_params = None

        result = await _discover_rpc_functions(session)
        assert result is None

    @pytest.mark.anyio
    async def test_empty_functions_list_returns_namespace(self):
        """Handles empty functions list without error; namespace.is_available() True."""
        session = _make_session(has_capability=True)

        with patch('mcpyida.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {'functions': []}
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert isinstance(result, RPCNamespace)
        assert result.is_available() is True
        assert result.available() == []

    @pytest.mark.anyio
    async def test_discover_functions_handles_pagination(self):
        """Discovery follows nextCursor for paginated function lists."""
        session = _make_session(has_capability=True)

        def _make_fn_entry(name: str) -> dict:
            return {
                'name': name,
                'parameterOrder': ['x'],
                'inputSchema': {
                    'type': 'object',
                    'properties': {'x': {'type': 'string'}},
                    'required': ['x'],
                },
            }

        page1 = {'functions': [_make_fn_entry('function_a')], 'nextCursor': 'page2'}
        page2 = {'functions': [_make_fn_entry('function_b')]}

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = [page1, page2]
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert 'function_a' in result._definitions
        assert 'function_b' in result._definitions
        assert mock_send.call_count == 2
        assert mock_send.call_args_list[1].args[2] == {'cursor': 'page2'}

    @pytest.mark.anyio
    async def test_discover_functions_retries_after_failure(self):
        """Transient failure allows retry on next call."""
        import mcpyida.server as srv

        session = _make_session(has_capability=True)

        fn_entry = {
            'name': 'my_fn',
            'parameterOrder': ['x'],
            'inputSchema': {
                'type': 'object',
                'properties': {'x': {'type': 'string'}},
                'required': ['x'],
            },
        }

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = RuntimeError('transient error')
            result1 = await _discover_rpc_functions(session)

        assert result1 is None
        assert srv._rpc_functions_discovered is False

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = None
            mock_send.return_value = {'functions': [fn_entry]}
            result2 = await _discover_rpc_functions(session)

        assert result2 is not None
        assert 'my_fn' in result2._definitions

    @pytest.mark.anyio
    async def test_session_identity_change_resets_cache(self):
        """When a new session connects, the cached namespace is invalidated."""
        session_a = _make_session(has_capability=True)
        session_b = _make_session(has_capability=True)

        fn_a = {
            'name': 'fn_a',
            'parameterOrder': ['x'],
            'inputSchema': {
                'type': 'object',
                'properties': {'x': {'type': 'string'}},
                'required': ['x'],
            },
        }
        fn_b = {
            'name': 'fn_b',
            'parameterOrder': ['y'],
            'inputSchema': {
                'type': 'object',
                'properties': {'y': {'type': 'string'}},
                'required': ['y'],
            },
        }

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'functions': [fn_a]}
            result_a = await _discover_rpc_functions(session_a)

        assert result_a is not None
        assert 'fn_a' in result_a._definitions

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'functions': [fn_b]}
            result_b = await _discover_rpc_functions(session_b)

        assert result_b is not None
        assert 'fn_b' in result_b._definitions
        assert 'fn_a' not in result_b._definitions


# ---------------------------------------------------------------------------
# TestBuildRpcGlobals
# ---------------------------------------------------------------------------

class TestBuildRpcGlobals:
    """Tests for _build_rpc_globals — per-execution globals injection."""

    def _make_ns(self, names: list[str] | None = None) -> RPCNamespace:
        return _make_populated_namespace(names)

    def _make_loop(self) -> MagicMock:
        return MagicMock(spec=asyncio.AbstractEventLoop)

    def test_rpc_key_always_present(self):
        """'rpc' key is always injected even when all functions have name collisions."""
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        assert 'rpc' in injected

    def test_rpc_value_is_rpc_namespace(self):
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        assert isinstance(injected['rpc'], RPCNamespace)

    def test_function_globals_injected(self):
        """Callback function names are injected as top-level globals."""
        ns = self._make_ns(['search_web', 'ask_llm'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        assert 'search_web' in injected
        assert 'ask_llm' in injected

    def test_injected_functions_are_callable(self):
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        assert callable(injected['search_web'])

    def test_name_collision_with_existing_globals_skipped(self):
        """Functions whose names collide with existing script globals are not injected."""
        ns = self._make_ns(['search_web', 'ask_llm'])
        scope = CallbackScope()
        existing = {'search_web': 'already_here'}
        injected = _build_rpc_globals(ns, None, scope, existing, self._make_loop())
        assert 'search_web' not in injected
        assert 'ask_llm' in injected

    def test_injected_functions_share_exec_namespace(self):
        """The 'rpc' namespace and individual globals come from the same RPCNamespace."""
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        rpc_ns = injected['rpc']
        assert 'search_web' in rpc_ns._functions

    def test_scope_invalidation_expires_injected_functions(self):
        """Injected callback functions raise RuntimeError after scope invalidation."""
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        fn = injected['search_web']
        scope.invalidate()
        with pytest.raises(RuntimeError, match='Callback expired'):
            fn('hello')

    def test_empty_namespace_returns_only_rpc_key(self):
        """Empty RPCNamespace yields only the 'rpc' global."""
        ns = RPCNamespace()
        ns.update_functions({}, {})
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        assert set(injected.keys()) == {'rpc'}

    def test_rpc_namespace_in_injected_is_available(self):
        """The injected 'rpc' namespace reports is_available() == True."""
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {}, self._make_loop())
        assert injected['rpc'].is_available() is True


# ---------------------------------------------------------------------------
# TestDeclareRpcCapability
# ---------------------------------------------------------------------------

class TestDeclareRpcCapability:
    """Tests for _declare_rpc_capability — experimental capability injection."""

    def _make_mcp(self) -> MagicMock:
        """Build a minimal FastMCP mock."""
        from mcp.server.models import InitializationOptions
        from mcp.types import ServerCapabilities

        mcp = MagicMock()
        low_level = MagicMock()

        def _real_create(notification_options=None, experimental_capabilities=None):
            caps = experimental_capabilities or {}
            return InitializationOptions(
                server_name='test',
                server_version='0.0.0',
                capabilities=ServerCapabilities(experimental=caps),
            )

        low_level.create_initialization_options = _real_create
        mcp._mcp_server = low_level
        return mcp

    def test_experimental_capability_added(self):
        """After patching, create_initialization_options includes mcpy/rpcCallbacks."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options()
        assert opts.capabilities.experimental is not None
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental

    def test_existing_capabilities_preserved(self):
        """Existing experimental capabilities are not removed by the patch."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options(
            experimental_capabilities={'some/other': {'value': 1}}
        )
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental
        assert 'some/other' in opts.capabilities.experimental

    def test_setdefault_semantics_when_already_present(self):
        """If mcpy/rpcCallbacks is already declared, the existing value is kept."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        existing_value = {'version': 1}
        opts = mcp._mcp_server.create_initialization_options(
            experimental_capabilities={'mcpy/rpcCallbacks': existing_value}
        )
        assert opts.capabilities.experimental['mcpy/rpcCallbacks'] == existing_value

    def test_patch_is_idempotent(self):
        """Calling _declare_rpc_capability twice does not corrupt capabilities."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options()
        assert opts.capabilities.experimental is not None
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental

    def test_original_called_with_correct_args(self):
        """The patched function delegates to the original with merged caps."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options(
            experimental_capabilities={'extra/cap': {}}
        )
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental
        assert 'extra/cap' in opts.capabilities.experimental


# ---------------------------------------------------------------------------
# TestMakeSyncCallerIda
# ---------------------------------------------------------------------------

class TestMakeSyncCallerIda:
    """Tests for _make_sync_caller_ida — IDA-specific sync→async bridge.

    Key differences from Ghidra's _make_sync_caller:
    - Uses asyncio.run_coroutine_threadsafe + work queue pump
    - Needs an explicit event_loop argument
    - Timeout implemented by polling future.done() with deadline
    """

    def _make_scope(self) -> CallbackScope:
        return CallbackScope()

    def _make_session(self) -> MagicMock:
        return _make_session()

    # ------------------------------------------------------------------
    # scope check
    # ------------------------------------------------------------------

    def test_sync_caller_checks_scope_before_bridging(self):
        """Expired scope raises RuntimeError before run_coroutine_threadsafe is called."""
        session = self._make_session()
        scope = self._make_scope()
        scope.invalidate()

        loop = MagicMock(spec=asyncio.AbstractEventLoop)
        sync_call = _make_sync_caller_ida(session, scope, loop)

        with patch('asyncio.run_coroutine_threadsafe') as mock_rctf:
            with pytest.raises(RuntimeError, match='Callback expired'):
                sync_call('my_fn', {}, 30.0)
            mock_rctf.assert_not_called()

    # ------------------------------------------------------------------
    # normal invocation — work queue pump
    # ------------------------------------------------------------------

    def test_sync_caller_returns_future_result(self):
        """sync_call returns the result from the completed future."""
        session = self._make_session()
        scope = self._make_scope()
        loop = MagicMock(spec=asyncio.AbstractEventLoop)

        sync_call = _make_sync_caller_ida(session, scope, loop)

        mock_future = MagicMock()
        mock_future.done.return_value = True  # immediately done
        mock_future.result.return_value = 'rpc_answer'

        with patch('asyncio.run_coroutine_threadsafe', return_value=mock_future):
            result = sync_call('my_fn', {'x': 1}, 30.0)

        assert result == 'rpc_answer'

    def test_sync_caller_pumps_work_queue_while_waiting(self):
        """sync_call drains the IDA work queue items while waiting for future."""
        session = self._make_session()
        scope = self._make_scope()
        loop = MagicMock(spec=asyncio.AbstractEventLoop)

        sync_call = _make_sync_caller_ida(session, scope, loop)

        executed_work: list[str] = []

        def work_item_a():
            executed_work.append('a')

        def work_item_b():
            executed_work.append('b')

        # Future is not done until we put items; simulate 2 queue drains then done.
        done_calls = [False, False, True]
        done_iter = iter(done_calls)

        mock_future = MagicMock()
        mock_future.done.side_effect = lambda: next(done_iter)
        mock_future.result.return_value = 'done'

        work_q: queue.Queue = queue.Queue()
        work_q.put(work_item_a)
        work_q.put(work_item_b)

        with patch('asyncio.run_coroutine_threadsafe', return_value=mock_future):
            with patch('mcpyida.mcpserver._ida_work_queue', work_q):
                result = sync_call('fn', {}, 30.0)

        assert result == 'done'
        assert 'a' in executed_work
        assert 'b' in executed_work

    def test_sync_caller_timeout_cancels_future(self):
        """sync_call raises RPCTimeoutError and cancels the future when deadline passes."""
        session = self._make_session()
        scope = self._make_scope()
        loop = MagicMock(spec=asyncio.AbstractEventLoop)

        sync_call = _make_sync_caller_ida(session, scope, loop)

        mock_future = MagicMock()
        mock_future.done.return_value = False  # never completes

        empty_q: queue.Queue = queue.Queue()

        with patch('asyncio.run_coroutine_threadsafe', return_value=mock_future):
            with patch('mcpyida.mcpserver._ida_work_queue', empty_q):
                with pytest.raises(RPCTimeoutError, match='timed out after'):
                    sync_call('slow_fn', {}, timeout=0.05)

        mock_future.cancel.assert_called_once()

    def test_sync_caller_passes_correct_arguments_to_future(self):
        """run_coroutine_threadsafe is called with the event loop and correct args."""
        session = self._make_session()
        scope = self._make_scope()
        loop = MagicMock(spec=asyncio.AbstractEventLoop)

        sync_call = _make_sync_caller_ida(session, scope, loop)

        mock_future = MagicMock()
        mock_future.done.return_value = True
        mock_future.result.return_value = None

        captured_calls: list = []

        def _fake_rctf(coro, evt_loop):
            captured_calls.append((coro, evt_loop))
            return mock_future

        with patch('asyncio.run_coroutine_threadsafe', side_effect=_fake_rctf):
            sync_call('test_fn', {'arg': 'val'}, 10.0)

        assert len(captured_calls) == 1
        _, passed_loop = captured_calls[0]
        assert passed_loop is loop

    # ------------------------------------------------------------------
    # _async_call behaviour (tested via asyncio event loop)
    # ------------------------------------------------------------------

    @pytest.mark.anyio
    async def test_async_call_sends_callfunction_request(self):
        """_async_call sends mcpy/callFunction with correct method and params."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'content': 'answer'}
            result = await _async_call('search_web', {'q': 'test'}, 30.0)

        assert result == 'answer'
        mock_send.assert_called_once_with(
            session, 'mcpy/callFunction',
            {'name': 'search_web', 'arguments': {'q': 'test'}},
            timeout=30.0,
        )

    @pytest.mark.anyio
    async def test_async_call_returns_content(self):
        """_async_call extracts content from CallFunctionResult."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'content': 42}
            result = await _async_call('fn', {}, 30.0)

        assert result == 42

    @pytest.mark.anyio
    async def test_async_call_timeout_raises_rpc_timeout(self):
        """TimeoutError from _send_custom_request becomes RPCTimeoutError."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = TimeoutError('timed out')
            with pytest.raises(RPCTimeoutError, match='timed out after'):
                await _async_call('slow_fn', {}, 5.0)

    @pytest.mark.anyio
    async def test_async_call_mcp_error_raises_rpc_error(self):
        """McpError from _send_custom_request becomes RPCError."""
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData

        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = McpError(ErrorData(code=-32600, message='bad request'))
            with pytest.raises(RPCError, match='MCP error calling'):
                await _async_call('bad_fn', {}, 30.0)

    @pytest.mark.anyio
    async def test_async_call_disconnect_raises_rpc_disconnected(self):
        """Unexpected Exception from _send_custom_request becomes RPCDisconnectedError."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = ConnectionResetError('connection lost')
            with pytest.raises(RPCDisconnectedError, match='Lost connection'):
                await _async_call('fn', {}, 30.0)

    @pytest.mark.anyio
    async def test_async_call_exception_response_mapped(self):
        """CallFunctionException in response dict raises the mapped Python exception."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {
                'exception': {
                    'type': 'ValueError',
                    'message': 'bad value',
                    'traceback': 'File "x.py", line 1',
                }
            }
            with pytest.raises(ValueError, match='bad value'):
                await _async_call('fn', {}, 30.0)

    @pytest.mark.anyio
    async def test_async_call_unknown_exception_type_uses_runtime_error(self):
        """Unknown exception type in response falls back to RuntimeError."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {
                'exception': {
                    'type': 'SomeCustomError',
                    'message': 'custom error message',
                }
            }
            with pytest.raises(RuntimeError, match='custom error message'):
                await _async_call('fn', {}, 30.0)

    @pytest.mark.anyio
    async def test_async_call_scope_checked_before_send(self):
        """Expired scope raises RuntimeError inside _async_call before sending."""
        session = self._make_session()
        scope = self._make_scope()
        loop = asyncio.get_running_loop()
        sync_call = _make_sync_caller_ida(session, scope, loop)
        _async_call = _get_async_call(sync_call)
        scope.invalidate()

        with patch(
            'mcpyida.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            with pytest.raises(RuntimeError, match='Callback expired'):
                await _async_call('fn', {}, 30.0)
            mock_send.assert_not_called()


# ---------------------------------------------------------------------------
# TestScriptingIntegration
# ---------------------------------------------------------------------------

class TestScriptingIntegration:
    """Tests for the scripting.py changes — scope lifecycle and globals injection.

    We test _idapython_eval_sync directly (sync, no IDA main thread dispatch)
    since we can supply a mock rpc_namespace without needing IDA.
    """

    def _make_ns(self, names: list[str] | None = None) -> RPCNamespace:
        return _make_populated_namespace(names)

    def _make_loop(self) -> MagicMock:
        return MagicMock(spec=asyncio.AbstractEventLoop)

    def test_callback_scope_invalidated_after_execution(self):
        """CallbackScope is invalidated once _idapython_eval_sync returns."""
        from mcpyida.tools.scripting import _idapython_eval_sync
        import mcpyida.tools.scripting as scripting_mod

        captured_scopes: list[CallbackScope] = []

        def _capture_scope(*args, **kwargs):
            scope = kwargs.get('scope') or args[2]
            captured_scopes.append(scope)
            return {'rpc': RPCNamespace()}

        ns = self._make_ns(['search_web'])

        # Pre-seed persistent_globals so the __main__ import path is skipped.
        import sys
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.server._build_rpc_globals', side_effect=_capture_scope):
                _idapython_eval_sync('x = 1', rpc_namespace=ns, event_loop=self._make_loop())
        finally:
            scripting_mod._persistent_globals = saved

        assert len(captured_scopes) == 1
        assert not captured_scopes[0].is_valid

    def test_callback_scope_invalidated_even_on_error(self):
        """Scope is invalidated even when script execution raises an exception."""
        from mcpyida.tools.scripting import _idapython_eval_sync
        import mcpyida.tools.scripting as scripting_mod

        captured_scopes: list[CallbackScope] = []

        def _capture_scope(*args, **kwargs):
            scope = kwargs.get('scope') or args[2]
            captured_scopes.append(scope)
            return {'rpc': RPCNamespace()}

        ns = self._make_ns(['search_web'])

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.server._build_rpc_globals', side_effect=_capture_scope):
                result = _idapython_eval_sync(
                    'raise ValueError("intentional")',
                    rpc_namespace=ns,
                    event_loop=self._make_loop(),
                )
        finally:
            scripting_mod._persistent_globals = saved

        assert result.success is False
        assert len(captured_scopes) == 1
        assert not captured_scopes[0].is_valid

    def test_no_rpc_namespace_no_scope_created(self):
        """When rpc_namespace is None no CallbackScope is created."""
        from mcpyida.tools.scripting import _idapython_eval_sync
        import mcpyida.tools.scripting as scripting_mod

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.server._build_rpc_globals') as mock_build_globals:
                _idapython_eval_sync('1 + 1', rpc_namespace=None)
                mock_build_globals.assert_not_called()
        finally:
            scripting_mod._persistent_globals = saved

    def test_unavailable_namespace_no_scope_created(self):
        """When rpc_namespace.is_available() is False, no CallbackScope is created."""
        from mcpyida.tools.scripting import _idapython_eval_sync
        import mcpyida.tools.scripting as scripting_mod

        ns = RPCNamespace()  # freshly created — not available yet

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.server._build_rpc_globals') as mock_build_globals:
                _idapython_eval_sync('1 + 1', rpc_namespace=ns)
                mock_build_globals.assert_not_called()
        finally:
            scripting_mod._persistent_globals = saved

    def test_rpc_globals_cleaned_up_after_execution(self):
        """RPC globals injected during execution are removed from _persistent_globals."""
        from mcpyida.tools.scripting import _idapython_eval_sync
        import mcpyida.tools.scripting as scripting_mod

        ns = self._make_ns(['my_callback'])
        injected_globals: dict[str, Any] = {}

        def _fake_build_globals(namespace, session, scope, existing, event_loop=None):
            injected_globals['rpc'] = RPCNamespace()
            injected_globals['my_callback'] = lambda: 'ok'
            return injected_globals

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.server._build_rpc_globals', side_effect=_fake_build_globals):
                _idapython_eval_sync('1', rpc_namespace=ns, event_loop=self._make_loop())
        finally:
            pg = scripting_mod._persistent_globals
            scripting_mod._persistent_globals = saved

        # After execution, persistent_globals should not contain injected keys.
        if pg is not None:
            assert 'my_callback' not in pg
            assert 'rpc' not in pg

    def test_rpc_globals_injected_during_execution(self):
        """_build_rpc_globals result is merged into _persistent_globals during exec."""
        from mcpyida.tools.scripting import _idapython_eval_sync
        import mcpyida.tools.scripting as scripting_mod

        ns = self._make_ns(['my_callback'])

        def _fake_build_globals(namespace, session, scope, existing, event_loop=None):
            return {'rpc': RPCNamespace(), 'my_callback': lambda: 'ok'}

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.server._build_rpc_globals', side_effect=_fake_build_globals):
                result = _idapython_eval_sync('1', rpc_namespace=ns, event_loop=self._make_loop())
        finally:
            scripting_mod._persistent_globals = saved

        assert result.success is True


# ---------------------------------------------------------------------------
# TestBuildRpcGlobalsUsesRealCaller
# ---------------------------------------------------------------------------

class TestBuildRpcGlobalsUsesRealCaller:
    """Verify _build_rpc_globals uses _make_sync_caller_ida, not a stub."""

    def test_build_rpc_globals_uses_real_caller(self):
        """_build_rpc_globals creates a sync caller via _make_sync_caller_ida."""
        import mcpyida.server as srv

        assert not hasattr(srv, '_stub_rpc_caller'), (
            '_stub_rpc_caller should not exist; '
            '_make_sync_caller_ida is the real implementation'
        )
        assert hasattr(srv, '_make_sync_caller_ida')

    def test_build_rpc_globals_make_sync_caller_called(self):
        """_build_rpc_globals calls _make_sync_caller_ida with session, scope, and loop."""
        import mcpyida.server as srv

        session = _make_session()
        scope = CallbackScope()
        loop = MagicMock(spec=asyncio.AbstractEventLoop)
        ns = RPCNamespace()
        ns.update_functions({}, {})  # empty namespace

        with patch.object(srv, '_make_sync_caller_ida', wraps=srv._make_sync_caller_ida) as mock_maker:
            _build_rpc_globals(ns, session, scope, {}, loop)

        mock_maker.assert_called_once_with(session, scope, loop)


# ---------------------------------------------------------------------------
# TestSnapshotIsolation
# ---------------------------------------------------------------------------

class TestSnapshotIsolation:
    """Tests for snapshot isolation — function list updates deferred during execution.

    The invariant: once a script begins executing, _on_functions_changed() must
    not mutate the function-list cache.  Instead it sets _rpc_update_deferred so
    that the next tool call sees fresh functions.
    """

    def setup_method(self):
        """Reset all module-level RPC state before each test."""
        _reset_rpc_discovery()

    # ------------------------------------------------------------------
    # _on_functions_changed — idle path
    # ------------------------------------------------------------------

    def test_functions_changed_when_idle_invalidates_immediately(self):
        """functionsChanged when no script is running sets _rpc_functions_discovered=False."""
        import mcpyida.server as srv

        # Simulate a previously discovered cache.
        srv._rpc_functions_discovered = True
        srv._script_executing = False

        _on_functions_changed()

        assert srv._rpc_functions_discovered is False
        assert srv._rpc_update_deferred is False

    def test_functions_changed_when_idle_does_not_set_deferred(self):
        """When idle, _on_functions_changed sets no deferred flag."""
        import mcpyida.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = False

        _on_functions_changed()

        assert srv._rpc_update_deferred is False

    # ------------------------------------------------------------------
    # _on_functions_changed — executing path
    # ------------------------------------------------------------------

    def test_functions_changed_during_execution_sets_deferred_flag(self):
        """functionsChanged during script execution sets deferred flag, not cache."""
        import mcpyida.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = True

        _on_functions_changed()

        # Cache must NOT be invalidated mid-execution.
        assert srv._rpc_functions_discovered is True
        # Deferred flag must be set.
        assert srv._rpc_update_deferred is True

    def test_functions_changed_during_execution_preserves_discovery_flag(self):
        """Cache invalidation is deferred, not applied immediately."""
        import mcpyida.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = True

        _on_functions_changed()

        assert srv._rpc_functions_discovered is True

    # ------------------------------------------------------------------
    # Script execution lifecycle — _script_executing flag management
    # ------------------------------------------------------------------

    def test_script_executing_flag_set_during_execution(self):
        """_script_executing is True while _idapython_eval_sync runs the script body."""
        import mcpyida.server as srv
        from mcpyida.tools.scripting import _idapython_eval_sync

        executing_during: list[bool] = []

        def _spy_eval_ast(tree, code, exec_globals):
            executing_during.append(srv._script_executing)
            return None

        import mcpyida.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.tools.scripting._eval_ast', side_effect=_spy_eval_ast):
                _idapython_eval_sync('x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        assert len(executing_during) == 1
        assert executing_during[0] is True

    def test_script_executing_flag_cleared_after_execution(self):
        """_script_executing is False after _idapython_eval_sync returns."""
        import mcpyida.server as srv
        from mcpyida.tools.scripting import _idapython_eval_sync

        import mcpyida.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            _idapython_eval_sync('x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        assert srv._script_executing is False

    def test_script_executing_flag_cleared_even_on_error(self):
        """_script_executing is False after a script that raises an exception."""
        import mcpyida.server as srv
        from mcpyida.tools.scripting import _idapython_eval_sync

        import mcpyida.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            result = _idapython_eval_sync('raise RuntimeError("boom")')
        finally:
            scripting_mod._persistent_globals = saved

        assert result.success is False
        assert srv._script_executing is False

    # ------------------------------------------------------------------
    # Deferred update applied after execution
    # ------------------------------------------------------------------

    def test_deferred_update_applied_after_execution(self):
        """After script completes with a pending deferred flag, cache is invalidated."""
        import mcpyida.server as srv
        from mcpyida.tools.scripting import _idapython_eval_sync

        # Pre-seed state: cache is valid.
        srv._rpc_functions_discovered = True
        srv._rpc_update_deferred = False

        def _spy_and_notify(tree, code, exec_globals):
            # Simulate the notification arriving during execution.
            _on_functions_changed()
            return None

        import mcpyida.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.tools.scripting._eval_ast', side_effect=_spy_and_notify):
                _idapython_eval_sync('x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        # After completion, discovery is invalidated and deferred flag is cleared.
        assert srv._rpc_functions_discovered is False
        assert srv._rpc_update_deferred is False
        assert srv._script_executing is False

    def test_no_deferred_update_leaves_cache_intact(self):
        """If no deferred flag was set, the cache remains valid after execution."""
        import mcpyida.server as srv
        from mcpyida.tools.scripting import _idapython_eval_sync

        srv._rpc_functions_discovered = True
        srv._rpc_update_deferred = False

        import mcpyida.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            _idapython_eval_sync('x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        # No notification arrived — cache should still be valid.
        assert srv._rpc_functions_discovered is True
        assert srv._rpc_update_deferred is False

    def test_deferred_flag_cleared_after_apply(self):
        """_rpc_update_deferred is reset to False after being applied on execution end."""
        import mcpyida.server as srv
        from mcpyida.tools.scripting import _idapython_eval_sync

        srv._rpc_functions_discovered = True

        def _set_deferred(tree, code, exec_globals):
            _on_functions_changed()  # sets deferred while executing
            return None

        import mcpyida.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyida.tools.scripting._eval_ast', side_effect=_set_deferred):
                _idapython_eval_sync('x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        assert srv._rpc_update_deferred is False

    # ------------------------------------------------------------------
    # _reset_rpc_discovery also resets snapshot state
    # ------------------------------------------------------------------

    def test_reset_rpc_discovery_clears_snapshot_state(self):
        """_reset_rpc_discovery resets both _rpc_update_deferred and _script_executing."""
        import mcpyida.server as srv

        srv._rpc_update_deferred = True
        srv._script_executing = True

        _reset_rpc_discovery()

        assert srv._rpc_update_deferred is False
        assert srv._script_executing is False
