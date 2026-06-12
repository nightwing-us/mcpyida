"""E2E tests for mcpy/rpcCallbacks protocol extension.

Verifies the full round-trip:
  1. Client declares mcpy/rpcCallbacks experimental capability
  2. Server sends mcpy/listFunctions after initialization
  3. Client returns mock function definitions
  4. Server injects callback functions into the idapython scripting environment
  5. Script calls the callback function -> server sends mcpy/callFunction
  6. Client executes the mock logic and returns the result
  7. Script receives the result and returns it to the caller

SDK validation challenge
------------------------
The MCP SDK's ClientSession validates every incoming JSON-RPC request against
the ServerRequest type union.  Our custom methods (mcpy/listFunctions and
mcpy/callFunction) are NOT in that union, so the stock ClientSession would
reject them with INVALID_PARAMS before our handler ever runs.

We work around this by subclassing ClientSession and overriding _receive_loop
to pre-screen for our custom methods.  When we see one of our methods we
intercept the raw JSONRPCRequest directly (before model_validate is called)
and dispatch it to a registered handler.  All other messages follow the normal
SDK path unchanged.

Capability injection
---------------------
ClientSession.initialize() hard-codes experimental=None.  We override
initialize() in our subclass to inject experimental={'mcpy/rpcCallbacks': {}}.

SDK compatibility
-----------------
The project environment may have two MCP SDK installations on sys.path (a thin
client-only package and the full SDK).  The versions may differ in whether
protocol-message fields carry default values (e.g. method: Literal[...]).
All Literal fields are passed explicitly to stay compatible with both versions.
"""
from __future__ import annotations

import logging
from typing import Any

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.message import SessionMessage
from mcp.shared.session import RequestResponder

from mcpyida.rpc_types import (
    CallFunctionResult,
    FunctionDefinition,
    ListFunctionsResult,
)

logger = logging.getLogger(__name__)

# Generous timeout for IDA operations (analysis + script execution)
MCP_CALL_TIMEOUT = 90

# Our custom JSON-RPC method names
_LIST_FUNCTIONS_METHOD = 'mcpy/listFunctions'
_CALL_FUNCTION_METHOD = 'mcpy/callFunction'


# ---------------------------------------------------------------------------
# RpcClientSession — ClientSession subclass with custom-method support
# ---------------------------------------------------------------------------

class RpcClientSession(ClientSession):
    """ClientSession subclass that handles mcpy/* server-to-client requests.

    Overrides two things:
    1. _receive_loop: intercepts raw JSONRPCRequests for our custom methods
       before the SDK's model_validate() would reject them as unknown.
    2. initialize: injects experimental={'mcpy/rpcCallbacks': {}} so the
       server knows to send mcpy/listFunctions after the handshake.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Maps JSON-RPC method -> async callable(params: dict) -> pydantic | dict
        self._custom_handlers: dict[str, Any] = {}

    def register_custom_handler(self, method: str, handler: Any) -> None:
        """Register an async handler for a custom server-to-client method.

        Args:
            method:  JSON-RPC method name, e.g. 'mcpy/listFunctions'.
            handler: async callable(params: dict) -> pydantic model or dict.
                     Its return value is serialised as the JSON-RPC result body.
        """
        self._custom_handlers[method] = handler

    async def initialize(self) -> Any:
        """Override to inject mcpy/rpcCallbacks experimental capability.

        All Literal-typed fields are passed explicitly to remain compatible
        with older SDK versions where these fields have no default values.
        """
        import mcp.types as types
        from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS

        result = await self.send_request(
            types.ClientRequest(
                types.InitializeRequest(
                    method='initialize',
                    params=types.InitializeRequestParams(
                        protocolVersion=types.LATEST_PROTOCOL_VERSION,
                        capabilities=types.ClientCapabilities(
                            sampling=None,
                            elicitation=None,
                            experimental={'mcpy/rpcCallbacks': {'listChanged': False}},
                            roots=None,
                        ),
                        clientInfo=self._client_info,
                    ),
                )
            ),
            types.InitializeResult,
        )

        if result.protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RuntimeError(
                f'Unsupported protocol version from the server: {result.protocolVersion}'
            )

        # Store server capabilities when the attribute exists (newer SDK).
        if hasattr(self, '_server_capabilities'):
            self._server_capabilities = result.capabilities

        await self.send_notification(
            types.ClientNotification(
                types.InitializedNotification(method='notifications/initialized')
            )
        )
        return result

    async def _receive_loop(self) -> None:  # type: ignore[override]
        """Override _receive_loop to intercept custom methods before SDK validation.

        For any incoming JSONRPCRequest whose method is in our custom_handlers:
        - Bypass model_validate (which would reject unknown methods).
        - Dispatch to our handler and send the result as a JSON-RPC response.

        For all other message types the standard SDK behaviour is preserved.
        The response path uses _handle_response() when available (newer SDK)
        and falls back to inline stream dispatch for older SDK versions.
        """
        import mcp.types as types
        from mcp.types import (
            CancelledNotification,
            ErrorData,
            INVALID_PARAMS,
            JSONRPCError,
            JSONRPCMessage,
            JSONRPCNotification,
            JSONRPCRequest,
            JSONRPCResponse,
            ProgressNotification,
        )
        connection_closed_code: int = getattr(types, 'CONNECTION_CLOSED', -32000)

        async with (
            self._read_stream,
            self._write_stream,
        ):
            try:
                async for message in self._read_stream:
                    if isinstance(message, Exception):
                        await self._handle_incoming(message)

                    elif isinstance(message.message.root, JSONRPCRequest):
                        raw_req = message.message.root
                        if raw_req.method in self._custom_handlers:
                            # Custom method: handle without SDK validation.
                            await self._dispatch_custom_request(raw_req)
                        else:
                            # Standard path: validate and dispatch.
                            await self._dispatch_sdk_request(message)

                    elif isinstance(message.message.root, JSONRPCNotification):
                        try:
                            notification = self._receive_notification_type.model_validate(
                                message.message.root.model_dump(
                                    by_alias=True, mode='json', exclude_none=True
                                )
                            )
                            if isinstance(notification.root, CancelledNotification):
                                cancelled_id = notification.root.params.requestId
                                if cancelled_id in self._in_flight:
                                    await self._in_flight[cancelled_id].cancel()
                            else:
                                if isinstance(notification.root, ProgressNotification):
                                    token = notification.root.params.progressToken
                                    if token in self._progress_callbacks:
                                        cb = self._progress_callbacks[token]
                                        try:
                                            await cb(
                                                notification.root.params.progress,
                                                notification.root.params.total,
                                                notification.root.params.message,
                                            )
                                        except Exception as exc:
                                            logger.error('Progress callback raised: %s', exc)
                                await self._received_notification(notification)
                                await self._handle_incoming(notification)
                        except Exception as exc:
                            logger.warning(
                                'Failed to validate notification: %s. Message: %s',
                                exc, message.message.root,
                            )

                    else:
                        # Response or error.  Use _handle_response() for newer SDK,
                        # fall back to direct stream dispatch for older SDK.
                        if hasattr(self, '_handle_response'):
                            await self._handle_response(message)
                        else:
                            root = message.message.root
                            response_id = root.id
                            stream = self._response_streams.pop(response_id, None)
                            if stream:
                                await stream.send(root)
                            else:
                                await self._handle_incoming(
                                    RuntimeError(
                                        f'Received response with unknown request ID: {message}'
                                    )
                                )

            except anyio.ClosedResourceError:
                logger.debug('RpcClientSession: read stream closed')
            except Exception as exc:
                logger.exception(
                    'RpcClientSession: unhandled exception in receive loop: %s', exc
                )
            finally:
                for req_id, stream in list(self._response_streams.items()):
                    error = ErrorData(
                        code=connection_closed_code,
                        message='Connection closed',
                    )
                    try:
                        await stream.send(
                            JSONRPCError(jsonrpc='2.0', id=req_id, error=error)
                        )
                        await stream.aclose()
                    except Exception:
                        pass
                self._response_streams.clear()

    async def _dispatch_custom_request(self, raw_req: Any) -> None:
        """Dispatch a custom server-to-client request to its registered handler.

        Serialises the handler's return value and sends a JSON-RPC response.
        On handler exception, sends an INVALID_PARAMS error response.
        """
        from mcp.types import (
            ErrorData,
            INVALID_PARAMS,
            JSONRPCError,
            JSONRPCMessage,
            JSONRPCResponse,
        )

        handler = self._custom_handlers[raw_req.method]
        raw_params: dict[str, Any] = raw_req.params or {}

        try:
            result_obj = await handler(raw_params)
            if hasattr(result_obj, 'model_dump'):
                result_dict: dict[str, Any] = result_obj.model_dump(
                    by_alias=True, mode='json', exclude_none=True
                )
            elif isinstance(result_obj, dict):
                result_dict = result_obj
            else:
                result_dict = {}

            response = JSONRPCResponse(
                jsonrpc='2.0',
                id=raw_req.id,
                result=result_dict,
            )
            await self._write_stream.send(
                SessionMessage(message=JSONRPCMessage(response))
            )
        except Exception as exc:
            logger.warning('Custom handler for %r raised: %s', raw_req.method, exc)
            error_resp = JSONRPCError(
                jsonrpc='2.0',
                id=raw_req.id,
                error=ErrorData(
                    code=INVALID_PARAMS,
                    message=str(exc),
                    data=None,
                ),
            )
            await self._write_stream.send(
                SessionMessage(message=JSONRPCMessage(error_resp))
            )

    async def _dispatch_sdk_request(self, message: Any) -> None:
        """Validate and dispatch a standard SDK request (mirrors BaseSession logic)."""
        from mcp.types import (
            ErrorData,
            INVALID_PARAMS,
            JSONRPCError,
            JSONRPCMessage,
        )

        try:
            validated_request = self._receive_request_type.model_validate(
                message.message.root.model_dump(
                    by_alias=True, mode='json', exclude_none=True
                )
            )
            responder = RequestResponder(
                request_id=message.message.root.id,
                request_meta=(
                    validated_request.root.params.meta
                    if validated_request.root.params
                    else None
                ),
                request=validated_request,
                session=self,
                on_complete=lambda r: self._in_flight.pop(r.request_id, None),
                message_metadata=message.metadata,
            )
            self._in_flight[responder.request_id] = responder
            await self._received_request(responder)

            if not responder._completed:  # type: ignore[reportPrivateUsage]
                await self._handle_incoming(responder)

        except Exception as exc:
            logger.warning('Failed to validate SDK request: %s', exc)
            error_response = JSONRPCError(
                jsonrpc='2.0',
                id=message.message.root.id,
                error=ErrorData(
                    code=INVALID_PARAMS,
                    message='Invalid request parameters',
                    data='',
                ),
            )
            await self._write_stream.send(
                SessionMessage(message=JSONRPCMessage(error_response))
            )


# ---------------------------------------------------------------------------
# Helper: build standard test function definitions
# ---------------------------------------------------------------------------

def _make_test_functions() -> list[FunctionDefinition]:
    """Return a minimal list of FunctionDefinitions for test use."""
    return [
        FunctionDefinition(
            name='test_add',
            description='Add two integers and return the sum',
            parameterOrder=['a', 'b'],
            inputSchema={
                'type': 'object',
                'properties': {
                    'a': {'type': 'integer', 'description': 'First operand'},
                    'b': {'type': 'integer', 'description': 'Second operand'},
                },
                'required': ['a', 'b'],
            },
            returnDescription='Sum of a and b',
        ),
    ]


# ---------------------------------------------------------------------------
# Async helpers — each creates its own RpcClientSession connection
# ---------------------------------------------------------------------------

async def _call_with_rpc(
    server_status: dict,
    code: str,
    functions: list[FunctionDefinition] | None = None,
    call_handler: Any = None,
) -> dict:
    """Connect with RpcClientSession, run an idapython snippet, return result dict.

    Args:
        server_status: The headless_server fixture dict.
        code:          Python code to execute via the idapython tool.
        functions:     FunctionDefinitions to return from mcpy/listFunctions.
                       Defaults to [test_add].
        call_handler:  async callable(params: dict) -> CallFunctionResult.
                       Defaults to a handler that evaluates test_add(a, b) = a + b.
    """
    import json

    if functions is None:
        functions = _make_test_functions()

    if call_handler is None:
        async def _default_call_handler(params: dict) -> CallFunctionResult:
            name = params.get('name')
            args = params.get('arguments') or {}
            if name == 'test_add':
                return CallFunctionResult(content=args['a'] + args['b'])
            raise ValueError(f'Unknown function: {name}')
        call_handler = _default_call_handler

    async def _list_functions_handler(params: dict) -> ListFunctionsResult:
        return ListFunctionsResult(functions=functions)

    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    async with streamablehttp_client(url) as (read, write, _):
        async with RpcClientSession(read, write) as session:
            session.register_custom_handler(_LIST_FUNCTIONS_METHOD, _list_functions_handler)
            session.register_custom_handler(_CALL_FUNCTION_METHOD, call_handler)

            await session.initialize()

            with anyio.fail_after(MCP_CALL_TIMEOUT):
                result = await session.call_tool('idapython', {'code': code, 'reset': True})

    if result.isError:
        error_texts = [
            item.text for item in result.content if hasattr(item, 'text')
        ]
        raise AssertionError(
            f"idapython tool returned error: {' '.join(error_texts)}"
        )

    texts = [item.text for item in result.content if hasattr(item, 'text')]
    for text in texts:
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
    raise AssertionError(f'No JSON in tool result: {texts}')


async def _call_standard(server_status: dict, code: str) -> dict:
    """Connect with a standard (unmodified) ClientSession, run an idapython snippet.

    No experimental capability is declared, so the server will NOT inject
    callback functions.
    """
    import json

    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    async with streamablehttp_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                result = await session.call_tool('idapython', {'code': code, 'reset': True})

    if result.isError:
        error_texts = [
            item.text for item in result.content if hasattr(item, 'text')
        ]
        raise AssertionError(
            f"idapython tool returned error: {' '.join(error_texts)}"
        )

    texts = [item.text for item in result.content if hasattr(item, 'text')]
    for text in texts:
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
    raise AssertionError(f'No JSON in tool result: {texts}')


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestRpcCallbacks:
    """E2E tests for the mcpy/rpcCallbacks protocol extension.

    All tests use the module-scoped headless_server fixture (crackme.elf).
    Each test creates its own MCP connection so handlers are connection-scoped.
    """

    def test_callback_function_works(self, headless_server: dict) -> None:
        """Server discovers test_add via mcpy/listFunctions; script calls it."""

        async def _test() -> None:
            data = await _call_with_rpc(headless_server, 'test_add(3, 4)')
            assert data['success'] is True, f"Script failed: {data.get('error')}"
            assert data['result'] == '7', (
                f"Expected result='7', got {data['result']!r}.\n"
                f"stdout={data.get('stdout')!r}\nstderr={data.get('stderr')!r}"
            )

        anyio.run(_test)

    def test_nested_namespace_projection(self, headless_server: dict) -> None:
        """A '__'-separated function name projects into nested namespaces."""

        async def _test() -> None:
            functions = [
                FunctionDefinition(
                    name='mcp__svc__test_add',
                    description='Add two integers and return the sum',
                    parameterOrder=['a', 'b'],
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'a': {'type': 'integer', 'description': 'First operand'},
                            'b': {'type': 'integer', 'description': 'Second operand'},
                        },
                        'required': ['a', 'b'],
                    },
                    returnDescription='Sum of a and b',
                ),
            ]

            async def _handler(params: dict) -> CallFunctionResult:
                # The server calls back with the ORIGINAL (raw) function name.
                args = params.get('arguments') or {}
                if params.get('name') == 'mcp__svc__test_add':
                    return CallFunctionResult(content=args['a'] + args['b'])
                raise ValueError(f"Unknown function: {params.get('name')}")

            data = await _call_with_rpc(
                headless_server,
                'mcp.svc.test_add(8, 9)',
                functions=functions,
                call_handler=_handler,
            )
            assert data['success'] is True, f"Script failed: {data.get('error')}"
            assert data['result'] == '17', (
                f"Expected result='17', got {data['result']!r}.\n"
                f"stdout={data.get('stdout')!r}\nstderr={data.get('stderr')!r}"
            )

        anyio.run(_test)

    def test_callback_with_rpc_timeout(self, headless_server: dict) -> None:
        """_rpc_timeout keyword argument is accepted and call still succeeds."""

        async def _test() -> None:
            data = await _call_with_rpc(
                headless_server, 'test_add(10, 5, _rpc_timeout=30)'
            )
            assert data['success'] is True, f"Script failed: {data.get('error')}"
            assert data['result'] == '15', (
                f"Expected result='15', got {data['result']!r}"
            )

        anyio.run(_test)

    def test_no_callbacks_when_client_unsupported(self, headless_server: dict) -> None:
        """Without mcpy/rpcCallbacks capability, test_add is not in script globals."""

        async def _test() -> None:
            data = await _call_standard(headless_server, "'test_add' in dir()")
            assert data['success'] is True, f"Script failed: {data.get('error')}"
            assert data['result'] == 'False', (
                f"Expected test_add not injected, but result={data['result']!r}"
            )

        anyio.run(_test)

    def test_rpc_not_available_standard_client(self, headless_server: dict) -> None:
        """Without capability, the 'rpc' namespace object is not injected at all."""

        async def _test() -> None:
            # When no mcpy/rpcCallbacks capability is declared, the server does not
            # inject the 'rpc' global — so 'rpc' is simply not in scope.
            data = await _call_standard(headless_server, "'rpc' in dir()")
            assert data['success'] is True, f"Script failed: {data.get('error')}"
            assert data['result'] == 'False', (
                f"Expected 'rpc' not in globals, got result={data['result']!r}"
            )

        anyio.run(_test)

    def test_multiple_callbacks_in_sequence(self, headless_server: dict) -> None:
        """Script can call the same callback multiple times in sequence."""

        async def _test() -> None:
            code = 'result = test_add(1, 2) + test_add(3, 4)'
            data = await _call_with_rpc(headless_server, code)
            assert data['success'] is True, f"Script failed: {data.get('error')}"
            # 1+2=3, 3+4=7, total=10
            assert data['result'] == '10', (
                f"Expected result='10', got {data['result']!r}"
            )

        anyio.run(_test)

    def test_callback_error_propagates(self, headless_server: dict) -> None:
        """A client-side exception in the handler causes the script call to fail."""

        async def _raise_handler(params: dict) -> CallFunctionResult:
            raise ValueError('intentional test error from client')

        async def _test() -> None:
            data = await _call_with_rpc(
                headless_server,
                'test_add(1, 2)',
                call_handler=_raise_handler,
            )
            # The script call should fail because the callback returned an error.
            assert data['success'] is False, (
                f"Expected script to fail when callback raises, but success=True. "
                f"result={data.get('result')!r}"
            )

        anyio.run(_test)
