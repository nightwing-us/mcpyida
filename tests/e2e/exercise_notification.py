"""Live check: notifications/mcpy/functions/list_changed triggers re-discovery.

The client exposes function set A (host__foo), runs idapython to discover it, then
sends notifications/mcpy/functions/list_changed while switching to set B
(host__bar). After the notification, a second idapython call must see the NEW set
(bar present, foo gone) — proving the receive-side mcpy/ notification routing
reached _on_functions_changed and invalidated the discovery cache.

Run against a RUNNING MCPyIDA server (real IDA):
    MCPYIDA_URL=http://127.0.0.1:6153/mcp python3 -m tests.e2e.exercise_notification
"""
from __future__ import annotations

import json
import os

import anyio
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCNotification

from mcpyida.rpc_types import CallFunctionResult, FunctionDefinition, ListFunctionsResult
from tests.e2e.test_rpc_callbacks import (
    RpcClientSession,
    _CALL_FUNCTION_METHOD,
    _LIST_FUNCTIONS_METHOD,
)

URL = os.environ.get('MCPYIDA_URL', 'http://127.0.0.1:6153/mcp')
_state = {'which': 'foo'}


def _fns(which: str) -> list[FunctionDefinition]:
    return [
        FunctionDefinition(
            name=f'host__{which}',
            description='probe',
            parameterOrder=[],
            inputSchema={'type': 'object', 'properties': {}},
        ),
    ]


def _result(tool_result) -> str:
    texts = [i.text for i in tool_result.content if hasattr(i, 'text')]
    for t in texts:
        try:
            return str(json.loads(t).get('result'))
        except (json.JSONDecodeError, ValueError):
            continue
    return f'<no json: {texts!r}>'


async def _run() -> dict:
    async def _list(params: dict) -> ListFunctionsResult:
        return ListFunctionsResult(functions=_fns(_state['which']))

    async def _call(params: dict) -> CallFunctionResult:
        return CallFunctionResult(content='ok')

    out: dict = {}
    async with streamablehttp_client(URL) as (read, write, _):
        async with RpcClientSession(read, write) as session:
            session.register_custom_handler(_LIST_FUNCTIONS_METHOD, _list)
            session.register_custom_handler(_CALL_FUNCTION_METHOD, _call)
            await session.initialize()

            with anyio.fail_after(30):
                r1 = await session.call_tool(
                    'idapython', {'code': 'sorted(dir(host))', 'reset': True}
                )
            out['after_init'] = _result(r1)

            # Switch the exposed set, then notify the server its list changed.
            _state['which'] = 'bar'
            note = SessionMessage(
                message=JSONRPCMessage(
                    JSONRPCNotification(
                        jsonrpc='2.0', method='notifications/mcpy/functions/list_changed'
                    )
                )
            )
            await session._write_stream.send(note)
            await anyio.sleep(0.7)  # let the notification be routed

            with anyio.fail_after(30):
                r2 = await session.call_tool(
                    'idapython', {'code': 'sorted(dir(host))', 'reset': True}
                )
            out['after_notification'] = _result(r2)
    return out


def main() -> None:
    print(f'Notification re-discovery test vs {URL}')
    data = anyio.run(_run)
    init = data.get('after_init', '')
    after = data.get('after_notification', '')
    discovered_a = "'foo'" in init or 'foo' in init
    rediscovered_b = ('bar' in after) and ('foo' not in after)
    print(f"  after_init        : {init!r}   (expect host.foo)")
    print(f"  after_notification: {after!r}   (expect host.bar, no foo)")
    print(
        f"\n[{'PASS' if discovered_a and rediscovered_b else 'FAIL'}] "
        f"re-discovery on mcpy/functions/list_changed"
    )


if __name__ == '__main__':
    main()
