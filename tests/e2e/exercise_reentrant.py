"""Live exerciser for the FORBIDDEN re-entrant path.

An idapython script calls host.reenter(); the client-side handler for that
callback calls BACK into this server's own `list` tool (a tools/call on the same
session) while the script is suspended waiting for the callback result.

Per docs/specs/rpc-callbacks.md ("Re-Entrancy & Recursion Limits"), clients
MUST NOT re-enter the originating server during a callback. This script just
observes the server's actual behavior:
  - headless: the re-entrant call's IDA work is queued on _ida_work_queue, which
    the suspended script's pump drains, so it may complete.
  - GUI: the script busy-pumps a Python loop inside an execute_sync callback on
    the IDA main thread, so the re-entrant call's nested execute_sync starves —
    expected to time out (bounded below).

Run against a RUNNING MCPyIDA server (real IDA):
    MCPYIDA_URL=http://127.0.0.1:6150/mcp python3 -m tests.e2e.exercise_reentrant
(or with PYTHONPATH=. python3 tests/e2e/exercise_reentrant.py)
"""
from __future__ import annotations

import json
import os
import time

import anyio
from mcp.client.streamable_http import streamablehttp_client

from mcpyida.rpc_types import CallFunctionResult, FunctionDefinition, ListFunctionsResult
from tests.e2e.test_rpc_callbacks import (
    RpcClientSession,
    _CALL_FUNCTION_METHOD,
    _LIST_FUNCTIONS_METHOD,
)

URL = os.environ.get('MCPYIDA_URL', 'http://127.0.0.1:6150/mcp')
# Our own tool the client re-enters during the callback. 'list' is read-only and
# hits the IDA-thread dispatch path; 'idapython' hits the single-flight lock and
# (with the re-entrancy guard) fast-fails with a clear message instead of hanging.
REENTRANT_TOOL = os.environ.get('REENTRANT_TOOL', 'list')
_REENTRANT_ARGS = {
    'list': {'entry_type': 'function', 'offset': 0, 'limit': 1},
    'idapython': {'code': '1 + 1', 'reset': True},
}
# Bound the inner re-entrant call so a deadlock surfaces as a timeout, not a hang.
INNER_TIMEOUT = float(os.environ.get('REENTRANT_INNER_TIMEOUT', '15'))
OUTER_TIMEOUT = float(os.environ.get('REENTRANT_OUTER_TIMEOUT', '50'))


def _reenter_fn() -> list[FunctionDefinition]:
    return [
        FunctionDefinition(
            name='host__reenter',
            description='Client callback that re-enters the originating server.',
            parameterOrder=[],
            inputSchema={'type': 'object', 'properties': {}},
            returnDescription='status string',
        ),
    ]


async def _run() -> dict:
    holder: dict = {}

    async def _list(params: dict) -> ListFunctionsResult:
        return ListFunctionsResult(functions=_reenter_fn())

    async def _call(params: dict) -> CallFunctionResult:
        if params.get('name') == 'host__reenter':
            session = holder['session']
            inner_t0 = time.monotonic()
            try:
                args = _REENTRANT_ARGS.get(
                    REENTRANT_TOOL, {'entry_type': 'function', 'limit': 1}
                )
                with anyio.fail_after(INNER_TIMEOUT):
                    r = await session.call_tool(REENTRANT_TOOL, args)
                dt = time.monotonic() - inner_t0
                texts = [i.text for i in r.content if hasattr(i, 'text')]
                return CallFunctionResult(
                    content=f'reentered in {dt:.2f}s (isError={r.isError}): {" ".join(texts)[:200]}'
                )
            except TimeoutError:
                dt = time.monotonic() - inner_t0
                return CallFunctionResult(
                    content=f'reentrant call TIMED OUT after {dt:.2f}s'
                )
        raise ValueError(f'unknown function {params.get("name")!r}')

    async with streamablehttp_client(URL) as (read, write, _):
        async with RpcClientSession(read, write) as session:
            holder['session'] = session
            session.register_custom_handler(_LIST_FUNCTIONS_METHOD, _list)
            session.register_custom_handler(_CALL_FUNCTION_METHOD, _call)
            await session.initialize()
            with anyio.fail_after(OUTER_TIMEOUT):
                result = await session.call_tool(
                    'idapython', {'code': 'host.reenter()', 'reset': True}
                )

    texts = [i.text for i in result.content if hasattr(i, 'text')]
    for t in texts:
        try:
            return json.loads(t)
        except (json.JSONDecodeError, ValueError):
            continue
    return {'success': False, 'error': f'no JSON in {texts!r}', 'isError': result.isError}


def main() -> None:
    print(f'Re-entrancy test vs {URL} (script: host.reenter() -> server.{REENTRANT_TOOL})')
    t0 = time.monotonic()
    try:
        data = anyio.run(_run)
        dt = time.monotonic() - t0
        print(
            f'({dt:.2f}s) success={data.get("success")} '
            f'result={data.get("result")!r} error={data.get("error")!r}'
        )
    except Exception as exc:  # noqa: BLE001 - exerciser surfaces any failure mode
        dt = time.monotonic() - t0
        print(f'({dt:.2f}s) RAISED {type(exc).__name__}: {exc}')


if __name__ == '__main__':
    main()
