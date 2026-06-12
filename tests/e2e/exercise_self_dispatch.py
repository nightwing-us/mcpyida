"""Standalone live exerciser for mcp.self.* in-process dispatch.

Run against a RUNNING MCPyIDA server (real IDA):
    MCPYIDA_URL=http://127.0.0.1:6150/mcp python3 tests/e2e/exercise_self_dispatch.py

Not a CI test — reuses the RpcClientSession harness from test_rpc_callbacks.py.
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


def _wing_echo_fn() -> list[FunctionDefinition]:
    return [
        FunctionDefinition(
            name='host__echo',
            description='Echo the input back',
            parameterOrder=['text'],
            inputSchema={
                'type': 'object',
                'properties': {'text': {'type': 'string'}},
                'required': ['text'],
            },
            returnDescription='the same text',
        ),
    ]


async def _run(code: str) -> dict:
    async def _list(params: dict) -> ListFunctionsResult:
        return ListFunctionsResult(functions=_wing_echo_fn())

    async def _call(params: dict) -> CallFunctionResult:
        if params.get('name') == 'host__echo':
            return CallFunctionResult(content=(params.get('arguments') or {}).get('text'))
        raise ValueError(f'unknown function {params.get("name")!r}')

    async with streamablehttp_client(URL) as (read, write, _):
        async with RpcClientSession(read, write) as session:
            session.register_custom_handler(_LIST_FUNCTIONS_METHOD, _list)
            session.register_custom_handler(_CALL_FUNCTION_METHOD, _call)
            await session.initialize()
            with anyio.fail_after(45):
                result = await session.call_tool('idapython', {'code': code, 'reset': True})

    texts = [i.text for i in result.content if hasattr(i, 'text')]
    for t in texts:
        try:
            return json.loads(t)
        except (json.JSONDecodeError, ValueError):
            continue
    return {'success': False, 'error': f'no JSON in {texts!r}', 'isError': result.isError}


# (label, code, expected substring in str(result))
CHECKS = [
    ('self namespace exists', "'self' in dir(mcp)", 'True'),
    ('self.decompile callable', 'callable(mcp.self.decompile)', 'True'),
    ('idapython excluded', "'idapython' in dir(mcp.self)", 'False'),
    ('self.list runs in-process', "len(mcp.self.list(entry_type='function').items) >= 0", 'True'),
    ('host.echo reverse-RPC', "host.echo(text='hi')", 'hi'),
]


def main() -> None:
    print(f'Exercising {URL}')
    failures = 0
    for label, code, expect in CHECKS:
        t0 = time.monotonic()
        data = anyio.run(_run, code)
        dt = time.monotonic() - t0
        ok = bool(data.get('success')) and expect in str(data.get('result'))
        failures += 0 if ok else 1
        print(
            f"[{'PASS' if ok else 'FAIL'}] {label} ({dt:.2f}s) -> "
            f"result={data.get('result')!r} err={data.get('error')!r}"
        )
    print(f'\n{len(CHECKS) - failures}/{len(CHECKS)} checks passed')


if __name__ == '__main__':
    main()
