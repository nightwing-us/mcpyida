"""Test that the MCP server handles concurrent requests."""
import anyio
import pytest

from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession

# Timeout for each concurrent tool call (seconds)
MCP_CALL_TIMEOUT = 60


class TestConcurrency:
    """Verify the async server can handle multiple simultaneous tool calls."""

    def test_concurrent_tool_calls(self, headless_server):
        """Two tool calls made concurrently should both succeed."""

        async def _test():
            url = f"http://{headless_server['host']}:{headless_server['port']}/mcp"

            async with streamablehttp_client(url) as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()

                    results = [None, None]

                    async with anyio.create_task_group() as tg:
                        async def call_list():
                            with anyio.fail_after(MCP_CALL_TIMEOUT):
                                results[0] = await session.call_tool('list', {
                                    'entry_type': 'function',
                                    'offset': 0,
                                    'limit': 5,
                                })

                        async def call_context():
                            with anyio.fail_after(MCP_CALL_TIMEOUT):
                                results[1] = await session.call_tool('context', {})

                        tg.start_soon(call_list)
                        tg.start_soon(call_context)

                    # Both should have results
                    assert results[0] is not None, 'list call returned None'
                    assert results[1] is not None, 'context call returned None'
                    assert not results[0].isError, f'list call failed: {results[0]}'
                    assert not results[1].isError, f'context call failed: {results[1]}'

        anyio.run(_test)

    def test_concurrent_decompile_calls(self, headless_server):
        """Two decompile calls for different functions should both succeed."""

        async def _test():
            url = f"http://{headless_server['host']}:{headless_server['port']}/mcp"

            async with streamablehttp_client(url) as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()

                    results = [None, None]

                    async with anyio.create_task_group() as tg:
                        async def decompile_main():
                            with anyio.fail_after(MCP_CALL_TIMEOUT):
                                results[0] = await session.call_tool('decompile', {
                                    'items': [{'name': 'main'}],
                                })

                        async def decompile_check():
                            with anyio.fail_after(MCP_CALL_TIMEOUT):
                                results[1] = await session.call_tool('decompile', {
                                    'items': [{'name': 'check_password'}],
                                })

                        tg.start_soon(decompile_main)
                        tg.start_soon(decompile_check)

                    assert results[0] is not None
                    assert results[1] is not None
                    assert not results[0].isError
                    assert not results[1].isError

        anyio.run(_test)
