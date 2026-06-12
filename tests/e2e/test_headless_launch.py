"""E2E test: prove that MCPyIDA headless launch works.

This test IS the contract for MCP client integration.
"""
import anyio
import pytest

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_CALL_TIMEOUT = 30


class TestHeadlessLaunch:
    """Validate the headless launch contract."""

    def test_server_reports_ready(self, headless_server):
        assert headless_server['status'] == 'ready'
        assert headless_server['port'] > 0
        assert headless_server['host'] == '127.0.0.1'
        assert 'crackme' in headless_server['binary']

    def test_mcp_endpoint_reachable(self, headless_server):
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 1,
        })
        assert result is not None

    def test_list_functions_finds_main(self, headless_server):
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 100,
        })
        assert 'main' in result, (
            f'Expected "main" in function list, got: {result[:500]}'
        )

    def test_decompile_main(self, headless_server):
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'main'}],
        })
        assert 'check_password' in result, (
            f'Expected "check_password" in decompilation, got: {result[:500]}'
        )


async def _mcp_call(url: str, tool_name: str, arguments: dict) -> str:
    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                result = await session.call_tool(tool_name, arguments)
            if result.isError:
                error_texts = [
                    item.text for item in result.content if hasattr(item, 'text')
                ]
                raise AssertionError(
                    f"MCP tool '{tool_name}' returned error: {' '.join(error_texts)}"
                )
            texts = [
                item.text
                for item in result.content
                if hasattr(item, 'text')
            ]
            return '\n'.join(texts)


def mcp_call(server_status: dict, tool_name: str, arguments: dict) -> str:
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call, url, tool_name, arguments)
