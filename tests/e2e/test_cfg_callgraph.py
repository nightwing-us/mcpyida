"""E2E tests for cfg, callgraph, and server info via MCP transport.

Tests run against a headless IDA server loaded with crackme.elf.

All tests use the module-scoped headless_server fixture so IDA is
launched only once per test session.

Known properties of tests/fixtures/crackme.elf:
- Functions: main, check_password
- Imports: strcmp (called by check_password)

IDA-specific notes:
- Uses ``idapython`` tool instead of ``pyghidra``
- Callee detection uses ``CodeRefsFrom`` + ``is_call_insn``
- No ``open_program`` tool or ``project://binaries`` resource
- server://info returns ``tool: 'ida'``
"""
from __future__ import annotations

import base64
import json

import anyio
import pytest

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from pydantic import AnyUrl

# Timeout for individual MCP tool calls (seconds)
MCP_CALL_TIMEOUT = 60


# ---------------------------------------------------------------------------
# MCP transport helpers (mirrors test_all_tools.py)
# ---------------------------------------------------------------------------

async def _mcp_call_raw(url: str, tool_name: str, arguments: dict):
    """Call an MCP tool and return the raw CallToolResult."""
    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                return await session.call_tool(tool_name, arguments)


async def _mcp_call(url: str, tool_name: str, arguments: dict) -> str:
    """Call an MCP tool and return concatenated text, raising on MCP error."""
    result = await _mcp_call_raw(url, tool_name, arguments)
    if result.isError:
        error_texts = [
            item.text for item in result.content if hasattr(item, 'text')
        ]
        raise AssertionError(
            f"MCP tool '{tool_name}' returned error: {' '.join(error_texts)}"
        )
    texts = [item.text for item in result.content if hasattr(item, 'text')]
    return '\n'.join(texts)


def mcp_call(server_status: dict, tool_name: str, arguments: dict) -> str:
    """Synchronous wrapper — raises AssertionError on MCP error."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call, url, tool_name, arguments)


def mcp_call_raw(server_status: dict, tool_name: str, arguments: dict):
    """Synchronous wrapper — returns raw CallToolResult."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call_raw, url, tool_name, arguments)


# ---------------------------------------------------------------------------
# Resource reading helper
# ---------------------------------------------------------------------------

async def _read_resource(url: str, uri: str) -> str:
    """Read an MCP resource via the transport and return text content."""
    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                result = await session.read_resource(AnyUrl(uri))
                return result.contents[0].text


def read_resource(server_status: dict, uri: str) -> str:
    """Synchronous wrapper for reading an MCP resource."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_read_resource, url, uri)


# ---------------------------------------------------------------------------
# CFG tests
# ---------------------------------------------------------------------------

class TestCfgTool:
    """E2E tests for the cfg tool via MCP transport."""

    def test_cfg_via_mcp(self, headless_server):
        """cfg tool returns valid CFG through MCP transport."""
        result = mcp_call(headless_server, 'cfg', {'address': 'main'})
        data = json.loads(result)
        assert 'blocks' in data
        assert data['block_count'] > 0
        assert 'features' in data
        for block in data['blocks'].values():
            assert 'address' in block
            assert 'size' in block
            assert 'successors' in block
            assert 'instruction_count' in block

    def test_cfg_normalize_reduces_blocks(self, headless_server):
        """Normalized CFG has fewer or equal blocks than raw."""
        raw_text = mcp_call(headless_server, 'cfg', {'address': 'main', 'normalize': False})
        norm_text = mcp_call(headless_server, 'cfg', {'address': 'main', 'normalize': True})
        raw_data = json.loads(raw_text)
        norm_data = json.loads(norm_text)
        assert norm_data['block_count'] <= raw_data['block_count']

    def test_cfg_with_disassembly(self, headless_server):
        """cfg with include_disassembly returns instruction details."""
        result = mcp_call(
            headless_server, 'cfg',
            {'address': 'main', 'include_disassembly': True}
        )
        data = json.loads(result)
        for block in data['blocks'].values():
            assert block.get('instructions') is not None
            if block['instructions']:
                assert 'mnemonic' in block['instructions'][0]

    def test_cfg_with_bytes(self, headless_server):
        """cfg with include_bytes returns base64-encoded bytes matching block size."""
        result = mcp_call(
            headless_server, 'cfg',
            {'address': 'main', 'include_bytes': True}
        )
        data = json.loads(result)
        for block in data['blocks'].values():
            assert block.get('bytes') is not None
            decoded = base64.b64decode(block['bytes'])
            assert len(decoded) == block['size']

    def test_cfg_called_funcs(self, headless_server):
        """cfg features include called functions (check_password calls strcmp).

        IDA's callee detection uses CodeRefsFrom + is_call_insn.
        """
        result = mcp_call(headless_server, 'cfg', {'address': 'check_password'})
        data = json.loads(result)
        all_called = data['features']['called_funcs']
        assert any('strcmp' in name for name in all_called.values()), (
            f"Expected strcmp in called_funcs, got: {list(all_called.values())}"
        )

    def test_cfg_entry_in_blocks(self, headless_server):
        """cfg entry point address is the key of one of the blocks."""
        result = mcp_call(headless_server, 'cfg', {'address': 'main'})
        data = json.loads(result)
        assert data['entry'] in data['blocks'], (
            f"Entry {data['entry']!r} not found in block keys: {list(data['blocks'].keys())[:5]}"
        )

    def test_cfg_invalid_address_returns_error(self, headless_server):
        """cfg with unknown function name returns an MCP-level error."""
        result = mcp_call_raw(
            headless_server, 'cfg', {'address': 'nonexistent_func_xyz_123'}
        )
        assert result.isError, 'Expected MCP error for unknown function'


# ---------------------------------------------------------------------------
# Callgraph tests
# ---------------------------------------------------------------------------

class TestCallgraphTool:
    """E2E tests for the callgraph tool via MCP transport."""

    def test_callgraph_callees(self, headless_server):
        """callgraph returns callee graph from main."""
        result = mcp_call(headless_server, 'callgraph', {
            'address': 'main', 'direction': 'callees', 'max_depth': 2
        })
        data = json.loads(result)
        assert data['root'] is not None
        assert data['direction'] == 'callees'
        assert len(data['nodes']) > 1
        assert len(data['edges']) > 0
        # Edges should use 'from'/'to' aliases (set via Pydantic Field alias)
        edge = data['edges'][0]
        assert 'from' in edge
        assert 'to' in edge

    def test_callgraph_callers(self, headless_server):
        """callgraph callers direction works.

        IDA uses CodeRefsTo for caller detection.
        """
        result = mcp_call(headless_server, 'callgraph', {
            'address': 'check_password', 'direction': 'callers', 'max_depth': 1
        })
        data = json.loads(result)
        assert data['direction'] == 'callers'
        caller_names = [n['name'] for n in data['nodes'] if n['depth'] == 1]
        assert 'main' in caller_names, (
            f"Expected 'main' in callers of check_password, got: {caller_names}"
        )

    def test_callgraph_depth_limit(self, headless_server):
        """callgraph depth=0 returns only the root node."""
        result = mcp_call(headless_server, 'callgraph', {
            'address': 'main', 'direction': 'callees', 'max_depth': 0
        })
        data = json.loads(result)
        assert len(data['nodes']) == 1
        assert data['nodes'][0]['depth'] == 0

    def test_callgraph_root_is_main(self, headless_server):
        """callgraph root address resolves to main."""
        result = mcp_call(headless_server, 'callgraph', {
            'address': 'main', 'direction': 'callees', 'max_depth': 1
        })
        data = json.loads(result)
        root_addr = data['root']
        root_nodes = [n for n in data['nodes'] if n['addr'] == root_addr]
        assert len(root_nodes) == 1
        assert root_nodes[0]['depth'] == 0
        assert root_nodes[0]['name'] == 'main'

    def test_callgraph_nodes_have_required_fields(self, headless_server):
        """All callgraph nodes have addr, name, and depth fields."""
        result = mcp_call(headless_server, 'callgraph', {
            'address': 'main', 'direction': 'callees', 'max_depth': 2
        })
        data = json.loads(result)
        for node in data['nodes']:
            assert 'addr' in node
            assert 'name' in node
            assert 'depth' in node

    def test_callgraph_invalid_direction_returns_error(self, headless_server):
        """callgraph with invalid direction returns an MCP-level error."""
        result = mcp_call_raw(headless_server, 'callgraph', {
            'address': 'main', 'direction': 'invalid_direction'
        })
        assert result.isError, 'Expected MCP error for invalid direction'


# ---------------------------------------------------------------------------
# Server info resource tests
# ---------------------------------------------------------------------------

class TestServerInfoResource:
    """E2E tests for the server://info resource and MCP handshake."""

    def test_server_info_resource(self, headless_server):
        """server://info resource returns valid JSON via MCP.

        Note: idalib's ``ida_nalt.get_root_filename()`` may return None in some
        environments even when a binary is loaded (idalib limitation).  We only
        assert the binary field when it is non-None.
        """
        raw = read_resource(headless_server, 'server://info')
        data = json.loads(raw)
        assert 'tool' in data
        assert data['tool'] == 'ida'
        assert 'mode' in data
        assert data['mode'] == 'headless'
        assert 'binary' in data
        # binary may be None in idalib environments where get_root_filename() returns ''
        if data['binary'] is not None:
            assert 'crackme' in data['binary'].lower(), (
                f"Expected 'crackme' in binary name, got: {data['binary']!r}"
            )
        assert 'port' in data
        assert data['port'] == headless_server['port']

    def test_server_info_architecture_present(self, headless_server):
        """server://info includes architecture field.

        Note: idalib's ``get_inf_structure()`` may return None in some
        environments.  We assert the key is present; the value may be None.
        """
        raw = read_resource(headless_server, 'server://info')
        data = json.loads(raw)
        assert 'architecture' in data
        # architecture may be None when get_inf_structure() is unavailable
        assert 'architecture' in data  # key must exist; value may be None

    def test_instructions_in_handshake(self, headless_server):
        """MCP instructions field contains server info in the initialize response."""
        async def _check():
            url = f"http://{headless_server['host']}:{headless_server['port']}/mcp"
            async with streamablehttp_client(url) as (read, write, _):
                async with ClientSession(read, write) as session:
                    result = await session.initialize()
                    return result

        result = anyio.run(_check)
        assert result.instructions is not None, 'Expected non-None instructions in handshake'
        assert 'MCP Server' in result.instructions or 'MCPyIDA' in result.instructions, (
            f"Expected server name in instructions, got: {result.instructions[:200]!r}"
        )
        assert 'headless' in result.instructions.lower(), (
            f"Expected 'headless' in instructions, got: {result.instructions[:200]!r}"
        )
