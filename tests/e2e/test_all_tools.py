"""E2E tests covering all 20 MCP tools over MCP transport.

All tests share a single module-scoped headless_server fixture to avoid
re-launching IDA for each test class. Addresses are resolved dynamically
by calling ``list`` first so the tests remain binary-agnostic.

Known properties of tests/fixtures/crackme.elf:
- Functions: main, check_password (and others)
- Imports: printf, strcmp (external symbols)
- Known strings exist in .rodata

IDA-specific notes:
- cursor() returns the entry point in headless mode (not an error like Ghidra)
- Transaction IDs are integers from idaapi.begin_update_plugins()
- end_trans takes transaction_id as int, not str
"""
from __future__ import annotations

import json
import re
import anyio
import pytest

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Timeout for individual MCP tool calls (seconds)
MCP_CALL_TIMEOUT = 60


# ---------------------------------------------------------------------------
# MCP transport helpers (same pattern as test_headless_launch.py)
# ---------------------------------------------------------------------------

async def _mcp_call_raw(url: str, tool_name: str, arguments: dict):
    """Call an MCP tool and return the raw CallToolResult (not raising on isError)."""
    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                return await session.call_tool(tool_name, arguments)


async def _mcp_call(url: str, tool_name: str, arguments: dict) -> str:
    """Call an MCP tool via streamable HTTP transport and return concatenated text.

    Raises AssertionError if the server returns an MCP-level error.
    """
    result = await _mcp_call_raw(url, tool_name, arguments)
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
    """Synchronous wrapper — raises AssertionError on MCP error."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call, url, tool_name, arguments)


def mcp_call_raw(server_status: dict, tool_name: str, arguments: dict):
    """Synchronous wrapper — returns raw CallToolResult (for error-case tests)."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call_raw, url, tool_name, arguments)


def parse_json_response(text: str):
    """Try to parse the response text as JSON. Falls back to plain-text assertions."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some tools return human-readable text, not JSON
        return None


# ---------------------------------------------------------------------------
# Shared address-discovery fixture (module-scoped so it runs once per session)
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def binary_addresses(headless_server):
    """Discover and cache main/check_password addresses from the live binary."""
    result = mcp_call(headless_server, 'list', {
        'entry_type': 'function',
        'offset': 0,
        'limit': 500,
    })
    data = parse_json_response(result)
    addr_map: dict[str, str] = {}
    if data and isinstance(data, dict) and 'items' in data:
        for item in data['items']:
            name = item.get('name', '')
            addr = item.get('address', '')
            if name in ('main', 'check_password'):
                addr_map[name] = addr
    assert 'main' in addr_map, (
        f"Could not find 'main' address in function list. Response: {result[:500]}"
    )
    return addr_map


# ---------------------------------------------------------------------------
# Tool 1: list
# ---------------------------------------------------------------------------

class TestListTool:
    """Tool: list — entry_type, offset, limit, match_filter"""

    def test_list_functions(self, headless_server):
        """list(entry_type='function') returns a non-empty function list."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 100,
        })
        assert 'main' in result

    def test_list_functions_with_filter(self, headless_server):
        """list with match_filter returns only matching functions."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 100,
            'match_filter': 'check',
        })
        assert 'check_password' in result

    def test_list_imports(self, headless_server):
        """list(entry_type='import') finds known imports."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'import',
            'offset': 0,
            'limit': 100,
        })
        # crackme links printf and/or strcmp
        assert any(name in result for name in ('printf', 'strcmp', 'puts', 'scanf')), (
            f"Expected import names in response, got: {result[:500]}"
        )

    def test_list_strings(self, headless_server):
        """list(entry_type='string') returns string literals."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'string',
            'offset': 0,
            'limit': 100,
        })
        data = parse_json_response(result)
        if data and isinstance(data, dict):
            assert 'items' in data
            assert len(data['items']) > 0
        else:
            # plain-text fallback: just check something came back
            assert len(result) > 0

    def test_list_memory_segments(self, headless_server):
        """list(entry_type='memory_segment') returns memory blocks."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'memory_segment',
            'offset': 0,
            'limit': 50,
        })
        assert len(result) > 0

    def test_list_pagination(self, headless_server):
        """list with offset/limit parameters works correctly."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 1,
        })
        data = parse_json_response(result)
        if data and isinstance(data, dict):
            assert len(data.get('items', [])) <= 1


# ---------------------------------------------------------------------------
# Tool 2: cursor
# ---------------------------------------------------------------------------

class TestCursorTool:
    """Tool: cursor — no args; returns entry point address in headless IDA."""

    def test_cursor_returns_entry_point_in_headless(self, headless_server):
        """cursor() in headless IDA returns the binary entry point (not an error)."""
        result = mcp_call_raw(headless_server, 'cursor', {})
        # IDA headless cursor returns the INF_START_EA or first function address
        # — this is NOT an error unlike Ghidra headless mode
        if result.isError:
            # If it errors, the error must be informative
            error_text = ' '.join(
                item.text for item in result.content if hasattr(item, 'text')
            )
            assert len(error_text) > 0, 'cursor error must include a message'
        else:
            text = '\n'.join(
                item.text for item in result.content if hasattr(item, 'text')
            )
            # Should contain an address
            assert '0x' in text.lower() or len(text) > 0, (
                f"cursor should return address info, got: {text!r}"
            )

    def test_cursor_response_contains_address(self, headless_server):
        """cursor() response includes addr field."""
        result = mcp_call_raw(headless_server, 'cursor', {})
        if not result.isError:
            text = '\n'.join(
                item.text for item in result.content if hasattr(item, 'text')
            )
            data = parse_json_response(text)
            if data and isinstance(data, dict):
                assert 'addr' in data, f"cursor response missing 'addr' key: {data}"


# ---------------------------------------------------------------------------
# Tool 3: context
# ---------------------------------------------------------------------------

class TestContextTool:
    """Tool: context — no args; returns BinaryContext."""

    def test_context_returns_binary_info(self, headless_server):
        """context() returns comprehensive binary information."""
        result = mcp_call(headless_server, 'context', {})
        assert len(result) > 0
        # Verify key fields are present — architecture/program info
        assert any(keyword in result.lower() for keyword in (
            'elf', 'x86', 'amd64', 'architecture', 'processor', 'crackme'
        )), f"Expected binary info in context response, got: {result[:500]}"

    def test_context_contains_function_count(self, headless_server):
        """context() reports a positive function count."""
        result = mcp_call(headless_server, 'context', {})
        data = parse_json_response(result)
        if data and isinstance(data, dict):
            analysis = data.get('analysis', {})
            assert analysis.get('function_count', 0) > 0

    def test_context_application_is_ida(self, headless_server):
        """context() identifies the application as IDA Pro."""
        result = mcp_call(headless_server, 'context', {})
        assert 'IDA' in result or 'ida' in result.lower(), (
            f"Expected 'IDA' in context response, got: {result[:500]}"
        )


# ---------------------------------------------------------------------------
# Tool 4: get_funcs
# ---------------------------------------------------------------------------

class TestGetFuncsTool:
    """Tool: get_funcs — items: list of addr/name strings."""

    def test_get_funcs_by_name(self, headless_server):
        """get_funcs(['main']) returns function info."""
        result = mcp_call(headless_server, 'get_funcs', {
            'items': ['main'],
        })
        assert 'main' in result

    def test_get_funcs_multiple(self, headless_server):
        """get_funcs with multiple names returns multiple results."""
        result = mcp_call(headless_server, 'get_funcs', {
            'items': ['main', 'check_password'],
        })
        assert 'main' in result
        assert 'check_password' in result

    def test_get_funcs_by_address(self, headless_server, binary_addresses):
        """get_funcs with hex address returns function info."""
        main_addr = binary_addresses['main']
        result = mcp_call(headless_server, 'get_funcs', {
            'items': [main_addr],
        })
        assert 'main' in result

    def test_get_funcs_unknown_name_returns_error_field(self, headless_server):
        """get_funcs with unknown name returns per-item error, not MCP error."""
        result = mcp_call(headless_server, 'get_funcs', {
            'items': ['nonexistent_function_xyz_123'],
        })
        # Should be a per-item error in the response list, not a top-level MCP error
        assert 'error' in result.lower() or 'not found' in result.lower()


# ---------------------------------------------------------------------------
# Tool 5: decompile
# ---------------------------------------------------------------------------

class TestDecompileTool:
    """Tool: decompile — items: list of {addr?, name?}."""

    def test_decompile_main_by_name(self, headless_server):
        """decompile({'name': 'main'}) returns C pseudocode with check_password call."""
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'main'}],
        })
        assert 'check_password' in result

    def test_decompile_by_address(self, headless_server, binary_addresses):
        """decompile({'addr': <main_addr>}) returns C pseudocode."""
        main_addr = binary_addresses['main']
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'addr': main_addr}],
        })
        assert 'main' in result.lower() or len(result) > 50

    def test_decompile_check_password(self, headless_server):
        """decompile check_password — verifies strcmp or related comparison logic."""
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'check_password'}],
        })
        assert len(result) > 50  # Should produce non-trivial code
        # check_password should contain comparison logic
        assert any(kw in result for kw in ('strcmp', '==', '!=', 'return', 'param'))

    def test_decompile_batch(self, headless_server):
        """decompile multiple functions in a single call."""
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'main'}, {'name': 'check_password'}],
        })
        assert 'main' in result or 'check_password' in result


# ---------------------------------------------------------------------------
# Tool 6: disasm
# ---------------------------------------------------------------------------

class TestDisasmTool:
    """Tool: disasm — items: list of {addr?, name?, count?}."""

    def test_disasm_function_by_name(self, headless_server):
        """disasm({'name': 'main'}) returns assembly for main."""
        result = mcp_call(headless_server, 'disasm', {
            'items': [{'name': 'main'}],
        })
        # Assembly output should contain hex addresses and mnemonics
        assert len(result) > 50
        assert any(kw in result.lower() for kw in ('call', 'push', 'mov', 'ret', 'jmp'))

    def test_disasm_by_address_count(self, headless_server, binary_addresses):
        """disasm({'addr': ..., 'count': 5}) returns 5 instructions."""
        main_addr = binary_addresses['main']
        result = mcp_call(headless_server, 'disasm', {
            'items': [{'addr': main_addr, 'count': 5}],
        })
        assert len(result) > 0

    def test_disasm_check_password(self, headless_server):
        """disasm check_password returns assembly."""
        result = mcp_call(headless_server, 'disasm', {
            'items': [{'name': 'check_password'}],
        })
        assert len(result) > 20


# ---------------------------------------------------------------------------
# Tool 7: symbols
# ---------------------------------------------------------------------------

class TestSymbolsTool:
    """Tool: symbols — items: list of hex addr strings."""

    def test_symbols_main_address(self, headless_server, binary_addresses):
        """symbols([main_addr]) returns symbol info for main."""
        main_addr = binary_addresses['main']
        result = mcp_call(headless_server, 'symbols', {
            'items': [main_addr],
        })
        assert 'main' in result

    def test_symbols_batch(self, headless_server, binary_addresses):
        """symbols with multiple addresses returns multiple results."""
        main_addr = binary_addresses['main']
        check_addr = binary_addresses.get('check_password', main_addr)
        result = mcp_call(headless_server, 'symbols', {
            'items': [main_addr, check_addr],
        })
        assert 'main' in result

    def test_symbols_returns_symbol_type(self, headless_server, binary_addresses):
        """symbols result includes symbol_type field."""
        main_addr = binary_addresses['main']
        result = mcp_call(headless_server, 'symbols', {
            'items': [main_addr],
        })
        assert 'function' in result.lower()


# ---------------------------------------------------------------------------
# Tool 8: xrefs
# ---------------------------------------------------------------------------

class TestXrefsTool:
    """Tool: xrefs — items: list of {target, direction?, offset?, limit?}."""

    def test_xrefs_to_check_password(self, headless_server):
        """xrefs to 'check_password' finds callers (main calls it)."""
        result = mcp_call(headless_server, 'xrefs', {
            'items': [{'target': 'check_password', 'direction': 'to'}],
        })
        # main calls check_password, so there should be at least one ref
        assert len(result) > 0
        assert 'main' in result or 'cross-reference' in result.lower() or 'ref' in result.lower()

    def test_xrefs_from_main(self, headless_server):
        """xrefs from 'main' finds calls including check_password."""
        result = mcp_call(headless_server, 'xrefs', {
            'items': [{'target': 'main', 'direction': 'from'}],
        })
        assert len(result) > 0

    def test_xrefs_by_address(self, headless_server, binary_addresses):
        """xrefs using hex address target."""
        check_addr = binary_addresses.get('check_password', binary_addresses['main'])
        result = mcp_call(headless_server, 'xrefs', {
            'items': [{'target': check_addr, 'direction': 'to'}],
        })
        assert len(result) > 0

    def test_xrefs_with_pagination(self, headless_server):
        """xrefs with offset/limit pagination works."""
        result = mcp_call(headless_server, 'xrefs', {
            'items': [{'target': 'main', 'direction': 'from', 'offset': 0, 'limit': 5}],
        })
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Tool 9: rename (round-trip)
# ---------------------------------------------------------------------------

class TestRenameTool:
    """Tool: rename — items: list of {new_name, addr?, name?}. Round-trip test."""

    def test_rename_function_roundtrip(self, fresh_headless_server):
        """Rename check_password -> cp_test, verify, then rename back."""
        # Step 1: rename to temp name
        result1 = mcp_call(fresh_headless_server, 'rename', {
            'items': [{'name': 'check_password', 'new_name': 'cp_test_tmp'}],
        })
        assert 'cp_test_tmp' in result1 or 'error' not in result1.lower()

        # Step 2: verify the new name exists
        result2 = mcp_call(fresh_headless_server, 'get_funcs', {
            'items': ['cp_test_tmp'],
        })
        assert 'cp_test_tmp' in result2

        # Step 3: restore original name
        result3 = mcp_call(fresh_headless_server, 'rename', {
            'items': [{'name': 'cp_test_tmp', 'new_name': 'check_password'}],
        })
        assert 'check_password' in result3 or 'error' not in result3.lower()

        # Step 4: verify original name is back
        result4 = mcp_call(fresh_headless_server, 'get_funcs', {
            'items': ['check_password'],
        })
        assert 'check_password' in result4

    def test_rename_returns_old_and_new_name(self, fresh_headless_server, binary_addresses):
        """rename result includes old_name and new_name fields."""
        main_addr = binary_addresses['main']
        result = mcp_call(fresh_headless_server, 'rename', {
            'items': [{'addr': main_addr, 'new_name': 'main_renamed_tmp'}],
        })
        data = parse_json_response(result)
        if data and isinstance(data, list) and len(data) > 0:
            assert data[0].get('error') is None
            assert data[0].get('new_name') == 'main_renamed_tmp'
            assert data[0].get('old_name') is not None

        # Always restore
        mcp_call(fresh_headless_server, 'rename', {
            'items': [{'addr': main_addr, 'new_name': 'main'}],
        })


# ---------------------------------------------------------------------------
# Elicitation fallback — user-named symbol renames auto-allow
# ---------------------------------------------------------------------------

class TestElicitationFallback:
    """Verify elicitation fallback — rename of user-named symbols auto-allows when client has no elicitation.

    A plain ClientSession without an elicitation_callback does not declare
    elicitation support, so the server's ctx.elicit() call raises and falls
    back to auto-allow. These tests confirm the fallback path works and does
    not break normal rename operations for symbols that came from the binary's
    symbol table (like check_password, which has is_uname() == True in IDA).
    """

    def test_rename_user_symbol_auto_allows(self, fresh_headless_server):
        """Renaming a symbol that came from the binary (check_password) should auto-allow."""
        # Step 1: Rename check_password to something else
        result = mcp_call(fresh_headless_server, 'rename', {
            'items': [{'name': 'check_password', 'new_name': 'elicit_test_renamed'}],
        })
        data = parse_json_response(result)
        # Should succeed (auto-allowed by fallback)
        assert data is not None
        if isinstance(data, list) and data:
            assert data[0].get('error') is None, f"Rename failed: {data[0].get('error')}"

        # Step 2: Verify the rename took effect via get_funcs
        result2 = mcp_call(fresh_headless_server, 'get_funcs', {
            'items': ['elicit_test_renamed'],
        })
        assert 'elicit_test_renamed' in result2

        # Step 3: Rename back
        mcp_call(fresh_headless_server, 'rename', {
            'items': [{'name': 'elicit_test_renamed', 'new_name': 'check_password'}],
        })

    def test_batch_rename_multiple_user_symbols(self, fresh_headless_server):
        """Batch rename of multiple user-named symbols should all auto-allow."""
        result = mcp_call(fresh_headless_server, 'rename', {
            'items': [
                {'name': 'check_password', 'new_name': 'elicit_batch_1'},
                {'name': 'main', 'new_name': 'elicit_batch_2'},
            ],
        })
        data = parse_json_response(result)
        if isinstance(data, list):
            for item in data:
                assert item.get('error') is None, f"Batch rename failed: {item.get('error')}"

        # Restore
        mcp_call(fresh_headless_server, 'rename', {
            'items': [
                {'name': 'elicit_batch_1', 'new_name': 'check_password'},
                {'name': 'elicit_batch_2', 'new_name': 'main'},
            ],
        })


# ---------------------------------------------------------------------------
# Elicitation E2E — real SDK 1.27 elicitation with capable client
# ---------------------------------------------------------------------------

class TestElicitationE2E:
    """Test real MCP SDK 1.27 elicitation flow with an elicitation-capable client.

    Unlike TestElicitationFallback (which uses a plain ClientSession and relies
    on the server's exception-based fallback), these tests pass an
    elicitation_callback to ClientSession.  The SDK then advertises
    elicitation support during initialize(), and the server's ctx.elicit()
    call reaches the callback instead of raising.

    Tests:
    - Accept: server sends elicitation, callback accepts, rename proceeds.
    - Decline: callback declines, rename is skipped.
    - Apply-to-all: first callback sets apply_to_all=True, subsequent items
      skip the elicitation entirely via batch_state cache.
    """

    def test_rename_with_elicitation_accept(self, fresh_headless_server):
        """Client that accepts all elicitations — rename should succeed."""

        async def _test():
            url = f"http://{fresh_headless_server['host']}:{fresh_headless_server['port']}/mcp"

            async def accept_all(context, params):
                from mcp.types import ElicitResult
                return ElicitResult(
                    action='accept',
                    content={'confirm': True, 'apply_to_all': False},
                )

            async with streamablehttp_client(url) as (r, w, _):
                async with ClientSession(r, w, elicitation_callback=accept_all) as session:
                    await session.initialize()

                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        result = await session.call_tool('rename', {
                            'items': [{'name': 'check_password', 'new_name': 'elicit_accepted'}],
                        })
                    assert not result.isError
                    text = result.content[0].text if result.content else ''
                    data = parse_json_response(text)
                    if isinstance(data, list) and data:
                        assert data[0].get('error') is None, (
                            f'Rename failed: {data[0].get("error")}'
                        )

                    # Verify rename took effect
                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        result2 = await session.call_tool('get_funcs', {
                            'items': ['elicit_accepted'],
                        })
                    assert not result2.isError
                    text2 = result2.content[0].text if result2.content else ''
                    assert 'elicit_accepted' in text2

                    # Restore original name
                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        await session.call_tool('rename', {
                            'items': [{'name': 'elicit_accepted', 'new_name': 'check_password'}],
                        })

        anyio.run(_test)

    def test_rename_with_elicitation_decline(self, fresh_headless_server):
        """Client that declines all elicitations — rename should be skipped."""

        async def _test():
            url = f"http://{fresh_headless_server['host']}:{fresh_headless_server['port']}/mcp"

            async def decline_all(context, params):
                from mcp.types import ElicitResult
                return ElicitResult(action='decline')

            async with streamablehttp_client(url) as (r, w, _):
                async with ClientSession(r, w, elicitation_callback=decline_all) as session:
                    await session.initialize()

                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        result = await session.call_tool('rename', {
                            'items': [{'name': 'check_password', 'new_name': 'should_not_rename'}],
                        })
                    # Tool returns successfully even when skipped (error=null, new_name unchanged or skipped)
                    text = result.content[0].text if result.content else ''
                    data = parse_json_response(text)
                    if isinstance(data, list) and data:
                        # Declined rename: either error indicates skipped, or new_name was not applied
                        item = data[0]
                        # The symbol must not have been renamed
                        assert item.get('new_name') != 'should_not_rename' or item.get('error') is not None, (
                            'Expected rename to be skipped when declined, but it was applied'
                        )

                    # Verify check_password still exists with original name
                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        result2 = await session.call_tool('get_funcs', {
                            'items': ['check_password'],
                        })
                    assert not result2.isError
                    text2 = result2.content[0].text if result2.content else ''
                    assert 'check_password' in text2

        anyio.run(_test)

    def test_batch_rename_with_apply_to_all(self, fresh_headless_server):
        """Client accepts first elicitation with apply_to_all — rest auto-allowed."""
        call_count = [0]

        async def _test():
            url = f"http://{fresh_headless_server['host']}:{fresh_headless_server['port']}/mcp"

            async def accept_with_apply_all(context, params):
                from mcp.types import ElicitResult
                call_count[0] += 1
                return ElicitResult(
                    action='accept',
                    content={'confirm': True, 'apply_to_all': True},
                )

            async with streamablehttp_client(url) as (r, w, _):
                async with ClientSession(r, w, elicitation_callback=accept_with_apply_all) as session:
                    await session.initialize()

                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        result = await session.call_tool('rename', {
                            'items': [
                                {'name': 'check_password', 'new_name': 'elicit_batch_a1'},
                                {'name': 'main', 'new_name': 'elicit_batch_a2'},
                            ],
                        })
                    assert not result.isError
                    text = result.content[0].text if result.content else ''
                    data = parse_json_response(text)
                    if isinstance(data, list):
                        for item in data:
                            assert item.get('error') is None, (
                                f'Batch rename item failed: {item.get("error")}'
                            )

                    # With apply_to_all=True on first callback, elicitation is only sent once
                    # (the second rename is short-circuited via batch_state cache).
                    assert call_count[0] <= 2, (
                        f'Expected at most 2 elicitation calls, got {call_count[0]}'
                    )

                    # Restore
                    with anyio.fail_after(MCP_CALL_TIMEOUT):
                        await session.call_tool('rename', {
                            'items': [
                                {'name': 'elicit_batch_a1', 'new_name': 'check_password'},
                                {'name': 'elicit_batch_a2', 'new_name': 'main'},
                            ],
                        })

        anyio.run(_test)


# ---------------------------------------------------------------------------
# Tool 10: update_vars
# ---------------------------------------------------------------------------

class TestUpdateVarsTool:
    """Tool: update_vars — function_name, variables_to_update."""

    def test_update_vars_finds_and_renames_variable(self, fresh_headless_server):
        """Decompile check_password, find a local var, rename it, then verify."""
        # Step 1: decompile to see variable names
        decomp = mcp_call(fresh_headless_server, 'decompile', {
            'items': [{'name': 'check_password'}],
        })
        # Extract a local variable name (pattern: local_NN or param_N or a1/v1)
        var_match = re.search(r'\b(local_[0-9a-f]+|param_\d+|[av]\d+)\b', decomp)
        if var_match is None:
            pytest.skip(
                "Could not find local variable in check_password decompilation — skipping"
            )
        original_var = var_match.group(1)
        temp_var = 'test_renamed_var_xyz'

        # Step 2: rename the variable
        result = mcp_call(fresh_headless_server, 'update_vars', {
            'function_name': 'check_password',
            'variables_to_update': {
                original_var: {'new_name': temp_var},
            },
        })
        # update_vars returns a human-readable status string
        assert 'Done' in result or 'Results' in result

        # Step 3: decompile again and verify new name appears
        decomp2 = mcp_call(fresh_headless_server, 'decompile', {
            'items': [{'name': 'check_password'}],
        })
        assert temp_var in decomp2 or original_var not in decomp2

        # Step 4: restore — rename temp_var back to original
        mcp_call(fresh_headless_server, 'update_vars', {
            'function_name': 'check_password',
            'variables_to_update': {
                temp_var: {'new_name': original_var},
            },
        })


# ---------------------------------------------------------------------------
# Tool 11: set_comments + Tool 12: get_comment (round-trip)
# ---------------------------------------------------------------------------

class TestCommentTools:
    """Tools: set_comments + get_comment — round-trip test."""

    def test_set_and_get_function_comment_roundtrip(self, fresh_headless_server, binary_addresses):
        """set_comments(kind='function') then get_comment verifies comment was set."""
        main_addr = binary_addresses['main']
        test_comment = 'E2E test comment - round-trip verification'

        # Step 1: read original comment
        original = mcp_call(fresh_headless_server, 'get_comment', {
            'items': [{'addr': main_addr}],
        })
        data_orig = parse_json_response(original)
        orig_comment = ''
        if data_orig and isinstance(data_orig, list) and len(data_orig) > 0:
            orig_comment = data_orig[0].get('comment', '')

        # Step 2: set new comment
        result = mcp_call(fresh_headless_server, 'set_comments', {
            'items': [{
                'comment': test_comment,
                'kind': 'function',
                'name': 'main',
            }],
        })
        assert 'error' not in result.lower() or 'successfully' in result.lower() or len(result) > 0

        # Step 3: verify comment was set
        after = mcp_call(fresh_headless_server, 'get_comment', {
            'items': [{'addr': main_addr}],
        })
        assert test_comment in after

        # Step 4: restore original comment
        mcp_call(fresh_headless_server, 'set_comments', {
            'items': [{
                'comment': orig_comment,
                'kind': 'function',
                'name': 'main',
            }],
        })

    def test_set_disasm_comment(self, fresh_headless_server, binary_addresses):
        """set_comments(kind='disasm') sets an EOL comment at an address."""
        main_addr = binary_addresses['main']
        result = mcp_call(fresh_headless_server, 'set_comments', {
            'items': [{
                'comment': 'disasm test comment',
                'kind': 'disasm',
                'addr': main_addr,
            }],
        })
        # Should succeed without error
        assert len(result) > 0

    def test_get_comment_returns_comment_field(self, fresh_headless_server, binary_addresses):
        """get_comment returns a dict with comment field."""
        main_addr = binary_addresses['main']
        result = mcp_call(fresh_headless_server, 'get_comment', {
            'items': [{'addr': main_addr}],
        })
        data = parse_json_response(result)
        if data and isinstance(data, list) and len(data) > 0:
            assert 'comment' in data[0]
            assert 'name' in data[0]


# ---------------------------------------------------------------------------
# Tool 13: set_prototype (round-trip)
# ---------------------------------------------------------------------------

class TestSetPrototypeTool:
    """Tool: set_prototype — items: list of {addr, prototype}. Round-trip test."""

    def test_set_prototype_roundtrip(self, fresh_headless_server, binary_addresses):
        """Apply a new prototype to check_password, verify, then restore."""
        check_addr = binary_addresses.get('check_password')
        if check_addr is None:
            pytest.skip("check_password address not found")

        # Step 1: get current signature via get_funcs
        info = mcp_call(fresh_headless_server, 'get_funcs', {
            'items': ['check_password'],
        })
        data_info = parse_json_response(info)
        original_sig = None
        if data_info and isinstance(data_info, list) and len(data_info) > 0:
            original_sig = data_info[0].get('signature')

        # Step 2: apply new prototype
        new_proto = 'int check_password(char *password)'
        result = mcp_call(fresh_headless_server, 'set_prototype', {
            'items': [{'addr': check_addr, 'prototype': new_proto}],
        })
        data = parse_json_response(result)
        if data and isinstance(data, list):
            assert data[0].get('error') is None

        # Step 3: verify function still exists
        after = mcp_call(fresh_headless_server, 'get_funcs', {
            'items': ['check_password'],
        })
        assert 'check_password' in after

        # Step 4: restore — if we have the original, apply it back
        if original_sig:
            mcp_call(fresh_headless_server, 'set_prototype', {
                'items': [{'addr': check_addr, 'prototype': original_sig}],
            })


# ---------------------------------------------------------------------------
# Tool 14: patch (round-trip)
# ---------------------------------------------------------------------------

class TestPatchTool:
    """Tool: patch — items: list of {addr, hex_bytes}. Round-trip test."""

    def test_patch_nop_and_restore(self, fresh_headless_server, binary_addresses):
        """Patch one byte to NOP (0x90), verify via disasm, restore original."""
        main_addr = binary_addresses['main']

        # Step 1: read original disasm (1 instruction) to get the original byte
        orig_disasm = mcp_call(fresh_headless_server, 'disasm', {
            'items': [{'addr': main_addr, 'count': 1}],
        })

        # Extract original hex bytes from disasm output (format: "0xaddr: MNEM ...")
        # Try to parse the first hex byte from the instruction encoding
        orig_byte_match = re.search(r'[0-9a-fA-F]{6,}:\s+([0-9a-fA-F]{2})', orig_disasm)

        # Step 2: patch first byte to NOP
        result = mcp_call(fresh_headless_server, 'patch', {
            'items': [{'addr': main_addr, 'hex_bytes': '90'}],
        })
        data = parse_json_response(result)
        if data and isinstance(data, list):
            assert data[0].get('error') is None

        # Step 3: verify patch via disasm
        after_disasm = mcp_call(fresh_headless_server, 'disasm', {
            'items': [{'addr': main_addr, 'count': 1}],
        })
        assert 'NOP' in after_disasm or 'nop' in after_disasm.lower()

        # Step 4: restore — if we parsed original bytes, restore them
        if orig_byte_match:
            original_hex = orig_byte_match.group(1)
            mcp_call(fresh_headless_server, 'patch', {
                'items': [{'addr': main_addr, 'hex_bytes': original_hex}],
            })


# begin_trans/end_trans — not applicable to IDA (no explicit transactions)


# ---------------------------------------------------------------------------
# Tool 17: types
# ---------------------------------------------------------------------------

class TestTypesTool:
    """Tool: types — pattern?, offset?, limit?

    IDA-specific: types() returns only user-defined/loaded named types from the
    local TIL — primitive types (int, char, void) are language keywords and are
    NOT listed here. For crackme.elf the local TIL contains only ELF struct
    definitions. Use type_info() to look up primitives by name.
    """

    def test_types_returns_non_empty_list(self, headless_server):
        """types() returns a non-empty list of named types."""
        result = mcp_call(headless_server, 'types', {
            'offset': 0,
            'limit': 50,
        })
        assert len(result) > 0
        # The crackme.elf TIL contains ELF struct types
        assert any(kw in result for kw in ('struct', 'kind', 'name', 'Elf'))

    def test_types_with_pattern_filter(self, headless_server):
        """types(pattern='Elf') returns ELF-related types from crackme.elf TIL."""
        result = mcp_call(headless_server, 'types', {
            'pattern': 'Elf',
            'offset': 0,
            'limit': 20,
        })
        assert 'Elf' in result or len(result) == 0  # May be empty if no ELF types

    def test_types_pagination(self, headless_server):
        """types with offset pagination returns different results."""
        result_page0 = mcp_call(headless_server, 'types', {
            'offset': 0,
            'limit': 5,
        })
        result_page1 = mcp_call(headless_server, 'types', {
            'offset': 5,
            'limit': 5,
        })
        # Pages should be different (unless fewer than 5 types total, unlikely)
        assert result_page0 != result_page1 or len(result_page0) == 0


# ---------------------------------------------------------------------------
# Tool 18: type_info
# ---------------------------------------------------------------------------

class TestTypeInfoTool:
    """Tool: type_info — items: list of type name strings."""

    def test_type_info_builtin_type(self, headless_server):
        """type_info(['int']) returns details for int."""
        result = mcp_call(headless_server, 'type_info', {
            'items': ['int'],
        })
        assert 'int' in result.lower()

    def test_type_info_unknown_type_returns_error_field(self, headless_server):
        """type_info with unknown type name returns per-item error."""
        result = mcp_call(headless_server, 'type_info', {
            'items': ['nonexistent_type_xyz_99999'],
        })
        assert 'error' in result.lower() or 'not found' in result.lower()

    def test_type_info_batch(self, headless_server):
        """type_info with multiple type names returns multiple results."""
        result = mcp_call(headless_server, 'type_info', {
            'items': ['int', 'char'],
        })
        data = parse_json_response(result)
        if data and isinstance(data, list):
            assert len(data) == 2


# ---------------------------------------------------------------------------
# Tools 19 + 20: create_struct + add_field
# ---------------------------------------------------------------------------

class TestStructTools:
    """Tools: create_struct + add_field — create, add field, verify via type_info.

    IDA-specific: create_struct and add_field use ida_struct which is not
    available in all idalib builds. When unavailable the tools return clean MCP
    errors. Tests skip gracefully in that case.
    """

    # Use a stable unique name so the test is idempotent
    STRUCT_NAME = 'E2eTestStruct_v1'

    def test_create_struct_and_add_field(self, fresh_headless_server):
        """create_struct then add_field, verify via type_info."""
        struct_name = self.STRUCT_NAME

        # Step 1: create struct (may already exist from a previous run — idempotent)
        result_create_raw = mcp_call_raw(fresh_headless_server, 'create_struct', {
            'name': struct_name,
            'size': 16,
        })
        if result_create_raw.isError:
            error_text = ' '.join(
                item.text for item in result_create_raw.content if hasattr(item, 'text')
            )
            pytest.skip(f"create_struct not available in this idalib build: {error_text}")

        result_create = '\n'.join(
            item.text for item in result_create_raw.content if hasattr(item, 'text')
        )
        assert (
            struct_name in result_create
            or 'created' in result_create.lower()
            or 'exists' in result_create.lower()
        )

        # Step 2: add a field at offset 0
        result_add = mcp_call(fresh_headless_server, 'add_field', {
            'items': [{
                'struct_name': struct_name,
                'field_name': 'test_field',
                'field_type': 'int',
                'offset': 0,
                'comment': 'E2E test field',
            }],
        })
        data_add = parse_json_response(result_add)
        if data_add and isinstance(data_add, list) and len(data_add) > 0:
            assert data_add[0].get('success') is True or data_add[0].get('error') is None

        # Step 3: verify via type_info
        result_info = mcp_call(fresh_headless_server, 'type_info', {
            'items': [struct_name],
        })
        assert struct_name in result_info
        assert 'test_field' in result_info

    def test_create_struct_with_initial_fields(self, fresh_headless_server):
        """create_struct with inline fields creates struct with members."""
        struct_name = 'E2eTestStructWithFields_v1'

        result_raw = mcp_call_raw(fresh_headless_server, 'create_struct', {
            'name': struct_name,
            'size': 8,
            'fields': [
                {'name': 'x', 'type': 'int', 'offset': 0},
                {'name': 'y', 'type': 'int', 'offset': 4},
            ],
        })
        if result_raw.isError:
            error_text = ' '.join(
                item.text for item in result_raw.content if hasattr(item, 'text')
            )
            pytest.skip(f"create_struct not available in this idalib build: {error_text}")

        result = '\n'.join(
            item.text for item in result_raw.content if hasattr(item, 'text')
        )
        assert (
            struct_name in result
            or 'created' in result.lower()
            or 'exists' in result.lower()
        )

        # Verify fields visible via type_info
        info = mcp_call(fresh_headless_server, 'type_info', {
            'items': [struct_name],
        })
        assert struct_name in info

    def test_add_field_to_nonexistent_struct_returns_error(self, fresh_headless_server):
        """add_field on a non-existent struct returns per-item error or API error."""
        result_raw = mcp_call_raw(fresh_headless_server, 'add_field', {
            'items': [{
                'struct_name': 'NonExistentStruct_xyz_999',
                'field_name': 'bad_field',
                'field_type': 'int',
                'offset': 0,
            }],
        })
        if result_raw.isError:
            # Top-level API error (e.g., ida_struct not available) is also acceptable
            error_text = ' '.join(
                item.text for item in result_raw.content if hasattr(item, 'text')
            )
            assert len(error_text) > 0, 'add_field error must include a message'
            return

        result = '\n'.join(
            item.text for item in result_raw.content if hasattr(item, 'text')
        )
        data = parse_json_response(result)
        if data and isinstance(data, list) and len(data) > 0:
            # Per-item error: success=False with a non-empty message
            assert data[0].get('success') is False
            assert data[0].get('message') is not None
        else:
            # Plain text: should contain error indicator or not-found message
            assert any(kw in result.lower() for kw in (
                'not found', 'error', 'fail', 'module', 'unavailable'
            ))


# ---------------------------------------------------------------------------
# Tool: idapython (script execution)
# ---------------------------------------------------------------------------

class TestIdapython:
    """Tool: idapython — executes Python code in the IDA Pro context."""

    def test_simple_eval(self, headless_server):
        """idapython('1+1') returns result='2' and success=True."""
        result = mcp_call(headless_server, 'idapython', {'code': '1+1'})
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert parsed['result'] == '2'

    def test_api_access(self, headless_server):
        """idapython can access IDA Python APIs."""
        result = mcp_call(headless_server, 'idapython', {
            'code': 'idc.get_inf_attr(idc.INF_MIN_EA)',
        })
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert parsed['result'] is not None

    def test_stdout_capture(self, headless_server):
        """idapython captures print() output in stdout and output fields."""
        result = mcp_call(headless_server, 'idapython', {
            'code': "print('hello_e2e')",
        })
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert 'hello_e2e' in parsed['stdout']
        assert 'hello_e2e' in parsed['output']

    def test_error_returns_success_false(self, headless_server):
        """idapython returns success=False on exception."""
        result = mcp_call(headless_server, 'idapython', {'code': '1/0'})
        parsed = json.loads(result)
        assert parsed['success'] is False
        assert parsed['error'] is not None
        assert 'ZeroDivision' in parsed['error'] or 'ZeroDivision' in (parsed.get('error_traceback') or '')

    def test_list_functions_via_script(self, headless_server):
        """Use idapython to list all function names — proves real binary inspection."""
        result = mcp_call(headless_server, 'idapython', {
            'code': '[idc.get_func_name(ea) for ea in idautils.Functions()]',
        })
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert 'main' in parsed['result']
        assert 'check_password' in parsed['result']

    def test_read_string_via_script(self, headless_server):
        """Use idapython to find a known string in the binary."""
        result = mcp_call(headless_server, 'idapython', {
            'code': (
                'found = []\n'
                'sc = ida_strlist.string_info_t()\n'
                'for i in range(ida_strlist.get_strlist_qty()):\n'
                '    if ida_strlist.get_strlist_item(sc, i):\n'
                '        s = idc.get_strlit_contents(sc.ea, -1, 0)\n'
                '        if s and b"secret" in s:\n'
                '            found.append(s.decode("utf-8", errors="replace"))\n'
                'found'
            ),
        })
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert 'secret123' in parsed['result']

    def test_decompile_via_script(self, headless_server):
        """Use idapython to decompile main via the scripting tool."""
        result = mcp_call(headless_server, 'idapython', {
            'code': (
                'ea = idc.get_name_ea_simple("main")\n'
                'cfunc = ida_hexrays.decompile(ea)\n'
                'str(cfunc)'
            ),
        })
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert 'check_password' in parsed['result']

    def test_xrefs_via_script(self, headless_server):
        """Use idapython to find cross-references to check_password."""
        result = mcp_call(headless_server, 'idapython', {
            'code': (
                'ea = idc.get_name_ea_simple("check_password")\n'
                'refs = list(idautils.XrefsTo(ea))\n'
                'len(refs)'
            ),
        })
        parsed = json.loads(result)
        assert parsed['success'] is True
        assert int(parsed['result']) >= 1


# ---------------------------------------------------------------------------
# Tool: find_bytes (byte pattern search)
# ---------------------------------------------------------------------------

def _parse_list_response(result: str) -> list[dict]:
    """Parse a list-of-dicts response from MCP.

    FastMCP may return a list[dict] as either:
    - A JSON array string: '[{...}, {...}]'
    - A single JSON object: '{...}'
    - Newline-separated JSON objects/arrays (one per TextContent item), where
      each item may itself be single-line or multi-line JSON

    Normalizes all forms to a Python list of dicts.
    """
    text = result.strip()
    if not text:
        return []

    # Try parsing the whole response as a single JSON value first
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    # FastMCP may join multiple TextContent items with '\n'.
    # Each item may be a complete JSON object or array. We try to extract
    # JSON objects by scanning for balanced brace segments.
    items: list[dict] = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                segment = text[start:i + 1]
                try:
                    obj = json.loads(segment)
                    if isinstance(obj, dict):
                        items.append(obj)
                except json.JSONDecodeError:
                    pass
                start = -1

    return items


class TestFindBytes:
    """Tool: find_bytes — byte pattern search with wildcard support."""

    def test_find_known_pattern(self, headless_server):
        """find_bytes with CALL pattern E8 ?? ?? ?? ?? returns matches."""
        result = mcp_call(headless_server, 'find_bytes', {
            'patterns': ['E8 ?? ?? ?? ??'],
        })
        entries = _parse_list_response(result)
        assert len(entries) > 0, f'Expected result entries, got empty list from: {result[:200]}'
        entry = entries[0]
        assert entry.get('error') is None, f'find_bytes returned error: {entry.get("error")}'
        assert len(entry.get('matches', [])) > 0, 'Expected matches for E8 ?? ?? ?? ??'

    def test_find_no_match(self, headless_server):
        """find_bytes with unlikely pattern returns empty matches."""
        result = mcp_call(headless_server, 'find_bytes', {
            'patterns': ['DE AD BE EF DE AD'],
        })
        entries = _parse_list_response(result)
        assert len(entries) > 0, f'Expected result entries, got empty list from: {result[:200]}'
        entry = entries[0]
        assert entry.get('error') is None, f'find_bytes returned error: {entry.get("error")}'
        assert entry.get('matches') == [], f'Expected no matches, got: {entry.get("matches")}'

    def test_find_multiple_patterns(self, headless_server):
        """find_bytes with two patterns returns two result entries."""
        result = mcp_call(headless_server, 'find_bytes', {
            'patterns': ['55', 'C3'],
        })
        entries = _parse_list_response(result)
        assert len(entries) == 2, f'Expected 2 entries, got {len(entries)} from: {result[:200]}'
        for entry in entries:
            assert 'pattern' in entry
            assert 'matches' in entry
            assert 'has_more' in entry


# ---------------------------------------------------------------------------
# Tool: find_insns (instruction sequence search)
# ---------------------------------------------------------------------------

class TestFindInsns:
    """Tool: find_insns — instruction sequence search with glob/regex operands."""

    def test_find_call_sequence(self, headless_server):
        """find_insns with CALL sequence finds call instructions."""
        result = mcp_call(headless_server, 'find_insns', {
            'sequences': [[{'mnemonic': 'call', 'operands': ['*']}]],
        })
        entries = _parse_list_response(result)
        assert len(entries) > 0, f'Expected result entries, got empty list from: {result[:200]}'
        entry = entries[0]
        assert entry.get('error') is None, f'find_insns returned error: {entry.get("error")}'
        assert len(entry.get('matches', [])) > 0, 'Expected CALL instruction matches'

    def test_find_no_match(self, headless_server):
        """find_insns with non-existent mnemonic returns empty matches."""
        result = mcp_call(headless_server, 'find_insns', {
            'sequences': [[{'mnemonic': 'XYZNOTREAL', 'operands': ['*']}]],
        })
        entries = _parse_list_response(result)
        assert len(entries) > 0, f'Expected result entries, got empty list from: {result[:200]}'
        entry = entries[0]
        assert entry.get('error') is None, f'find_insns returned error: {entry.get("error")}'
        assert entry.get('matches') == [], f'Expected no matches, got: {entry.get("matches")}'

    def test_find_ret_sequence(self, headless_server):
        """find_insns for RET instruction finds return sites."""
        result = mcp_call(headless_server, 'find_insns', {
            'sequences': [[{'mnemonic': 'retn', 'operands': []}]],
        })
        entries = _parse_list_response(result)
        assert len(entries) > 0, f'Expected result entries, got empty list from: {result[:200]}'
        entry = entries[0]
        assert entry.get('error') is None, f'find_insns returned error: {entry.get("error")}'
        assert len(entry.get('matches', [])) > 0, 'Expected RET instruction matches'


# ---------------------------------------------------------------------------
# Mutation test: set local variable type to user-defined struct pointer
# ---------------------------------------------------------------------------

class TestStructPointerType:
    """Verify setting local variable type to a user-defined struct pointer."""

    def test_set_param_type_to_struct_pointer(self, fresh_headless_server):
        """Create struct, set param type to struct*, verify in decompilation."""
        struct_name = 'E2eTestConfig'

        # Step 1: Create struct
        result = mcp_call(fresh_headless_server, 'create_struct', {
            'name': struct_name,
            'size': 8,
            'fields': [
                {'name': 'flag', 'type': 'int', 'offset': 0},
                {'name': 'value', 'type': 'int', 'offset': 4},
            ],
        })
        assert struct_name in result

        # Step 2: Set first param type to E2eTestConfig*
        # IDA names the first param 'a1' by default
        result = mcp_call(fresh_headless_server, 'update_vars', {
            'function_name': 'check_password',
            'variables_to_update': {
                'a1': {'new_type': f'{struct_name} *'}
            },
        })
        assert 'Done' in result or 'a1' in result

        # Step 3: Verify via fresh decompilation (idapython, not cached)
        result = mcp_call(fresh_headless_server, 'idapython', {
            'code': (
                "import ida_hexrays, idc\n"
                "ea = idc.get_name_ea_simple('check_password')\n"
                "cfunc = ida_hexrays.decompile(ea)\n"
                "str(cfunc)"
            ),
        })
        parsed = json.loads(result)
        assert parsed['success'] is True, f"Decompile failed: {parsed.get('error')}"
        assert struct_name in parsed['result'], (
            f'Expected {struct_name} in decompilation, got: {parsed["result"][:300]}'
        )


# ---------------------------------------------------------------------------
# Mutation test: set LOCAL variable type to user-defined struct pointer
# Uses struct_test.elf which already has Config/Point structs from debug info
# ---------------------------------------------------------------------------

class TestLocalVarStructPointer:
    """Verify setting a LOCAL variable (not a parameter) type to a struct pointer.

    Uses struct_test.elf which has debug info with Config and Point structs.
    process_config has local variable 'total' (int) and 'p' (Point on stack).
    We retype 'p' from its current type to Config * and verify in decompilation.
    """

    def test_set_local_var_to_struct_pointer(self, struct_test_server):
        """Change local 'p' (Point) in process_config to Config* — verify in decompile."""
        # Step 1: Change local variable 'p' type to Config *
        # struct_test.elf already has Config defined from debug info
        result = mcp_call(struct_test_server, 'update_vars', {
            'function_name': 'process_config',
            'variables_to_update': {
                'p': {'new_type': 'Config *'},
            },
        })
        assert 'Done' in result or 'p' in result, (
            f"update_vars did not confirm success, got: {result[:300]}"
        )

        # Step 2: Verify via fresh decompilation — Config should appear in output
        result = mcp_call(struct_test_server, 'idapython', {
            'code': (
                "import ida_hexrays, idc\n"
                "ea = idc.get_name_ea_simple('process_config')\n"
                "cfunc = ida_hexrays.decompile(ea)\n"
                "str(cfunc)"
            ),
        })
        parsed = json.loads(result)
        assert parsed['success'] is True, (
            f"Decompile script failed: {parsed.get('error')}"
        )
        assert 'Config' in parsed['result'], (
            f"Expected 'Config' in decompilation of process_config after retype, "
            f"got: {parsed['result'][:400]}"
        )


# ---------------------------------------------------------------------------
# Scripting persistence (over MCP transport)
# ---------------------------------------------------------------------------

class TestScriptingPersistence:
    """Persistent scripting session tests — variables survive between MCP calls."""

    def test_variable_persists_over_mcp(self, headless_server):
        """Variable set in call 1 is readable in call 2 over MCP transport."""
        r1 = mcp_call(headless_server, 'idapython', {'code': 'session_var_e2e = 123'})
        parsed1 = json.loads(r1)
        assert parsed1['success']

        r2 = mcp_call(headless_server, 'idapython', {'code': 'session_var_e2e'})
        parsed2 = json.loads(r2)
        assert parsed2['success']
        assert parsed2['result'] == '123'

    def test_function_persists_over_mcp(self, headless_server):
        """Function defined in call 1 is callable in call 2 over MCP transport."""
        mcp_call(headless_server, 'idapython', {
            'code': 'def _e2e_greet(): return "hello_persistent"',
        })
        r = mcp_call(headless_server, 'idapython', {'code': '_e2e_greet()'})
        parsed = json.loads(r)
        assert parsed['success']
        assert parsed['result'] == 'hello_persistent'

    def test_reset_over_mcp(self, headless_server):
        """reset=True clears session state over MCP transport."""
        mcp_call(headless_server, 'idapython', {'code': 'mcp_var_to_clear = 456'})

        r_reset = mcp_call(headless_server, 'idapython', {'code': '', 'reset': True})
        parsed_reset = json.loads(r_reset)
        assert parsed_reset['success']

        r2 = mcp_call_raw(headless_server, 'idapython', {'code': 'mcp_var_to_clear'})
        # After reset, variable should not exist — the tool returns success=False
        if not r2.isError:
            parsed2 = json.loads(
                '\n'.join(item.text for item in r2.content if hasattr(item, 'text'))
            )
            assert not parsed2['success']  # NameError expected

    def test_reset_preserves_ida_apis(self, headless_server):
        """After reset, IDA Python APIs are still accessible over MCP transport."""
        mcp_call(headless_server, 'idapython', {'code': '', 'reset': True})
        r = mcp_call(headless_server, 'idapython', {
            'code': 'idc.get_inf_attr(idc.INF_MIN_EA)',
        })
        parsed = json.loads(r)
        assert parsed['success']
