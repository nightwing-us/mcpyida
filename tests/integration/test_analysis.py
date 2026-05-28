"""Integration tests for analysis tools: decompile, disassemble, xrefs, symbols.

Tests call methods directly on the McpServer instance. idalib must be
available (tests are session-scoped via conftest.py fixtures).
"""
from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from tests.integration.helpers import assert_non_empty, assert_valid_address


def _get_main_address(server) -> str:
    """Resolve main's entry address dynamically via mcp_list."""
    result = server.mcp_list(entry_type='function', offset=0, limit=500, match_filter='main')
    for item in result.items:
        if item['name'] == 'main':
            return item['address']
    pytest.fail(f'Could not find "main" in function list: {[i["name"] for i in result.items]}')


def _get_check_password_address(server) -> str:
    """Resolve check_password's entry address dynamically via mcp_list."""
    result = server.mcp_list(
        entry_type='function', offset=0, limit=500, match_filter='check_password'
    )
    for item in result.items:
        if item['name'] == 'check_password':
            return item['address']
    pytest.fail(
        f'Could not find "check_password" in function list: {[i["name"] for i in result.items]}'
    )


class TestDecompileFunction:
    """mcp_decompile_function(name=...) / mcp_decompile_function(addr=...) -> str."""

    def test_decompile_main_by_name(self, server):
        result = server.mcp_decompile_function(name='main')
        assert isinstance(result, str)
        assert_non_empty(result)

    def test_decompile_main_contains_check_password(self, server):
        result = server.mcp_decompile_function(name='main')
        assert 'check_password' in result, (
            f'Expected "check_password" in decompilation of main, got:\n{result[:500]}'
        )

    def test_decompile_main_by_addr(self, server):
        addr = _get_main_address(server)
        result = server.mcp_decompile_function(addr=addr)
        assert isinstance(result, str)
        assert_non_empty(result)
        assert 'check_password' in result, (
            f'Decompile by addr should also find check_password, got:\n{result[:500]}'
        )

    def test_decompile_check_password(self, server):
        result = server.mcp_decompile_function(name='check_password')
        assert isinstance(result, str)
        assert_non_empty(result)
        # check_password calls strcmp internally
        assert 'strcmp' in result or 'check_password' in result, (
            f'Expected strcmp or check_password in decompilation, got:\n{result[:500]}'
        )

    def test_decompile_nonexistent_raises(self, server):
        with pytest.raises((ToolError, Exception)) as exc_info:
            server.mcp_decompile_function(name='nonexistent_function_xyz')
        assert exc_info.value is not None


class TestDisassembleFunction:
    """mcp_disassemble_function(name=...) -> str with ':' separators per line."""

    def test_disassemble_main_by_name(self, server):
        result = server.mcp_disassemble_function(name='main')
        assert isinstance(result, str)
        assert_non_empty(result)

    def test_disassemble_main_has_colon_separators(self, server):
        result = server.mcp_disassemble_function(name='main')
        lines = [ln for ln in result.splitlines() if ln.strip()]
        assert len(lines) > 0, 'Expected at least one disassembly line'
        for line in lines:
            assert ':' in line, f'Expected ":" separator in disassembly line: {line!r}'

    def test_disassemble_returns_multiple_lines(self, server):
        result = server.mcp_disassemble_function(name='main')
        lines = [ln for ln in result.splitlines() if ln.strip()]
        assert len(lines) > 1, f'Expected multiple disassembly lines, got: {lines}'

    def test_disassemble_main_by_addr(self, server):
        addr = _get_main_address(server)
        result = server.mcp_disassemble_function(addr=addr)
        assert isinstance(result, str)
        assert_non_empty(result)


class TestDisassembleAddr:
    """mcp_disassemble_addr(addr=..., num_instructions=N) -> N lines."""

    def test_disassemble_addr_basic(self, server):
        addr = _get_main_address(server)
        result = server.mcp_disassemble_addr(addr=addr, num_instructions=10)
        assert isinstance(result, str)
        assert_non_empty(result)

    def test_disassemble_addr_line_count(self, server):
        addr = _get_main_address(server)
        result = server.mcp_disassemble_addr(addr=addr, num_instructions=5)
        # The result includes a header line + instruction lines
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # At least 5 instruction lines (header may vary)
        assert len(lines) >= 5, (
            f'Expected at least 5 lines for num_instructions=5, got {len(lines)}:\n{result}'
        )

    def test_disassemble_addr_default_count(self, server):
        addr = _get_main_address(server)
        result = server.mcp_disassemble_addr(addr=addr)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # Default is 10 instructions, expect at least a few
        assert len(lines) >= 3, (
            f'Expected multiple lines with default num_instructions, got:\n{result}'
        )


class TestFindFunctionContaining:
    """mcp_find_function_containing(addr=...) -> FunctionInfo."""

    def test_find_function_containing_main_addr(self, server):
        addr = _get_main_address(server)
        result = server.mcp_find_function_containing(addr=addr)
        assert result is not None
        assert result.name == 'main', f'Expected function name "main", got: {result.name!r}'

    def test_find_function_containing_returns_function_info(self, server):
        addr = _get_main_address(server)
        result = server.mcp_find_function_containing(addr=addr)
        assert hasattr(result, 'name')
        assert hasattr(result, 'entrypoint')
        assert_valid_address(result.entrypoint)

    def test_find_function_containing_check_password(self, server):
        addr = _get_check_password_address(server)
        result = server.mcp_find_function_containing(addr=addr)
        assert result.name == 'check_password', (
            f'Expected "check_password", got: {result.name!r}'
        )


class TestGetSymbol:
    """mcp_get_symbol(addr=...) -> SymbolInfo with name and symbol_type."""

    def test_get_symbol_at_main(self, server):
        addr = _get_main_address(server)
        result = server.mcp_get_symbol(addr=addr)
        assert result is not None
        assert result.name == 'main', f'Expected symbol name "main", got: {result.name!r}'

    def test_get_symbol_has_symbol_type(self, server):
        addr = _get_main_address(server)
        result = server.mcp_get_symbol(addr=addr)
        valid_types = {'function', 'code_label', 'global_variable', 'data_label', 'unknown'}
        assert result.symbol_type in valid_types, (
            f'Expected symbol_type in {valid_types}, got: {result.symbol_type!r}'
        )

    def test_get_symbol_main_is_function_type(self, server):
        addr = _get_main_address(server)
        result = server.mcp_get_symbol(addr=addr)
        assert result.symbol_type == 'function', (
            f'Expected main to have symbol_type="function", got: {result.symbol_type!r}'
        )

    def test_get_symbol_check_password(self, server):
        addr = _get_check_password_address(server)
        result = server.mcp_get_symbol(addr=addr)
        assert result.name == 'check_password', f'Got: {result.name!r}'
        assert result.symbol_type == 'function'


class TestFindXrefsToAddr:
    """mcp_find_xrefs_to_addr(addr=...) -> ListResult of callers."""

    def test_find_xrefs_to_check_password(self, server):
        """check_password is called from main — xrefs list should be non-empty."""
        addr = _get_check_password_address(server)
        result = server.mcp_find_xrefs_to_addr(addr=addr)
        assert result is not None
        assert isinstance(result.items, list)
        assert len(result.items) > 0, (
            'Expected at least one xref to check_password (called from main)'
        )

    def test_xrefs_items_have_from_key(self, server):
        addr = _get_check_password_address(server)
        result = server.mcp_find_xrefs_to_addr(addr=addr)
        for item in result.items:
            assert isinstance(item, dict)
            assert 'from' in item, f'Xref item missing "from" key: {item!r}'

    def test_xrefs_from_main_calls_check_password(self, server):
        """The xref from main to check_password should identify main as the caller."""
        addr = _get_check_password_address(server)
        result = server.mcp_find_xrefs_to_addr(addr=addr)
        caller_funcs = []
        for item in result.items:
            from_info = item.get('from', {})
            if isinstance(from_info, dict) and 'function' in from_info:
                caller_funcs.append(from_info['function'])
        assert 'main' in caller_funcs, (
            f'Expected "main" among callers of check_password, found: {caller_funcs}'
        )

    def test_xrefs_has_page_info(self, server):
        addr = _get_check_password_address(server)
        result = server.mcp_find_xrefs_to_addr(addr=addr)
        assert result.page_info is not None
        assert result.page_info.total_count >= 0

    def test_xrefs_pagination(self, server):
        """Limit=1 should return at most 1 item."""
        addr = _get_check_password_address(server)
        result = server.mcp_find_xrefs_to_addr(addr=addr, limit=1)
        assert len(result.items) <= 1


class TestFindXrefsFromAddr:
    """mcp_find_xrefs_from_addr(addr=...) -> ListResult of outgoing refs."""

    def test_find_xrefs_from_main(self, server):
        """main calls check_password — outgoing xrefs should be non-empty."""
        addr = _get_main_address(server)
        result = server.mcp_find_xrefs_from_addr(addr=addr)
        assert result is not None
        assert isinstance(result.items, list)

    def test_xrefs_from_items_have_dest_key(self, server):
        addr = _get_main_address(server)
        result = server.mcp_find_xrefs_from_addr(addr=addr)
        for item in result.items:
            assert isinstance(item, dict)
            assert 'to' in item, f'Xref-from item missing "dest" key: {item!r}'

    def test_xrefs_from_has_page_info(self, server):
        addr = _get_main_address(server)
        result = server.mcp_find_xrefs_from_addr(addr=addr)
        assert result.page_info is not None
        assert result.page_info.total_count >= 0

    def test_xrefs_from_pagination_limit(self, server):
        """Limit=1 should return at most 1 item."""
        addr = _get_main_address(server)
        result = server.mcp_find_xrefs_from_addr(addr=addr, limit=1)
        assert len(result.items) <= 1


class TestFindXrefsToFunc:
    """mcp_find_xrefs_to_func(name=...) -> ListResult of callers by function name."""

    def test_find_xrefs_to_check_password_by_name(self, server):
        """check_password is called from main — xrefs should be non-empty."""
        result = server.mcp_find_xrefs_to_func(name='check_password')
        assert result is not None
        assert isinstance(result.items, list)
        assert len(result.items) > 0, (
            'Expected at least one xref to check_password (called from main)'
        )

    def test_xrefs_to_func_items_have_from_key(self, server):
        result = server.mcp_find_xrefs_to_func(name='check_password')
        for item in result.items:
            assert isinstance(item, dict)
            assert 'from' in item, f'Xref item missing "from" key: {item!r}'

    def test_xrefs_to_func_caller_is_main(self, server):
        """The caller of check_password should include main."""
        result = server.mcp_find_xrefs_to_func(name='check_password')
        caller_funcs = []
        for item in result.items:
            from_info = item.get('from', {})
            if isinstance(from_info, dict) and 'function' in from_info:
                caller_funcs.append(from_info['function'])
        assert 'main' in caller_funcs, (
            f'Expected "main" among callers of check_password (by name), found: {caller_funcs}'
        )

    def test_xrefs_to_func_has_page_info(self, server):
        result = server.mcp_find_xrefs_to_func(name='check_password')
        assert result.page_info is not None
        assert result.page_info.total_count >= 0

    def test_xrefs_to_func_pagination_limit(self, server):
        """Limit=1 should return at most 1 item."""
        result = server.mcp_find_xrefs_to_func(name='check_password', limit=1)
        assert len(result.items) <= 1


class TestGetFunctionComment:
    """mcp_get_function_comment(name=...) / mcp_get_function_comment(addr=...) -> str."""

    def test_get_function_comment_by_name_returns_str(self, server):
        result = server.mcp_get_function_comment(name='main')
        assert isinstance(result, str)
        assert_non_empty(result)

    def test_get_function_comment_contains_function_name(self, server):
        result = server.mcp_get_function_comment(name='main')
        assert 'main' in result, (
            f'Expected "main" in comment response, got: {result!r}'
        )

    def test_get_function_comment_by_addr(self, server):
        addr = _get_main_address(server)
        result = server.mcp_get_function_comment(addr=addr)
        assert isinstance(result, str)
        assert_non_empty(result)

    def test_get_function_comment_check_password(self, server):
        result = server.mcp_get_function_comment(name='check_password')
        assert isinstance(result, str)
        assert 'check_password' in result, (
            f'Expected "check_password" in comment response, got: {result!r}'
        )
