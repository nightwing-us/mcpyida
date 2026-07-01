"""Integration test fixtures — loads binary via idalib, exposes tool functions.

The ``server`` fixture is kept for backward compatibility but now returns a
thin namespace that exposes tool function imports directly (no McpServer
method calls — those no longer exist on the refactored McpServer class).

The database is loaded once per session and IDA auto-analysis is waited on
before any test runs. Stale IDA database files are removed first so we
always get a fresh analysis.
"""
from __future__ import annotations

import glob
import os
import types

import pytest

from tests.conftest import CRACKME_ELF
from tests.integration.helpers import _run_async


def _xref_flat_to_listresult(flat: dict) -> object:
    """Adapt a flat xrefs item (the standardized contract) back into a
    ListResult for the per-direction xref test helpers.

    xrefs returns a flat per-item dict (rows under ``items``, no ``['result']``
    wrapper). These adapters present the merged tool in the old per-direction
    ListResult shape the integration tests were written against.
    """
    from mcpyida.models import ListResult

    fields = {
        k: flat[k]
        for k in ('summary', 'entry_type', 'schema_version', 'page_info', 'items')
        if k in flat
    }
    return ListResult(**fields)


def _clean_stale_ida_files(binary_path: str) -> None:
    """Remove stale IDA database files next to binary_path."""
    directory = os.path.dirname(binary_path)
    stale_extensions = ['*.id0', '*.id1', '*.id2', '*.nam', '*.til', '*.i64']
    for pattern in stale_extensions:
        for path in glob.glob(os.path.join(directory, pattern)):
            try:
                os.remove(path)
            except OSError:
                pass


@pytest.fixture(scope='session')
def server():
    """Load binary via idalib, yield a namespace of tool functions, then close the database.

    The namespace exposes the same names the tests used to call on McpServer,
    but now delegates to standalone tool functions from mcpyida.tools.*

    Skips the entire session if idalib (idapro) is not available.
    """
    idapro = pytest.importorskip('idapro')
    import ida_auto

    _clean_stale_ida_files(CRACKME_ELF)
    idapro.open_database(CRACKME_ELF, run_auto_analysis=True)
    ida_auto.auto_wait()

    from mcpyida.tools.core import list_entries, cursor, context, get_funcs
    from mcpyida.tools.analysis import decompile, disasm, symbols, xrefs
    from mcpyida.tools.modify import (
        rename,
        update_vars,
        set_comments,
        get_comment,
        set_prototype,
        patch,
        begin_trans,
        end_trans,
    )

    # Build a compatibility shim that maps the old McpServer method names to
    # the new standalone tool function signatures. The integration tests call
    # e.g. ``server.mcp_list(entry_type='function', offset=0, limit=10)`` —
    # these shims forward those calls to the correct tool functions.

    ns = types.SimpleNamespace()

    # Core tools — wrap async functions with _run_async for synchronous test use
    def _mcp_list(*args, **kwargs):
        return _run_async(list_entries, *args, **kwargs)

    def _mcp_get_context():
        return _run_async(context)

    ns.mcp_list = _mcp_list
    ns.mcp_get_context = _mcp_get_context

    # Analysis tools — old methods took keyword args; new functions take
    # list-based batched APIs or direct keyword args depending on the tool.
    # Provide compatibility wrappers only where the signature changed.

    def _mcp_decompile_function(name: str = '', addr: str = '') -> str:
        result = _run_async(decompile, [{'name': name, 'addr': addr}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        return result[0]['code'] if result else ''

    def _mcp_disassemble_function(name: str = '', addr: str = '') -> str:
        result = _run_async(disasm, [{'name': name, 'addr': addr}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        entry = result[0]
        return entry.get('asm', '')

    def _mcp_disassemble_addr(addr: str = '', num_instructions: int = 10) -> str:
        result = _run_async(disasm, [{'addr': addr, 'count': num_instructions}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        return result[0].get('asm', '')

    def _mcp_find_function_containing(addr: str = '') -> object:
        """Return a FunctionInfo-like object for the function containing addr."""
        # Use get_funcs on address to resolve the function
        result = _run_async(get_funcs, [addr])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        if not result:
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(f'No function found containing {addr}')
        item = result[0]
        return types.SimpleNamespace(
            name=item.get('name', ''),
            entrypoint=item.get('entrypoint', ''),
        )

    def _mcp_get_symbol(addr: str = '') -> object:
        result = _run_async(symbols, [addr])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        if not result:
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(f'No symbol at {addr}')
        item = result[0]
        return types.SimpleNamespace(
            name=item.get('name', ''),
            symbol_type=item.get('symbol_type', 'unknown'),
        )

    def _mcp_find_xrefs_to_addr(addr: str = '', limit: int = 500) -> object:
        result = _run_async(xrefs, [{'addr': addr, 'direction': 'to', 'limit': limit}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        return _xref_flat_to_listresult(result[0]) if result else None

    def _mcp_find_xrefs_from_addr(addr: str = '', limit: int = 500) -> object:
        result = _run_async(xrefs, [{'addr': addr, 'direction': 'from', 'limit': limit}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        return _xref_flat_to_listresult(result[0]) if result else None

    def _mcp_find_xrefs_to_func(name: str = '', limit: int = 500) -> object:
        result = _run_async(xrefs, [{'name': name, 'direction': 'to', 'limit': limit}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        return _xref_flat_to_listresult(result[0]) if result else None

    def _mcp_get_function_comment(name: str = '', addr: str = '') -> str:
        result = _run_async(get_comment, [{'name': name, 'addr': addr}])
        if result and result[0].get('error'):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(result[0]['error'])
        item = result[0]
        func_name = item.get('name', name)
        comment = item.get('comment', '')
        if comment:
            return f'{func_name}: {comment}'
        return func_name

    ns.mcp_decompile_function = _mcp_decompile_function
    ns.mcp_disassemble_function = _mcp_disassemble_function
    ns.mcp_disassemble_addr = _mcp_disassemble_addr
    ns.mcp_find_function_containing = _mcp_find_function_containing
    ns.mcp_get_symbol = _mcp_get_symbol
    ns.mcp_find_xrefs_to_addr = _mcp_find_xrefs_to_addr
    ns.mcp_find_xrefs_from_addr = _mcp_find_xrefs_from_addr
    ns.mcp_find_xrefs_to_func = _mcp_find_xrefs_to_func
    ns.mcp_get_function_comment = _mcp_get_function_comment

    yield ns

    idapro.close_database()
