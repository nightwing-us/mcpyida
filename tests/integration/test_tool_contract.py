"""Conformance test for the shared tool-surface contract.

Iterates the batched read tools and asserts the one input/output convention the
whole surface follows, so a tool can't silently drift back to a per-tool shape
(the failure mode reported in mcpyida_patches.zip). Mirrors MCPyGhidra's
tests/integration/test_tool_contract.py so the two surfaces stay aligned.

The shared contract:
- per-item address is under `addr` (never `address`); segment ranges use
  `start`/`end`.
- batched-tool rows are under `items` (never `matches`/`result`).
- every batched item carries a top-level `error` key (None on success).
- `xrefs` is addressed like its siblings: `addr`/`name` (and the legacy `target`
  alias), output flat — rows under `items`, no `['result']` wrapper.

idalib must be available; the session-scoped `server` fixture loads the binary.
"""

from __future__ import annotations

import pytest

from mcpyida.tools.analysis import decompile, disasm, symbols, xrefs
from mcpyida.tools.core import get_funcs, list_entries
from mcpyida.tools.search import find_bytes, find_insns
from mcpyida.tools.types import type_info
from tests.integration.helpers import _run_async

# Keys that must never appear on a per-item dict — the deviations the contract
# standardization removed.
BANNED_ITEM_KEYS = ('address', 'matches', 'result')


def _main_addr() -> str:
    result = _run_async(
        list_entries, entry_type='function', offset=0, limit=500, match_filter='main'
    )
    for item in result.items:
        if item['name'] == 'main':
            return item['addr']
    pytest.fail('could not resolve "main" address')


class TestListContract:
    def test_items_use_addr_not_address(self, server):
        result = _run_async(list_entries, entry_type='function', offset=0, limit=25)
        assert result.items, 'expected at least one function'
        for item in result.items:
            assert 'address' not in item, f'list item leaked "address": {item!r}'
            # functions carry a single address; segments carry start/end
            assert 'addr' in item or ('start' in item and 'end' in item), (
                f'list item missing addr (or start/end): {item!r}'
            )


class TestBatchedReadToolsContract:
    """Every batched read tool returns flat items with `error` and no banned keys."""

    def _assert_contract(self, items: list[dict]) -> None:
        assert isinstance(items, list) and items, 'expected a non-empty list of items'
        for item in items:
            assert isinstance(item, dict)
            assert 'error' in item, f'batched item missing top-level "error": {item!r}'
            for banned in BANNED_ITEM_KEYS:
                assert banned not in item, (
                    f'batched item leaked banned key {banned!r}: {item!r}'
                )

    def test_funcs(self, server):
        self._assert_contract(_run_async(get_funcs, ['main']))

    def test_symbols(self, server):
        self._assert_contract(_run_async(symbols, [_main_addr()]))

    def test_decompile(self, server):
        self._assert_contract(_run_async(decompile, [{'name': 'main'}]))

    def test_disasm(self, server):
        self._assert_contract(_run_async(disasm, [{'name': 'main'}]))

    def test_type_info(self, server):
        # Both success and failure items must carry `error`; we don't care which
        # this resolves to — only that the contract key is present.
        self._assert_contract(_run_async(type_info, ['int']))

    def test_find_bytes(self, server):
        self._assert_contract(_run_async(find_bytes, ['55']))

    def test_find_insns(self, server):
        self._assert_contract(_run_async(find_insns, [[{'mnemonic': 'CALL'}]]))

    def test_xrefs(self, server):
        self._assert_contract(_run_async(xrefs, [{'name': 'main', 'direction': 'to'}]))


class TestXrefsAddressingParity:
    """xrefs accepts the sibling addressing keys and emits the flat shape."""

    def test_accepts_name(self, server):
        out = _run_async(xrefs, [{'name': 'main', 'direction': 'from'}])[0]
        assert out['error'] is None
        assert 'items' in out and 'result' not in out
        assert out['addr'].startswith('0x')

    def test_accepts_addr(self, server):
        out = _run_async(xrefs, [{'addr': _main_addr(), 'direction': 'from'}])[0]
        assert out['error'] is None
        assert 'items' in out and 'result' not in out

    def test_accepts_legacy_target_alias(self, server):
        out = _run_async(xrefs, [{'target': 'main', 'direction': 'from'}])[0]
        assert out['error'] is None
        assert 'items' in out and 'result' not in out
        # target is an input alias only — it must not echo into the output
        assert 'target' not in out
