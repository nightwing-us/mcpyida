"""Integration tests for find_bytes and find_insns — search tools.

Tests call tool functions directly. idalib must be available
(tests are session-scoped via conftest.py server fixture which loads the binary).
"""
from __future__ import annotations

import pytest

from mcpyida.tools.search import find_bytes, find_insns
from tests.integration.helpers import _run_async


class TestFindBytes:
    """find_bytes(patterns, limit, offset) -> list[dict]"""

    def test_find_bytes_prologue(self, server):
        """Search for function prologue bytes returns at least one match."""
        # x86-64 prologue: PUSH RBP (0x55) or MOV RSP,RBP (48 89)
        result = _run_async(find_bytes, ['55'])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None, f'Unexpected error: {entry["error"]}'
        assert len(entry['items']) > 0, 'Expected at least one match for prologue byte 0x55'

    def test_find_bytes_wildcard(self, server):
        """CALL instruction pattern E8 ?? ?? ?? ?? finds call instructions."""
        result = _run_async(find_bytes, ['E8 ?? ?? ?? ??'])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None, f'Unexpected error: {entry["error"]}'
        assert len(entry['items']) > 0, 'Expected CALL instructions in binary'
        # Verify match structure
        match = entry['items'][0]
        assert 'addr' in match
        assert 'bytes' in match
        assert '0x' in match['addr']

    def test_find_bytes_no_match(self, server):
        """Searching for unlikely bytes returns empty matches list."""
        result = _run_async(find_bytes, ['DE AD BE EF DE AD'])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert entry['items'] == []
        assert entry['has_more'] is False

    def test_find_bytes_pagination(self, server):
        """limit=2 returns at most 2 matches."""
        result = _run_async(find_bytes, ['55'], limit=2)
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert len(entry['items']) <= 2

    def test_find_bytes_multiple_patterns(self, server):
        """Batch search with two patterns returns two result entries."""
        result = _run_async(find_bytes, ['55', 'C3'])
        assert len(result) == 2
        for entry in result:
            assert entry['error'] is None
            assert 'pattern' in entry
            assert 'items' in entry
            assert 'has_more' in entry

    def test_find_bytes_match_structure(self, server):
        """Each match contains addr and bytes fields in correct format."""
        result = _run_async(find_bytes, ['55'], limit=5)
        entry = result[0]
        assert entry['error'] is None
        for match in entry['items']:
            assert 'addr' in match
            assert 'bytes' in match
            assert match['addr'].startswith('0x')
            assert len(match['bytes']) > 0


class TestFindInsns:
    """find_insns(sequences, limit, offset) -> list[dict]"""

    def test_find_insns_call(self, server):
        """CALL instruction sequence finds call instructions in binary."""
        result = _run_async(find_insns, [[{'mnemonic': 'call', 'operands': ['*']}]])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None, f'Unexpected error: {entry["error"]}'
        assert len(entry['items']) > 0, 'Expected CALL instructions in binary'
        match = entry['items'][0]
        assert 'addr' in match
        assert 'instructions' in match
        assert '0x' in match['addr']

    def test_find_insns_no_match(self, server):
        """Searching for a non-existent mnemonic returns empty matches."""
        result = _run_async(find_insns, [[{'mnemonic': 'XYZNOTREAL', 'operands': ['*']}]])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert entry['items'] == []
        assert entry['has_more'] is False

    def test_find_insns_glob_operand(self, server):
        """RET instruction (no operands) is found in binary."""
        result = _run_async(find_insns, [[{'mnemonic': 'retn', 'operands': []}]])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert len(entry['items']) > 0, 'Expected RET instructions in binary'

    def test_find_insns_wildcard_mnemonic(self, server):
        """Wildcard mnemonic '*' matches any instruction."""
        result = _run_async(find_insns, [[{'mnemonic': '*', 'operands': ['*']}]], limit=5)
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert len(entry['items']) > 0

    def test_find_insns_multiple_sequences(self, server):
        """Batch search with two sequences returns two result entries."""
        result = _run_async(
            find_insns,
            [
                [{'mnemonic': 'call', 'operands': ['*']}],
                [{'mnemonic': 'retn', 'operands': []}],
            ],
        )
        assert len(result) == 2
        for entry in result:
            assert 'sequence' in entry
            assert 'items' in entry
            assert 'has_more' in entry
            assert 'error' in entry
