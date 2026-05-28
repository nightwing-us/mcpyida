"""Tests for batch-tool contract (no IDA runtime required).

These tests validate:
- Single-item normalization (non-list input becomes a one-element list)
- Batch helper logic: errors in one item do not propagate to others
- Each result contains an 'error' field
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Helpers — simulate the batch pattern used by all MCPyIDA tools
# ---------------------------------------------------------------------------

def _batch_tool(items: list[dict], process_fn) -> list[dict]:
    """Generic batch runner mirroring the MCPyIDA batch pattern."""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        try:
            result = process_fn(item)
            results.append({**result, 'error': None})
        except Exception as e:
            results.append({'error': str(e), **item})
    return results


def _process_ok(item: dict) -> dict:
    """A processing function that always succeeds."""
    return {'name': item.get('name', ''), 'value': 42}


def _process_fail(item: dict) -> dict:
    """A processing function that always raises."""
    raise ValueError(f"failed for {item.get('name', '?')}")


def _process_selective(item: dict) -> dict:
    """A processing function that fails only for items with fail=True."""
    if item.get('fail'):
        raise ValueError(f"deliberate failure: {item.get('name', '?')}")
    return {'name': item.get('name', ''), 'value': 1}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBatchNormalization:
    def test_single_dict_becomes_list(self):
        """A single dict (non-list) is normalized to a one-element list."""
        item = {'name': 'main'}
        results = _batch_tool(item, _process_ok)  # type: ignore[arg-type]
        assert len(results) == 1
        assert results[0]['name'] == 'main'
        assert results[0]['error'] is None

    def test_list_passes_through(self):
        """A list of items passes through without modification."""
        items = [{'name': 'foo'}, {'name': 'bar'}]
        results = _batch_tool(items, _process_ok)
        assert len(results) == 2
        assert results[0]['name'] == 'foo'
        assert results[1]['name'] == 'bar'

    def test_empty_list_passes_through(self):
        """An empty list returns an empty result list."""
        results = _batch_tool([], _process_ok)
        assert results == []

    def test_batch_result_has_error_field(self):
        """Every result dict contains an 'error' key."""
        items = [{'name': 'a'}, {'name': 'b'}]
        results = _batch_tool(items, _process_ok)
        for r in results:
            assert 'error' in r

    def test_error_in_one_item_does_not_fail_others(self):
        """An exception in one item is captured; other items still produce results."""
        items = [
            {'name': 'good1'},
            {'name': 'bad', 'fail': True},
            {'name': 'good2'},
        ]
        results = _batch_tool(items, _process_selective)
        assert len(results) == 3

        # First and last items succeeded
        assert results[0]['error'] is None
        assert results[0]['name'] == 'good1'
        assert results[2]['error'] is None
        assert results[2]['name'] == 'good2'

        # Middle item has an error
        assert results[1]['error'] is not None
        assert 'deliberate failure' in results[1]['error']

    def test_all_errors_captured_individually(self):
        """When all items fail, each result contains its own error message."""
        items = [{'name': 'x'}, {'name': 'y'}]
        results = _batch_tool(items, _process_fail)
        assert len(results) == 2
        for r in results:
            assert r['error'] is not None
            assert 'failed for' in r['error']

    def test_single_item_normalization_with_list_input(self):
        """Demonstrates the normalization guard: if not isinstance(items, list): items = [items]."""
        single: Any = {'name': 'only_one'}
        # Direct simulation of the guard used in tool functions
        if not isinstance(single, list):
            single = [single]
        assert isinstance(single, list)
        assert len(single) == 1
        assert single[0]['name'] == 'only_one'

    def test_list_input_not_double_wrapped(self):
        """A list is NOT wrapped in another list by the normalization guard."""
        many: Any = [{'name': 'a'}, {'name': 'b'}]
        if not isinstance(many, list):
            many = [many]
        assert len(many) == 2
