"""Unit tests for the standardized xrefs input/output contract.

xrefs is aligned with the sibling items-batched tools:
- INPUT: accept `addr`/`name` (plus `target`/`ea`/`function` aliases), not
  `target`-only.
- OUTPUT: a flat per-item dict with rows under `items` and `error` at the top
  level — NOT nested under `['result']`.

These exercise the pure helpers, so no IDA runtime is required.
"""
from __future__ import annotations

from mcpyida.models import ListResult, ResultPageInfo
from mcpyida.tools.analysis import _flatten_xref_item, _parse_xref_item


def _list_result(items):
    return ListResult(
        summary='Cross-references to 0x401000',
        entry_type='cross-reference',
        schema_version=1,
        page_info=ResultPageInfo(
            offset=0, limit=500, num_returned=len(items),
            total_count=len(items), has_more=False, next_offset=None,
        ),
        items=items,
    )


class TestParseXrefItem:
    def test_addr_key(self):
        assert _parse_xref_item({'addr': '0x401000'}) == ('0x401000', '')

    def test_name_key(self):
        assert _parse_xref_item({'name': 'main'}) == ('', 'main')

    def test_legacy_target_addr_like(self):
        assert _parse_xref_item({'target': '0x401000'}) == ('0x401000', '')

    def test_legacy_target_name_like(self):
        assert _parse_xref_item({'target': 'check_password'}) == ('', 'check_password')

    def test_ea_alias(self):
        assert _parse_xref_item({'ea': '0x401000'}) == ('0x401000', '')

    def test_function_alias(self):
        assert _parse_xref_item({'function': 'main'}) == ('', 'main')

    def test_addr_and_name_both_kept(self):
        assert _parse_xref_item({'addr': '0x401000', 'name': 'main'}) == (
            '0x401000', 'main',
        )

    def test_empty_item(self):
        assert _parse_xref_item({}) == ('', '')


class TestFlattenXrefItem:
    def test_rows_lifted_to_items_no_result_wrapper(self):
        lr = _list_result([{'addr': '0x401005', 'type': 'call'}])
        out = _flatten_xref_item({'addr': '0x401000'}, 'to', lr)
        assert 'result' not in out
        assert out['items'] == [{'addr': '0x401005', 'type': 'call'}]

    def test_echo_and_direction_and_error_present(self):
        lr = _list_result([])
        out = _flatten_xref_item({'addr': '0x401000', 'name': 'main'}, 'from', lr)
        assert out['addr'] == '0x401000'
        assert out['name'] == 'main'
        assert out['direction'] == 'from'
        assert out['error'] is None

    def test_listresult_fields_flattened(self):
        lr = _list_result([])
        out = _flatten_xref_item({'addr': '0x401000'}, 'to', lr)
        assert out['summary'] == 'Cross-references to 0x401000'
        assert out['entry_type'] == 'cross-reference'
        assert 'page_info' in out

    def test_echo_keys_not_clobbered_by_listresult(self):
        # ListResult has no 'addr' field, but the echo must always win.
        lr = _list_result([])
        out = _flatten_xref_item({'addr': '0xdeadbeef'}, 'to', lr)
        assert out['addr'] == '0xdeadbeef'
