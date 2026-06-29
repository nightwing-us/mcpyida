"""Unit tests for the single-or-batch dispatch helpers (no IDA needed)."""
import pytest

from mcp.server.fastmcp.exceptions import ToolError
from mcpyida.dispatch import single_or_batch, unwrap


def test_dict_flat_builds_single_item_and_drops_none():
    items, single = single_or_batch(
        None, {"addr": "0x401000", "name": None}, kind="dict"
    )
    assert items == [{"addr": "0x401000"}]
    assert single is True


def test_scalar_flat_builds_single_value():
    items, single = single_or_batch(None, {"addr": "0x401000"}, kind="scalar")
    assert items == ["0x401000"]
    assert single is True


def test_batch_list_passes_through():
    items, single = single_or_batch(
        [{"addr": "0x1"}, {"addr": "0x2"}], {"addr": None, "name": None}, kind="dict"
    )
    assert items == [{"addr": "0x1"}, {"addr": "0x2"}]
    assert single is False


def test_empty_list_is_batch_not_error():
    items, single = single_or_batch([], {"addr": None}, kind="dict")
    assert items == []
    assert single is False


def test_both_items_and_flat_is_error():
    with pytest.raises(ToolError, match="not both"):
        single_or_batch([{"addr": "0x1"}], {"addr": "0x2"}, kind="dict")


def test_neither_is_error_with_field_names():
    with pytest.raises(ToolError, match="addr"):
        single_or_batch(None, {"addr": None, "name": None}, kind="dict")


def test_empty_call_appends_hint():
    with pytest.raises(ToolError, match="list\\(entry_type=\"function\"\\)"):
        single_or_batch(
            None, {"target": None}, kind="scalar",
            empty_hint='list(entry_type="function")',
        )


def test_invalid_kind_raises_valueerror():
    with pytest.raises(ValueError, match="kind must be"):
        single_or_batch(None, {"addr": "0x1"}, kind="bogus")


def test_unwrap_single_returns_dict():
    assert unwrap([{"a": 1}], True) == {"a": 1}


def test_unwrap_batch_returns_list():
    assert unwrap([{"a": 1}, {"a": 2}], False) == [{"a": 1}, {"a": 2}]


def test_unwrap_single_but_multiple_returns_list():
    # Defensive: was_single but impl returned !=1 -> return the list unchanged.
    assert unwrap([{"a": 1}, {"a": 2}], True) == [{"a": 1}, {"a": 2}]
