"""Single-or-batch call normalization for MCP tool wrappers.

Framework-agnostic helpers shared by the server.py tool wrappers so that each
items-based tool accepts either a flat single call (decompile(addr=...)) or a
batch call (decompile(items=[...])). Pure functions — no IDA or FastMCP state
beyond ToolError — so they are unit-testable without IDA.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp.exceptions import ToolError


def single_or_batch(
    items: list | None,
    flat: dict[str, Any],
    *,
    kind: str,
    empty_hint: str | None = None,
) -> tuple[list, bool]:
    """Normalize a single-or-batch call into a list of items.

    kind="dict":   flat is {field: value|None}; a single item is the dict of
                   the non-None entries.
    kind="scalar": flat is a 1-entry {field: value|None}; a single item is the
                   scalar value itself.

    Returns (items_list, was_single). Raises ToolError when both items and a
    flat value are given, or when neither is given.
    """
    if kind not in ('dict', 'scalar'):
        raise ValueError(f"kind must be 'dict' or 'scalar', got {kind!r}")
    flat_given = {k: v for k, v in flat.items() if v is not None}
    fields = ', '.join(flat.keys())

    if items is not None and flat_given:
        raise ToolError(f'pass either items=[...] OR {fields}, not both')
    if items is not None:
        return items, False
    if flat_given:
        if kind == 'scalar':
            (value,) = flat_given.values()
            return [value], True
        return [flat_given], True

    msg = f'provide {fields} (or items=[...] for batch)'
    if empty_hint is not None:
        msg += f'. To enumerate, use {empty_hint}'
    raise ToolError(msg)


def unwrap(results: list, was_single: bool) -> Any:
    """Return a single dict for a single call, else the full list."""
    if was_single and len(results) == 1:
        return results[0]
    return results
