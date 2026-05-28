"""Integration test helpers — assertion utilities, async runner, and test data finders."""
from __future__ import annotations

from typing import Any

import anyio


def _run_async(async_fn, *args, **kwargs) -> Any:
    """Run an async function synchronously for integration tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


def assert_valid_address(addr: str) -> None:
    """Assert addr is a valid hex string."""
    assert isinstance(addr, str), f'Expected string, got {type(addr).__name__}'
    assert addr.startswith('0x') or addr.startswith('-0x'), (
        f'Expected hex address, got {addr!r}'
    )
    int(addr, 16)  # Raises ValueError if invalid


def assert_non_empty(value: Any) -> None:
    """Assert value is not None and not empty."""
    assert value is not None, 'Value is None'
    if hasattr(value, '__len__'):
        assert len(value) > 0, f'Value is empty: {value!r}'
