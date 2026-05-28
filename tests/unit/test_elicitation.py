"""Unit tests for MCP elicitation infrastructure in MCPyIDA.

Tests cover:
- ConfirmAction model
- elicit_confirmation fallback behaviour when no context is set
- _ida_batch_state cleared by context managers
- contextvars context threading
"""
from __future__ import annotations

import anyio
import pytest

from mcpyida.models import ConfirmAction


# ---------------------------------------------------------------------------
# ConfirmAction model tests
# ---------------------------------------------------------------------------

class TestConfirmAction:
    def test_confirm_true(self):
        ca = ConfirmAction(confirm=True)
        assert ca.confirm is True
        assert ca.apply_to_all is False

    def test_confirm_false(self):
        ca = ConfirmAction(confirm=False)
        assert ca.confirm is False

    def test_apply_to_all_default_false(self):
        ca = ConfirmAction(confirm=True)
        assert ca.apply_to_all is False

    def test_apply_to_all_true(self):
        ca = ConfirmAction(confirm=True, apply_to_all=True)
        assert ca.apply_to_all is True

    def test_missing_confirm_raises(self):
        with pytest.raises(Exception):
            ConfirmAction()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# elicit_confirmation fallback tests (no MCP context)
# ---------------------------------------------------------------------------

class TestElicitConfirmationFallback:
    """When no MCP context is set, elicit_confirmation should auto-allow."""

    def _run(self, coro):
        async def wrapper():
            return await coro
        return anyio.run(wrapper)

    def test_no_context_returns_true(self):
        """With no context, elicit_confirmation auto-allows (returns True)."""
        from mcpyida.server import elicit_confirmation, _current_mcp_context
        assert _current_mcp_context.get() is None
        result = self._run(elicit_confirmation('Confirm rename?', {}))
        assert result is True

    def test_apply_to_all_decision_cached_true(self):
        """When batch_state has apply_to_all_decision=True, returns True without elicitation."""
        from mcpyida.server import elicit_confirmation
        batch_state = {'apply_to_all_decision': True}
        result = self._run(elicit_confirmation('anything', batch_state))
        assert result is True

    def test_apply_to_all_decision_cached_false(self):
        """When batch_state has apply_to_all_decision=False, returns False without elicitation."""
        from mcpyida.server import elicit_confirmation
        batch_state = {'apply_to_all_decision': False}
        result = self._run(elicit_confirmation('anything', batch_state))
        assert result is False

    def test_ctx_elicit_exception_falls_back_to_true(self):
        """If ctx.elicit() raises (SDK doesn't support it), returns True."""
        from mcpyida.server import elicit_confirmation, _current_mcp_context
        from unittest.mock import MagicMock, AsyncMock

        mock_ctx = MagicMock()
        mock_ctx.elicit = AsyncMock(side_effect=AttributeError('elicit not supported'))

        token = _current_mcp_context.set(mock_ctx)
        try:
            result = self._run(elicit_confirmation('Confirm rename?', {}))
            assert result is True
        finally:
            _current_mcp_context.reset(token)


# ---------------------------------------------------------------------------
# get_current_context tests
# ---------------------------------------------------------------------------

class TestGetCurrentContext:
    def test_default_is_none(self):
        from mcpyida.server import get_current_context
        assert get_current_context() is None

    def test_set_returns_context(self):
        from mcpyida.server import get_current_context, _current_mcp_context
        from unittest.mock import MagicMock
        mock_ctx = MagicMock()
        token = _current_mcp_context.set(mock_ctx)
        try:
            assert get_current_context() is mock_ctx
        finally:
            _current_mcp_context.reset(token)

    def test_reset_returns_none(self):
        from mcpyida.server import get_current_context, _current_mcp_context
        from unittest.mock import MagicMock
        mock_ctx = MagicMock()
        token = _current_mcp_context.set(mock_ctx)
        _current_mcp_context.reset(token)
        assert get_current_context() is None


# ---------------------------------------------------------------------------
# _ida_batch_state tests
# ---------------------------------------------------------------------------

class TestIdaBatchState:
    """The module-level _ida_batch_state is cleared by server.py before/after tool calls."""

    def test_initial_state_is_empty_or_dict(self):
        from mcpyida.server import _ida_batch_state
        assert isinstance(_ida_batch_state, dict)

    def test_batch_state_can_be_populated_and_cleared(self):
        from mcpyida.server import _ida_batch_state
        _ida_batch_state['apply_to_all_decision'] = True
        assert _ida_batch_state.get('apply_to_all_decision') is True
        _ida_batch_state.clear()
        assert _ida_batch_state == {}


# ---------------------------------------------------------------------------
# elicit_confirmation_sync tests
# ---------------------------------------------------------------------------

class TestElicitConfirmationSync:
    """elicit_confirmation_sync bridges sync->async for IDA main thread."""

    def test_no_context_returns_true(self):
        """Without a running event loop or context, returns True (auto-allow)."""
        from mcpyida.server import elicit_confirmation_sync, _current_mcp_context
        assert _current_mcp_context.get() is None
        result = elicit_confirmation_sync('Confirm rename?', {})
        assert result is True

    def test_apply_to_all_cached_true(self):
        """Fast path: batch_state has apply_to_all_decision=True -> True immediately."""
        from mcpyida.server import elicit_confirmation_sync
        batch_state = {'apply_to_all_decision': True}
        result = elicit_confirmation_sync('anything', batch_state)
        assert result is True

    def test_apply_to_all_cached_false(self):
        """Fast path: batch_state has apply_to_all_decision=False -> False immediately."""
        from mcpyida.server import elicit_confirmation_sync
        batch_state = {'apply_to_all_decision': False}
        result = elicit_confirmation_sync('anything', batch_state)
        assert result is False
