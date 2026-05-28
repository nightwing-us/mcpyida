"""Integration tests for idapython_eval — script execution tool.

Tests call idapython_eval(code) directly. idalib must be available
(tests are session-scoped via conftest.py server fixture which loads the binary).
"""
from __future__ import annotations

import pytest

from mcpyida.tools.scripting import idapython_eval
from tests.integration.helpers import _run_async


class TestIdapythonEval:
    """idapython_eval(code) -> ScriptResult"""

    def test_simple_expression(self, server):
        """1+1 evaluates to '2' with success=True."""
        result = _run_async(idapython_eval, '1+1')
        assert result.success is True
        assert result.result == '2'
        assert result.error is None

    def test_stdout(self, server):
        """print() output is captured in stdout and output fields."""
        result = _run_async(idapython_eval, "print('hello')")
        assert result.success is True
        assert 'hello' in result.stdout
        assert 'hello' in result.output

    def test_multiline_jupyter(self, server):
        """Multi-line code with last expression returns that expression's value."""
        result = _run_async(idapython_eval, 'x=1\nx+1')
        assert result.success is True
        assert result.result == '2'

    def test_error(self, server):
        """Division by zero sets success=False and error contains ZeroDivision."""
        result = _run_async(idapython_eval, '1/0')
        assert result.success is False
        assert result.error is not None
        assert 'ZeroDivision' in result.error or 'ZeroDivision' in (result.error_traceback or '')

    def test_ida_api_access(self, server):
        """IDA Python API access: idc.get_inf_attr returns a valid address."""
        result = _run_async(idapython_eval, 'idc.get_inf_attr(idc.INF_MIN_EA)')
        assert result.success is True, f'Unexpected error: {result.error}'
        assert result.result is not None
        # Should be a numeric value (minimum address)
        val = int(result.result)
        assert val >= 0

    def test_function_count(self, server):
        """idautils.Functions() returns a non-empty list of functions."""
        result = _run_async(idapython_eval, 'len(list(idautils.Functions()))')
        assert result.success is True, f'Unexpected error: {result.error}'
        assert result.result is not None
        count = int(result.result)
        assert count > 0, f'Expected function count > 0, got {count}'

    def test_variable_assignment(self, server):
        """Assigning to 'result' variable returns that value."""
        result = _run_async(idapython_eval, 'result = 42')
        assert result.success is True
        assert result.result == '42'


class TestScriptingPersistence:
    """Persistent scripting session tests — variables survive between calls."""

    @pytest.fixture(autouse=True)
    def reset_scripting_state(self, server):
        """Reset persistent globals before and after each test."""
        _run_async(idapython_eval, '', reset=True)
        yield
        _run_async(idapython_eval, '', reset=True)

    def test_variable_persists_between_calls(self, server):
        """Variable set in call 1 is readable in call 2."""
        r1 = _run_async(idapython_eval, 'x = 42')
        assert r1.success

        r2 = _run_async(idapython_eval, 'x')
        assert r2.success
        assert r2.result == '42'

    def test_function_persists(self, server):
        """Function defined in call 1 is callable in call 2."""
        _run_async(idapython_eval, 'def greet(): return "hello"')
        r = _run_async(idapython_eval, 'greet()')
        assert r.success
        assert r.result == 'hello'

    def test_import_persists(self, server):
        """Module imported in call 1 is accessible in call 2."""
        _run_async(idapython_eval, 'import os')
        r = _run_async(idapython_eval, 'os.path.sep')
        assert r.success
        assert r.result in ('/', '\\')

    def test_reset_clears_user_state(self, server):
        """reset=True clears user-defined variables."""
        _run_async(idapython_eval, 'persist_var = 99')
        r = _run_async(idapython_eval, 'persist_var')
        assert r.result == '99'

        # Reset session
        _run_async(idapython_eval, '', reset=True)

        # Variable should be gone
        r = _run_async(idapython_eval, 'persist_var')
        assert r.success is False  # NameError

    def test_reset_preserves_platform_apis(self, server):
        """After reset, IDA Python APIs are still accessible."""
        _run_async(idapython_eval, '', reset=True)
        r = _run_async(idapython_eval, 'idc.get_inf_attr(idc.INF_MIN_EA)')
        assert r.success

    def test_reset_then_execute(self, server):
        """reset=True clears state before executing the supplied code."""
        _run_async(idapython_eval, 'x = 1')
        # After reset, x no longer exists — this should fail with NameError
        r = _run_async(idapython_eval, 'y = x + 1\ny', reset=True)
        assert r.success is False  # NameError on x

    def test_reset_only_returns_session_reset(self, server):
        """reset=True with empty code returns 'Session reset' result."""
        r = _run_async(idapython_eval, '', reset=True)
        assert r.success is True
        assert r.result == 'Session reset'
