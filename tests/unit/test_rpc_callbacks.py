"""Unit tests for mcpyida.rpc_callbacks.

These tests do NOT require IDA Pro or any IDA runtime — rpc_callbacks.py has
no IDA-specific imports.

Test classes:
- TestCallbackScope        — validity token lifecycle
- TestRPCNamespace         — available(), help(), mock(), is_available(), __getattr__
- TestIsNameSafe           — denylist: builtins, keywords, existing globals, safe names
- TestGenerateCallbackFunction — positional, keyword, both, defaults, _rpc_timeout, scope, mock
- TestBuildDocstring       — description, params, timeout, return
- TestMapException         — all mapped types, unknown → RuntimeError, traceback as __cause__
"""
from __future__ import annotations

import io
import sys
from unittest.mock import MagicMock

import pytest

from mcpyida.rpc_callbacks import (
    CallbackScope,
    RPCDisconnectedError,
    RPCError,
    RPCNamespace,
    RPCTimeoutError,
    _PYTHON_DENYLIST,
    _build_docstring,
    generate_callback_function,
    is_name_safe,
    map_exception,
)
from mcpyida.rpc_types import FunctionDefinition


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_defn(
    name: str = 'search_web',
    description: str | None = 'Search the web for information',
    param_order: list[str] | None = None,
    schema_props: dict | None = None,
    required: list[str] | None = None,
    return_description: str | None = 'Search results as formatted text',
) -> FunctionDefinition:
    """Factory for FunctionDefinition fixtures."""
    if param_order is None:
        param_order = ['query', 'max_results']
    if schema_props is None:
        schema_props = {
            'query': {'type': 'string', 'description': 'Search query'},
            'max_results': {'type': 'integer', 'description': 'Max results', 'default': 10},
        }
    if required is None:
        required = ['query']
    return FunctionDefinition(
        name=name,
        description=description,
        parameterOrder=param_order,
        inputSchema={
            'type': 'object',
            'properties': schema_props,
            'required': required,
        },
        returnDescription=return_description,
    )


def mock_rpc_caller(name: str, arguments: dict, timeout: float) -> dict:
    """Simple test double for the rpc_caller argument."""
    return {'called': name, 'args': arguments, 'timeout': timeout}


def _make_fn(
    defn: FunctionDefinition | None = None,
    scope: CallbackScope | None = None,
    ns: RPCNamespace | None = None,
    rpc_caller=mock_rpc_caller,
    default_timeout: float = 30.0,
):
    """Convenience factory: returns (fn, scope, ns)."""
    if defn is None:
        defn = _make_defn()
    if scope is None:
        scope = CallbackScope()
    if ns is None:
        ns = RPCNamespace()
    fn = generate_callback_function(defn, rpc_caller, scope, ns, default_timeout)
    return fn, scope, ns


# ===========================================================================
# TestCallbackScope
# ===========================================================================

class TestCallbackScope:
    def test_initial_state_is_valid(self):
        scope = CallbackScope()
        assert scope.is_valid is True

    def test_invalidate_sets_false(self):
        scope = CallbackScope()
        scope.invalidate()
        assert scope.is_valid is False

    def test_check_passes_when_valid(self):
        scope = CallbackScope()
        # Should not raise
        scope.check()

    def test_check_raises_after_invalidate(self):
        scope = CallbackScope()
        scope.invalidate()
        with pytest.raises(RuntimeError, match='Callback expired'):
            scope.check()

    def test_check_error_message_content(self):
        scope = CallbackScope()
        scope.invalidate()
        with pytest.raises(RuntimeError) as exc_info:
            scope.check()
        assert 'tool execution' in str(exc_info.value)

    def test_double_invalidate_is_idempotent(self):
        scope = CallbackScope()
        scope.invalidate()
        scope.invalidate()
        assert scope.is_valid is False

    def test_multiple_check_calls_while_valid(self):
        scope = CallbackScope()
        scope.check()
        scope.check()
        scope.check()

    def test_independent_scopes_do_not_interfere(self):
        scope_a = CallbackScope()
        scope_b = CallbackScope()
        scope_a.invalidate()
        assert scope_a.is_valid is False
        assert scope_b.is_valid is True


# ===========================================================================
# TestRPCNamespace
# ===========================================================================

class TestRPCNamespace:
    def _make_populated_ns(self) -> RPCNamespace:
        """Return an RPCNamespace with two functions registered."""
        ns = RPCNamespace()
        scope = CallbackScope()

        defn_a = _make_defn(name='search_web')
        defn_b = _make_defn(
            name='ask_llm',
            description='Ask the LLM',
            param_order=['prompt'],
            schema_props={'prompt': {'type': 'string', 'description': 'Prompt text'}},
            required=['prompt'],
            return_description='LLM response',
        )

        fn_a = generate_callback_function(defn_a, mock_rpc_caller, scope, ns)
        fn_b = generate_callback_function(defn_b, mock_rpc_caller, scope, ns)

        ns.update_functions(
            {'search_web': fn_a, 'ask_llm': fn_b},
            {'search_web': defn_a, 'ask_llm': defn_b},
        )
        return ns

    # --- available() ---

    def test_available_empty(self):
        ns = RPCNamespace()
        assert ns.available() == []

    def test_available_sorted(self):
        ns = self._make_populated_ns()
        result = ns.available()
        assert result == sorted(result)
        assert 'ask_llm' in result
        assert 'search_web' in result

    def test_available_returns_list(self):
        ns = RPCNamespace()
        assert isinstance(ns.available(), list)

    # --- is_available() ---

    def test_is_available_false_initially(self):
        ns = RPCNamespace()
        assert ns.is_available() is False

    def test_is_available_true_after_update(self):
        ns = self._make_populated_ns()
        assert ns.is_available() is True

    def test_is_available_false_after_clear(self):
        ns = self._make_populated_ns()
        ns.clear()
        assert ns.is_available() is False

    # --- update_functions() / clear() ---

    def test_update_then_clear_empties_available(self):
        ns = self._make_populated_ns()
        ns.clear()
        assert ns.available() == []

    def test_update_replaces_previous_functions(self):
        ns = RPCNamespace()
        scope = CallbackScope()
        defn = _make_defn(name='fn_v1')
        fn_v1 = generate_callback_function(defn, mock_rpc_caller, scope, ns)
        ns.update_functions({'fn_v1': fn_v1}, {'fn_v1': defn})

        defn2 = _make_defn(name='fn_v2')
        fn_v2 = generate_callback_function(defn2, mock_rpc_caller, scope, ns)
        ns.update_functions({'fn_v2': fn_v2}, {'fn_v2': defn2})

        assert 'fn_v1' not in ns.available()
        assert 'fn_v2' in ns.available()

    # --- __getattr__ ---

    def test_getattr_returns_function(self):
        ns = self._make_populated_ns()
        fn = ns.search_web
        assert callable(fn)

    def test_getattr_missing_raises_attribute_error(self):
        ns = RPCNamespace()
        with pytest.raises(AttributeError, match="No callback function 'nonexistent'"):
            _ = ns.nonexistent

    def test_getattr_private_raises_attribute_error(self):
        ns = RPCNamespace()
        with pytest.raises(AttributeError):
            _ = ns._nonexistent_private

    # --- mock() ---

    def test_mock_registered_in_mocks_dict(self):
        ns = RPCNamespace()
        handler = lambda: 42
        ns.mock('my_fn', handler)
        assert ns._mocks['my_fn'] is handler

    def test_mock_overrides_real_call(self):
        ns = RPCNamespace()
        scope = CallbackScope()
        defn = _make_defn(name='search_web')
        fn = generate_callback_function(defn, mock_rpc_caller, scope, ns)
        ns.update_functions({'search_web': fn}, {'search_web': defn})

        ns.mock('search_web', lambda query, max_results=10: f'mocked:{query}')
        result = fn('hello')
        assert result == 'mocked:hello'

    # --- help() ---

    def test_help_unknown_function_prints_unknown(self, capsys):
        ns = RPCNamespace()
        ns.help('nonexistent')
        out = capsys.readouterr().out
        assert 'Unknown function: nonexistent' in out

    def test_help_prints_function_name_and_params(self, capsys):
        ns = self._make_populated_ns()
        ns.help('search_web')
        out = capsys.readouterr().out
        assert 'search_web' in out
        assert 'query' in out
        assert 'max_results' in out

    def test_help_prints_description(self, capsys):
        ns = self._make_populated_ns()
        ns.help('search_web')
        out = capsys.readouterr().out
        assert 'Search the web for information' in out

    def test_help_prints_rpc_timeout(self, capsys):
        ns = self._make_populated_ns()
        ns.help('search_web')
        out = capsys.readouterr().out
        assert '_rpc_timeout' in out

    def test_help_prints_return_description(self, capsys):
        ns = self._make_populated_ns()
        ns.help('search_web')
        out = capsys.readouterr().out
        assert 'Returns' in out
        assert 'Search results' in out

    def test_help_marks_required_params(self, capsys):
        ns = self._make_populated_ns()
        ns.help('search_web')
        out = capsys.readouterr().out
        assert 'required' in out

    def test_help_shows_default_for_optional(self, capsys):
        ns = self._make_populated_ns()
        ns.help('search_web')
        out = capsys.readouterr().out
        # max_results has default: 10
        assert 'default' in out


# ===========================================================================
# TestIsNameSafe
# ===========================================================================

class TestIsNameSafe:
    # --- builtins blocked ---

    def test_print_is_blocked(self):
        assert is_name_safe('print') is False

    def test_list_is_blocked(self):
        assert is_name_safe('list') is False

    def test_open_is_blocked(self):
        assert is_name_safe('open') is False

    def test_type_is_blocked(self):
        assert is_name_safe('type') is False

    def test_id_is_blocked(self):
        assert is_name_safe('id') is False

    def test_input_is_blocked(self):
        assert is_name_safe('input') is False

    def test_format_is_blocked(self):
        assert is_name_safe('format') is False

    def test_vars_is_blocked(self):
        assert is_name_safe('vars') is False

    # --- keywords blocked ---

    def test_for_is_blocked(self):
        assert is_name_safe('for') is False

    def test_if_is_blocked(self):
        assert is_name_safe('if') is False

    def test_class_is_blocked(self):
        assert is_name_safe('class') is False

    def test_import_is_blocked(self):
        assert is_name_safe('import') is False

    def test_return_is_blocked(self):
        assert is_name_safe('return') is False

    def test_def_is_blocked(self):
        assert is_name_safe('def') is False

    # --- existing globals blocked ---

    def test_existing_global_is_blocked(self):
        existing = {'idc': object()}
        assert is_name_safe('idc', existing) is False

    def test_multiple_existing_globals(self):
        existing = {'idaapi': object(), 'idc': object()}
        assert is_name_safe('idaapi', existing) is False
        assert is_name_safe('idc', existing) is False

    def test_safe_name_not_in_existing_globals(self):
        existing = {'idc': object()}
        assert is_name_safe('search_web', existing) is True

    # --- safe names pass ---

    def test_safe_name_no_existing(self):
        assert is_name_safe('search_web') is True

    def test_safe_name_with_underscore(self):
        assert is_name_safe('ask_llm') is True

    def test_safe_name_with_digits(self):
        assert is_name_safe('fn_v2') is True

    def test_empty_existing_globals(self):
        assert is_name_safe('search_web', {}) is True

    def test_none_existing_globals(self):
        assert is_name_safe('search_web', None) is True

    # --- denylist content sanity checks ---

    def test_denylist_non_empty(self):
        assert len(_PYTHON_DENYLIST) > 0

    def test_denylist_contains_true_false(self):
        # True and False appear in builtins
        assert 'True' in _PYTHON_DENYLIST or 'False' in _PYTHON_DENYLIST


# ===========================================================================
# TestGenerateCallbackFunction
# ===========================================================================

class TestGenerateCallbackFunction:
    # --- basic invocation ---

    def test_positional_args(self):
        fn, _, _ = _make_fn()
        result = fn('hello', 5)
        assert result['called'] == 'search_web'
        assert result['args'] == {'query': 'hello', 'max_results': 5}

    def test_keyword_args(self):
        fn, _, _ = _make_fn()
        result = fn(query='hello', max_results=3)
        assert result['args'] == {'query': 'hello', 'max_results': 3}

    def test_positional_and_keyword_mixed(self):
        fn, _, _ = _make_fn()
        result = fn('hello', max_results=7)
        assert result['args'] == {'query': 'hello', 'max_results': 7}

    # --- defaults filled ---

    def test_default_filled_for_optional_param(self):
        fn, _, _ = _make_fn()
        # max_results has default=10, omit it
        result = fn('hello')
        assert result['args']['max_results'] == 10

    def test_required_param_not_filled_with_default(self):
        fn, _, _ = _make_fn()
        # query is required — if omitted, no default is inserted
        result = fn(max_results=5)
        assert 'query' not in result['args']

    def test_no_params_function(self):
        defn = FunctionDefinition(
            name='ping',
            parameterOrder=[],
            inputSchema={'type': 'object', 'properties': {}},
        )
        scope = CallbackScope()
        ns = RPCNamespace()
        fn = generate_callback_function(defn, mock_rpc_caller, scope, ns)
        result = fn()
        assert result['called'] == 'ping'
        assert result['args'] == {}

    # --- _rpc_timeout ---

    def test_default_timeout_passed_to_caller(self):
        fn, _, _ = _make_fn(default_timeout=30.0)
        result = fn('hello')
        assert result['timeout'] == 30.0

    def test_custom_default_timeout(self):
        fn, _, _ = _make_fn(default_timeout=60.0)
        result = fn('hello')
        assert result['timeout'] == 60.0

    def test_rpc_timeout_override(self):
        fn, _, _ = _make_fn()
        result = fn('hello', _rpc_timeout=5.0)
        assert result['timeout'] == 5.0

    def test_rpc_timeout_is_keyword_only(self):
        """_rpc_timeout must NOT be consumable as a positional argument."""
        fn, _, _ = _make_fn()
        # The function has two positional params (query, max_results).
        # Passing three positional args should NOT assign the third to _rpc_timeout.
        # Instead it raises TypeError (unexpected positional).
        with pytest.raises(TypeError):
            fn('hello', 5, 99.0)

    # --- scope check ---

    def test_call_raises_after_scope_invalidated(self):
        fn, scope, _ = _make_fn()
        scope.invalidate()
        with pytest.raises(RuntimeError, match='Callback expired'):
            fn('hello')

    def test_call_works_before_scope_invalidated(self):
        fn, scope, _ = _make_fn()
        result = fn('hello')
        assert result['called'] == 'search_web'

    def test_call_fails_after_scope_invalidated_even_with_ref(self):
        """Stale references captured before invalidation should still raise."""
        fn, scope, _ = _make_fn()
        saved_fn = fn  # capture reference
        scope.invalidate()
        with pytest.raises(RuntimeError, match='Callback expired'):
            saved_fn('hello')

    # --- mock override ---

    def test_mock_bypasses_rpc_caller(self):
        ns = RPCNamespace()
        scope = CallbackScope()
        defn = _make_defn()

        captured: list = []

        def mock_handler(query, max_results=10):
            captured.append((query, max_results))
            return 'mock_result'

        fn = generate_callback_function(defn, mock_rpc_caller, scope, ns)
        ns.mock('search_web', mock_handler)
        ns.update_functions({'search_web': fn}, {'search_web': defn})

        result = fn('test_query', 3)
        assert result == 'mock_result'
        assert captured == [('test_query', 3)]

    def test_mock_receives_positional_args(self):
        ns = RPCNamespace()
        scope = CallbackScope()
        defn = _make_defn()

        received: list = []
        ns.mock('search_web', lambda *a, **kw: received.append((a, kw)) or 'ok')
        fn = generate_callback_function(defn, mock_rpc_caller, scope, ns)

        fn('q1', 5)
        assert received[0][0] == ('q1', 5)

    # --- function metadata ---

    def test_function_name_set(self):
        fn, _, _ = _make_fn()
        assert fn.__name__ == 'search_web'

    def test_function_qualname_set(self):
        fn, _, _ = _make_fn()
        assert fn.__qualname__ == 'search_web'

    def test_function_has_docstring(self):
        fn, _, _ = _make_fn()
        assert fn.__doc__ is not None
        assert len(fn.__doc__) > 0

    # --- rpc_caller receives correct name ---

    def test_function_name_passed_to_caller(self):
        defn = _make_defn(name='custom_fn')
        scope = CallbackScope()
        ns = RPCNamespace()
        fn = generate_callback_function(defn, mock_rpc_caller, scope, ns)
        result = fn('hello')
        assert result['called'] == 'custom_fn'


# ===========================================================================
# TestBuildDocstring
# ===========================================================================

class TestBuildDocstring:
    def test_includes_description(self):
        defn = _make_defn(description='My function description')
        doc = _build_docstring(defn, 30.0)
        assert 'My function description' in doc

    def test_includes_required_param(self):
        defn = _make_defn()
        doc = _build_docstring(defn, 30.0)
        assert 'query' in doc
        assert 'str' in doc  # type mapped from 'string'

    def test_includes_optional_param_with_default(self):
        defn = _make_defn()
        doc = _build_docstring(defn, 30.0)
        assert 'max_results' in doc
        assert 'default=10' in doc

    def test_includes_rpc_timeout(self):
        defn = _make_defn()
        doc = _build_docstring(defn, 30.0)
        assert '_rpc_timeout' in doc
        assert '30.0' in doc

    def test_custom_timeout_in_docstring(self):
        defn = _make_defn()
        doc = _build_docstring(defn, 60.0)
        assert '60.0' in doc

    def test_includes_return_description(self):
        defn = _make_defn(return_description='A list of result strings')
        doc = _build_docstring(defn, 30.0)
        assert 'A list of result strings' in doc

    def test_no_return_description_absent(self):
        defn = _make_defn(return_description=None)
        doc = _build_docstring(defn, 30.0)
        assert 'Returns' not in doc

    def test_no_description_no_blank_line_at_top(self):
        defn = _make_defn(description=None)
        doc = _build_docstring(defn, 30.0)
        assert not doc.startswith('\n')

    def test_type_mapping_integer(self):
        defn = _make_defn()
        doc = _build_docstring(defn, 30.0)
        # max_results is 'integer' → should map to 'int'
        assert 'int' in doc

    def test_type_mapping_unknown(self):
        defn = FunctionDefinition(
            name='fn',
            parameterOrder=['x'],
            inputSchema={
                'type': 'object',
                'properties': {'x': {'description': 'some x'}},  # no 'type' key
                'required': ['x'],
            },
        )
        doc = _build_docstring(defn, 30.0)
        assert 'Any' in doc


# ===========================================================================
# TestMapException
# ===========================================================================

class TestMapException:
    # --- known type mappings ---

    def test_type_error(self):
        exc = map_exception('TypeError', 'wrong type')
        assert isinstance(exc, TypeError)
        assert 'wrong type' in str(exc)

    def test_value_error(self):
        exc = map_exception('ValueError', 'bad value')
        assert isinstance(exc, ValueError)

    def test_key_error(self):
        exc = map_exception('KeyError', 'missing key')
        assert isinstance(exc, KeyError)

    def test_file_not_found_error(self):
        exc = map_exception('FileNotFoundError', 'file missing')
        assert isinstance(exc, FileNotFoundError)

    def test_permission_error(self):
        exc = map_exception('PermissionError', 'access denied')
        assert isinstance(exc, PermissionError)

    def test_recursion_error(self):
        exc = map_exception('RecursionError', 'too deep')
        assert isinstance(exc, RecursionError)

    def test_name_error(self):
        exc = map_exception('NameError', 'undefined name')
        assert isinstance(exc, NameError)

    # --- unknown type → RuntimeError ---

    def test_unknown_type_gives_runtime_error(self):
        exc = map_exception('UnknownExceptionXYZ', 'something went wrong')
        assert isinstance(exc, RuntimeError)

    def test_timeout_error_gives_runtime_error(self):
        # 'TimeoutError' is not in our map — falls back to RuntimeError
        exc = map_exception('TimeoutError', 'timed out')
        assert isinstance(exc, RuntimeError)

    def test_empty_type_gives_runtime_error(self):
        exc = map_exception('', 'empty type')
        assert isinstance(exc, RuntimeError)

    # --- traceback as __cause__ ---

    def test_traceback_attached_as_cause(self):
        tb = 'Traceback (most recent call last):\n  File "x.py", line 1\nValueError: bad'
        exc = map_exception('ValueError', 'bad', tb=tb)
        assert exc.__cause__ is not None
        assert 'Remote traceback' in str(exc.__cause__)

    def test_traceback_content_preserved(self):
        tb = 'Traceback (most recent call last):\n  File "x.py", line 1\nValueError: bad'
        exc = map_exception('ValueError', 'bad', tb=tb)
        assert tb in str(exc.__cause__)

    def test_no_traceback_cause_is_none(self):
        exc = map_exception('ValueError', 'bad')
        assert exc.__cause__ is None

    def test_none_traceback_cause_is_none(self):
        exc = map_exception('ValueError', 'bad', tb=None)
        assert exc.__cause__ is None

    # --- exception hierarchy ---

    def test_rpc_error_is_runtime_error(self):
        from mcpyida.rpc_callbacks import RPCError
        assert issubclass(RPCError, RuntimeError)

    def test_rpc_timeout_error_is_rpc_error(self):
        from mcpyida.rpc_callbacks import RPCTimeoutError, RPCError
        assert issubclass(RPCTimeoutError, RPCError)

    def test_rpc_disconnected_error_is_rpc_error(self):
        from mcpyida.rpc_callbacks import RPCDisconnectedError, RPCError
        assert issubclass(RPCDisconnectedError, RPCError)
