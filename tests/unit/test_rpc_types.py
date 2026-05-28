"""Unit tests for pydantic models in mcpyida.rpc_types.

These tests do NOT require IDA Pro or any IDA runtime — rpc_types.py has no
IDA/IDAPython imports.
"""
from __future__ import annotations

import pytest

from mcpyida.rpc_types import (
    CallFunctionException,
    CallFunctionParams,
    CallFunctionRequest,
    CallFunctionResult,
    FunctionDefinition,
    FunctionsChangedNotification,
    ListFunctionsParams,
    ListFunctionsRequest,
    ListFunctionsResult,
)


_MINIMAL_SCHEMA: dict = {
    'type': 'object',
    'properties': {
        'query': {'type': 'string'},
    },
    'required': ['query'],
}


class TestFunctionDefinition:
    def test_all_fields(self):
        fd = FunctionDefinition(
            name='search_web',
            description='Search the web for information',
            parameterOrder=['query', 'max_results'],
            inputSchema={
                'type': 'object',
                'properties': {
                    'query': {'type': 'string', 'description': 'Search query'},
                    'max_results': {'type': 'integer', 'default': 10},
                },
                'required': ['query'],
            },
            returnDescription='Search results as formatted text',
            annotations={'readOnlyHint': True},
        )
        assert fd.name == 'search_web'
        assert fd.description == 'Search the web for information'
        assert fd.parameterOrder == ['query', 'max_results']
        assert fd.inputSchema['type'] == 'object'
        assert fd.returnDescription == 'Search results as formatted text'
        assert fd.annotations == {'readOnlyHint': True}

    def test_minimal_fields(self):
        fd = FunctionDefinition(
            name='ping',
            parameterOrder=[],
            inputSchema={'type': 'object', 'properties': {}},
        )
        assert fd.name == 'ping'
        assert fd.parameterOrder == []
        assert fd.description is None
        assert fd.returnDescription is None
        assert fd.annotations is None

    def test_missing_name_raises(self):
        with pytest.raises(Exception):
            FunctionDefinition(  # type: ignore[call-arg]
                parameterOrder=[],
                inputSchema={'type': 'object', 'properties': {}},
            )

    def test_missing_parameter_order_raises(self):
        with pytest.raises(Exception):
            FunctionDefinition(  # type: ignore[call-arg]
                name='foo',
                inputSchema={'type': 'object', 'properties': {}},
            )

    def test_missing_input_schema_raises(self):
        with pytest.raises(Exception):
            FunctionDefinition(  # type: ignore[call-arg]
                name='foo',
                parameterOrder=[],
            )


class TestListFunctionsResult:
    def test_empty_functions_list(self):
        result = ListFunctionsResult(functions=[])
        assert result.functions == []
        assert result.nextCursor is None

    def test_with_functions(self):
        fd = FunctionDefinition(
            name='search_web',
            parameterOrder=['query'],
            inputSchema=_MINIMAL_SCHEMA,
        )
        result = ListFunctionsResult(functions=[fd])
        assert len(result.functions) == 1
        assert result.functions[0].name == 'search_web'

    def test_with_pagination(self):
        result = ListFunctionsResult(
            functions=[],
            nextCursor='opaque-continuation-token',
        )
        assert result.nextCursor == 'opaque-continuation-token'

    def test_next_cursor_defaults_none(self):
        result = ListFunctionsResult(functions=[])
        assert result.nextCursor is None


class TestListFunctionsRequest:
    def test_default_method(self):
        req = ListFunctionsRequest()
        assert req.method == 'mcpy/listFunctions'

    def test_default_params(self):
        req = ListFunctionsRequest()
        assert req.params.cursor is None

    def test_with_cursor(self):
        req = ListFunctionsRequest(
            params=ListFunctionsParams(cursor='some-cursor')
        )
        assert req.params.cursor == 'some-cursor'


class TestCallFunctionRequest:
    def test_construction(self):
        req = CallFunctionRequest(
            params=CallFunctionParams(name='search_web', arguments={'query': 'ghidra'})
        )
        assert req.method == 'mcpy/callFunction'
        assert req.params.name == 'search_web'
        assert req.params.arguments == {'query': 'ghidra'}

    def test_default_method(self):
        req = CallFunctionRequest(
            params=CallFunctionParams(name='ping')
        )
        assert req.method == 'mcpy/callFunction'

    def test_arguments_defaults_none(self):
        req = CallFunctionRequest(
            params=CallFunctionParams(name='ping')
        )
        assert req.params.arguments is None

    def test_missing_params_raises(self):
        with pytest.raises(Exception):
            CallFunctionRequest()  # type: ignore[call-arg]


class TestCallFunctionResult:
    def test_content_none(self):
        result = CallFunctionResult()
        assert result.content is None

    def test_content_string(self):
        result = CallFunctionResult(content='hello world')
        assert result.content == 'hello world'

    def test_content_int(self):
        result = CallFunctionResult(content=42)
        assert result.content == 42

    def test_content_dict(self):
        result = CallFunctionResult(content={'key': 'value'})
        assert result.content == {'key': 'value'}

    def test_content_list(self):
        result = CallFunctionResult(content=[1, 2, 3])
        assert result.content == [1, 2, 3]

    def test_content_bool(self):
        result = CallFunctionResult(content=True)
        assert result.content is True

    def test_content_zero(self):
        result = CallFunctionResult(content=0)
        assert result.content == 0


class TestCallFunctionException:
    def test_construction(self):
        exc = CallFunctionException(
            type='ValueError',
            message='invalid argument',
        )
        assert exc.type == 'ValueError'
        assert exc.message == 'invalid argument'
        assert exc.traceback is None

    def test_with_traceback(self):
        exc = CallFunctionException(
            type='RuntimeError',
            message='something failed',
            traceback='Traceback (most recent call last):\n  ...\nRuntimeError: something failed',
        )
        assert exc.traceback is not None
        assert 'RuntimeError' in exc.traceback

    def test_missing_type_raises(self):
        with pytest.raises(Exception):
            CallFunctionException(message='oops')  # type: ignore[call-arg]

    def test_missing_message_raises(self):
        with pytest.raises(Exception):
            CallFunctionException(type='ValueError')  # type: ignore[call-arg]


class TestFunctionsChangedNotification:
    def test_default_method_name(self):
        notif = FunctionsChangedNotification()
        assert notif.method == 'notifications/mcpy/functions/list_changed'

    def test_method_name_exact(self):
        notif = FunctionsChangedNotification()
        assert notif.method == 'notifications/mcpy/functions/list_changed'
        # Verify it is not the wrong casing or separator
        assert '/' in notif.method
        assert notif.method.startswith('notifications/')
