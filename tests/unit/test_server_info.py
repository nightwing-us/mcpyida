"""Unit tests for build_instructions() in server.py (IDA)."""
from unittest.mock import MagicMock, patch
import os
import sys

import pytest


def _make_ida_mocks(
    version: str = '9.0',
    binary_name: str = 'crackme.elf',
    binary_path: str = '/tmp/crackme.elf',
    procname: str = 'metapc',
) -> tuple[MagicMock, MagicMock]:
    """Return (idaapi_mock, ida_nalt_mock) with sensible defaults."""
    idaapi_mock = MagicMock()
    idaapi_mock.get_kernel_version.return_value = version
    inf = MagicMock()
    inf.procname = procname
    idaapi_mock.get_inf_structure.return_value = inf

    ida_nalt_mock = MagicMock()
    ida_nalt_mock.get_root_filename.return_value = binary_name
    ida_nalt_mock.get_input_file_path.return_value = binary_path

    return idaapi_mock, ida_nalt_mock


def _call_build_instructions(**kwargs) -> str:
    """Import and call build_instructions with mocked IDA modules.

    Re-imports build_instructions each call to ensure the inner imports
    pick up the patched sys.modules entries.
    """
    idaapi_mock, ida_nalt_mock = _make_ida_mocks(**kwargs)
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        # Must import inside the patch context so inner `import idaapi` picks it up.
        # If already imported, reload to re-execute the inner imports.
        import importlib
        import mcpyida.server as srv
        importlib.reload(srv)
        return srv.build_instructions()


def test_build_instructions_contains_tool_name():
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert 'IDA' in result or 'MCPyIDA' in result


def test_build_instructions_contains_binary_name(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks(binary_name='crackme.elf')
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert 'crackme.elf' in result


def test_build_instructions_contains_mode(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert 'headless' in result


def test_build_instructions_contains_mode_gui(monkeypatch):
    monkeypatch.delenv('MCPYIDA_HEADLESS', raising=False)
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert 'gui' in result


def test_build_instructions_contains_architecture(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks(procname='metapc')
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert 'metapc' in result


def test_build_instructions_under_2kb(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert len(result.encode('utf-8')) < 2048


def test_build_instructions_contains_tool_list(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()
    assert 'decompile' in result
    assert 'idapython' in result
    assert 'cfg' in result
    assert 'callgraph' in result


def test_headless_instructions(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks(
        version='9.0',
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        procname='metapc',
    )
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()

    assert 'Mode: headless' in result
    assert 'crackme.elf' in result
    assert 'metapc' in result
    assert len(result.encode('utf-8')) < 2048


def test_instructions_contains_tools(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks(
        binary_name='test.elf',
        binary_path='/tmp/test.elf',
    )
    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        from mcpyida.server import build_instructions
        result = build_instructions()

    assert 'decompile' in result
    assert 'idapython' in result
    assert 'cfg' in result


# ---------------------------------------------------------------------------
# Tests for server://info resource
# ---------------------------------------------------------------------------

def _call_server_info(idaapi_mock, ida_nalt_mock, get_port=None):
    """Register resources and call the server://info handler within the mock context.

    The handler imports idaapi/ida_nalt at call time, so the call must happen
    inside the same patch.dict context where those mocks are registered.
    """
    import importlib

    class _FakeMcp:
        def resource(self, uri, **kwargs):
            def decorator(fn):
                captured[uri] = fn
                return fn
            return decorator

    captured = {}

    with patch.dict('sys.modules', {'idaapi': idaapi_mock, 'ida_nalt': ida_nalt_mock}):
        import mcpyida.server as srv
        importlib.reload(srv)
        srv.register_resources(_FakeMcp(), get_port=get_port)
        fn = captured.get('server://info')
        assert fn is not None, "server://info resource not registered"
        return fn()


def test_server_info_all_fields(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    result = _call_server_info(idaapi_mock, ida_nalt_mock, get_port=lambda: 6150)
    assert set(result.keys()) == {
        'tool', 'version', 'mode', 'binary', 'binary_path',
        'architecture', 'analysis_status', 'port',
    }


def test_server_info_with_port(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    result = _call_server_info(idaapi_mock, ida_nalt_mock, get_port=lambda: 9999)
    assert result['port'] == 9999


def test_server_info_no_port(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks()
    result = _call_server_info(idaapi_mock, ida_nalt_mock, get_port=lambda: None)
    assert result['port'] is None


def test_server_info_analysis_status_complete(monkeypatch):
    monkeypatch.setenv('MCPYIDA_HEADLESS', '1')
    idaapi_mock, ida_nalt_mock = _make_ida_mocks(
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        procname='metapc',
        version='9.0',
    )
    result = _call_server_info(idaapi_mock, ida_nalt_mock, get_port=lambda: 6150)
    assert result['analysis_status'] == 'complete'
    assert result['binary'] == 'crackme.elf'
    assert result['tool'] == 'ida'
    assert result['mode'] == 'headless'
    assert result['architecture'] == 'metapc'
    assert result['port'] == 6150
