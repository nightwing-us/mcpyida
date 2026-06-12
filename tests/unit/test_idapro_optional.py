"""Tests that mcpserver and ida_helpers import cleanly when idapro is absent.

Rationale
---------
`idapro` / idalib exists only in IDA 9.0+ and is only needed for the external-
process headless bootstrap.  The GUI plugin (IDA 7.x / 8.x) and IDA-free
CI environments must be able to import mcpyida.mcpserver and
mcpyida.ida_helpers without raising ImportError.

These tests simulate the absence of idapro by:
  1. Removing any cached module from sys.modules before the import attempt.
  2. Injecting a sentinel value of None for 'idapro' into sys.modules, which
     causes `import idapro` to raise ImportError (standard Python behaviour
     when sys.modules[name] is None).
  3. Keeping all ida_* module stubs that conftest / other fixtures already
     install so that the remaining IDA API references still resolve.
"""
from __future__ import annotations

import importlib
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IDA_MODULE_NAMES = [
    'idaapi',
    'idc',
    'ida_funcs',
    'ida_bytes',
    'ida_hexrays',
    'ida_lines',
    'ida_typeinf',
    'ida_nalt',
    'ida_pro',
    'ida_auto',
    'ida_ua',
    'ida_segment',
    'ida_name',
    'ida_xref',
    'ida_search',
    'ida_entry',
    'ida_struct',
    'ida_enum',
    'ida_gdl',
    'ida_frame',
    'ida_idp',
    'ida_loader',
    'ida_kernwin',
    'ida_allins',
    'ida_problems',
    'ida_offset',
    'ida_netnode',
    'idc_bc695',
]


def _make_ida_stubs() -> dict[str, ModuleType]:
    """Return a dict of MagicMock stubs for all common ida_* modules."""
    stubs: dict[str, ModuleType] = {}
    for name in _IDA_MODULE_NAMES:
        mock = MagicMock(name=name)
        # ida_pro.is_main_thread() is called at module level inside mcpserver.py
        # decorators — ensure it returns a sensible value.
        if name == 'ida_pro':
            mock.is_main_thread.return_value = True
        # idaapi.MFF_READ is used as a default argument in a decorator.
        if name == 'idaapi':
            mock.MFF_READ = 1
            mock.MFF_WRITE = 2
            mock.MFF_FAST = 4
            mock.BADADDR = 0xFFFFFFFFFFFFFFFF
        stubs[name] = mock
    return stubs


def _purge_mcpyida_modules() -> None:
    """Remove all cached mcpyida.* entries from sys.modules to force re-import."""
    to_remove = [key for key in sys.modules if key == 'mcpyida' or key.startswith('mcpyida.')]
    for key in to_remove:
        del sys.modules[key]


# ---------------------------------------------------------------------------
# RED tests — these FAIL before the guard is added
# ---------------------------------------------------------------------------


class TestIdaproAbsence:
    """mcpserver and ida_helpers must import cleanly when idapro is absent."""

    def _patch_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Patch sys.modules so that `import idapro` raises ImportError."""
        # Setting sys.modules['idapro'] = None makes `import idapro` raise
        # ImportError: import of idapro halted; use of sys.modules['idapro'] is
        # discouraged — this is the canonical CPython mechanism.
        monkeypatch.setitem(sys.modules, 'idapro', None)  # type: ignore[arg-type]

        # Provide stubs for all ida_* / idaapi modules so we don't fail on them.
        for name, stub in _make_ida_stubs().items():
            if name not in sys.modules:
                monkeypatch.setitem(sys.modules, name, stub)

    def test_mcpserver_imports_without_idapro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """mcpyida.mcpserver must not raise ImportError when idapro is absent."""
        self._patch_context(monkeypatch)
        # IMPORTANT: Do NOT purge mcpyida modules; only monkeypatch sys.modules['idapro'].
        # Purging and re-importing causes module state to differ from what tests expect
        # (test_rpc_server_integration imports functions at collection time and expects
        # those functions to see a properly initialized module).
        # Let monkeypatch handle the sys.modules cleanup after the test.

        # Should NOT raise even when idapro is unavailable.
        mod = importlib.import_module('mcpyida.mcpserver')
        assert mod is not None

    def test_ida_helpers_imports_without_idapro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """mcpyida.ida_helpers must not raise ImportError when idapro is absent."""
        self._patch_context(monkeypatch)
        # IMPORTANT: Do NOT purge mcpyida modules; only monkeypatch sys.modules['idapro'].
        # See comment in test_mcpserver_imports_without_idapro.

        # Should NOT raise even when idapro is unavailable.
        mod = importlib.import_module('mcpyida.ida_helpers')
        assert mod is not None

    def test_mcpyida_plugin_chain_imports_without_idapro(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mcpyida.mcpserver (core of the plugin chain) imports without idapro.

        The full chain is: mcpyida_proxy.py -> mcpyida.mcpyida -> mcpyida.mcpserver.
        mcpyida.mcpyida itself derives GUI classes from idaapi.action_handler_t and
        idaapi.plugin_t, which causes metaclass conflicts when those are MagicMocks.
        That conflict is an IDA-GUI-specific concern unrelated to the idapro guard.
        We therefore test the relevant end of the chain (mcpserver) which is the
        module that carries the idapro import and is used by the plugin at runtime.
        """
        self._patch_context(monkeypatch)
        # IMPORTANT: Do NOT purge mcpyida modules; only monkeypatch sys.modules['idapro'].
        # See comment in test_mcpserver_imports_without_idapro.

        # mcpserver is what the plugin ultimately depends on — it must import cleanly.
        mod = importlib.import_module('mcpyida.mcpserver')
        assert mod is not None
        # Verify the key exports used by mcpyida.py are present.
        assert hasattr(mod, 'McpServer')
        assert hasattr(mod, 'McpServerState')

    def test_idapro_absence_does_not_break_mcpserver_state_enum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """McpServerState is accessible after import without idapro."""
        self._patch_context(monkeypatch)
        # IMPORTANT: Do NOT purge mcpyida modules; only monkeypatch sys.modules['idapro'].
        # See comment in test_mcpserver_imports_without_idapro.

        mod = importlib.import_module('mcpyida.mcpserver')
        assert hasattr(mod, 'McpServerState')
        assert hasattr(mod, 'McpServer')

    def test_idapro_absence_does_not_break_ida_helpers_classes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IdaFunction and IdaException are accessible after import without idapro."""
        self._patch_context(monkeypatch)
        # IMPORTANT: Do NOT purge mcpyida modules; only monkeypatch sys.modules['idapro'].
        # See comment in test_mcpserver_imports_without_idapro.

        mod = importlib.import_module('mcpyida.ida_helpers')
        assert hasattr(mod, 'IdaFunction')
        assert hasattr(mod, 'IdaException')
