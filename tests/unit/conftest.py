"""Pytest configuration for unit tests.

This module ensures tests can run in IDA-free environments by stubbing
ida_* modules before any mcpyida code imports them.
"""
import sys
from unittest.mock import MagicMock


def _try_import(module_name: str) -> bool:
    """Check if a module can be imported."""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


# List of IDA modules that need to be available for mcpyida to import.
# These are standard IDAPython (IDA 7.x+) or idalib (IDA 9.0+).
_IDA_MODULES = [
    'idaapi',
    'ida_pro',
    'ida_bytes',
    'ida_funcs',
    'ida_hexrays',
    'ida_lines',
    'ida_name',
    'ida_nalt',
    'ida_segment',
    'ida_typeinf',
    'idc',
    # idapro is intentionally NOT stubbed here. headless.py imports it lazily
    # inside main(), and unit tests that reach that path (test_good_ida_dir_*
    # etc.) rely on `import idapro` failing naturally so the structured
    # missing_install_dir error is emitted. mcpserver.py wraps its own
    # module-level `import idapro` in try/except, so removing it from stubs
    # does not break any other unit test.
]


def _stub_missing_ida_modules() -> None:
    """Install MagicMock stubs for any missing IDA modules.

    This allows mcpyida to be imported in IDA-free test environments.
    Tests that actually need IDA functionality will fail appropriately
    when they try to use stubbed methods (or can be marked @requires_ida).
    """
    for module_name in _IDA_MODULES:
        if not _try_import(module_name):
            # Module not available; install a stub so subsequent imports don't fail
            sys.modules[module_name] = MagicMock()


# Install stubs BEFORE any mcpyida imports (before pytest collects test functions)
_stub_missing_ida_modules()
