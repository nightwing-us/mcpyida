import ast
from pathlib import Path

STUB = Path(__file__).resolve().parents[2] / "mcpyida_plugin.py"


def test_stub_defines_plugin_entry():
    tree = ast.parse(STUB.read_text())
    funcs = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert "PLUGIN_ENTRY" in funcs


def test_stub_imports_real_plugin_from_installed_package():
    src = STUB.read_text()
    assert "from mcpyida.mcpyida import MCPyIdaPlugin" in src
