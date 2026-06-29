"""The dual-interface tools must expose flat params AND items, none required.

Regression guard for the observed 'items is a required property' rejection that
broke small local models calling decompile(addr=...).
"""
import anyio
import pytest

from mcp.server.fastmcp import FastMCP
from mcpyida.server import McpToolRegistration


def _schema_for(tool_name: str, method_name: str) -> dict:
    reg = McpToolRegistration()
    mcp = FastMCP("test")
    mcp.tool(tool_name)(getattr(reg, method_name))
    tools = anyio.run(mcp.list_tools)
    tool = next(t for t in tools if t.name == tool_name)
    return tool.inputSchema


def test_decompile_dict_tool_schema():
    schema = _schema_for("decompile", "decompile")
    props = schema["properties"]
    assert "items" in props
    assert "addr" in props
    assert "name" in props
    required = schema.get("required", [])
    assert "items" not in required
    assert "addr" not in required


def test_symbols_scalar_tool_schema():
    schema = _schema_for("symbols", "symbols")
    props = schema["properties"]
    assert "items" in props
    assert "addr" in props
    assert "items" not in schema.get("required", [])
    assert "addr" not in schema.get("required", [])


def test_funcs_registered_not_get_funcs():
    reg = McpToolRegistration()
    names = {tool_name for (_m, tool_name, _a, _r) in reg.iter_tools()}
    assert "funcs" in names
    assert "get_funcs" not in names


# Locks the feature's central invariant for ALL 12 dual tools (each method name
# equals its registered tool name). Guards against the 'items is a required
# property' regression on any single tool.
@pytest.mark.parametrize(
    "tool",
    [
        "decompile", "disasm", "xrefs", "symbols", "type_info", "funcs",
        "get_comment", "rename", "set_comments", "set_prototype", "patch",
        "add_field",
    ],
)
def test_dual_tool_items_not_required(tool):
    schema = _schema_for(tool, tool)
    assert "items" not in (schema.get("required") or []), (
        f"{tool}: items must be optional"
    )
    assert "items" in schema.get("properties", {}), (
        f"{tool}: items must still be a param"
    )
