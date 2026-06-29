"""list(entry_type='type') folds in the former `types` tool (scope B)."""
from mcpyida.server import McpToolRegistration


def test_types_tool_removed_funcs_present():
    reg = McpToolRegistration()
    names = {tool_name for (_m, tool_name, _a, _r) in reg.iter_tools()}
    assert "types" not in names


def test_type_is_a_valid_entry_type():
    from mcpyida.models import EntryTypes
    import typing
    assert "type" in typing.get_args(EntryTypes)
