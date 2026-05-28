# Third Party Libraries
import idaapi

# Our Libraries
from mcpyida.mcpyida import MCPyIdaPlugin


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return MCPyIdaPlugin()
