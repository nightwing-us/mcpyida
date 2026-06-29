# mcpyida_plugin.py — IDA Plugin Manager entry stub.
#
# The IDA Plugin Manager (hcli) installs this file into IDA's plugins
# directory and pip-installs the `mcpyida` package (declared in
# ida-plugin.json -> plugin.pythonDependencies). The real plugin lives in
# that package; this stub only exposes PLUGIN_ENTRY at the archive root, as
# the manager requires.
from mcpyida.mcpyida import MCPyIdaPlugin


def PLUGIN_ENTRY():
    return MCPyIdaPlugin()
