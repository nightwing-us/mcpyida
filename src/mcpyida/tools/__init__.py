"""MCPyIDA tool modules.

Standalone tool functions extracted from the monolithic mcpserver.py.
Each module contains pure IDA-API functions decorated with @run_in_ida_main.
These functions are independent of McpServer and are registered via
McpToolRegistration in server.py.

Modules:
    core     — list_entries, cursor, context, get_funcs
    analysis — decompile, disasm, symbols, xrefs
    modify   — rename, update_vars, set_comments, get_comment,
               set_prototype, patch, begin_trans, end_trans
    types    — types, type_info, create_struct, add_field
"""
