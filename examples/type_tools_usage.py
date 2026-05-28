#!/usr/bin/env python3
"""
Example usage of the type discovery MCP tools.

This demonstrates how MCP clients can use list_types and get_type_info
to discover and inspect types before setting variable types.
"""

# NOTE: These examples assume you're calling the MCP tools via the MCP protocol.
# The actual implementation is in mcpserver.py and runs inside IDA.

# Example 1: List first 50 types
# Response: list[TypeSummary]
response = {
    "tool": "list_types",
    "arguments": {}
}
# Returns: [
#   {"name": "int", "full_path": "int", "type_string": "int", "kind": "primitive", "size": 4},
#   {"name": "char", "full_path": "char", "type_string": "char", "kind": "primitive", "size": 1},
#   ...
# ]

# Example 2: Search for stream-related types
response = {
    "tool": "list_types",
    "arguments": {
        "pattern": "stream",
        "limit": 100
    }
}
# Returns types with "stream" in the name (case-insensitive)

# Example 3: Paginate through results
response = {
    "tool": "list_types",
    "arguments": {
        "offset": 50,
        "limit": 50
    }
}
# Returns types 50-99

# Example 4: Get details about a primitive type
response = {
    "tool": "get_type_info",
    "arguments": {
        "type_name": "int"
    }
}
# Returns: {
#   "name": "int",
#   "full_path": "int",
#   "type_string": "int",
#   "kind": "primitive",
#   "size": 4,
#   "comment": null,
#   "members": null,
#   "values": null,
#   "underlying_type": null
# }

# Example 5: Get struct details with members
response = {
    "tool": "get_type_info",
    "arguments": {
        "type_name": "MEMORY_BASIC_INFORMATION"
    }
}
# Returns: {
#   "name": "MEMORY_BASIC_INFORMATION",
#   "full_path": "MEMORY_BASIC_INFORMATION",
#   "type_string": "MEMORY_BASIC_INFORMATION",
#   "kind": "struct",
#   "size": 48,
#   "comment": "Memory information structure",
#   "members": [
#     {"name": "BaseAddress", "type_string": "void *", "offset": 0, "size": 8},
#     {"name": "AllocationBase", "type_string": "void *", "offset": 8, "size": 8},
#     {"name": "AllocationProtect", "type_string": "DWORD", "offset": 16, "size": 4},
#     ...
#   ],
#   "values": null,
#   "underlying_type": null
# }

# Example 6: Get enum values
response = {
    "tool": "get_type_info",
    "arguments": {
        "type_name": "FILE_ACCESS_FLAGS"
    }
}
# Returns: {
#   "name": "FILE_ACCESS_FLAGS",
#   "full_path": "FILE_ACCESS_FLAGS",
#   "type_string": "FILE_ACCESS_FLAGS",
#   "kind": "enum",
#   "size": 4,
#   "comment": null,
#   "members": null,
#   "values": [
#     {"name": "FILE_READ_DATA", "value": 1},
#     {"name": "FILE_WRITE_DATA", "value": 2},
#     {"name": "FILE_APPEND_DATA", "value": 4},
#     ...
#   ],
#   "underlying_type": null
# }

# Example 7: Get typedef details
response = {
    "tool": "get_type_info",
    "arguments": {
        "type_name": "LPVOID"
    }
}
# Returns: {
#   "name": "LPVOID",
#   "full_path": "LPVOID",
#   "type_string": "LPVOID",
#   "kind": "typedef",
#   "size": 8,
#   "comment": null,
#   "members": null,
#   "values": null,
#   "underlying_type": "void *"
# }

# Example 8: Complete workflow - Find and use a type
# Step 1: Search for the type
search_response = {
    "tool": "list_types",
    "arguments": {
        "pattern": "FILE"
    }
}
# Returns list of FILE-related types

# Step 2: Get details about a specific type
details_response = {
    "tool": "get_type_info",
    "arguments": {
        "type_name": "FILE_HANDLE"
    }
}
# Returns full type details

# Step 3: Use the type_string to set a variable type
update_response = {
    "tool": "batch_update_function_variables",
    "arguments": {
        "function_name": "main",
        "variables_to_update": {
            "v1": {
                "new_name": "fileHandle",
                "new_type": "FILE_HANDLE"  # Use type_string from details_response
            }
        }
    }
}

# Example 9: Handle type not found error
try:
    response = {
        "tool": "get_type_info",
        "arguments": {
            "type_name": "NonExistentType"
        }
    }
except Exception as e:
    print(f"Error: {e}")
    # Prints: "Type 'NonExistentType' not found"

# Example 10: Pattern matching with wildcards (stripped automatically)
response = {
    "tool": "list_types",
    "arguments": {
        "pattern": "*ptr*"  # Asterisks are stripped, becomes "ptr"
    }
}
# Returns types containing "ptr" (case-insensitive)

print("Type tools usage examples complete!")
