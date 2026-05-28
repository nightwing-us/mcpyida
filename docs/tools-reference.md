# MCPyIDA Tools Reference

Authoritative reference for all 25 tools exposed by the MCPyIDA MCP server via Streamable HTTP.

**For setup:** See [docs/quickstart.md](./quickstart.md), [docs/index.md](./index.md), and [docs/mcp-client-config.md](./mcp-client-config.md).

**For RPC callbacks:** See [docs/specs/rpc-callbacks.md](./specs/rpc-callbacks.md).

---

## Core Listing & Navigation

### `list`

**Purpose:** Get a paginated list of binary entries by type (functions, imports, strings, etc.) with optional filtering.

**Parameters:**
- `entry_type` (string, required): Type of entries to list. Valid values: `function`, `memory_segment`, `import`, `export`, `string`, `class`, `namespace`
- `offset` (integer, optional, default: 0): Pagination offset (starting position)
- `limit` (integer, optional, default: 500, max: 10000): Maximum items to return per page
- `match_filter` (string, optional, default: ''): Substring filter on entry name (functions and strings only; case-insensitive)

**Returns:** `ListResult` containing:
- `items[]`: List of entries (each with name, address, and type-specific fields)
- `page_info`: Pagination state (offset, limit, total_count, has_more, next_offset)
- `summary`: Human-readable description of the list
- `entry_type`: The requested type
- `schema_version`: Format version (always 1)

**Examples:**
```
list(entry_type='function') → First 500 functions
list(entry_type='function', limit=50) → First 50 functions
list(entry_type='function', offset=100, limit=50) → Functions 100–149
list(entry_type='string', match_filter='error', limit=20) → Strings containing "error"
```

**Note:** Batch-capable (via pagination; individual requests are single-page).

---

### `cursor`

**Purpose:** Get the address and function info at the user's current cursor position in IDA.

**Parameters:** None

**Returns:** `CurrentLocation` with:
- `addr`: Current hex address (e.g., `"0x401000"`)
- `function`: `FunctionInfo` (name, entrypoint, signature) if cursor is inside a function; null otherwise

**Use Case:** Contextual operations relative to user focus.

---

### `context`

**Purpose:** Get comprehensive metadata about the currently open binary, including architecture, memory layout, analysis state, and file info.

**Parameters:** None

**Returns:** `BinaryContext` with:
- `current_location`: Current cursor position and function
- `program`: Binary file details (path, name, format, size, MD5 hash)
- `architecture`: Processor, bitness, endianness, compiler
- `memory`: Address space layout (base, entry point, min/max addresses)
- `analysis`: Database path, function count, debug symbols, type libraries, analysis state
- `application`: IDA version info

---

### `get_funcs`

**Purpose:** Get detailed function info by address or name. Accepts batch of addresses/names.

**Parameters:**
- `items` (array of strings, required): Addresses (hex, e.g., `"0x401000"`) or function names (e.g., `"main"`)

**Returns:** Array of dicts, each with:
- `name`: Resolved function name
- `entrypoint`: Function entry point (hex address)
- `signature`: Function signature (on success) or null (on failure)
- `error`: null on success; error message on failure

**Batch-capable:** Yes (processes multiple addresses/names in one call).

---

## Analysis & Decompilation

### `decompile`

**Purpose:** Decompile function(s) to C pseudocode with optional function comments prepended.

**Parameters:**
- `items` (array of dicts, required): Functions to decompile. Each item:
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): e.g., `"main"`
  - At least one of `addr` or `name` must be provided

**Returns:** Array of dicts, each with:
- `code`: Decompiled C pseudocode (on success)
- `name`: Resolved function name
- `entrypoint`: Function entry point (hex)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

**Note:** Requires Hex-Rays decompiler (paid feature in IDA Pro). Comments are prepended from function comment field.

**Example:**
```
decompile(items=[
  {"addr": "0x401000"},
  {"name": "main"},
  {"addr": "0x402000"}
])
```

---

### `disasm`

**Purpose:** Disassemble function(s) or address ranges (merged tool: both function and address modes).

**Parameters:**
- `items` (array of dicts, required): Disassembly requests. Each item:
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): Function name
  - `count` (integer, optional): Number of instructions to disassemble from addr
  - **Mode selection:**
    - `count` set → Address mode (N instructions from addr)
    - `name` → Function mode (entire function)
    - `addr` only → Auto-detect (function containing addr, or 20 instructions from addr)

**Returns:** Array of dicts, each with:
- `asm`: Disassembly text (on success)
- `addr`: Resolved address
- `name`: Function name (if function mode)
- `mode`: 'function' or 'address'
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

**Examples:**
```
disasm(items=[
  {"name": "main"},  # Entire main function
  {"addr": "0x401000", "count": 20},  # 20 instructions from address
  {"addr": "0x402000"}  # Auto-detect
])
```

---

### `symbols`

**Purpose:** Get symbol info for address(es) — resolve addresses to names and symbol types.

**Parameters:**
- `items` (array of strings, required): Hex addresses to look up (e.g., `["0x401000", "0x402000"]`)

**Returns:** Array of dicts, each with:
- `addr`: Input address
- `name`: Symbol name (on success)
- `symbol_type`: One of `function`, `code_label`, `global_variable`, `data_label`, `unknown`
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `xrefs`

**Purpose:** Find cross-references to/from addresses or functions (merged tool: both directions).

**Parameters:**
- `items` (array of dicts, required): Cross-reference requests. Each item:
  - `target` (string, required): Hex address (e.g., `"0x401000"`) or function name
  - `direction` (string, optional, default: 'to'): `"to"` (refs pointing to target) or `"from"` (refs from target)
  - `offset` (integer, optional, default: 0): Pagination offset
  - `limit` (integer, optional, default: 500): Max results

**Returns:** Array of dicts, each with:
- `result`: `ListResult` containing cross-reference items (on success)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

## Control Flow & Graphs

### `cfg`

**Purpose:** Extract control flow graph (CFG) for a function with basic blocks, successors, called functions, and strings.

**Parameters:**
- `address` (string, required): Function address (hex) or name
- `normalize` (boolean, optional, default: true): Apply cross-tool normalization
- `include_bytes` (boolean, optional, default: false): Include base64 raw bytes per block
- `include_disassembly` (boolean, optional, default: false): Include instruction list per block

**Returns:** `CFGResult` with:
- `function`: Function name and address
- `blocks[]`: Array of basic blocks, each with:
  - `address`: Block start address
  - `size`: Block size in bytes
  - `successors`: Array of successor block addresses
  - `called_functions[]`: Functions called from this block
  - `strings[]`: String references in this block
  - `bytes`: Base64-encoded bytes (if requested)
  - `disassembly`: Instruction list (if requested)

---

### `callgraph`

**Purpose:** Build call graph from a root function, traversing call relationships with configurable depth and limits.

**Parameters:**
- `address` (string, required): Root function address (hex) or name
- `direction` (string, optional, default: 'callees'): `'callees'` (called functions), `'callers'` (calling functions), or `'both'`
- `max_depth` (integer, optional, default: 5): Maximum traversal depth
- `max_nodes` (integer, optional, default: 1000): Maximum function nodes to return
- `max_edges` (integer, optional, default: 5000): Maximum call edges to return

**Returns:** `CallGraphResult` with:
- `root`: Root function name and address
- `direction`: Direction traversed
- `nodes[]`: Array of function nodes (name, address, depth)
- `edges[]`: Array of call edges (from, to)
- `depth`: Actual traversal depth

---

## Type Inspection & Manipulation

### `types`

**Purpose:** Enumerate and search available types across all type sources (structures, enums, typedefs, etc.) with pagination.

**Parameters:**
- `pattern` (string, optional, default: null): Substring filter (case-insensitive). Strips `*` if glob-style. None = no filter.
- `offset` (integer, optional, default: 0): Pagination offset
- `limit` (integer, optional, default: 500, max: 10000): Max items to return

**Returns:** Array of `TypeSummary` objects, each with:
- `name`: Short name (e.g., `"istream"`)
- `full_path`: Full path (e.g., `"std::istream"`)
- `type_string`: Exact string to pass to type-setting tools
- `kind`: Normalized type kind
- `size`: Size in bytes, or null if unknown/variable

**Paginated:** Yes (offset/limit).

**Examples:**
```
types() → First 500 types
types(pattern="stream", limit=100) → Search for stream-related types
types(offset=50, limit=50) → Next page
```

---

### `type_info`

**Purpose:** Get detailed type information (members, enum values, etc.) by type name. Batch-capable.

**Parameters:**
- `items` (array of strings, required): Type names to look up (short name or full path)

**Returns:** Array of dicts, each with:
- **On success:** `TypeDetails` with name, full_path, type_string, kind, size, comment, members[] (for struct/union), values[] (for enum), underlying_type (for typedef)
- **On failure:** `{target, error}`

**Batch-capable:** Yes.

---

### `create_struct`

**Purpose:** Create a new structure type in the IDA type database.

**Parameters:**
- `name` (string, required): Structure name (e.g., `"request_t"`)
- `size` (integer, optional, default: 0): Total size in bytes; 0 = auto-size from fields
- `fields` (array of dicts, optional): Initial fields, each with:
  - `name`: Field name
  - `type`: C-style type string (e.g., `"int"`, `"char *"`)
  - `offset`: Byte offset within structure
  - `comment` (optional): Field comment
- `packed` (boolean, optional, default: false): If true, no padding between fields

**Returns:** `StructureCreationResult` with:
- `name`: Structure name
- `size`: Structure size in bytes
- `created`: Boolean (true if new, false if already existed)
- `message`: Human-readable result summary

**Example:**
```
create_struct(
  name="NetworkPacket",
  fields=[
    {"name": "header_ptr", "type": "void *", "offset": 0},
    {"name": "length", "type": "int", "offset": 8}
  ]
)
```

---

### `add_field`

**Purpose:** Add field(s) to struct(s). Batch-capable. If a field already exists at the offset, it will be replaced. Structure is auto-expanded if needed.

**Parameters:**
- `items` (array of dicts, required): Field addition requests. Each item:
  - `struct_name` (string): Name of the target structure
  - `field_name` (string): New field name
  - `field_type` (string): C-style type string (e.g., `"int"`, `"char *"`)
  - `offset` (integer): Byte offset within structure
  - `comment` (string, optional): Field comment

**Returns:** Array of dicts with `FieldAdditionResult` fields (per-item status).

**Batch-capable:** Yes.

---

## Modification & Patching

### `rename`

**Purpose:** Rename symbol(s) in the database. Batched with per-item error handling. **This modifies the IDA database.**

**Parameters:**
- `items` (array of dicts, required): Symbol rename requests. Each item:
  - `new_name` (string, required): New symbol name
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): Existing symbol name
  - At least one of `addr` or `name` must be provided

**Returns:** Array of dicts, each with:
- `addr`: Resolved hex address
- `old_name`: Previous symbol name
- `new_name`: New name applied
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `update_vars`

**Purpose:** Rename and/or retype multiple variables in a function at once. **This modifies the IDA database.**

**Parameters:**
- `function_name` (string, required): Name of the function containing the variables
- `variables_to_update` (object, required): Mapping from current variable name to updates:
  - `new_name` (string, optional): New variable name
  - `new_type` (string, optional): New C-style type string
  - At least one of `new_name` or `new_type` per variable

**Returns:** Per-variable status report.

**Example:**
```
update_vars(
  function_name="main",
  variables_to_update={
    "local_8": {"new_name": "buffer", "new_type": "char *"},
    "param_1": {"new_name": "argc"}
  }
)
```

---

### `set_comments`

**Purpose:** Set comment(s) on addresses, functions, or lines (merged 3-in-1 tool). **This modifies the IDA database.**

**Parameters:**
- `items` (array of dicts, required): Comment set requests. Each item:
  - `comment` (string, required): Comment text
  - `kind` (string, optional, default: 'both'): Comment type:
    - `'disasm'` → EOL comment at address (requires addr)
    - `'decompiler'` → Pre-comment at decompiler line (requires line and addr or name)
    - `'function'` → Plate comment on function (requires addr or name)
    - `'both'` (default) → Disasm EOL at addr; ALSO decompiler if line given
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): Function name (alternative to addr)
  - `line` (integer, optional): Decompiler line number (for decompiler comments)

**Returns:** Array of dicts, each with:
- `kind`: Comment type applied
- `addr`: Target address
- `message`: Human-readable result (on success)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `get_comment`

**Purpose:** Get function plate comment(s) by address or name. Batch-capable.

**Parameters:**
- `items` (array of dicts, required): Functions to get comments for. Each item:
  - `addr` (hex address, optional)
  - `name` (string, optional)
  - At least one required

**Returns:** Array of dicts, each with:
- `name`: Function name
- `addr`: Function entry point address
- `comment`: Plate comment text (may be empty string)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `set_prototype`

**Purpose:** Set function prototype(s) to update signature. **This modifies the IDA database.** Old signature is saved in the function comment for reference.

**Parameters:**
- `items` (array of dicts, required): Function prototype set requests. Each item:
  - `addr` (hex address, required): Function address
  - `prototype` (string, required): C-style signature, e.g., `"int main(int argc, char **argv)"`

**Returns:** Array of dicts, each with:
- `addr`: Function address
- `name`: Function name
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `patch`

**Purpose:** Overwrite bytes at address(es) to modify instruction(s). **This modifies the IDA database and is destructive.** Clears existing code unit, writes bytes, re-disassembles.

**Parameters:**
- `items` (array of dicts, required): Patch requests. Each item:
  - `addr` (hex address, required): Target address
  - `hex_bytes` (string, required): New instruction bytes as hex string (space-separated, e.g., `"90 90 90"` for three NOPs)

**Returns:** Array of dicts, each with:
- `addr`: Patched address
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

## Transaction Management

### `begin_trans`

**Purpose:** Start a manual transaction for multiple modifications to be atomic.

**Parameters:**
- `description` (string, required): Human-readable transaction description

**Returns:** `{transaction_id: string}` — ID to pass to `end_trans`.

**When to use:** Most modification tools handle transactions internally. Only use when making multiple modifications that must be atomic.

**Example:**
```
tx = begin_trans("Rename related functions")
# ... call rename, update_vars, etc. ...
end_trans(tx, commit=True)
```

---

### `end_trans`

**Purpose:** End a manual transaction started with `begin_trans`.

**Parameters:**
- `transaction_id` (string, required): ID returned by `begin_trans`
- `commit` (boolean, optional, default: true): True to save changes; False to discard/rollback

**Returns:** `{transaction_id: string, committed: boolean, message: string}`

---

## Scripting & Custom Logic

### `idapython`

**Purpose:** Execute Python code in IDA context with full API access. Variables persist between calls for the MCP server lifetime. Last expression is returned (Jupyter-style).

**Parameters:**
- `code` (string, required): Python code to execute. Has access to:
  - **Pre-imported modules:** `idaapi`, `idc`, `idautils`, `ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_kernwin`, `ida_name`, `ida_nalt`, `ida_segment`, `ida_typeinf`, and all other `ida_*` modules
  - **Helper class:** `IdaFunction` (custom wrapper for function operations)
  - **RPC callbacks** (if client declares `mcpy/rpcCallbacks` capability): Functions injected via `rpc` namespace for callback invocation
- `reset` (boolean, optional, default: false): If True, clear persistent session state and restart from IDA's `__main__.__dict__`

**Returns:** `ScriptResult` with:
- `result`: Last expression value (Jupyter-style), or null if no value
- `stdout`: Captured stdout from script
- `stderr`: Captured stderr from script
- `output`: Combined stdout + stderr
- `success`: Boolean indicating execution success
- `error`: null on success; error message on failure
- `error_traceback`: Full Python traceback (on exception)

**Behavior:**
- **Variable persistence:** All global variables and function definitions persist for the server lifetime (reset with `reset=True`)
- **Snapshot isolation:** Function list updates deferred until script completes to avoid concurrent modification issues
- **RPC callbacks:** If the MCP client supports `mcpy/rpcCallbacks` capability, callback functions are injected into script globals (see [docs/specs/rpc-callbacks.md](./specs/rpc-callbacks.md))
- **Last expression return:** If code ends with an expression (not a statement), its value is returned as `result`

**Example:**
```python
# Simple execution
code = """
import idaapi
count = len(list(idautils.Functions()))
f"Found {count} functions"
"""
result = idapython(code=code)
# result.result == "Found 42 functions"

# Persistent state
idapython(code="x = 10")
idapython(code="y = x + 5; y")
# Second call can access x from first call

# Reset state
idapython(code="x = 100", reset=True)
idapython(code="x")  # Returns 100, not 10
```

---

## Search Tools

### `find_bytes`

**Purpose:** Search byte patterns with wildcards (exact and wildcard matching).

**Parameters:**
- `patterns` (array of strings, required): Space-separated hex tokens; `??` for wildcard. Example: `["48 8B ?? ??", "55 48 89 E5"]`
- `limit` (integer, optional, default: 1000, max: 100000): Max matches per pattern
- `offset` (integer, optional, default: 0): Skip first N matches per pattern

**Returns:** Array of dicts, one per pattern, each with:
- `pattern`: Input pattern string
- `matches`: Array of matching addresses (hex)
- `has_more`: Boolean (true if matches exceed limit)
- `error`: null on success; error message on failure

**Examples:**
```
find_bytes(patterns=["48 8B ?? ??"])  # mov rax, [rax+offset]
find_bytes(patterns=["FF ?? ?? 00"], limit=50)  # wildcards with limit
find_bytes(patterns=["55 48 89 E5", "48 83 EC ??"], offset=10, limit=100)  # multiple patterns
```

---

### `find_insns`

**Purpose:** Search instruction sequences with glob and regex operand patterns.

**Parameters:**
- `sequences` (array of arrays, required): Each sequence is a list of instruction objects `{mnemonic: str, operands?: list}`:
  - `mnemonic` (string): Exact (e.g., `"MOV"`) or glob (e.g., `"J*"`, `"CALL"`)
  - `operands` (array, optional): Glob patterns (e.g., `"RAX"`) or `/regex/` (e.g., `/R[AB]X/`)
- `limit` (integer, optional, default: 1000, max: 100000): Max matches per sequence
- `offset` (integer, optional, default: 0): Skip first N matches

**Returns:** Array of dicts, one per sequence, each with:
- `sequence`: Input sequence description
- `matches`: Array of matching addresses (hex)
- `has_more`: Boolean (true if matches exceed limit)
- `error`: null on success; error message on failure

**Examples:**
```python
# Simple instruction sequence
sequences = [
  [
    {"mnemonic": "PUSH", "operands": ["RBP"]},
    {"mnemonic": "MOV", "operands": ["RBP", "RSP"]}
  ]
]
find_insns(sequences=sequences)

# Wildcard and regex patterns
sequences = [
  [
    {"mnemonic": "CALL", "operands": ["/^[A-Z_]+/"]},  # Regex operand
    {"mnemonic": "J*"}  # Glob mnemonic (any jump)
  ]
]
find_insns(sequences=sequences, limit=100)
```

---

## MCP Resources

In addition to tools, MCPyIDA exposes read-only MCP Resources (URIs) for programmatic access:

### `server://info`

Get live server metadata including IDA version, mode (headless/GUI), binary name, architecture, and port.

**Example client access:**
```
GET http://localhost:6150/mcp/resources/server://info
```

**Returns:**
```json
{
  "tool": "ida",
  "version": "9.2",
  "mode": "headless",
  "binary": "test.elf",
  "binary_path": "/path/to/test.elf",
  "architecture": "metapc",
  "analysis_status": "complete",
  "port": 6150
}
```

---

### `ida://cursor`

Get current cursor position and function info.

**Example client access:**
```
GET http://localhost:6150/mcp/resources/ida://cursor
```

---

## Summary Table

| Tool | Category | Read-Only | Batch | Use Case |
|------|----------|-----------|-------|----------|
| `list` | Navigation | Yes | Yes | Enumerate functions, strings, imports |
| `cursor` | Navigation | Yes | No | Get current position |
| `context` | Navigation | Yes | No | Get binary metadata |
| `get_funcs` | Navigation | Yes | Yes | Resolve function names to addresses |
| `decompile` | Analysis | Yes | Yes | View pseudocode (requires Hex-Rays) |
| `disasm` | Analysis | Yes | Yes | View assembly |
| `symbols` | Analysis | Yes | Yes | Resolve addresses to symbol names |
| `xrefs` | Analysis | Yes | Yes | Find cross-references |
| `cfg` | Graphs | Yes | No | Extract control flow graph |
| `callgraph` | Graphs | Yes | No | Build function call graph |
| `types` | Type System | Yes | Yes | Search types |
| `type_info` | Type System | Yes | Yes | Get type details |
| `create_struct` | Type System | No | No | Create new structure |
| `add_field` | Type System | No | Yes | Add struct fields |
| `rename` | Modification | No | Yes | Rename symbols |
| `update_vars` | Modification | No | No | Rename/retype function variables |
| `set_comments` | Modification | No | Yes | Add/update comments |
| `get_comment` | Modification | Yes | Yes | Retrieve comments |
| `set_prototype` | Modification | No | Yes | Update function signatures |
| `patch` | Modification | No | Yes | Overwrite bytes (destructive) |
| `begin_trans` | Transactions | No | No | Start atomic transaction |
| `end_trans` | Transactions | No | No | Commit/rollback transaction |
| `idapython` | Scripting | No | No | Execute Python code in IDA context |
| `find_bytes` | Search | Yes | Yes | Pattern byte search |
| `find_insns` | Search | Yes | Yes | Instruction sequence search |

---

## Default Parameters

| Parameter | Default | Max/Range |
|-----------|---------|-----------|
| List/type limit | 500 | 10,000 |
| Search limit | 1000 | 100,000 |
| CFG max_depth | 5 | N/A |
| CFG max_nodes | 1000 | N/A |
| CFG max_edges | 5000 | N/A |
| Callgraph max_depth | 5 | N/A |
| Callgraph max_nodes | 1000 | N/A |
| Callgraph max_edges | 5000 | N/A |
| RPC callback timeout | 30 seconds | Per-call override via `_rpc_timeout` |

---

## Architecture & Processor Names

MCPyIDA normalizes architecture names from IDA's raw processor names:

- `'metapc'` → `'x86'`
- `'pc'` → `'x86'`
- `'ARM'` → `'ARM'`
- `'MIPS'` → `'MIPS'`
- `'PPC'` → `'PowerPC'`

---

## Error Handling

All batch tools (those accepting `items` arrays) return per-item error handling:

```json
{
  "items": [
    {"name": "renamed_func", "old_name": "old_func", "new_name": "renamed_func", "error": null},
    {"name": null, "error": "Symbol not found at 0x401000"}
  ]
}
```

Individual item failures do not prevent processing of other items in the batch.

---

## Address Format

All addresses are hex strings, with or without `0x` prefix:
- Accepted: `"0x401000"`, `"401000"`, `"0X401000"`
- Returned: `"0x401000"` (normalized with prefix)

---

## Transaction Behavior

Most modification tools (`rename`, `update_vars`, `set_comments`, `set_prototype`, `patch`) handle transactions internally. The explicit `begin_trans` / `end_trans` tools are for advanced use when multiple operations must be atomic.

If a transaction is already active (from a previous `begin_trans` without `end_trans`), subsequent modification tools participate in that transaction.

---

## Variable Persistence (idapython)

The `idapython` tool maintains a persistent execution context for the server lifetime:

```python
# Call 1: Define a function
idapython(code="def helper(): return 42")

# Call 2: Reuse the function
idapython(code="helper()")  # Returns 42
```

To clear all persistent state and restart from IDA's defaults:

```python
idapython(code="x = 100", reset=True)  # Clears all previous globals
```

---

## Limitations

- **Read-only disable flag:** Setting `MCPY_DISABLE_READONLY_TOOLS=1` disables all 14 read-only tools (list, cursor, context, get_funcs, decompile, disasm, symbols, xrefs, types, type_info, find_bytes, find_insns, cfg, callgraph, get_comment)
- **Hex-Rays requirement:** `decompile` requires the Hex-Rays decompiler (paid feature; absent in IDA Free)
- **IDA version:** Tested with IDA Pro 9.x via idalib (headless). GUI plugin mode tested on 8.x and 9.x. IDA Pro with UI initialized required for GUI mode.
- **Headless mode:** Cursor position in headless mode is the last-set position or entry point (no user interaction)

---

## For More Information

- **Setup:** [docs/quickstart.md](./quickstart.md)
- **Client configuration:** [docs/mcp-client-config.md](./mcp-client-config.md)
- **RPC callbacks protocol:** [docs/specs/rpc-callbacks.md](./specs/rpc-callbacks.md)
- **Architecture overview:** [docs/index.md](./index.md)
