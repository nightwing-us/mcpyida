# RPC Callbacks Protocol

**Version:** 1.0

## Overview

The RPC Callbacks Protocol extends the Model Context Protocol (MCP) to enable bidirectional function calling. While MCP's standard tool system allows servers to expose functions for clients to invoke, this extension defines the reverse: a mechanism for MCP **servers** to discover and invoke functions provided by the **client**.

The primary use case is exposing client-side capabilities (such as LLM access, web search, file operations, or connections to other MCP servers) as callable functions within a server's scripting environment. For example, MCPyIDA's reverse engineering MCP server makes a client's `search_web()` or `ask_llm()` functions available as Python globals inside its `idapython` tool.

## Capabilities Declaration

Servers and clients that support this protocol must declare the `mcpy/rpcCallbacks` capability during MCP initialization.

**Server capability (sent in initialize request):**
```json
{
  "capabilities": {
    "experimental": {
      "mcpy/rpcCallbacks": {}
    }
  }
}
```

**Client capability (sent in initialize response):**
```json
{
  "capabilities": {
    "experimental": {
      "mcpy/rpcCallbacks": {
        "listChanged": true
      }
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listChanged` | boolean | No | If `true`, the client will emit `notifications/mcpy/functions/list_changed` when its available function list changes. |

The client decides which functions to expose based on its configuration and policies. Per-function authorization is managed client-side. If either party does not declare the capability, function callbacks **MUST NOT** be used.

## Messages

### mcpy/listFunctions: Discover Available Functions

After initialization, if both parties declared the `mcpy/rpcCallbacks` capability, the server sends a request to discover what functions the client provides.

**Request (Server → Client):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "mcpy/listFunctions",
  "params": {
    "cursor": "opaque-continuation-token"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cursor` | string | No | Opaque pagination cursor from a prior response's `nextCursor`. Omit for the first request. |

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "functions": [
      {
        "name": "search_web",
        "description": "Search the web for information",
        "parameterOrder": ["query", "max_results"],
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            },
            "max_results": {
              "type": "integer",
              "description": "Maximum number of results to return",
              "default": 10
            }
          },
          "required": ["query"]
        },
        "returnDescription": "Search results as formatted text"
      }
    ],
    "nextCursor": "opaque-continuation-token"
  }
}
```

Each function in the `functions` array contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique function identifier. Projected into the scripting environment via the Namespace Projection rules below (`__` separators become nested namespaces; reserved-word and shadowing collisions are escaped with a leading underscore). |
| `description` | string | No | Human-readable description of the function's purpose. |
| `parameterOrder` | array of string | Yes | Ordered list of parameter names defining positional argument order. **MUST** match keys in `inputSchema.properties`. |
| `inputSchema` | object | Yes | JSON Schema object (type: "object") defining the function's parameters and their types. Properties listed in `required` are mandatory; others are optional. |
| `returnDescription` | string | No | Human-readable description of the return value. |
| `annotations` | object | No | Optional metadata (e.g., `title`, `readOnlyHint`, `destructiveHint`). |

The `parameterOrder` array is the authoritative source for argument order; do not rely on JSON object property order.

### notifications/mcpy/functions/list_changed: Function List Update

When the client's available function list changes (e.g., a downstream MCP server connects or disconnects), the client sends a notification:

**Notification (Client → Server):**
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/mcpy/functions/list_changed"
}
```

Upon receiving this notification, the server re-sends `mcpy/listFunctions` to refresh its function list. Functions that were previously available but are no longer listed are removed from the scripting environment. New functions are added. Changes are deferred until the current tool execution completes to prevent mid-execution surprises.

### mcpy/callFunction: Invoke a Client Function

To invoke a client function, the server sends a request:

**Request (Server → Client):**
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "mcpy/callFunction",
  "params": {
    "name": "search_web",
    "arguments": {
      "query": "ida struct recovery",
      "max_results": 5
    },
    "_meta": {
      "progressToken": "some-progress-token"
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Name of the function to call. **MUST** match a function from the most recent `mcpy/listFunctions` response. |
| `arguments` | object | No | Arguments to pass to the function. **MUST** conform to the function's `inputSchema`. |
| `_meta` | object | No | MCP metadata object. MAY include `progressToken` for progress reporting. |

**Response (success):**
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": "Results: 1. IDA Struct Recovery Tutorial..."
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `content` | any | The raw return value of the function. MAY be a string, number, boolean, null, object, or array. This is a deliberate deviation from MCP's `list[ContentBlock]` pattern: callback return values are raw return values, not MCP content blocks. |

**Response (error):**
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32603,
    "message": "Function 'search_web' failed: connection timeout",
    "data": {
      "name": "search_web",
      "exception": {
        "type": "TimeoutError",
        "message": "connection timeout after 30s",
        "traceback": "Traceback (most recent call last):..."
      }
    }
  }
}
```

Common error codes:

| Code | Scenario |
|------|----------|
| `-32601` | Function not found |
| `-32602` | Invalid arguments (do not conform to `inputSchema`) |
| `-32603` | Internal error; function execution failed |

When raising exceptions in the scripting environment from a remote error response, implementations **SHOULD** attach the remote error as a cause using Python's `raise ... from ...` mechanism.

## Message Flow Example

```
1. Server connects to client
2. Server sends initialize (with mcpy/rpcCallbacks capability)
3. Client responds with initialize (with mcpy/rpcCallbacks capability)
4. Server sends mcpy/listFunctions
5. Client responds with available functions
6. Client invokes a server tool (e.g., idapython)
7. Script inside the tool calls search_web() (a callback function)
8. Server sends mcpy/callFunction(search_web, ...)
9. Client executes the function and responds
10. Script receives result and continues
11. Server sends tool result back to client
12. Tool execution completes; callback functions expire
```

## Scripting Integration

MCPyIDA injects callback functions into the scripting environment of the `idapython` tool by **namespace projection** (see "Namespace Projection" below):

1. **Flat globals** — a name with no `__` separator is injected directly by name: `search_web("query")`.
2. **Nested namespaces** — a name with `__` separators is projected into nested namespace objects: `mcp__ghidra1__list` becomes `mcp.ghidra1.list("...")`.

Discovery and documentation use native Python introspection — `dir(mcp.ghidra1)` lists the available calls and `help(mcp.ghidra1.list)` prints the generated signature and docstring. (Earlier revisions injected a dedicated `rpc` helper object; that is no longer provided.)

### Namespace Projection

Function names are projected into the scripting environment by splitting on `__`:

- **Separators are greedy.** A run of two or more underscores is a single
  separator: `mcp___ghidra1` → `mcp.ghidra1`. Leading, trailing, and repeated
  separators collapse (`__mcp__ghidra1__list__` → `mcp.ghidra1.list`). A single
  underscore is preserved within a segment (`search_web` stays one name).
- **No separator → flat global.** `search_web` is injected directly by name.
- **A name with no usable segments is skipped.** If a name is entirely
  underscores (e.g. `____`), it yields no segments and the function is skipped
  and logged.
- **Reserved words are escaped, not dropped.** A segment that is a Python hard
  keyword (e.g. `import`, `class`) is prefixed with `_` so it stays reachable
  via dotted access (`mcp.import` is a `SyntaxError`; `mcp._import` is valid).
  Builtins (`list`, `type`) and soft keywords (`match`, `case`) are valid
  attribute names, so they are left unescaped as sub/leaf segments. (As the
  top-level global, soft keywords and builtins are still escaped — see
  top-level shadowing below.)
- **Top-level shadowing is escaped.** Only the first segment becomes a real
  global. If it would shadow an existing scripting global, a builtin, or a
  keyword, it is prefixed with `_` (`list` → `_list`, `list__foo` →
  `_list.foo`). If the escaped name also collides, the function is skipped and
  logged.
- **Leaf-vs-namespace conflicts are skipped deterministically.** If one name
  needs a path as a callable and another needs the same path as a namespace
  (e.g. `mcp__ghidra1` and `mcp__ghidra1__list`), functions are processed in
  sorted name order and the first claim wins; the conflicting function is
  skipped and logged.

Projection affects only how functions are *named* in the scripting environment.
The wire protocol (`mcpy/callFunction`) always uses the original function name.

### Generating Function Signatures

When creating callable wrappers from `FunctionDefinition` objects in the idapython execution context:

- Required properties (in `inputSchema.required`) become positional parameters
- Optional properties with defaults become keyword parameters
- Use `parameterOrder` to determine the correct argument order
- Provide a keyword-only `_rpc_timeout` parameter to allow per-call timeout overrides (e.g., `search_web("query", _rpc_timeout=60)`)

Example generated function signature:
```python
def search_web(query, max_results=10, *, _rpc_timeout=30.0):
    """Search the web for information
    
    Args:
        query (str, required): Search query
        max_results (int, default=10): Maximum number of results to return
        _rpc_timeout (float, default=30.0): Per-call timeout override
    
    Returns: Search results as formatted text
    """
```

### JSON Schema to Python Type Mapping

| JSON Schema type | Python type |
|-----------------|-------------|
| `"string"` | `str` |
| `"integer"` | `int` |
| `"number"` | `float` |
| `"boolean"` | `bool` |
| `"array"` | `list` |
| `"object"` | `dict` |
| `"null"` | `None` |
| `["string", "null"]` | `Optional[str]` |

These mappings are used to generate parameter type annotations in docstrings (see `_build_docstring()` in `src/mcpyida/rpc_callbacks.py:198-225`).

## Scope and Validity

Callback functions are scoped to the execution lifetime of the tool invocation that triggered them. Once tool execution completes, all callback function handles become invalid and **MUST** raise `RuntimeError("Callback expired — function callbacks are only usable during tool execution")` when invoked.

Implementations **MUST** use an execution-scoped validity token (`CallbackScope`) to enforce this expiration, even when closures or local variable bindings capture references to callback functions.

**Example:**
```python
# During idapython execution: works
result = search_web("query")

# After idapython execution completes: raises RuntimeError
saved_fn = search_web           # captured during execution
# ... tool execution ends ...
saved_fn("query")               # raises RuntimeError("Callback expired — ...")
```

The `CallbackScope` is invalidated at the end of `_idapython_eval_sync()` (see `src/mcpyida/tools/scripting.py:148-149`), ensuring that any lingering references to callback functions become inoperable.

## Name Collision Protection

Function names are projected into the scripting environment by the Namespace
Projection rules above, which resolve collisions by escaping rather than by
forbidding names:

- A top-level name that would shadow a Python builtin, a keyword (including soft
  keywords like `match`), or an existing scripting global (e.g. `idaapi`, `idc`,
  `idautils`, `IdaFunction`) is escaped with a leading underscore.
- Hard-keyword path segments at any level are escaped with a leading underscore.
- A function whose escaped top-level name still collides, or whose path conflicts
  with an already-claimed namespace/callable, is skipped and logged.

The reserved-name denylist used for top-level safety is `_PYTHON_DENYLIST` in
`src/mcpyida/rpc_callbacks.py`.

## Re-Entrancy & Recursion Limits

Implementations **MUST** enforce a maximum callback depth of **3** to prevent accidental infinite recursion or deadlocks (particularly in IDA Pro's single-threaded environment).

**Rules:**
1. Clients **MUST NOT** re-enter the originating server during a callback (i.e., issue a `tools/call` to MCPyIDA's `idapython` tool while handling a `mcpy/callFunction`).
2. If the depth limit is exceeded, the server **MUST** return error code `-32603` with `exception.type: "RecursionError"`.
3. Implementations **MUST** track the current nesting depth across all concurrent callbacks within a single tool execution.

## Security Considerations

### Servers MUST:
- Only invoke functions discovered via `mcpy/listFunctions`
- Validate that function arguments conform to the declared `inputSchema` before sending
- Enforce timeouts on all function calls (default: 30 seconds; see `src/mcpyida/rpc_callbacks.py:238, 264`) to prevent resource exhaustion
- Enforce callback scope expiration via validity tokens, not merely by removing globals (see `src/mcpyida/rpc_callbacks.py:62-67`)
- Enforce maximum callback depth to prevent re-entrancy attacks

### Clients MUST:
- Only expose functions appropriate for the server's context
- Validate incoming `mcpy/callFunction` requests against the published function list
- Apply the same authorization and rate-limiting policies as for direct function invocations
- Not execute functions from servers that did not declare the `mcpy/rpcCallbacks` capability

### Both parties SHOULD:
- Log all function calls for auditing purposes
- Implement rate limiting to prevent abuse
- In production, sanitize tracebacks in `exception.traceback` to remove absolute filesystem paths before transmission

## Error Handling & Exception Mapping

Standard exception types should map to their native equivalents in the scripting environment:

| Remote exception.type | Python Exception |
|-----------------------|------------------|
| `"TypeError"` | `TypeError` |
| `"ValueError"` | `ValueError` |
| `"KeyError"` | `KeyError` |
| `"FileNotFoundError"` | `FileNotFoundError` |
| `"PermissionError"` | `PermissionError` |
| `"RecursionError"` | `RecursionError` |
| `"TimeoutError"` | `TimeoutError` (or custom `RPCTimeoutError`) |
| `"NameError"` | `NameError` |
| *(unrecognized)* | `RuntimeError` |

The exception mapping is implemented in `src/mcpyida/rpc_callbacks.py:317-336` via the `map_exception()` function.

Servers **MUST** handle gracefully:
- Client disconnection during an in-flight function call
- Function removed between discovery and invocation (raise `NameError`)
- Timeout exceeded (raise `TimeoutError` or custom `RPCTimeoutError`)
- Arguments that do not match the declared schema (raise `TypeError`)

## Related Documentation

- **[Tools Reference: idapython Tool](../tools-reference.md#idapython)** — How MCPyIDA uses RPC callbacks in the `idapython` scripting tool
- **[Tools Reference](../tools-reference.md)** — Overview of all MCPyIDA tools
- **[Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)** — Official MCP specification

## References

This protocol is implemented in MCPyIDA's:
- `/src/mcpyida/rpc_callbacks.py` — Function generation, callback scope, exception mapping, name collision protection
- `/src/mcpyida/rpc_types.py` — Pydantic models for protocol messages
- `/src/mcpyida/server.py` — Capability declaration, discovery, RPC call dispatch
- `/src/mcpyida/tools/scripting.py` — Callback injection into idapython execution context
