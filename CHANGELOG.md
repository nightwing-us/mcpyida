# Changelog

All notable changes to **MCPyIDA** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.1] - 2026-06-17

Headless database-location control and crash-safe persistence.

### Added

- **`--idb-path` for the headless server.** Controls where the IDA database
  (`.i64`/`.idb`) is written, instead of the default location beside the input
  binary. The extension is optional; the path must not contain whitespace.

### Fixed

- **Headless analysis and edits are now saved on `SIGTERM`.** A `SIGTERM`
  previously terminated the process without saving, losing auto-analysis results
  and any edits made over MCP. The server now shuts down gracefully and saves the
  database.

### Upgrade

Drop-in upgrade — no breaking API changes.

## [0.7.0] - 2026-06-12

Enhancements to the embedded `idapython` scripting environment and the
`mcpy/rpcCallbacks` client-callback protocol extension.

### Added

- **Nested namespace projection for callback tools in `idapython`.** When a
  connected MCP client exposes callback tools through the `mcpy/rpcCallbacks`
  extension, a tool named `mcp__server__list` is now projected into the embedded
  Python environment as a nested call — `mcp.server.list(...)` — instead of a
  flat `mcp__server__list(...)`. The mapping is fully generic: every `__`
  separator becomes a namespace level, with automatic escaping for Python
  reserved words (e.g. `mcp._import`) and collisions with real top-level names.
- **The server's own tools are callable from `idapython` as `mcp.self.*`.**
  MCPyIDA now projects its own MCP tools into the scripting environment and
  dispatches them in-process, so a script can call e.g. `mcp.self.decompile(ea)`
  directly without a network round-trip. The code-execution tool itself is
  excluded, to prevent re-entrant execution.
- **Faux namespaces are importable inside the `idapython` REPL.** `import mcp`,
  `import mcp.server as s`, and `from mcp.server import tool` now resolve against
  the projected namespace tree within a running script, while real modules
  (`os`, `ida_*`, …) continue to import normally. Import resolution is scoped to
  script execution and never alters the host interpreter.
- **`executesCode` annotation on the code-execution tool**, so clients can
  identify the tool that runs arbitrary Python.

### Changed

- Callback-tool changes are now picked up mid-session: when a callback-providing
  client signals that its function list changed, MCPyIDA re-discovers the
  available callback tools instead of reusing a stale set.

### Fixed

- **Reverse-RPC callback discovery now fires reliably.** The MCP `Context` is
  injected into the tool invocation so the server can issue callback requests to
  the client; previously discovery could silently fail to start.

### Upgrade

Drop-in upgrade — no breaking API changes. Note one behavior change: callback
tools that previously appeared as flat `prefix__name()` callables now appear as
nested `prefix.name()`. Update any scripts that referenced the flat form.

## [0.6.0] and earlier

Releases up to and including v0.6.0 predate this changelog; see the Git history
and the GitHub release notes for details.

[0.7.1]: https://github.com/nightwing-us/mcpyida/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/nightwing-us/mcpyida/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/nightwing-us/mcpyida/releases/tag/v0.6.0
