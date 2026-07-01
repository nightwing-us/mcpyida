# Changelog

All notable changes to **MCPyIDA** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.3] - 2026-06-29

Tool-surface consistency. Several tools that deviated from the shared
input/output convention are brought in line, so the API is uniform to call:
one address key (`addr`), one result/row shape, and a top-level `error` on
every batched item.

### Changed (breaking)

- **`list` items use `addr`** (was `address`) for the per-entry address, matching
  every other tool. Segment-style entries keep `start`/`end`.
- **`xrefs` is addressed like its siblings.** Input now takes `addr`/`name`
  (aliases: `ea`, `function`, and the legacy `target`, auto-detected) instead of
  `target`-only. Output is a flat per-item dict — cross-reference rows under
  `items` with `error` at the top level — instead of nesting a `ListResult` under
  `['result']`. The `ida://xrefs/*` resources return the flat shape.
- **`find_bytes` / `find_insns` rows are under `items`** (was `matches`), matching
  the row-container key the rest of the surface uses.
- **`update_vars` returns a structured result** (was a human-readable status
  string): `{function, addr, results, error}`, where each item of `results` is
  `{var, new_name, new_type, error}` (`error` null on success). A function-level
  failure sets the top-level `error` with empty `results`. Per-variable
  success/failure is now machine-readable.

### Added

- **`add_field` items carry a top-level `error` key** (None on success, the
  failure message otherwise), so every batched-item result follows the shared
  `error` convention. `success`/`message` are unchanged.
- **`type_info` success items carry `error: None`**, so every batched item — not
  just failures — exposes the shared `error` key.
- **`StructureCreationResult` carries a top-level `error` key** (None on success;
  `create_struct` raises on failure), making its shape uniform with the other
  result models.

### Notes

- `BasicBlock.address` and `FunctionInfo.entrypoint` are intentionally **not**
  renamed — external tools depend on those model definitions. `entrypoint`
  remains the accepted "function entry point" key (`decompile`, `funcs`,
  `FunctionInfo`); `BasicBlock.address` remains the CFG block key.

## [0.7.2] - 2026-06-26

Single-or-batch tool calls, parallel-safe port binding, and headless launcher
ergonomics.

### Added

- **IDA Plugin Manager support.** MCPyIDA can be installed on IDA Pro 9.0+
  through the Hex-Rays IDA Plugin Manager (`hcli plugin install mcpyida`),
  backed by a root `ida-plugin.json` whose `pythonDependencies` pins the
  matching `mcpyida` PyPI release. This installs the GUI plugin only; headless
  mode remains `pip install mcpyida`.
- **Single-or-batch tool calls.** Every multi-target tool accepts either a flat
  single call (`decompile(addr="0x401000")`) or a batch
  (`decompile(items=[{...}, ...])`). A flat call returns one result; a batch
  returns a list. Applies to `decompile`, `disasm`, `xrefs`, `symbols`,
  `type_info`, `funcs`, `get_comment`, `rename`, `set_comments`,
  `set_prototype`, `patch`, and `add_field`. A no-argument call returns an
  instructive error pointing at the matching enumeration tool.
- **`--port` range binding (headless).** `--port` accepts a range (default
  `6150-6159`) and binds the first free port in it, so multiple headless servers
  can launch in parallel without a port clash. A bare `--port N` is strict (that
  port only — fails if busy); `--port 0` lets the OS auto-assign. The bound port
  is reported in the JSON ready signal.
- **`--ida-dir <dir>` (headless)** pins the IDA install (precedence `--ida-dir`
  → `IDADIR` → `~/.idapro/ida-config.json`), so the command is self-contained.

### Changed

- **Servers bind the first free port** (GUI and headless) instead of a single
  fixed port.
- **Renamed the `get_funcs` tool to `funcs`** (no alias).
- **`mcpyida-headless` takes the binary as a positional argument** —
  `mcpyida-headless /path/to/binary …` (the `--binary` flag is removed).
- **Headless failures are reported as one structured JSON line on stdout** —
  `{"status":"error","reason":"…","detail":"…"}` (reasons: `binary_not_found`,
  `missing_install_dir`, `bad_port`, `port_unavailable`, `open_failed`) with a
  distinct exit code per class, so a background launcher can diagnose without a
  foreground re-run. A `Using IDA <version> (<dir>) · binary <name>` line is
  printed at startup.

### Removed

- **Removed the standalone `types` tool.** Enumerate types with
  `list(entry_type="type")`, which returns the same fields in the standard
  paginated list envelope.

### Upgrade

The tool surface changed: update any client that called `get_funcs` (now
`funcs`) or the `types` tool (now `list(entry_type="type")`). The batch
`items=[...]` form is unchanged, so existing batch callers keep working. The
headless CLI also changed: pass the binary positionally
(`mcpyida-headless <binary>`), not `--binary <binary>`.

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

[0.7.2]: https://github.com/nightwing-us/mcpyida/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/nightwing-us/mcpyida/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/nightwing-us/mcpyida/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/nightwing-us/mcpyida/releases/tag/v0.6.0
