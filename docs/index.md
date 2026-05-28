# MCPyIDA Documentation

MCPyIDA is an MCP (Model Context Protocol) server that exposes IDA Pro reverse-engineering tools to LLM clients. The documents below cover installation, running the server, client configuration, and tool usage.

## Getting Started

- **[Installation & Setup](installation.md)** — Prerequisites, installing from PyPI, configuring IDA Pro
- **[Quickstart Guide](quickstart.md)** — Your first MCPyIDA server and client connection
- **[Connecting MCP Clients](mcp-client-config.md)** — Configure Claude, Cline, and other MCP clients

## Using MCPyIDA

- **[Tools Reference](tools-reference.md)** — Every exposed tool, grouped by category: listing & navigation, analysis & decompilation, control flow, types, modification & patching, scripting, and search
- Running modes (headless server and IDA Pro GUI plugin) are covered in the **[Quickstart Guide](quickstart.md)**

## Advanced Topics

- **[RPC Callbacks Protocol](specs/rpc-callbacks.md)** — Bidirectional function calls between server and client (for advanced `idapython` scripts)

## FAQ & Troubleshooting

Refer to the Quickstart and Installation guides for common setup issues. If you encounter problems:

- Verify IDA Pro 9.x is installed with idalib activated (or use GUI plugin on 8.x)
- Ensure Python 3.10+ is in use
- Check that idalib has been activated via `py-activate-idalib.py`
- Review logs for connection errors between client and server

## Related Projects

MCPyIDA and [MCPyGhidra](https://github.com/nightwing-us/mcpyghidra) are maintained
in parallel as sister projects with intended feature parity — MCPyIDA targets IDA Pro
and MCPyGhidra targets Ghidra. If you use Ghidra, see MCPyGhidra (and the
[pyghidra-decaf](https://github.com/nightwing-us/pyghidra-decaf) plugin framework that
underpins it).

## Contributing

MCPyIDA welcomes contributions! See the repository's [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on code style, testing, and submitting pull requests.

## License

MCPyIDA is licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

Copyright © 2026 Nightwing Group, LLC.
