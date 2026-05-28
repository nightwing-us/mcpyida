# Quickstart Guide (Headless Mode)

> **Note:** This guide covers headless mode using idalib, which requires **IDA Pro 9.0 or later**. If you have IDA 8.x, see [Installation & Setup — GUI Mode](installation.md#gui-mode-interactive---ida-8x-and-9x) instead.

## Step 1: Create and Activate a Python Virtual Environment

Create an isolated Python environment for MCPyIDA. This ensures clean dependency management and avoids conflicts with your system Python:

```bash
# Create a virtual environment (use Python 3.13 for IDA Pro 9.2)
python3.13 -m venv ~/idavenv
source ~/idavenv/bin/activate

# Verify the venv is active
which python
python --version
```

**Important:** Keep this venv active for all subsequent steps. Do not deactivate and switch Python versions between steps, or idalib activation will not work correctly.

## Step 2: Install MCPyIDA

With your venv activated, install MCPyIDA from PyPI:

```bash
pip install mcpyida
```

For detailed instructions, see [Installation & Setup](installation.md).

## Step 3: Activate idalib (IDA 9.0+ Only)

Still within the same activated venv, run the idalib activation script from your IDA Pro installation. **This requires IDA Pro 9.0+; idalib does not exist on IDA 8.x.**

```bash
python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py
```

This writes `~/.idapro/ida-config.json` and enables the `idapro` Python module in your current environment.

Verify it worked:

```bash
python -c "import idapro; print('idalib activated')"
```

## Step 4: Launch the Headless Server

Still within the same activated venv, start MCPyIDA with a binary to analyze:

```bash
mcpyida-headless --binary /path/to/firmware.elf
```

Expected output:

```
{"status": "ready", "host": "127.0.0.1", "port": 6150, "binary": "/path/to/firmware.elf"}
```

The server is now running and listening on `http://127.0.0.1:6150/mcp`.

## Step 5: Configure an MCP Client

In a separate terminal, configure your MCP client to connect to the running server.

### Using Claude Desktop (via mcpo)

If using mcpo as a bridge to Claude Desktop, configure it in `~/.mcpo/config.json`:

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:6150/mcp"
    }
  }
}
```

Ensure mcpo is installed and running. Restart Claude Desktop. You should now see `ida` in the MCP server list.

### Using a Generic MCP Client

Any MCP-compatible client supporting Streamable HTTP can connect. Configure it with:

- **Type:** Streamable HTTP
- **URL:** `http://127.0.0.1:6150/mcp`

## Step 6: Use MCPyIDA from Your Client

Once connected, you can use the exposed tools. For example, in Claude:

> What functions are in the binary? Use the `list` tool to show me functions with "main" in their name.

The client will:

1. Send a request to MCPyIDA (via MCP)
2. MCPyIDA calls IDA Pro APIs to extract function information
3. Returns results to the client
4. The client displays or processes the results

## Common Commands

### List Functions

View functions in the binary:

```
Use list tool with entry_type="function" and limit=20
```

### Decompile a Function

Get high-level code for a function (by name or address):

```
Use decompile tool with the function name or address
```

### Find Cross-References

See where a function is called:

```
Use xrefs tool with direction="to" and target="function_name"
```

### Patch Instructions

Modify binary instructions:

```
Use patch tool to replace instruction bytes at an address
```

### Inspect Types

List and inspect custom types (structures, enums, unions):

```
Use types tool to enumerate, type_info to inspect details
```

## Stopping the Server

In the terminal where MCPyIDA is running, press **Ctrl+C**:

```
^CShutting down...
```

The server will stop gracefully.

## Headless Server Options

The `mcpyida-headless` command accepts these flags:

```bash
mcpyida-headless --binary <path> [--host <host>] [--port <port>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--binary` (required) | — | Path to the binary to analyze |
| `--host` | `127.0.0.1` | Host to bind the server (localhost by default) |
| `--port` | `6150` | Port number (use `0` for automatic assignment) |

Example: auto-assign port and bind to all interfaces:

```bash
mcpyida-headless --binary /path/to/firmware.elf --host 0.0.0.0 --port 0
```

The readiness JSON will show the actual assigned port.

## Next Steps

- Explore [Tools Reference](tools-reference.md) for all available functions
- Learn [MCP Client Configuration](mcp-client-config.md) for advanced setups
- See [RPC Callbacks](specs/rpc-callbacks.md) for advanced scripting features

## Troubleshooting

### "idalib not configured"

Ensure you activated idalib in the same venv that's running `mcpyida-headless`:

```bash
# Activate your venv
source ~/idavenv/bin/activate

# Run the activation script
python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py

# Verify it works
python -c "import idapro; print('OK')"

# Then run the server in the same venv
mcpyida-headless --binary /path/to/firmware.elf
```

### "idapro" module import fails or version mismatch

If you see errors like `cannot import name 'idapro'` or `libpython version mismatch`:

1. Check your current Python version:
   ```bash
   python --version
   ```

2. Check what Python version idalib supports:
   ```bash
   ls /path/to/ida-pro-9.2/idalib/python/wheels/
   # Look for: idapro-9.2-cp313-cp313-linux_x86_64.whl (Python 3.13)
   ```

3. If they don't match, create a venv with the correct Python version and repeat the installation steps.

**See [Installation & Setup — Python Version Mismatch](installation.md#error-python-version-mismatch-idalib-import-fails) for detailed troubleshooting.**

### "Binary file not found"

Verify the binary path exists and is readable:

```bash
ls -la /path/to/firmware.elf
```

### Client can't connect

Ensure the server is still running and listening:

```bash
curl http://127.0.0.1:6150/mcp
# Should show a streaming response (may not print visually, Ctrl+C to cancel)
```

### Server startup hangs

Analysis of large binaries can take minutes. Wait longer or use a smaller test binary:

```bash
mcpyida-headless --binary /bin/ls
```

On the first run after idalib activation, IDA may perform one-time setup operations, which can take several minutes.

For more help, see [Installation & Setup](installation.md) and [Tools Reference](tools-reference.md).
