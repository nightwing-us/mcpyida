# Connecting MCP Clients

MCPyIDA exposes a standard MCP (Model Context Protocol) Streamable HTTP endpoint. This guide shows how to configure various MCP clients to connect.

## MCP Server Connection Details

When MCPyIDA is running (either headless or as a GUI plugin), it provides a Streamable HTTP endpoint at:

```
http://<host>:<port>/mcp
```

Default (headless): `http://127.0.0.1:6150/mcp`

The server prints a JSON readiness signal:

```json
{"status": "ready", "host": "127.0.0.1", "port": 6150, "binary": "/path/to/binary"}
```

## Claude Desktop (via mcpo)

If using mcpo as a bridge to Claude Desktop, configure MCPyIDA in mcpo's own config file.

### Setup

1. Start MCPyIDA:
   ```bash
   mcpyida-headless /path/to/binary
   ```

2. Create or edit `~/.mcpo/config.json` to configure mcpo's connection to MCPyIDA:
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

   This file is mcpo's own configuration. Ensure mcpo is installed and running as a separate service.

3. Restart Claude Desktop
4. In the toolbox (bottom right), you should see "ida" as an available MCP server
5. Click to activate it

### Usage

Once enabled, you can ask Claude questions about the binary:

> What functions are in this binary?
> Decompile the main function.
> Find all calls to malloc.

## Cline (VS Code Extension)

Cline integrates MCP servers through its settings configuration.

### Setup

1. Open VS Code settings (or `settings.json`)
2. Add MCPyIDA to your MCP configuration:
   ```json
   {
     "cline.mcpServers": {
       "ida": {
         "type": "streamable-http",
         "url": "http://127.0.0.1:6150/mcp"
       }
     }
   }
   ```

3. Restart Cline or reload VS Code
4. Cline should recognize the ida server

### Usage

In your Cline conversation, mention the MCPyIDA tools:

> Use the tools from the ida MCP server to list all functions in the binary.

## Generic MCP Clients

Any MCP-compatible client that supports Streamable HTTP can connect to MCPyIDA:

### Configuration Template

Replace `<host>` and `<port>` with your actual values (default: `127.0.0.1:6150`):

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamable-http",
      "url": "http://<host>:<port>/mcp"
    }
  }
}
```

### Supported Transports

- **Streamable HTTP:** The primary MCP transport used by MCPyIDA (MCP 1.x specification)
- **stdio:** MCPyIDA does not support stdio transport; use HTTP/Streamable HTTP only

## Remote Connections

If MCPyIDA is running on a different machine (not localhost):

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamable-http",
      "url": "http://remote-host.example.com:6150/mcp"
    }
  }
}
```

**Note:** The headless server binds to `127.0.0.1` by default for security. To allow remote connections, bind to `0.0.0.0`:

```bash
mcpyida-headless /path/to/binary --host 0.0.0.0 --port 6150
```

Then connect via the remote IP:

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamable-http",
      "url": "http://remote-ip:6150/mcp"
    }
  }
}
```

## HTTPS (TLS)

MCPyIDA's headless server does not directly support TLS. If you need HTTPS:

1. Run MCPyIDA on localhost (default)
2. Use a reverse proxy (nginx, Apache, caddy, etc.) to add TLS:

   ```nginx
   # nginx example
   server {
       listen 443 ssl;
       server_name ida.example.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location /mcp {
           proxy_pass http://127.0.0.1:6150/mcp;
       }
   }
   ```

3. Configure clients to use `https://ida.example.com/mcp`

## Testing Connection

To verify a client can reach MCPyIDA:

```bash
# From the client machine
curl -i http://<host>:<port>/mcp
```

You will see a `200 OK` response with streaming headers (stays open until Ctrl+C).

## Troubleshooting

### "Connection refused" or "Cannot reach server"

- Verify MCPyIDA is still running:
  ```bash
  ps aux | grep mcpyida
  ```

- Check the server is bound correctly:
  ```bash
  netstat -tlnp | grep 6150  # or ss -tlnp | grep 6150
  ```

- Verify the URL is correct (match `--host` and `--port` flags)

### Client doesn't show MCPyIDA tools

- Restart your client application
- Verify the URL is reachable (test with `curl`)
- Check client logs for connection errors

### Port already in use

Use a different port:

```bash
mcpyida-headless /path/to/binary --port 6151
# Update client config to use :6151
```

Or use automatic port assignment:

```bash
mcpyida-headless /path/to/binary --port 0
# Check the readiness JSON for the actual port
```

## Next Steps

- [Tools Reference](tools-reference.md) — Learn what operations are available
- [Quickstart](quickstart.md) — End-to-end walkthrough
- [RPC Callbacks](specs/rpc-callbacks.md) — Advanced scripting with Python callbacks
