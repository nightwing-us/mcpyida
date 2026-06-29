# Installation & Setup

This guide covers installing MCPyIDA and configuring its dependencies.

## Prerequisites

Before installing MCPyIDA, ensure you have:

### IDA Pro Version Requirements

MCPyIDA supports IDA Pro in two distinct modes with different version requirements:

- **GUI Plugin Mode** (interactive IDA Pro with MCPyIDA plugin): **IDA Pro 8.x and 9.x**
- **Headless Mode** (automated analysis without GUI): **IDA Pro 9.0+ only** (requires idalib/idapro)

IDA Pro is commercial software and must be purchased from [Hex-Rays](https://hex-rays.com/ida-pro/).

> **Important:** MCPyIDA does not bundle or distribute IDA Pro. You must supply your own IDA Pro installation and license.

Download IDA Pro from [hex-rays.com](https://hex-rays.com/ida-pro/) and extract it to a location of your choice:

```bash
# Example: extract to ~/tools/ida-pro-9.2
cd ~/tools
unzip ida-pro-9.2_*.zip
# or on macOS
unzip ida-pro-9.2_*.dmg
```

**Tested versions:** IDA Pro 8.3+, 9.0, 9.1, 9.2+

### idalib (Python Headless API — IDA 9.0+ Only)

idalib is the Python API that allows MCPyIDA to run without the IDA GUI (headless mode). **idalib and its `idapro` Python module were introduced in IDA Pro 9.0 and do not exist in IDA 7.x or 8.x.**

**Headless mode requires IDA Pro 9.0+.** If you have IDA 8.x, you can only use GUI plugin mode (see [GUI Mode](installation.md#gui-mode-interactive) below).

To activate idalib on IDA 9.x, run the activation script from your IDA installation:

```bash
python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py
```

This writes `~/.idapro/ida-config.json` to enable IDA Pro's Python module (`idapro`).

> **Note:** If you skip this step, `mcpyida-headless` will fail with an error message containing instructions.

**RPC Callback Features:** The advanced bidirectional RPC callback features (the `mcpy/rpcCallbacks` protocol used by the `idapython` scripting tool) are verified and supported on **IDA Pro 9.x only** and remain untested on earlier versions. See [RPC Callbacks](specs/rpc-callbacks.md) for details.

### Python Environment and Version Compatibility

MCPyIDA and idalib's Python bindings must use the **same Python version**. This is critical:

- **idalib wheel compatibility:** idalib is distributed as a wheel compiled for a specific Python version (e.g., IDA Pro 9.2 ships idalib for Python 3.13). When you activate idalib or `pip install mcpyida`, the Python interpreter running that command must match idalib's compiled version.
- **Virtual environment:** You can (and should) use a Python virtual environment. However, all activation commands (`py-activate-idalib.py`) and server commands (`mcpyida-headless`) **must use the same venv**.
- **Version mismatch symptoms:** If Python versions don't match, you'll see cryptic errors like "cannot import name 'idapro'" or "libpython version not found."

**Check your Python version:**

```bash
python3 --version
# Python 3.10 or later (3.13+ for IDA Pro 9.2)
```

**Verify idalib supports your Python version:** Look for wheel files in your IDA installation:

```bash
ls /path/to/ida-pro-9.2/idalib/python/wheels/
# You'll see wheels like: idapro-9.2-cp313-cp313-linux_x86_64.whl (Python 3.13)
```

If the wheel version doesn't match your Python version, you may need to use a different Python version on your system or contact Hex-Rays support.

## Setting Up Your Python Environment

**Strongly recommended:** Use a Python virtual environment to isolate MCPyIDA and idalib from your system Python:

```bash
# Create a virtual environment
python3.13 -m venv ~/idavenv
source ~/idavenv/bin/activate

# Verify the activated venv
which python
python --version
# Should show Python 3.13.x from ~/idavenv/bin
```

**Important:** All subsequent steps (installing MCPyIDA, activating idalib, running headless server) must use the same activated venv. Do not deactivate and switch venvs between steps.

## Installing MCPyIDA

### From PyPI

The easiest way to install is from PyPI (with venv activated):

```bash
pip install mcpyida
```

This installs mcpyida and its dependencies (including fastapi).

### From Source (Development)

To work on MCPyIDA itself, clone the repository and use `uv`:

```bash
git clone https://github.com/nightwing-us/mcpyida.git
cd mcpyida
uv venv  # Creates .venv inside the repo
source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Configuring IDA Pro

MCPyIDA works with IDA Pro in two distinct modes, each with separate setup requirements:

### GUI Mode (Interactive — IDA 8.x and 9.x)

In GUI mode, MCPyIDA runs as a plugin inside IDA Pro while you use the interactive interface. This mode works on both IDA 8.x and 9.x.

**Setup steps (with venv activated):**

1. Install MCPyIDA: `pip install mcpyida`
2. Register the plugin: `mcpyida_install`
   - This copies the MCPyIDA proxy plugin to IDA's plugins directory (`~/.idapro/plugins`)
   - Next time you launch IDA Pro, the plugin will auto-load
3. Ensure IDAPython can import `mcpyida`:
   - **IDA 9.0+:** Launch IDA from within your activated venv:
     ```bash
     source ~/idavenv/bin/activate
     ida /path/to/binary
     ```
     IDA 9.0 natively supports running from an activated virtual environment; IDAPython will use packages from that venv.
   - **IDA 8.x or if your Python version differs from IDA's bundled Python:** Use the `idapyswitch` tool to rebind IDAPython (the **GUI's** Python) to your Python version:
     ```bash
     /path/to/ida-pro-installation/idapyswitch
     # Follow the interactive menu to select your Python installation
     # Then launch IDA normally: ida /path/to/binary
     ```
     After running idapyswitch, IDAPython will use the selected Python version, allowing it to import `mcpyida` from your venv.

For more details on configuring IDAPython, see the [IDA Pro documentation](https://hex-rays.com/products/ida/support/idadoc/) or the official [IDAPython Getting Started guide](https://docs.hex-rays.com/developer/idapython/idapython-getting-started).

#### IDA Plugin Manager (IDA Pro 9.0+)

On IDA Pro 9.0+, the GUI plugin can be installed through the Hex-Rays IDA
Plugin Manager, which is built into HCLI:

```bash
hcli plugin install mcpyida
```

The manager reads MCPyIDA's `ida-plugin.json`, installs the `mcpyida` package
from PyPI (resolving `fastapi`, `mcp`, and `asgi-lifespan`), and drops the
plugin loader into your IDA `plugins/` directory. Use `hcli plugin
upgrade mcpyida` / `hcli plugin uninstall mcpyida` to manage it.

This path installs the **GUI plugin only**. Headless mode (idalib) is always
installed via `pip install mcpyida` as described above.

### Headless Mode (Scripting / idalib — IDA 9.0+ Only)

In headless mode, MCPyIDA runs without the IDA GUI using the idalib Python API. This is useful for automated analysis pipelines and is the recommended approach for most users.

**Requirement:** Headless mode requires **IDA Pro 9.0 or later** (idalib is not available on IDA 7.x or 8.x). If you have IDA 8.x, use GUI plugin mode instead.

**Prerequisite:** idalib must be activated in the **same Python environment** (venv) that will run `mcpyida-headless`.

**Setup steps (all within the same activated venv):**

1. Activate your venv (if not already active):
   ```bash
   source ~/idavenv/bin/activate
   ```

2. Install MCPyIDA (if not already done):
   ```bash
   pip install mcpyida
   ```

3. Activate idalib in this venv:
   ```bash
   python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py
   ```
   This writes `~/.idapro/ida-config.json`, which tells the `idapro` Python module where your IDA installation is located.

4. Verify idalib is accessible:
   ```bash
   python -c "import idapro; print('idalib activated in', idapro.__file__)"
   ```

5. Launch the headless server:
   ```bash
   mcpyida-headless /path/to/firmware.elf
   ```

The server will print a JSON readiness signal to stdout:

```json
{"status": "ready", "host": "127.0.0.1", "port": 6150, "binary": "/path/to/firmware.elf"}
```

**Critical:** If you deactivate the venv and later activate a different Python version, `mcpyida-headless` will fail to find idalib. Always run headless commands in the same venv where you activated idalib.

## Verifying the Installation

### Test the Headless Server

Create a simple binary or use an existing one:

```bash
mcpyida-headless /bin/ls
```

You should see output like:

```
{"status": "ready", "host": "127.0.0.1", "port": 6150, "binary": "/bin/ls"}
```

Press Ctrl+C to stop the server.

### Verify Dependencies

Check that all dependencies are installed:

```bash
python -c "import mcpyida; import fastapi; print('All dependencies OK')"
```

## Troubleshooting

### Error: idalib not configured

If you see this error:

```
Error: idalib not configured.
Run the activation script from your IDA installation:
  python /path/to/ida-pro-9/idalib/python/py-activate-idalib.py
```

**Solution:** Run the activation script from your IDA installation **in the same venv** that will run `mcpyida-headless`:

```bash
# 1. Activate your venv
source ~/idavenv/bin/activate

# 2. Run the activation script in that venv
python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py

# 3. Verify it worked
python -c "import idapro; print('OK')"
```

This must be done once per Python environment/venv to enable IDA Pro's Python bindings.

### Error: Python version mismatch (idalib import fails)

If you see errors like `cannot import name 'idapro'`, `No module named 'idapro'`, or `libpython version mismatch`, your Python version may not match idalib's compiled version.

**Diagnosis:**

```bash
# Check your current Python version
python --version

# Check what Python version idalib supports
ls /path/to/ida-pro-9.2/idalib/python/wheels/ | grep idapro
# Example output: idapro-9.2-cp313-cp313-linux_x86_64.whl (requires Python 3.13)
```

**Solution:**

1. **Use the correct Python version:** If idalib requires Python 3.13 but you're using Python 3.12, create a new venv with Python 3.13:
   ```bash
   python3.13 -m venv ~/idavenv-3.13
   source ~/idavenv-3.13/bin/activate
   pip install mcpyida
   python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py
   ```

2. **Ensure you haven't mixed Python versions:** Verify your current venv's Python matches the one you used to activate idalib:
   ```bash
   python --version
   # Should match the version where you ran py-activate-idalib.py
   ```

### Error: idalib activated in different venv (headless fails)

If you activated idalib in one venv but later try to run `mcpyida-headless` in a different venv or with a different Python interpreter:

```bash
# Wrong: activated idalib in Python 3.13
# but now running with Python 3.12
python3.12 mcpyida-headless /path/to/elf
```

**Solution:** Always use the same venv and Python version:

```bash
# Activate the correct venv
source ~/idavenv/bin/activate
# Verify it's the one where you activated idalib
python --version
# Now run the server
mcpyida-headless /path/to/elf
```

### Error: Binary file not found

Ensure the binary path is correct and readable:

```bash
ls -la /path/to/firmware.elf
# Should show the file
```

### Error: Port in use

If the default port 6150 is already in use, specify a different port:

```bash
mcpyida-headless /path/to/firmware.elf --port 6151
```

Or use `--port 0` for automatic port assignment:

```bash
mcpyida-headless /path/to/firmware.elf --port 0
```

The server will print the actual port in the JSON readiness signal.

### IDA Pro plugin fails to load in GUI mode

If the plugin does not load in IDA Pro after running `mcpyida_install`:

1. Verify the plugin was copied to IDA's plugin directory:
   ```bash
   ls ~/.idapro/plugins/mcpyida_proxy.py
   ```

2. **IDA 9.0+:** Ensure you're launching IDA from within the activated venv where `mcpyida` is installed:
   ```bash
   source ~/idavenv/bin/activate
   ida /path/to/binary
   ```

3. **IDA 8.x:** Use `idapyswitch` to bind IDAPython to the Python version where `mcpyida` is installed:
   ```bash
   /path/to/ida-pro-installation/idapyswitch
   # Follow the interactive menu to select your Python version
   # Then verify: python -c "import mcpyida; print('OK')"
   # Then launch IDA: ida /path/to/binary
   ```

4. Check the IDA output window for error messages. IDA loads plugins during startup and may report import errors there.

### IDA Pro installation not found or idalib fails to load

Verify your IDA Pro installation is correct:

```bash
ls -la /path/to/ida-pro-9.2/idalib/
# Should show idalib.so (Linux), idalib.dylib (macOS), or idalib.dll (Windows)
```

If you moved IDA Pro after installation, re-run the activation script:

```bash
python /path/to/ida-pro-9.2/idalib/python/py-activate-idalib.py
```

### Server startup hangs on first run

On the first run after idalib activation, IDA may perform one-time setup operations such as creating analysis directories or initializing the database format. This can take several minutes even for small binaries.

**Solution:** Wait longer, or test with a very small binary first:

```bash
mcpyida-headless /bin/ls
```

Once the first analysis completes, subsequent analyses should be faster.

## Next Steps

Once installation is complete, proceed to [Quickstart Guide](quickstart.md) to run your first MCPyIDA server.
