"""Script execution tool — idapython.

Executes Python code using the same environment as IDA's embedded
Python console. The execution context inherits from __main__.__dict__
which IDA populates with idc, idaapi, idautils, and convenience
functions like here(), ScreenEA(), etc.

Variables persist between calls for the lifetime of the MCP server.
Use reset=True to clear state and start fresh from __main__.__dict__.
"""

from __future__ import annotations

import ast
import io
import sys
import threading
import traceback
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncio
    from mcpyida.rpc_callbacks import RPCNamespace

from mcpyida.mcpserver import run_on_ida_main_async
from mcpyida.models import ScriptResult


_script_lock = threading.Lock()
_persistent_globals: dict | None = None

# ---------------------------------------------------------------------------
# REPL faux-namespace imports
# ---------------------------------------------------------------------------
#
# Inside an idapython script, agents naturally write `import mcp`,
# `import mcp.ghidra1 as g`, `from mcp.ghidra1 import tool` for the projected
# namespaces. Import resolves through __builtins__.__import__, not the script
# globals, so we install a script-scoped __import__ (in _add_extras) that
# resolves faux namespace roots against the injected tree and defers everything
# else (os, json, ida_*) to the real importer. It's gated to script execution
# by _active_import_roots and is never process-wide.

import builtins as _builtins  # noqa: E402

from mcpyida.rpc_callbacks import ToolNamespace  # noqa: E402

_real_import = _builtins.__import__
_active_import_roots: 'dict[str, Any] | None' = None


def _repl_import(
    name: str,
    globals: 'dict | None' = None,
    locals: 'dict | None' = None,
    fromlist: tuple = (),
    level: int = 0,
) -> Any:
    """Script-scoped ``__import__`` that makes faux namespaces importable.

    ``import mcp``, ``import mcp.ghidra1 as g`` and ``from mcp.ghidra1 import
    tool`` (and the same for any other projected top-level namespace) resolve
    against the injected namespace tree. Everything else defers to the real
    importer. Active only while a script runs (``_active_import_roots`` set);
    relative imports (level>0) always defer.

    Real-module shadowing is prevented upstream — server._build_rpc_globals
    escapes any projected top-level that names an importable module (e.g.
    ``os__foo`` → ``_os.foo``), so a real module name never appears here.
    """
    roots = _active_import_roots
    if roots is not None and level == 0:
        top = name.split('.', 1)[0]
        node = roots.get(top)
        if isinstance(node, ToolNamespace):
            ok = True
            for part in name.split('.')[1:]:
                try:
                    node = getattr(node, part)
                except AttributeError:
                    ok = False
                    break
            if ok:
                # `from a.b import x` -> deepest node; `import a.b` -> top (a).
                return node if fromlist else roots[top]
    return _real_import(name, globals, locals, fromlist, level)


async def idapython_eval(
    code: str,
    reset: bool = False,
    rpc_namespace: 'RPCNamespace | None' = None,
    session: Any = None,
    event_loop: 'asyncio.AbstractEventLoop | None' = None,
) -> ScriptResult:
    """Execute Python code in IDA's embedded Python environment.

    The execution context is identical to IDA's Python console:
    - idc, idaapi, idautils pre-loaded
    - All ida_* modules accessible
    - Convenience functions: here(), ScreenEA(), etc.
    - Full access to the IDA Python API

    Variables persist between calls for the MCP server lifetime.
    Use reset=True to clear state before executing code.

    If rpc_namespace is provided (and the client declared mcpy/rpcCallbacks),
    callback functions are injected into the script globals for this execution
    and the callback scope is invalidated when execution completes.

    Returns ScriptResult with result, stdout, stderr, interleaved output.
    Jupyter-style: the last expression value is returned as 'result'.
    """
    return await run_on_ida_main_async(
        _idapython_eval_sync, code, reset, rpc_namespace, session, event_loop
    )


def _idapython_eval_sync(
    code: str,
    reset: bool = False,
    rpc_namespace: 'RPCNamespace | None' = None,
    session: Any = None,
    event_loop: 'asyncio.AbstractEventLoop | None' = None,
) -> ScriptResult:
    """Sync implementation — runs on IDA main thread."""
    global _persistent_globals, _active_import_roots

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    shared_buf = io.StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = _TeeStream(stdout_buf, shared_buf)  # type: ignore[assignment]
        sys.stderr = _TeeStream(stderr_buf, shared_buf)  # type: ignore[assignment]

        # idapython is single-flight: one script at a time against the shared
        # persistent namespace. Acquire WITHOUT blocking so a re-entrant
        # invocation — a script that called a client tool (mcp.<server>.*) that
        # calls back into idapython — fails fast with a clear error instead of
        # blocking on the lock until the reverse-RPC callback times out (~30s)
        # and wedging idapython for that window. An overlapping concurrent call
        # likewise gets a retryable error rather than racing on shared state.
        if not _script_lock.acquire(blocking=False):
            return ScriptResult(
                result=None,
                stdout=stdout_buf.getvalue(),
                stderr=stderr_buf.getvalue(),
                output=shared_buf.getvalue(),
                success=False,
                error=(
                    'idapython is already executing and cannot be invoked '
                    're-entrantly or concurrently: the scripting session has a '
                    'single shared persistent namespace and runs one script at '
                    'a time. This typically happens when a script calls a client '
                    'tool (mcp.<server>.*) that calls back into idapython. Retry '
                    'after the current execution completes.'
                ),
            )
        try:
            if reset or _persistent_globals is None:
                import __main__

                _persistent_globals = dict(__main__.__dict__)
                _add_extras(_persistent_globals)

            # Always project this server's own tools as mcp.self.* (in-process).
            # Reverse-RPC callbacks (mcp.<other>.*) merge into the same mcp root
            # when the client supports mcpy/rpcCallbacks.
            from mcpyida.server import _build_self_globals, _build_rpc_globals

            scope = None
            injected_globals: dict[str, Any] = _build_self_globals()
            if rpc_namespace is not None and rpc_namespace.is_available():
                from mcpyida.rpc_callbacks import CallbackScope

                scope = CallbackScope()
                _build_rpc_globals(
                    rpc_namespace,
                    session,
                    scope,
                    _persistent_globals,
                    event_loop,
                    roots=injected_globals,
                )
            _persistent_globals.update(injected_globals)

            # Mark script execution active for snapshot isolation.
            import mcpyida.server as _srv

            _srv._script_executing = True

            # Activate REPL faux-namespace import resolution for this execution.
            _active_import_roots = injected_globals

            try:
                if not code.strip():
                    # Reset-only or empty code — no execution needed
                    return ScriptResult(
                        success=True,
                        result='Session reset' if reset else None,
                        stdout=stdout_buf.getvalue(),
                        stderr=stderr_buf.getvalue(),
                        output=shared_buf.getvalue(),
                    )

                result_value = None

                # AST-based Jupyter-style eval using persistent globals
                try:
                    tree = ast.parse(code)
                except SyntaxError:
                    exec(code, _persistent_globals)
                    result_value = _extract_result(_persistent_globals)
                else:
                    result_value = _eval_ast(tree, code, _persistent_globals)

                return ScriptResult(
                    result=str(result_value) if result_value is not None else None,
                    stdout=stdout_buf.getvalue(),
                    stderr=stderr_buf.getvalue(),
                    output=shared_buf.getvalue(),
                    success=True,
                )

            finally:
                # Deactivate faux-namespace import resolution.
                _active_import_roots = None
                # Clear execution flag and apply any deferred function-list update.
                _srv._script_executing = False
                if _srv._rpc_update_deferred:
                    _srv._rpc_update_deferred = False
                    _srv._rpc_functions_discovered = False

                # Always invalidate the callback scope after execution completes,
                # and remove all injected globals (mcp.self.* and reverse-RPC) to
                # prevent stale references.
                if scope is not None:
                    scope.invalidate()
                for key in injected_globals:
                    _persistent_globals.pop(key, None)
        finally:
            _script_lock.release()

    except Exception as e:
        return ScriptResult(
            result=None,
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            output=shared_buf.getvalue(),
            success=False,
            error=str(e),
            error_traceback=traceback.format_exc(),
        )
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


class _TeeStream:
    """Writes to both a target buffer and a shared interleaved buffer."""

    def __init__(self, target: io.StringIO, shared: io.StringIO) -> None:
        self._target = target
        self._shared = shared

    def write(self, s: str) -> int:
        self._target.write(s)
        self._shared.write(s)
        return len(s)

    def flush(self) -> None:
        self._target.flush()
        self._shared.flush()


def _add_extras(g: dict) -> None:
    """Add extra modules to globals that may not be in __main__."""
    # Install a script-scoped __builtins__ whose __import__ resolves faux
    # namespaces (mcp.*, etc.) — see _repl_import. A copy of the real builtins
    # with only __import__ overridden; gated to script execution by
    # _active_import_roots, so it behaves as the real importer otherwise.
    script_builtins = dict(vars(_builtins))
    script_builtins['__import__'] = _repl_import
    g['__builtins__'] = script_builtins

    # Lazy-import additional ida_* modules that may not be in __main__
    def _lazy(module_name: str) -> object:
        try:
            return __import__(module_name)
        except Exception:
            return None

    for mod in [
        'ida_allins',
        'ida_auto',
        'ida_bytes',
        'ida_dirtree',
        'ida_diskio',
        'ida_entry',
        'ida_enum',
        'ida_fixup',
        'ida_frame',
        'ida_funcs',
        'ida_gdl',
        'ida_graph',
        'ida_hexrays',
        'ida_ida',
        'ida_idp',
        'ida_kernwin',
        'ida_lines',
        'ida_loader',
        'ida_moves',
        'ida_nalt',
        'ida_name',
        'ida_netnode',
        'ida_offset',
        'ida_pro',
        'ida_problems',
        'ida_range',
        'ida_search',
        'ida_segment',
        'ida_segregs',
        'ida_srclang',
        'ida_strlist',
        'ida_struct',
        'ida_tryblks',
        'ida_typeinf',
        'ida_ua',
        'ida_xref',
    ]:
        if mod not in g:
            val = _lazy(mod)
            if val is not None:
                g[mod] = val

    # Also ensure core modules are present even if __main__ is sparse
    for mod in ['idaapi', 'idc', 'idautils']:
        if mod not in g:
            val = _lazy(mod)
            if val is not None:
                g[mod] = val

    # Add our helper
    try:
        from mcpyida.ida_helpers import IdaFunction

        g.setdefault('IdaFunction', IdaFunction)
    except Exception:
        pass


def _eval_ast(tree: ast.Module, code: str, exec_globals: dict) -> object:
    """Jupyter-style AST evaluation.

    Uses exec_globals as both globals AND locals so that variables
    assigned by exec'd code are visible to subsequent statements.
    """
    if not tree.body:
        return None

    if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
        return eval(code, exec_globals)

    if isinstance(tree.body[-1], ast.Expr):
        if len(tree.body) > 1:
            exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
            exec(compile(exec_tree, '<idapython>', 'exec'), exec_globals)
        eval_tree = ast.Expression(body=tree.body[-1].value)
        return eval(compile(eval_tree, '<idapython>', 'eval'), exec_globals)

    before_keys = set(exec_globals.keys())
    exec(code, exec_globals)
    new_keys = [k for k in exec_globals if k not in before_keys]
    if 'result' in new_keys:
        return exec_globals['result']
    if new_keys:
        return exec_globals[new_keys[-1]]
    return None


def _extract_result(exec_locals: dict) -> object:
    """Extract result from executed locals."""
    if 'result' in exec_locals:
        return exec_locals['result']
    if exec_locals:
        last_key = list(exec_locals.keys())[-1]
        return exec_locals[last_key]
    return None
