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
    global _persistent_globals

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    shared_buf = io.StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = _TeeStream(stdout_buf, shared_buf)  # type: ignore[assignment]
        sys.stderr = _TeeStream(stderr_buf, shared_buf)  # type: ignore[assignment]

        with _script_lock:
            if reset or _persistent_globals is None:
                import __main__

                _persistent_globals = dict(__main__.__dict__)
                _add_extras(_persistent_globals)

            # Inject RPC callback globals for this execution.
            scope = None
            rpc_globals: dict[str, Any] = {}
            if rpc_namespace is not None and rpc_namespace.is_available():
                from mcpyida.server import _build_rpc_globals
                from mcpyida.rpc_callbacks import CallbackScope

                scope = CallbackScope()
                rpc_globals = _build_rpc_globals(
                    rpc_namespace, session, scope, _persistent_globals, event_loop
                )
                _persistent_globals.update(rpc_globals)

            # Mark script execution active for snapshot isolation.
            import mcpyida.server as _srv

            _srv._script_executing = True

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
                # Clear execution flag and apply any deferred function-list update.
                _srv._script_executing = False
                if _srv._rpc_update_deferred:
                    _srv._rpc_update_deferred = False
                    _srv._rpc_functions_discovered = False

                # Always invalidate the callback scope after execution completes,
                # and remove all injected RPC globals to prevent stale references.
                if scope is not None:
                    scope.invalidate()
                for key in rpc_globals:
                    _persistent_globals.pop(key, None)

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
    # Ensure builtins are available
    g.setdefault('__builtins__', __builtins__)

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
