"""Python function generator and RPC namespace for mcpy/rpcCallbacks.

Implements:
- Exception hierarchy (RPCError, RPCTimeoutError, RPCDisconnectedError)
- CallbackScope: execution-scoped validity token
- RPCNamespace: the 'rpc' object injected into scripting globals
- generate_callback_function: builds a callable from a FunctionDefinition
- is_name_safe: name collision protection against Python builtins/keywords
- map_exception: maps remote exception types to Python exceptions
"""

from __future__ import annotations

import builtins
import keyword
from typing import Any

from mcpyida.rpc_types import FunctionDefinition


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class RPCError(RuntimeError):
    """Base exception for RPC callback failures."""


class RPCTimeoutError(RPCError):
    """RPC callback timed out."""


class RPCDisconnectedError(RPCError):
    """MCP client disconnected during callback."""


# ---------------------------------------------------------------------------
# CallbackScope — execution-scoped validity token
# ---------------------------------------------------------------------------


class CallbackScope:
    """Execution-scoped validity token.

    Each tool execution is assigned one CallbackScope.  Generated callback
    wrappers check this token on every call and raise if it has been
    invalidated (i.e. tool execution has completed).
    """

    def __init__(self) -> None:
        self._valid = True

    def invalidate(self) -> None:
        """Mark the scope as expired.  Called when tool execution ends."""
        self._valid = False

    @property
    def is_valid(self) -> bool:
        return self._valid

    def check(self) -> None:
        """Raise RuntimeError if the scope has been invalidated."""
        if not self._valid:
            raise RuntimeError(
                'Callback expired — function callbacks are only usable during tool execution'
            )


# ---------------------------------------------------------------------------
# Name collision protection
# ---------------------------------------------------------------------------

# Python builtins + keywords that MUST NOT be shadowed by callback functions.
_PYTHON_DENYLIST: set[str] = set(dir(builtins)) | set(keyword.kwlist)
if hasattr(keyword, 'softkwlist'):
    _PYTHON_DENYLIST |= set(keyword.softkwlist)


def is_name_safe(name: str, existing_globals: dict[str, Any] | None = None) -> bool:
    """Return True if *name* is safe to inject as a global callback function.

    A name is unsafe if it:
    - Appears in the Python builtins / keyword denylist, or
    - Already exists in *existing_globals* (e.g. IDA scripting globals).
    """
    if name in _PYTHON_DENYLIST:
        return False
    if existing_globals is not None and name in existing_globals:
        return False
    return True


# ---------------------------------------------------------------------------
# JSON Schema → Python type annotation mapping
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, str] = {
    'string': 'str',
    'integer': 'int',
    'number': 'float',
    'boolean': 'bool',
    'array': 'list',
    'object': 'dict',
    'null': 'None',
}


# ---------------------------------------------------------------------------
# RPCNamespace
# ---------------------------------------------------------------------------


class RPCNamespace:
    """The 'rpc' namespace object injected into scripting globals.

    Provides discovery (available, help), testing (mock, is_available),
    and attribute-based function access (rpc.search_web(...)).
    """

    def __init__(self) -> None:
        self._functions: dict[str, Any] = {}
        self._definitions: dict[str, FunctionDefinition] = {}
        self._mocks: dict[str, Any] = {}
        self._is_available: bool = False

    def available(self) -> list[str]:
        """Return sorted list of available callback function names."""
        return sorted(self._functions.keys())

    def help(self, name: str) -> None:
        """Print function description, parameters, and _rpc_timeout to stdout."""
        defn = self._definitions.get(name)
        if defn is None:
            print(f'Unknown function: {name}')
            return

        print(f'{name}({", ".join(defn.parameterOrder)})')
        if defn.description:
            print(f'  {defn.description}')

        props = defn.inputSchema.get('properties', {})
        required = set(defn.inputSchema.get('required', []))
        for param_name in defn.parameterOrder:
            prop = props.get(param_name, {})
            ptype = prop.get('type', 'any')
            desc = prop.get('description', '')
            default = prop.get('default')
            req_str = (
                '(required)' if param_name in required else f'(default: {default})'
            )
            print(f'  {param_name}: {ptype} {req_str} — {desc}')

        print('  _rpc_timeout: float (default: 30.0) — per-call timeout override')

        if defn.returnDescription:
            print(f'Returns: {defn.returnDescription}')

    def mock(self, name: str, handler: Any) -> None:
        """Register a mock handler that bypasses the real RPC call for *name*."""
        self._mocks[name] = handler

    def is_available(self) -> bool:
        """Return True if RPC callbacks are currently active."""
        return self._is_available

    def __getattr__(self, name: str) -> Any:
        # Guard: do not intercept private/dunder attributes — raise AttributeError
        # so that normal attribute machinery (including pickling, copying, etc.) works.
        if name.startswith('_'):
            raise AttributeError(name)
        if name in self._functions:
            return self._functions[name]
        raise AttributeError(f"No callback function '{name}'")

    def update_functions(
        self,
        functions: dict[str, Any],
        definitions: dict[str, FunctionDefinition],
    ) -> None:
        """Replace the active function set (called after mcpy/listFunctions)."""
        self._functions = functions
        self._definitions = definitions
        self._is_available = True

    def clear(self) -> None:
        """Remove all functions and mark as unavailable."""
        self._functions.clear()
        self._definitions.clear()
        self._is_available = False


# ---------------------------------------------------------------------------
# Docstring builder
# ---------------------------------------------------------------------------


def _build_docstring(defn: FunctionDefinition, default_timeout: float) -> str:
    lines: list[str] = []
    if defn.description:
        lines.append(defn.description)
        lines.append('')

    lines.append('Args:')
    props = defn.inputSchema.get('properties', {})
    required = set(defn.inputSchema.get('required', []))
    for param_name in defn.parameterOrder:
        prop = props.get(param_name, {})
        ptype = _TYPE_MAP.get(prop.get('type', ''), 'Any')
        desc = prop.get('description', '')
        if param_name in required:
            lines.append(f'    {param_name} ({ptype}): {desc}')
        else:
            default = prop.get('default', 'None')
            lines.append(f'    {param_name} ({ptype}, default={default}): {desc}')

    lines.append(
        f'    _rpc_timeout (float, default={default_timeout}): Per-call timeout override'
    )

    if defn.returnDescription:
        lines.append('')
        lines.append(f'Returns: {defn.returnDescription}')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Function generator
# ---------------------------------------------------------------------------


def generate_callback_function(
    defn: FunctionDefinition,
    rpc_caller: Any,
    scope: CallbackScope,
    rpc_namespace: RPCNamespace,
    default_timeout: float = 30.0,
) -> Any:
    """Generate a Python callable from a FunctionDefinition.

    The returned function:
    - Accepts positional and keyword arguments per *defn.parameterOrder*
    - Checks the validity token (raises RuntimeError if scope expired)
    - Honours mock overrides registered via rpc_namespace.mock()
    - Fills optional parameter defaults when callers omit them
    - Accepts a keyword-only _rpc_timeout argument for per-call timeout override
    - Delegates to rpc_caller(name, arguments, timeout) for the actual RPC call

    Args:
        defn: FunctionDefinition describing the remote function.
        rpc_caller: Synchronous callable(name, arguments, timeout) -> Any.
        scope: Validity token for the current tool execution.
        rpc_namespace: The RPCNamespace instance (used for mock look-ups).
        default_timeout: Default per-call timeout in seconds.
    """
    name = defn.name
    props = defn.inputSchema.get('properties', {})
    required = set(defn.inputSchema.get('required', []))

    param_count = len(defn.parameterOrder)

    def callback_fn(
        *args: Any, _rpc_timeout: float = default_timeout, **kwargs: Any
    ) -> Any:
        # Enforce that callers cannot pass more positional args than there are
        # declared parameters, which ensures _rpc_timeout is keyword-only.
        if len(args) > param_count:
            raise TypeError(
                f'{name}() takes {param_count} positional argument(s) but {len(args)} were given'
            )

        scope.check()  # raises RuntimeError if scope is expired

        # Mock override takes priority over the real RPC call.
        if name in rpc_namespace._mocks:
            return rpc_namespace._mocks[name](*args, **kwargs)

        # Build arguments dict from positional args (by order) and keyword args.
        arguments: dict[str, Any] = {}
        for i, param_name in enumerate(defn.parameterOrder):
            if i < len(args):
                arguments[param_name] = args[i]
        arguments.update(kwargs)

        # Fill defaults for missing optional parameters.
        for param_name in defn.parameterOrder:
            if param_name not in arguments and param_name not in required:
                default = props.get(param_name, {}).get('default')
                if default is not None:
                    arguments[param_name] = default

        return rpc_caller(name, arguments, _rpc_timeout)

    callback_fn.__name__ = name
    callback_fn.__qualname__ = name
    callback_fn.__doc__ = _build_docstring(defn, default_timeout)

    return callback_fn


# ---------------------------------------------------------------------------
# Exception mapping
# ---------------------------------------------------------------------------

_EXCEPTION_MAP: dict[str, type[Exception]] = {
    'TypeError': TypeError,
    'ValueError': ValueError,
    'KeyError': KeyError,
    'FileNotFoundError': FileNotFoundError,
    'PermissionError': PermissionError,
    'RecursionError': RecursionError,
    'NameError': NameError,
}


def map_exception(exc_type: str, message: str, tb: str | None = None) -> Exception:
    """Map a remote exception type string to a Python exception instance.

    The remote traceback (if provided) is attached as *__cause__* so that the
    full remote error chain is visible in local tracebacks.

    Args:
        exc_type: Remote exception class name (e.g. 'ValueError').
        message: Human-readable error message.
        tb: Optional remote traceback string.

    Returns:
        A Python exception instance of the most appropriate type.
    """
    exc_class = _EXCEPTION_MAP.get(exc_type, RuntimeError)
    exc = exc_class(message)
    if tb:
        remote = RuntimeError(f'Remote traceback:\n{tb}')
        exc.__cause__ = remote
    return exc
