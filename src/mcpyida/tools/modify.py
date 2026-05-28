"""Modify tools: rename, update_vars, set_comments, get_comment, set_prototype, patch, transactions.

These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.

IDA-specific: all functions call ida_* APIs directly (global state).
No backend parameter — IDA state is implicit.

Tool merges implemented here:
- rename: single batched rename replacing set_symbol_name
- set_comments: merges set_function_disassembly_comment + set_function_decompiler_comment
               + set_function_comment  (kind param: 'disasm'|'decompiler'|'function'|'both')
- patch: batched version of patch_instruction
"""

from __future__ import annotations

import traceback
from typing import Dict

from mcp.server.fastmcp.exceptions import ToolError

from mcpyida.mcpserver import (
    is_headless,
    run_on_ida_main_async,
)
from mcpyida.tools.core import (
    _get_func_ea,
    _get_function,
)


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------


async def rename(items: list[dict]) -> list[dict]:
    """Rename symbol(s). Each item: {new_name, addr?, name?}. Batched with per-item errors.

    Each item in ``items`` is a dict with:
    - new_name: new symbol name (required)
    - addr: hex address of the symbol (optional)
    - name: current symbol name (optional, alternative to addr)

    Provide EITHER addr OR name per item. If addr has no symbol, creates a new user label.

    RETURNS: list of dicts, each with:
    - addr: resolved hex address
    - old_name: previous symbol name
    - new_name: new name applied
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]

    from mcpyida.server import _ida_batch_state

    batch_state = (
        _ida_batch_state  # reference to the module-level dict (cleared by server.py)
    )

    results: list[dict] = []
    for item in items:
        new_name: str = item.get('new_name', '') or ''
        addr: str = item.get('addr', '') or ''
        name: str = item.get('name', '') or ''
        try:
            result = await run_on_ida_main_async(
                _rename_one_sync,
                new_name=new_name,
                addr=addr,
                name=name,
                batch_state=batch_state,
            )
            results.append(result)
        except Exception as e:
            results.append({
                'addr': addr,
                'name': name,
                'new_name': new_name,
                'error': str(e),
            })
    return results


def _rename_one_sync(new_name: str, addr: str, name: str, batch_state: dict) -> dict:
    """Rename a single symbol (must run in IDA main thread with write lock).

    Checks whether the existing name is a user-set name (via ida_name.is_uname)
    and, if so, asks for confirmation via MCP elicitation before overwriting.
    """
    import idc
    import ida_bytes
    import ida_name

    if not new_name:
        raise ToolError('new_name is required')

    if addr:
        try:
            ea = int(addr, 16)
        except ValueError:
            raise ToolError(f'Invalid address format: {addr}')
    elif name:
        ea = _get_func_ea(name=name)
    else:
        raise ToolError('Provide either addr or name')

    if ea == idc.BADADDR:
        raise ToolError(f'Failed to parse address: {addr}')
    if not ida_bytes.is_loaded(ea):
        raise ToolError(f'Address {ea:#x} not mapped')

    old_name_val = ida_name.get_ea_name(ea) or None

    if name:
        if old_name_val and old_name_val != name:
            raise ToolError(f"mismatch: current_name='{old_name_val}' != name='{name}'")

    # Check if the current name is a user-set name — confirm before overwriting
    if old_name_val and ida_name.is_uname(old_name_val):
        from mcpyida.server import elicit_confirmation_sync

        description = (
            f'Confirm renaming {old_name_val} (USER_DEFINED) at {ea:#x} to {new_name}?'
        )
        if not elicit_confirmation_sync(description, batch_state):
            return {
                'addr': f'{ea:#x}',
                'old_name': old_name_val,
                'new_name': new_name,
                'error': 'skipped: user declined overwrite of user-defined name',
            }

    flags = ida_name.SN_CHECK
    ok = ida_name.set_name(ea, new_name, flags)
    if not ok:
        raise ToolError('Failed (invalid name or name already used?)')

    return {
        'addr': f'{ea:#x}',
        'old_name': old_name_val,
        'new_name': new_name,
        'error': None,
    }


# ---------------------------------------------------------------------------
# update_vars
# ---------------------------------------------------------------------------


async def update_vars(
    function_name: str,
    variables_to_update: Dict[str, Dict[str, str]],
) -> str:
    """Rename/retype variables in a function. Keeps existing dict-of-dicts interface.

    THIS MODIFIES THE IDA DATABASE.

    PARAMETERS:
    - function_name: Name of the function containing the variables
    - variables_to_update: Dict mapping old_name -> {new_name?, new_type?}

    EXAMPLE:
      update_vars(
        function_name="main",
        variables_to_update={
          "v1": {"new_name": "buffer", "new_type": "char*"},
          "a1": {"new_name": "argc"}
        }
      )

    RETURNS: Per-variable status report."""
    if not variables_to_update:
        return 'ERROR: No variables were provided to update'
    return await run_on_ida_main_async(
        _update_vars_impl_sync, function_name, variables_to_update
    )


def _update_vars_impl_sync(
    function_name: str,
    variables_to_update: Dict[str, Dict[str, str]],
) -> str:
    """Implementation of update_vars (must run in IDA main thread with write lock)."""
    func = _get_function(name=function_name)
    aggregate_status: list[str] = []

    for var_name, new_vals in variables_to_update.items():
        new_name = new_vals.get('new_name', None)
        new_type = new_vals.get('new_type', None)

        lvar = func.locals.get(var_name)
        if not lvar:
            aggregate_status.append(
                f'{var_name}: Variable not found in function {function_name!r}.'
            )
            continue

        existing_var = func.locals.get(new_name) if new_name else None
        if lvar and not existing_var:
            try:
                if new_name:
                    lvar.name = new_name
                if new_type:
                    lvar.type = new_type
            except Exception as e:
                tb = traceback.format_exc()
                aggregate_status.append(f'{var_name}: ERROR: {e}\n{tb}')
            else:
                aggregate_status.append(f'{var_name}: Done')
        else:
            aggregate_status.append(f'{var_name}: Variable {new_name} already exists.')

    conclusion_msg = (
        f'Results from updating {len(variables_to_update)} function variables:\n'
    )
    conclusion_msg += '\n'.join(aggregate_status)
    return conclusion_msg


# ---------------------------------------------------------------------------
# Comment helpers
# ---------------------------------------------------------------------------


def _set_eol_comment_sync(addr_str: str, comment: str) -> str:
    """Set an EOL (end-of-line) comment at the given address in the disassembly view."""
    import ida_bytes

    try:
        ea = int(addr_str, 16)
    except ValueError:
        raise ToolError(f'Invalid address format: {addr_str}')

    if ida_bytes.set_cmt(ea, comment, False):
        return f'Set disasm comment at {ea:#x}'
    return f'Failed to set disasm comment at {ea:#x}'


def _set_decompiler_pre_comment_sync(
    line: int,
    comment: str,
    addr: str = '',
    name: str = '',
) -> str:
    """Set a pre-comment at ``line`` in the decompiler view of a function."""
    func = _get_function(addr=addr, name=name)
    if not func:
        return f'No function found for address {addr!r}'
    if commented_line := func.set_pseudocode_comment_line(line, comment):
        return f'Added decompiler comment at line {commented_line}'
    return (
        f'Unable to set comment at line {line}. '
        f'No valid code element found within ±10 lines.'
    )


def _set_function_plate_comment_sync(
    comment: str,
    addr: str = '',
    name: str = '',
) -> str:
    """Set the plate (function-level) comment on a function."""
    func = _get_function(addr=addr, name=name)
    func.comment = comment
    if not is_headless():
        pc_widget = func.get_decompiler_view()
        if pc_widget:
            pc_widget.refresh_view(True)
    return f'Comment updated for function {func.demangled_name} @ {func.addr:#x}'


def _validate_comment_item(kind: str, addr: str, name: str, line: int | None) -> None:
    """Validate required fields for each comment kind. Raises ToolError on violation."""
    if kind == 'disasm':
        if not addr:
            raise ToolError("kind='disasm' requires addr")
    elif kind == 'decompiler':
        if line is None:
            raise ToolError("kind='decompiler' requires line")
        if not addr and not name:
            raise ToolError("kind='decompiler' requires addr or name")
    elif kind == 'function':
        if not addr and not name:
            raise ToolError("kind='function' requires addr or name")
    elif kind == 'both':
        if not addr:
            raise ToolError("kind='both' requires addr")


# ---------------------------------------------------------------------------
# set_comments (MERGED: disasm + decompiler + function)
# ---------------------------------------------------------------------------


async def set_comments(items: list[dict]) -> list[dict]:
    """Set comment(s). MERGED 3->1. Each item: {comment, kind?, addr?, name?, line?}

    kind values and their effect:
    - 'disasm'     -> EOL comment at addr (requires addr)
    - 'decompiler' -> pre-comment at line in function (requires line and addr or name)
    - 'function'   -> plate comment on function (requires addr or name)
    - 'both'       (default) -> disasm comment at addr; ALSO decompiler comment IF line provided

    RETURNS: list of dicts, each with:
    - kind: the effective kind used
    - addr: address string
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        comment: str = item.get('comment', '') or ''
        kind: str = item.get('kind', 'both') or 'both'
        addr: str = item.get('addr', '') or ''
        name: str = item.get('name', '') or ''
        line: int | None = item.get('line', None)

        # Normalize addr to hex format
        if addr and not addr.startswith('0x') and not addr.startswith('0X'):
            addr = f'0x{addr}'

        try:
            _validate_comment_item(kind, addr, name, line)

            if kind == 'disasm':
                msg = await run_on_ida_main_async(_set_eol_comment_sync, addr, comment)
                results.append({
                    'kind': kind,
                    'addr': addr,
                    'message': msg,
                    'error': None,
                })

            elif kind == 'decompiler':
                assert line is not None
                msg = await run_on_ida_main_async(
                    _set_decompiler_pre_comment_sync, line, comment, addr, name
                )
                results.append({
                    'kind': kind,
                    'addr': addr,
                    'name': name,
                    'line': line,
                    'message': msg,
                    'error': None,
                })

            elif kind == 'function':
                msg = await run_on_ida_main_async(
                    _set_function_plate_comment_sync, comment, addr, name
                )
                results.append({
                    'kind': kind,
                    'addr': addr,
                    'name': name,
                    'message': msg,
                    'error': None,
                })

            elif kind == 'both':
                messages: list[str] = []
                msg_disasm = await run_on_ida_main_async(
                    _set_eol_comment_sync, addr, comment
                )
                messages.append(msg_disasm)
                if line is not None:
                    msg_dec = await run_on_ida_main_async(
                        _set_decompiler_pre_comment_sync, line, comment, addr, name
                    )
                    messages.append(msg_dec)
                results.append({
                    'kind': kind,
                    'addr': addr,
                    'name': name,
                    'line': line,
                    'message': '; '.join(messages),
                    'error': None,
                })

            else:
                raise ToolError(
                    f"Invalid kind '{kind}'. Must be one of: disasm, decompiler, function, both"
                )

        except Exception as e:
            results.append({
                'kind': kind,
                'addr': addr,
                'name': name,
                'error': str(e),
            })

    return results


# ---------------------------------------------------------------------------
# get_comment
# ---------------------------------------------------------------------------


async def get_comment(items: list[dict]) -> list[dict]:
    """Get function comment(s). Each item: {addr?, name?}. Batched.

    RETURNS: list of dicts, each with:
    - name: function name
    - addr: function entry point address
    - comment: plate comment text (may be empty string)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        addr: str = item.get('addr', '') or ''
        name: str = item.get('name', '') or ''
        try:
            result = await run_on_ida_main_async(
                _get_comment_one_sync, addr=addr, name=name
            )
            results.append(result)
        except Exception as e:
            results.append({'addr': addr, 'name': name, 'error': str(e)})
    return results


def _get_comment_one_sync(addr: str, name: str) -> dict:
    """Get the plate comment for a function (must run in IDA main thread)."""
    func = _get_function(addr=addr, name=name)
    return {
        'name': func.demangled_name,
        'addr': f'{func.addr:#x}',
        'comment': func.comment or '',
        'error': None,
    }


# ---------------------------------------------------------------------------
# set_prototype
# ---------------------------------------------------------------------------


async def set_prototype(items: list[dict]) -> list[dict]:
    """Set function prototype(s). Each item: {addr, prototype}. Batched.

    THIS MODIFIES THE IDA DATABASE.

    PARAMETERS per item:
    - addr: hex address of function (required)
    - prototype: new signature in C style (e.g., "int main(int argc, char **argv)")

    The old signature is saved in the function comment for reference.

    RETURNS: list of dicts, each with:
    - addr: function address
    - name: function name
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        addr: str = item.get('addr', '') or ''
        prototype: str = item.get('prototype', '') or ''
        try:
            result = await run_on_ida_main_async(
                _set_prototype_one_sync, addr=addr, prototype=prototype
            )
            results.append(result)
        except Exception as e:
            results.append({'addr': addr, 'prototype': prototype, 'error': str(e)})
    return results


def _set_prototype_one_sync(addr: str, prototype: str) -> dict:
    """Apply a prototype to a function (must run in IDA main thread with write lock)."""
    import idc
    import ida_typeinf
    import ida_nalt

    if not addr:
        raise ToolError('addr is required')
    if not prototype:
        raise ToolError('prototype is required')

    func = _get_function(addr=addr)
    orig_sig = idc.get_type(func.addr) or ''
    orig_comment = func.comment or ''
    new_comment = f'{orig_comment}\n\nMCP: Updating signature from:\n  {orig_sig}\nto:\n  {prototype}'
    func.comment = new_comment

    # Parse the declaration and apply it
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    result = ida_typeinf.parse_decl(tif, til, f'{prototype};', 0)
    if result is None or not tif.is_correct():
        raise ToolError(f"Failed to parse prototype: '{prototype}'")

    if not ida_nalt.set_tinfo(func.addr, tif):
        raise ToolError(
            f'Error applying prototype for function {func.demangled_name} @ {func.addr:#x}.'
        )

    return {
        'addr': f'{func.addr:#x}',
        'name': func.demangled_name,
        'error': None,
    }


# ---------------------------------------------------------------------------
# patch
# ---------------------------------------------------------------------------


async def patch(items: list[dict]) -> list[dict]:
    """Patch instruction(s). Each item: {addr, hex_bytes}. Batched.

    THIS MODIFIES THE IDA DATABASE.

    PARAMETERS per item:
    - addr: hex address (e.g., "401000" or "0x401000")
    - hex_bytes: new bytes as hex string (e.g., "90" for NOP, "EB05" for short jump)

    BEHAVIOR: Clears existing code unit, writes bytes, re-disassembles.

    RETURNS: list of dicts, each with:
    - addr: patched address
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        addr: str = item.get('addr', '') or ''
        hex_bytes: str = item.get('hex_bytes', '') or ''
        try:
            result = await run_on_ida_main_async(
                _patch_one_sync, addr=addr, hex_bytes=hex_bytes
            )
            results.append(result)
        except Exception as e:
            results.append({'addr': addr, 'hex_bytes': hex_bytes, 'error': str(e)})
    return results


def _patch_one_sync(addr: str, hex_bytes: str) -> dict:
    """Patch bytes at an address (must run in IDA main thread with write lock)."""
    import ida_bytes
    import idaapi

    if not addr:
        raise ToolError('addr is required')
    if not hex_bytes:
        raise ToolError('hex_bytes is required')

    try:
        ea = int(addr, 16)
    except ValueError:
        raise ToolError(f'Invalid address format: {addr}')

    new_bytes = bytes.fromhex(hex_bytes)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(new_bytes))
    ida_bytes.patch_bytes(ea, new_bytes)
    idaapi.create_insn(ea)

    return {'addr': f'{ea:#x}', 'error': None}


# ---------------------------------------------------------------------------
# begin_trans / end_trans
# ---------------------------------------------------------------------------


def begin_trans(description: str = '') -> str:
    """Start a manual transaction for multiple modifications.

    NOTE: IDA does not use explicit transactions. Modifications are auto-committed.
    This tool exists for API compatibility with Ghidra-based workflows.

    RETURNS: Informative message (IDA auto-commits all changes).

    EXAMPLE:
      begin_trans("Rename related functions")
      rename([...])
      end_trans()"""
    return 'IDA does not use explicit transactions. Modifications are auto-committed.'


def end_trans(transaction_id: int = 0, commit: bool = True) -> str:
    """End a manual transaction started with begin_trans.

    NOTE: IDA does not use explicit transactions. Modifications are auto-committed.
    This tool exists for API compatibility with Ghidra-based workflows.

    PARAMETERS:
    - transaction_id: Ignored (IDA has no transaction IDs)
    - commit: Ignored (IDA auto-commits all changes)

    RETURNS: Informative message."""
    return 'IDA does not use explicit transactions. Modifications are auto-committed.'
