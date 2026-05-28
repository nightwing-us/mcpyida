"""Analysis tools: decompile, disasm, symbols, xrefs.

These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.

IDA-specific: all functions call ida_* APIs directly (global state).
No backend parameter — IDA state is implicit.

Tool merges implemented here:
- disasm: merges disassemble_function + disassemble_addr
- xrefs:  merges find_xrefs_to_addr + find_xrefs_from_addr + find_xrefs_to_func
"""

from __future__ import annotations

from typing import (
    Any,
    Dict,
    Tuple,
)

from mcp.server.fastmcp.exceptions import ToolError

from mcpyida.mcpserver import (
    run_on_ida_main_async,
)
from mcpyida.models import (
    ListResult,
    SymbolInfo,
)
from mcpyida.tools.core import (
    _get_func_ea,
    _get_function,
    _tool_result_list_formatter,
)


# ---------------------------------------------------------------------------
# xref type mapping
# ---------------------------------------------------------------------------


def _get_xref_types() -> dict[int, str]:
    import ida_xref

    return {
        ida_xref.fl_U: 'Data_Unknown',
        ida_xref.dr_O: 'Data_Offset',
        ida_xref.dr_W: 'Data_Write',
        ida_xref.dr_R: 'Data_Read',
        ida_xref.dr_T: 'Data_Text',
        ida_xref.dr_I: 'Data_Informational',
        ida_xref.fl_CF: 'Code_Far_Call',
        ida_xref.fl_CN: 'Code_Near_Call',
        ida_xref.fl_JF: 'Code_Far_Jump',
        ida_xref.fl_JN: 'Code_Near_Jump',
        20: 'Code_User',
        ida_xref.fl_F: 'Ordinary_Flow',
    }


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------


async def decompile(items: list[dict]) -> list[dict]:
    """Decompile function(s). Each item: {addr?, name?}.

    Returns C pseudocode WITH function comment prepended as a block comment.

    Each item in ``items`` is a dict with optional keys:
    - addr: hex address string (e.g. '0x401000' or '401000')
    - name: function name string

    RETURNS: list of dicts, each with:
    - code: decompiled C pseudocode (on success), including comment block
    - name: resolved function name
    - entrypoint: function entry point (hex)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        addr = item.get('addr', '') or ''
        name = item.get('name', '') or ''
        try:
            result = await run_on_ida_main_async(_decompile_one_sync, addr, name)
            results.append(result)
        except Exception as e:
            results.append({'addr': addr, 'name': name, 'error': str(e)})
    return results


def _decompile_one_sync(addr: str, name: str) -> dict:
    """Decompile a single function (must run in IDA main thread)."""
    func = _get_function(addr=addr, name=name)
    comment = func.comment
    code = func.pseudocode
    if comment:
        code = f'/* {comment} */\n{code}'
    return {
        'name': func.demangled_name,
        'entrypoint': f'{func.addr:#x}',
        'code': code,
        'error': None,
    }


# ---------------------------------------------------------------------------
# disasm helpers
# ---------------------------------------------------------------------------


def _disasm_function_by_ea_sync(ea: int) -> Tuple[str, str, str]:
    """Disassemble an entire function by entry address.

    Returns (name, entrypoint_hex, asm_text).
    """
    from mcpyida.ida_helpers import IdaFunction

    func = IdaFunction(ea)
    return func.demangled_name, f'{func.addr:#x}', func.disasm


def _disasm_addr_instructions_sync(addr_str: str, count: int) -> str:
    """Disassemble count instructions from addr_str."""
    import idc
    import idaapi
    import ida_bytes
    import ida_ua
    import ida_lines

    try:
        ea = int(addr_str, 16)
    except ValueError:
        raise ToolError(f'Invalid address format: {addr_str}')

    seg = idaapi.getseg(ea)
    seg_end = seg.end_ea if seg else idc.BADADDR

    disasm_lines: list[str] = []
    for _ in range(count):
        if ea == idc.BADADDR or ea >= seg_end or not ida_bytes.is_mapped(ea):
            disasm_lines.append(
                f'{ea:#x}: Out of mapped memory or reached segment end.'
            )
            break

        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_code(flags):
            disasm_lines.append(f'{ea:#x}: not recognized as code.')
            break

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0 or insn.size <= 0:
            disasm_lines.append(f'{ea:#x}: Failed to decode instruction at {ea:#x}')
            break

        line = ida_lines.generate_disasm_line(
            ea, ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS
        )
        if not line:
            disasm_lines.append(f'{ea:#x}: Could not generate disassembly')
            break

        disasm_lines.append(f'{ea:#x}: {line}')
        ea += insn.size

    return '\n'.join(disasm_lines)


def _get_func_containing_addr_sync(addr_str: str) -> Tuple[bool, int, str, str]:
    """Check if addr is inside a function.

    Returns (found, func_ea, func_name, func_disasm).
    """
    import idaapi
    from mcpyida.ida_helpers import IdaFunction

    try:
        ea = int(addr_str, 16)
    except ValueError:
        raise ToolError(f'Invalid address format: {addr_str}')

    func = idaapi.get_func(ea)
    if func is not None:
        ida_func = IdaFunction(func.start_ea)
        return True, func.start_ea, ida_func.demangled_name, ida_func.disasm
    return False, 0, '', ''


# ---------------------------------------------------------------------------
# disasm (merged)
# ---------------------------------------------------------------------------


async def disasm(items: list[dict]) -> list[dict]:
    """Disassemble function(s) or address ranges. MERGED from disassemble_function + disassemble_addr.

    Each item in ``items`` is a dict with optional keys:
    - addr: hex address string (e.g. '0x401000' or '401000')
    - name: function name string
    - count: number of instructions (int, optional)

    Mode detection per item:
    - count is set (not None) -> address mode: disassemble count instructions from addr
    - name provided -> function mode: disassemble the named function
    - addr inside a function, no count -> function mode: disassemble containing function
    - addr not in a function, no count -> address mode with default 20 instructions

    RETURNS: list of dicts, each with:
    - asm: disassembly text (on success)
    - addr: resolved address
    - name: function name (if function mode)
    - mode: 'function' or 'address'
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        addr = item.get('addr', '') or ''
        name = item.get('name', '') or ''
        count = item.get('count', None)

        try:
            if count is not None:
                # Address mode: N instructions from addr
                if not addr:
                    raise ToolError('addr is required when count is specified')
                # Normalize addr to have 0x prefix for _disasm_addr_instructions_sync
                norm_addr = (
                    addr
                    if addr.startswith('0x') or addr.startswith('0X')
                    else f'0x{addr}'
                )
                asm_text = await run_on_ida_main_async(
                    _disasm_addr_instructions_sync, norm_addr, count
                )
                results.append({
                    'addr': addr,
                    'mode': 'address',
                    'count': count,
                    'asm': asm_text,
                    'error': None,
                })
            elif name:
                # Function mode by name
                func_ea = _get_func_ea(name=name)
                func_name, entrypoint, asm_text = await run_on_ida_main_async(
                    _disasm_function_by_ea_sync, func_ea
                )
                results.append({
                    'addr': entrypoint,
                    'name': func_name,
                    'mode': 'function',
                    'asm': asm_text,
                    'error': None,
                })
            elif addr:
                # Try function mode first, fallback to address mode
                norm_addr = (
                    addr
                    if addr.startswith('0x') or addr.startswith('0X')
                    else f'0x{addr}'
                )
                found, func_ea, func_name, asm_text = await run_on_ida_main_async(
                    _get_func_containing_addr_sync, norm_addr
                )
                if found:
                    results.append({
                        'addr': f'{func_ea:#x}',
                        'name': func_name,
                        'mode': 'function',
                        'asm': asm_text,
                        'error': None,
                    })
                else:
                    # Fallback: disassemble 20 instructions
                    asm_text = await run_on_ida_main_async(
                        _disasm_addr_instructions_sync, norm_addr, 20
                    )
                    results.append({
                        'addr': addr,
                        'mode': 'address',
                        'count': 20,
                        'asm': asm_text,
                        'error': None,
                    })
            else:
                raise ToolError('Either addr or name must be provided')
        except Exception as e:
            results.append({'addr': addr, 'name': name, 'error': str(e)})
    return results


# ---------------------------------------------------------------------------
# symbols
# ---------------------------------------------------------------------------


def _classify_symbol_at_addr_sync(addr_str: str) -> SymbolInfo:
    """Return SymbolInfo for the primary symbol at addr_str."""
    import idc
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment

    try:
        ea = int(addr_str, 16)
    except ValueError:
        raise ToolError(f'Failed to parse address: {addr_str}')

    if ea == idc.BADADDR:
        raise ToolError(f'Failed to parse address: {addr_str}')
    if not ida_bytes.is_loaded(ea):
        raise ToolError(f'Address is not loaded: {ea:#x}')

    name = ida_name.get_ea_name(ea)
    if not name:
        raise ToolError(f'No symbol at addr: {ea:#x}')

    ret_val = SymbolInfo(name=name, symbol_type='unknown')
    f = ida_funcs.get_func(ea)
    if f and f.start_ea == ea:
        ret_val.symbol_type = 'function'
        return ret_val

    seg = ida_segment.getseg(ea)
    if not seg:
        return ret_val

    seg_type = ida_segment.get_segm_class(seg)
    if seg_type and seg_type.lower().startswith('data'):
        ret_val.symbol_type = 'data_label'
        return ret_val

    if ida_bytes.is_code(ida_bytes.get_flags(ea)):
        ret_val.symbol_type = 'code_label'
        return ret_val

    if ida_bytes.is_data(ida_bytes.get_flags(ea)):
        ret_val.symbol_type = 'global_variable'
        return ret_val

    return ret_val


async def symbols(items: list[str]) -> list[dict]:
    """Get symbol info for address(es). Batch: accepts list of hex addresses.

    Each entry in ``items`` is a hex address string (e.g. '0x401000' or '401000').

    RETURNS: list of dicts, each with:
    - addr: input address
    - name: symbol name (on success)
    - symbol_type: one of function, code_label, global_variable, data_label, unknown (on success)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for addr in items:
        try:
            norm_addr = (
                addr if addr.startswith('0x') or addr.startswith('0X') else f'0x{addr}'
            )
            info = await run_on_ida_main_async(_classify_symbol_at_addr_sync, norm_addr)
            results.append({
                'addr': addr,
                'name': info.name,
                'symbol_type': info.symbol_type,
                'error': None,
            })
        except Exception as e:
            results.append({'addr': addr, 'error': str(e)})
    return results


# ---------------------------------------------------------------------------
# xrefs helpers
# ---------------------------------------------------------------------------


def _xrefs_to_addr_sync(
    ea: int,
    offset: int = 0,
    limit: int = 500,
) -> ListResult:
    """Find all references TO ea."""
    import idautils
    from mcpyida.ida_helpers import IdaFunction

    xref_types = _get_xref_types()
    xref_iter = idautils.XrefsTo(ea, 0)

    def process_xref(xref: Any) -> Dict[str, Any]:
        from_ea = xref.frm
        from_info: Dict[str, Any] = {'addr': f'{from_ea:#x}'}
        try:
            ref_func = IdaFunction(from_ea)
            func_name = (
                ref_func.demangled_name if ref_func.demangled_name else ref_func.name
            )
            from_info['function'] = func_name
        except (ValueError, Exception):
            pass
        return {
            'type': 'Cross-Reference To Address',
            'from': from_info,
            'xref-type': xref_types.get(xref.type, 'Unknown'),
        }

    return _tool_result_list_formatter(
        f'Cross-references to {ea:#x}',
        'cross-reference',
        process_xref,
        xref_iter,
        offset,
        limit,
    )


def _xrefs_from_addr_sync(
    ea: int,
    offset: int = 0,
    limit: int = 500,
) -> ListResult:
    """Find all references FROM ea."""
    import idautils
    from mcpyida.ida_helpers import IdaFunction

    xref_types = _get_xref_types()
    xref_iter = idautils.XrefsFrom(ea, 0)

    def process_xref(xref: Any) -> Dict[str, Any]:
        to_ea = xref.to
        try:
            ref_func = IdaFunction(to_ea)
            func_name = (
                ref_func.demangled_name if ref_func.demangled_name else ref_func.name
            )
            dest_info: Dict[str, Any] = {
                'function': func_name,
                'addr': f'{to_ea:#x}',
            }
        except (ValueError, Exception):
            dest_info = {'addr': f'{to_ea:#x}'}
        return {
            'type': f'Cross-Reference From {ea:#x}',
            'to': dest_info,
            'xref-type': xref_types.get(xref.type, 'Unknown'),
        }

    return _tool_result_list_formatter(
        f'Cross-references from {ea:#x}',
        'cross-reference',
        process_xref,
        xref_iter,
        offset,
        limit,
    )


def _resolve_target_to_ea_sync(target: str) -> int:
    """Resolve a target string (hex addr or function name) to an effective address."""
    if target.startswith('0x') or target.startswith('0X'):
        try:
            return int(target, 16)
        except ValueError:
            raise ToolError(f'Failed to parse address: {target}')
    else:
        # Resolve function name
        ea = _get_func_ea(name=target)
        return ea


# ---------------------------------------------------------------------------
# xrefs (merged)
# ---------------------------------------------------------------------------


async def xrefs(items: list[dict]) -> list[dict]:
    """Cross-references. MERGED from find_xrefs_to_addr + find_xrefs_from_addr + find_xrefs_to_func.

    Each item in ``items`` is a dict with keys:
    - target: hex address string (e.g. '0x401000') OR function name string
      Auto-detection: starts with '0x' -> address, otherwise -> function name resolved to entry point
    - direction: 'to' (default) or 'from'
    - offset: pagination start (default 0)
    - limit: max results per item (default 500)

    RETURNS: list of dicts, each with:
    - target: input target value
    - direction: 'to' or 'from'
    - result: ListResult (on success)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    results: list[dict] = []
    for item in items:
        target: str = item.get('target', '') or ''
        direction: str = item.get('direction', 'to') or 'to'
        item_offset: int = int(item.get('offset', 0) or 0)
        item_limit: int = int(item.get('limit', 500) or 500)

        if item_offset < 0:
            results.append({
                'target': target,
                'direction': direction,
                'error': 'offset must be non-negative',
            })
            continue
        if item_limit <= 0:
            results.append({
                'target': target,
                'direction': direction,
                'error': 'limit must be positive',
            })
            continue

        try:
            ea = await run_on_ida_main_async(_resolve_target_to_ea_sync, target)

            if direction == 'to':
                list_result = await run_on_ida_main_async(
                    _xrefs_to_addr_sync, ea, item_offset, item_limit
                )
            elif direction == 'from':
                list_result = await run_on_ida_main_async(
                    _xrefs_from_addr_sync, ea, item_offset, item_limit
                )
            else:
                raise ToolError(f"direction must be 'to' or 'from', got {direction!r}")

            results.append({
                'target': target,
                'direction': direction,
                'result': list_result,
                'error': None,
            })
        except Exception as e:
            results.append({'target': target, 'direction': direction, 'error': str(e)})
    return results
