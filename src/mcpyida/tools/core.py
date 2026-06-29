"""Core read-only tools: list_entries, cursor, context, get_funcs.

These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.

IDA-specific: all functions call ida_* APIs directly (global state).
No backend parameter — IDA state is implicit.
"""

from __future__ import annotations

from typing import (
    Annotated,
    Any,
    Callable,
    cast,
    Dict,
    Iterable,
    Tuple,
    TypeVar,
    Union,
)

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import Field

from mcpyida.mcpserver import (
    is_headless,
    run_on_ida_main_async,
    _normalize_format,
    _normalize_processor,
    _Skip,
)
from mcpyida.models import (
    AnalysisState,
    ApplicationInfo,
    ArchitectureInfo,
    BinaryContext,
    CurrentLocation,
    EntryTypes,
    FunctionInfo,
    ListResult,
    MemoryLayout,
    page_limit,
    ProgramInfo,
    ResultPageInfo,
)
from mcpyida.util import paginate_with_total


T = TypeVar('T')


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _smart_split_demangled(name: str) -> list[str]:
    """Split a demangled C++ name on '::' separators, respecting template and paren depth."""
    parts: list[str] = []
    current = ''
    template_depth = 0
    paren_depth = 0
    i = 0
    while i < len(name):
        if name[i] == '<':
            template_depth += 1
        elif name[i] == '>':
            template_depth = max(template_depth - 1, 0)
        elif name[i] == '(':
            paren_depth += 1
        elif name[i] == ')':
            paren_depth = max(paren_depth - 1, 0)
        elif name[i : i + 2] == '::' and template_depth == 0 and paren_depth == 0:
            parts.append(current.strip())
            current = ''
            i += 2
            continue
        current += name[i]
        i += 1
    if current:
        parts.append(current.strip())
    return parts


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_func_ea(
    addr: str | None = '',
    name: str | None = '',
) -> int:
    """Resolve effective address of a function by address string or name.

    Tries hex address first if provided.
    Then tries direct name lookup (mangled or unmangled).
    Falls back to scanning all functions for a demangled match.
    Raises ValueError if resolution fails.
    """
    import idc
    import idautils
    import ida_name

    if addr:
        try:
            return int(addr, 16)
        except ValueError:
            raise ValueError(f'Invalid address format: {addr}')

    if not name:
        raise ValueError('Either addr or name must be provided.')

    ea = idc.get_name_ea_simple(name)
    if ea != idc.BADADDR:
        return ea

    for func_ea in idautils.Functions():
        mangled = ida_name.get_name(func_ea)
        demangled = idc.demangle_name(mangled, idc.DEMNAM_FIRST)
        if demangled and (name in (demangled, demangled.split('(')[0])):
            return func_ea

    raise ValueError(f'Function not found by name: {name}')


def _get_function(
    addr: str | int | None = '',
    name: str | None = '',
) -> 'Any':  # returns IdaFunction
    """Resolve an IdaFunction by address or name."""
    from mcpyida.ida_helpers import IdaFunction

    if not isinstance(addr, int):
        addr = _get_func_ea(addr, name)
    return IdaFunction(addr)


def _tool_result_list_formatter(
    results_heading: str,
    entry_type: EntryTypes,
    entry_proc: Callable[[T], Dict[str, Any]],
    entries: Iterable[T],
    offset: int,
    limit: int = page_limit,
) -> ListResult:
    """Build a paginated ListResult from an iterable of raw IDA objects."""
    from typing import Any as _Any

    results: list[_Any] = []
    entries_page, total, start, stop = paginate_with_total(entries, offset, limit)
    for entry in entries_page:
        try:
            result_entry = entry_proc(entry)
            result_entry['result_index'] = offset + len(results)
            result_entry['page_pos'] = len(results)
            results.append(result_entry)
        except _Skip:
            continue
    if not results:
        if offset > total:
            raise ToolError(
                f'No {results_heading} found because offset ({offset}) exceeds total ({total})'
            )
        return ListResult(
            summary=f'No {results_heading} found starting at position {offset}',
            entry_type=entry_type,
            schema_version=1,
            page_info=ResultPageInfo(
                offset=offset,
                limit=limit,
                num_returned=0,
                total_count=total,
                has_more=False,
                next_offset=None,
            ),
            items=[],
        )
    return ListResult(
        summary=f'{results_heading} {start}-{stop - 1} of {total}',
        entry_type=entry_type,
        schema_version=1,
        page_info=ResultPageInfo(
            offset=start,
            limit=limit,
            num_returned=stop - start,
            total_count=total,
            has_more=stop < total,
            next_offset=stop if (stop < total) else None,
        ),
        items=results,
    )


# ---------------------------------------------------------------------------
# Sub-dispatchers for list_entries (sync, run on IDA main thread)
# ---------------------------------------------------------------------------


def _list_functions_sync(
    offset: int = 0,
    limit: int = page_limit,
    match_filter: str = '',
) -> ListResult:
    import idc
    import idautils
    import ida_funcs
    import ida_nalt
    import ida_typeinf

    def process_func(func_addr: int) -> Dict[str, Any]:
        func_name = idc.get_func_name(func_addr)
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, func_addr):
            sig = ida_typeinf.print_tinfo(
                '',
                0,
                0,
                ida_typeinf.PRTYPE_1LINE,
                tif,
                func_name,
                '',
            )
        else:
            sig = idc.get_type(func_addr)
        return {
            'type': 'function',
            'name': func_name,
            'address': f'{func_addr:#x}',
            'signature': sig,
        }

    match_info = f" matching '{match_filter}'" if match_filter else ''
    return _tool_result_list_formatter(
        f'Functions{match_info}',
        'function',
        process_func,
        filter(
            lambda addr: (
                (match_filter.lower() in ida_funcs.get_func_name(addr).lower())
                if match_filter
                else True
            ),
            idautils.Functions(),
        ),
        offset,
        limit,
    )


def _list_segments_sync(
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    import idaapi

    seg_addrs = [idaapi.getnseg(i).start_ea for i in range(idaapi.get_segm_qty())]

    def process_segment(seg_addr: int) -> Dict[str, Any]:
        seg = idaapi.getseg(seg_addr)
        if seg:
            return {
                'type': 'memory_segment',
                'name': idaapi.get_segm_name(seg),
                'start': f'{seg.start_ea:#x}',
                'end': f'{seg.end_ea:#x}',
            }
        raise _Skip()

    return _tool_result_list_formatter(
        'Memory Segments',
        'memory_segment',
        process_segment,
        seg_addrs,
        offset,
        limit,
    )


def _list_imports_sync(
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    import ida_nalt

    imports: list[Tuple[int, str, int]] = []

    def imp_cb(ea: int, name: str, ordinal: int) -> bool:
        if name:
            imports.append((ea, name, ordinal))
        return True

    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        ida_nalt.enum_import_names(i, imp_cb)

    def process_import(entry: Tuple[int, str, int]) -> Dict[str, Any]:
        ea, name, ordinal = entry
        return {
            'type': 'import',
            'name': name,
            'address': f'{ea:#x}',
            'ordinal': ordinal,
        }

    return _tool_result_list_formatter(
        'Imported symbols',
        'import',
        process_import,
        imports,
        offset,
        limit,
    )


def _list_exports_sync(
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    import ida_entry
    import ida_bytes
    import idaapi

    def _get_symbol_type(ea: int) -> str:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_func(flags):
            return 'FUNCTION'
        elif ida_bytes.is_code(flags):
            return 'CODE'
        elif ida_bytes.is_data(flags):
            return 'GLOBAL_VAR'
        elif idaapi.segtype(ea) == idaapi.SEG_XTRN:
            return 'LIBRARY'
        return 'LABEL'

    exports: list[Tuple[str, str, int]] = []
    for i in range(ida_entry.get_entry_qty()):
        ea = cast(int, ida_entry.get_entry(i))
        name = ida_entry.get_entry_name(ida_entry.get_entry_ordinal(i))
        sym_type = _get_symbol_type(ea)
        exports.append((sym_type, name, ea))

    def process_export(entry: Tuple[str, str, int]) -> Dict[str, Any]:
        sym_type, name, ea = entry
        return {
            'type': 'export',
            'name': name,
            'address': f'{ea:#x}',
            'symbol_type': sym_type,
        }

    return _tool_result_list_formatter(
        'Exported symbols',
        'export',
        process_export,
        exports,
        offset,
        limit,
    )


def _list_strings_sync(
    offset: int = 0,
    limit: int = page_limit,
    match_filter: str = '',
) -> ListResult:
    import idautils
    import ida_strlist

    strings = idautils.Strings()
    matched = [
        s
        for s in strings
        if not match_filter or (match_filter.lower() in str(s).lower())
    ]

    def process_string(s: 'ida_strlist.string_info_t') -> Dict[str, Any]:
        return {
            'type': 'string',
            'value': repr(str(s)),
            'address': f'{s.ea:#x}',
        }

    matching_info = f' matching {repr(match_filter)}' if match_filter else ''
    return _tool_result_list_formatter(
        f'Strings{matching_info}',
        'string',
        process_string,
        matched,
        offset,
        limit,
    )


def _list_classes_sync(
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    import idautils
    import ida_name
    import idc

    class_map: dict[str, int] = {}
    for func_ea in idautils.Functions():
        name = ida_name.get_name(func_ea)
        if not name:
            continue
        demangled = idc.demangle_name(name, idc.DEMNAM_FIRST)
        if not demangled or '::' not in demangled:
            continue
        parts = _smart_split_demangled(demangled)
        if len(parts) < 2:
            continue
        fq_class = '::'.join(parts[:-1])
        if fq_class not in class_map:
            class_map[fq_class] = func_ea

    def process_class(entry: Tuple[str, int]) -> Dict[str, Any]:
        fq_name, ea = entry
        return {
            'type': 'class',
            'name': fq_name,
            'address': f'{ea:#x}',
        }

    return _tool_result_list_formatter(
        'Classes',
        'class',
        process_class,
        sorted(class_map.items()),
        offset,
        limit,
    )


def _list_namespaces_sync(
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    import idautils
    import ida_name
    import idc

    namespace_map: dict[str, int] = {}
    for func_ea in idautils.Functions():
        name = ida_name.get_name(func_ea)
        if not name:
            continue
        demangled = idc.demangle_name(name, idc.DEMNAM_FIRST)
        if not demangled or '::' not in demangled:
            continue
        parts = _smart_split_demangled(demangled)
        if len(parts) >= 3:
            ns_parts = parts[:-2]
        elif len(parts) == 2:
            ns_parts = parts[:-1]
        else:
            continue
        if not ns_parts:
            continue
        fq_ns = '::'.join(ns_parts)
        if fq_ns not in namespace_map:
            namespace_map[fq_ns] = func_ea

    def process_ns(entry: Tuple[str, int]) -> Dict[str, Any]:
        fq_name, ea = entry
        return {
            'type': 'namespace',
            'name': fq_name,
            'address': f'{ea:#x}',
        }

    return _tool_result_list_formatter(
        'Namespaces',
        'namespace',
        process_ns,
        sorted(namespace_map.items()),
        offset,
        limit,
    )


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


async def list_entries(
    entry_type: Annotated[EntryTypes, Field(description='Type of entry to fetch')],
    offset: Annotated[
        Union[str, int, None],
        Field(description='Starting position for pagination (default 0)'),
    ] = 0,
    limit: Annotated[
        int, Field(description='Maximum results to return (default 500)')
    ] = 500,
    match_filter: Annotated[
        Union[str, None],
        Field(
            description='Optionally return only entries containing the filter string in the name'
        ),
    ] = '',
) -> ListResult:
    """Get a paginated list of binary entries by type.

    RETURNS: ListResult with items[], page_info (has_more, next_offset), total_count

    PARAMETERS:
    - entry_type: Type of entry to list
    - offset: Starting position for pagination (default 0)
    - limit: Maximum results to return (default 500)
    - match_filter: Substring filter (only works for function, string, type types)

    VALID entry_type VALUES: function, memory_segment, import, export, string, class, namespace, type

    EXAMPLES:
    - list(entry_type='function') -> first 500 functions
    - list(entry_type='function', limit=50) -> first 50 functions
    - list(entry_type='function', offset=100, limit=50) -> functions 100-149
    - list(entry_type='string', match_filter='error', limit=20) -> first 20 strings containing 'error'
    - list(entry_type='type', match_filter='stream') -> types matching 'stream'"""
    offset = int(offset) if offset else 0
    if offset < 0:
        raise ToolError('offset must be non-negative')
    if limit <= 0:
        raise ToolError('limit must be positive')
    match_filter = match_filter or ''

    if entry_type == 'function':
        return await run_on_ida_main_async(
            _list_functions_sync, offset, limit, match_filter
        )
    elif entry_type == 'memory_segment':
        return await run_on_ida_main_async(_list_segments_sync, offset, limit)
    elif entry_type == 'import':
        return await run_on_ida_main_async(_list_imports_sync, offset, limit)
    elif entry_type == 'export':
        return await run_on_ida_main_async(_list_exports_sync, offset, limit)
    elif entry_type == 'string':
        return await run_on_ida_main_async(
            _list_strings_sync, offset, limit, match_filter
        )
    elif entry_type == 'class':
        return await run_on_ida_main_async(_list_classes_sync, offset, limit)
    elif entry_type == 'namespace':
        return await run_on_ida_main_async(_list_namespaces_sync, offset, limit)
    elif entry_type == 'type':
        from mcpyida.tools.types import _list_types_sync

        return await run_on_ida_main_async(
            _list_types_sync, offset, limit, match_filter
        )
    else:
        raise ToolError(f'Unsupported entry type: {entry_type}')


def _cursor_sync() -> CurrentLocation:
    """Sync implementation of cursor — runs on IDA main thread."""
    import idc
    import ida_kernwin
    import ida_funcs
    import ida_name
    import idaapi

    if is_headless():
        ea = idc.get_inf_attr(idc.INF_START_EA)
        if ea == idc.BADADDR:
            first_func = ida_funcs.get_next_func(0)
            if first_func:
                ea = first_func.start_ea
            else:
                raise ToolError(
                    'No entry point or functions available in headless mode'
                )
    else:
        ea = ida_kernwin.get_screen_ea()
        if ea == idc.BADADDR:
            # Fall back to entry point instead of crashing
            ea = idc.get_inf_attr(idc.INF_START_EA)
            if ea == idc.BADADDR:
                first_func = ida_funcs.get_next_func(0)
                if first_func:
                    ea = first_func.start_ea
                else:
                    raise ToolError(
                        'Current location unknown and no fallback available'
                    )

    cur_loc = CurrentLocation(addr=f'{ea:#x}')
    func = idaapi.get_func(ea)
    if func:
        raw_name = ida_name.get_name(ea)
        demangled_name = idc.demangle_name(
            raw_name, idc.DEMNAM_FIRST
        ) or ida_name.get_name(func.start_ea)
        type_str = idc.get_type(func.start_ea)
        cur_loc.function = FunctionInfo(
            name=demangled_name,
            entrypoint=f'{func.start_ea:#x}',
            signature=type_str or None,
        )
    return cur_loc


async def cursor() -> CurrentLocation:
    """Get the address and function info at the user's current cursor position in IDA.

    RETURNS: CurrentLocation with:
    - addr: Current hex address (e.g., "0x401000")
    - function: FunctionInfo if cursor is inside a function (name, entrypoint, signature), or null

    USE CASE: Find where the user is looking before taking contextual actions."""
    return await run_on_ida_main_async(_cursor_sync)


def _context_sync() -> BinaryContext:
    """Sync implementation of context — runs on IDA main thread."""
    import os
    import idc
    import idaapi
    import ida_funcs
    import ida_ida
    import ida_loader
    import ida_nalt
    import ida_name
    import ida_typeinf
    import idautils

    # Get current location — don't let a failure here crash the entire context
    try:
        current_location = _cursor_sync()
    except Exception:
        # Fallback: return a minimal location with no function info
        current_location = CurrentLocation(addr='0x0')

    # Program info
    try:
        file_path = ida_nalt.get_input_file_path()
    except Exception:
        file_path = None

    try:
        file_name = ida_nalt.get_root_filename()
    except Exception:
        file_name = 'unknown'

    try:
        file_format_raw = ida_loader.get_file_type_name()
        file_format = _normalize_format(file_format_raw)
    except Exception:
        file_format = 'unknown'

    file_size = None
    if file_path:
        try:
            file_size = os.path.getsize(file_path)
        except Exception:
            pass

    md5_hash = None
    try:
        md5_bytes = ida_nalt.retrieve_input_file_md5()
        if md5_bytes:
            md5_hash = md5_bytes.hex()
    except Exception:
        pass

    program = ProgramInfo(
        file_path=file_path,
        file_name=file_name,
        file_format=file_format,
        file_size=file_size,
        md5=md5_hash,
    )

    # Architecture info
    try:
        inf = idaapi.get_inf_structure()
        proc_name_raw = inf.procname if hasattr(inf, 'procname') else 'unknown'
        processor = _normalize_processor(proc_name_raw)
    except Exception:
        processor = 'unknown'

    try:
        inf = idaapi.get_inf_structure()
        if hasattr(inf, 'is_64bit') and inf.is_64bit():
            bitness = 64
        elif hasattr(inf, 'is_32bit') and inf.is_32bit():
            bitness = 32
        else:
            bitness = 64 if idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF else 32
    except Exception:
        bitness = 32

    try:
        inf = idaapi.get_inf_structure()
        is_be = inf.is_be() if hasattr(inf, 'is_be') else False
        endianness = 'big' if is_be else 'little'
    except Exception:
        endianness = 'little'

    compiler = None
    try:
        inf = idaapi.get_inf_structure()
        if hasattr(inf, 'cc') and hasattr(inf.cc, 'id'):
            comp_map = {
                0: 'Unknown',
                1: 'MS Visual C++',
                2: 'Borland C++',
                3: 'Watcom C++',
                4: 'GNU C++',
                5: 'Visual Age C++',
                6: 'Delphi',
            }
            compiler = comp_map.get(inf.cc.id)
    except Exception:
        pass

    architecture = ArchitectureInfo(
        processor=processor,
        bitness=bitness,
        endianness=endianness,
        compiler=compiler,
    )

    # Memory layout
    try:
        image_base = idaapi.get_imagebase()
        image_base_str = f'{image_base:#x}'
    except Exception:
        image_base_str = '0x0'

    try:
        entry_point = idc.get_inf_attr(idc.INF_START_EA)
        entry_point_str = f'{entry_point:#x}'
    except Exception:
        entry_point_str = '0x0'

    try:
        min_ea = ida_ida.inf_get_min_ea()
        min_address = f'{min_ea:#x}'
    except Exception:
        try:
            min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
            min_address = f'{min_ea:#x}'
        except Exception:
            min_address = '0x0'

    try:
        max_ea = ida_ida.inf_get_max_ea()
        max_address = f'{max_ea:#x}'
    except Exception:
        try:
            max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
            max_address = f'{max_ea:#x}'
        except Exception:
            max_address = '0x0'

    memory = MemoryLayout(
        image_base=image_base_str,
        entry_point=entry_point_str,
        min_address=min_address,
        max_address=max_address,
    )

    # Analysis state
    try:
        database_path = idc.get_idb_path()
    except Exception:
        database_path = 'unknown'

    try:
        function_count = ida_funcs.get_func_qty()
    except Exception:
        function_count = 0

    has_debug_symbols = False
    try:
        named_count = 0
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                for ea in range(seg.start_ea, seg.end_ea):
                    name = ida_name.get_name(ea)
                    if (
                        name
                        and not name.startswith('sub_')
                        and not name.startswith('loc_')
                    ):
                        named_count += 1
                        if named_count > 100:
                            has_debug_symbols = True
                            break
            if has_debug_symbols:
                break
    except Exception:
        pass

    has_type_libraries = False
    try:
        ti = ida_typeinf.get_idati()
        if ti:
            has_type_libraries = True
    except Exception:
        pass

    analysis_complete = None
    try:
        analysis_complete = idaapi.auto_is_ok()
    except Exception:
        pass

    analysis = AnalysisState(
        database_path=database_path,
        function_count=function_count,
        has_debug_symbols=has_debug_symbols,
        has_type_libraries=has_type_libraries,
        analysis_complete=analysis_complete,
    )

    # Application info
    try:
        app_version = idaapi.get_kernel_version()
    except Exception:
        app_version = 'unknown'

    application = ApplicationInfo(name='IDA Pro', version=app_version)

    return BinaryContext(
        current_location=current_location,
        program=program,
        architecture=architecture,
        memory=memory,
        analysis=analysis,
        application=application,
    )


async def context() -> BinaryContext:
    """Get comprehensive context about the currently open binary.

    RETURNS: BinaryContext with complete information about:
    - current_location: Cursor position and current function
    - program: Binary file details (path, format, size, hash)
    - architecture: Processor, bitness, endianness
    - memory: Address space layout (base, entry point, min/max)
    - analysis: Database path, function count, symbols, analysis state
    - application: RE application name and version"""
    return await run_on_ida_main_async(_context_sync)


def _get_funcs_sync(items: list[str]) -> list[dict]:
    """Sync implementation of get_funcs — runs on IDA main thread."""
    results: list[dict] = []
    for target in items:
        try:
            stripped = target.strip()
            is_addr = (
                stripped.startswith('0x')
                or stripped.startswith('0X')
                or (
                    len(stripped) > 0
                    and all(c in '0123456789abcdefABCDEF' for c in stripped)
                )
            )
            if is_addr:
                func = _get_function(addr=stripped, name='')
            else:
                func = _get_function(addr='', name=stripped)
            results.append({
                'name': func.demangled_name,
                'entrypoint': f'{func.addr:#x}',
                'signature': func.signature or None,
                'error': None,
            })
        except Exception as e:
            results.append({'target': target, 'error': str(e)})
    return results


async def get_funcs(
    items: list[str],
) -> list[dict]:
    """Get function info by address or name. Accepts a list of addresses or names.

    Each entry in items is either:
    - A hex address (starts with '0x' or all hex digits) -> look up by address
    - A function name string -> look up by name

    RETURNS: list of dicts, each with:
    - name, entrypoint, signature: function details (on success)
    - target, error: input target and error message (on failure)"""
    if not isinstance(items, list):
        items = [items]
    return await run_on_ida_main_async(_get_funcs_sync, items)
