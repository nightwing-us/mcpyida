"""Type tools: types, type_info, create_struct, add_field.

These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.

IDA-specific: all functions call ida_* APIs directly (global state).
No backend parameter — IDA state is implicit.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp.exceptions import ToolError

from mcpyida.mcpserver import run_on_ida_main_async
from mcpyida.models import (
    EnumValue,
    FieldAdditionResult,
    MemberInfo,
    StructureCreationResult,
    StructureFieldInput,
    TypeDetails,
    TypeSummary,
)


# ---------------------------------------------------------------------------
# Private helpers — mirrors of the static methods on McpServer
# ---------------------------------------------------------------------------


def _normalize_type_kind(tif: Any) -> str:
    """Normalize IDA type kind to standard values."""

    try:
        if tif.is_struct():
            return 'struct'
        elif tif.is_union():
            return 'union'
        elif tif.is_enum():
            return 'enum'
        elif hasattr(tif, 'is_typedef') and tif.is_typedef():
            return 'typedef'
        elif tif.is_ptr():
            return 'pointer'
        elif tif.is_array():
            return 'array'
        elif tif.is_func():
            return 'function'
        elif tif.is_integral() or tif.is_floating() or tif.is_bool() or tif.is_void():
            return 'primitive'
        else:
            return 'unknown'
    except Exception:
        return 'unknown'


def _get_type_size(tif: Any) -> int | None:
    """Get type size, returning None if variable/unknown."""
    import idaapi

    try:
        size = tif.get_size()
        if size == idaapi.BADSIZE or size < 0:
            return None
        return size
    except Exception:
        return None


def _get_type_name_and_path(
    ordinal: int,
    til: Any,
    til_name: str | None = None,
) -> tuple[str, str]:
    """Get both short name and full path for a type ordinal."""
    import ida_typeinf

    name = ida_typeinf.get_numbered_type_name(til, ordinal)
    if not name:
        return '', ''
    full_path = f'{til_name}/{name}' if til_name else name
    return name, full_path


def _get_til_name(til: Any) -> str:
    """Get the name of a type library."""
    try:
        if hasattr(til, 'name') and til.name:
            return til.name
        if hasattr(til, 'desc') and til.desc:
            return til.desc
        return ''
    except Exception:
        return ''


def _iter_all_tils(local_til: Any) -> list[tuple[Any, str]]:
    """Iterate through all loaded type libraries.

    Returns list of (til, til_name) tuples, starting with local TIL.
    """
    tils: list[tuple[Any, str]] = [(local_til, '')]
    try:
        current_til = local_til
        visited = {id(local_til)}
        while True:
            if not hasattr(current_til, 'base'):
                break
            try:
                base_til = current_til.base
            except Exception:
                break
            if not base_til:
                break
            til_id = id(base_til)
            if til_id in visited:
                break
            visited.add(til_id)
            til_name = ''
            try:
                if hasattr(base_til, 'name') and base_til.name:
                    til_name = base_til.name
                elif hasattr(base_til, 'desc') and base_til.desc:
                    til_name = base_til.desc
            except Exception:
                pass
            tils.append((base_til, til_name))
            current_til = base_til
    except Exception:
        pass
    return tils


def _get_struct_members(tif: Any) -> list[MemberInfo]:
    """Extract struct/union members."""
    import ida_typeinf

    members: list[MemberInfo] = []
    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return members
    for i in range(udt_data.size()):
        member = udt_data[i]
        member_tif = member.type
        members.append(
            MemberInfo(
                name=member.name,
                type_string=str(member_tif),
                offset=member.offset // 8,
                size=_get_type_size(member_tif),
            )
        )
    return members


def _get_enum_values(tif: Any) -> list[EnumValue]:
    """Extract enum values."""
    import ida_typeinf

    values: list[EnumValue] = []
    enum_data = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(enum_data):
        return values
    for i in range(enum_data.size()):
        member = enum_data[i]
        values.append(EnumValue(name=member.name, value=member.value))
    return values


def _get_typedef_target(tif: Any) -> str | None:
    """Get the underlying type for a typedef."""
    import ida_typeinf

    try:
        if not hasattr(tif, 'is_typedef') or not tif.is_typedef():
            return None
        real_type = ida_typeinf.tinfo_t()
        if tif.get_realtype(real_type):
            return str(real_type)
    except Exception:
        pass
    return None


def _resolve_field_type(field_type: str) -> Any:
    """Resolve a type string to a tinfo_t.

    Tries get_named_type first, then parse_decl, then falls back to a
    simple-type table for common primitive names.  Raises ToolError if the
    type cannot be resolved.
    """
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()

    if tif.get_named_type(til, field_type):
        return tif

    result = ida_typeinf.parse_decl(tif, til, f'{field_type};', 0)
    if result is not None and tif.is_correct():
        return tif

    # Fallback table for bare primitive names
    simple_map: dict[str, int] = {
        'void': ida_typeinf.BT_VOID,
        'bool': ida_typeinf.BT_BOOL,
        'char': ida_typeinf.BT_INT8,
        'uchar': ida_typeinf.BT_INT8,
        'unsigned char': ida_typeinf.BT_INT8,
        'short': ida_typeinf.BT_INT16,
        'unsigned short': ida_typeinf.BT_INT16,
        'int': ida_typeinf.BT_INT32,
        'unsigned int': ida_typeinf.BT_INT32,
        'uint': ida_typeinf.BT_INT32,
        'long': ida_typeinf.BT_INT32,
        'unsigned long': ida_typeinf.BT_INT32,
        '__int64': ida_typeinf.BT_INT64,
        'long long': ida_typeinf.BT_INT64,
        'unsigned long long': ida_typeinf.BT_INT64,
        'float': ida_typeinf.BT_FLOAT,
        'double': ida_typeinf.BT_FLOAT,
    }
    bt = simple_map.get(field_type.strip())
    if bt is not None:
        tif2 = ida_typeinf.tinfo_t()
        tif2.create_simple_type(bt)
        return tif2

    raise ToolError(f"Invalid type string: '{field_type}'")


def _udt_add_member(
    udt: Any,
    field_name: str,
    field_type_str: str,
    offset_bytes: int,
    comment: str | None = None,
) -> None:
    """Append a udt_member_t to an existing udt_type_data_t.

    offset_bytes is in bytes; IDA stores offsets in bits internally.
    Raises ToolError on bad type or size.
    """
    import ida_typeinf

    member_tif = _resolve_field_type(field_type_str)
    size_bytes = member_tif.get_size()
    if size_bytes == ida_typeinf.BADSIZE or size_bytes <= 0:
        raise ToolError(f"Cannot determine size for type '{field_type_str}'")

    member = ida_typeinf.udt_member_t()
    member.name = field_name
    member.offset = offset_bytes * 8  # bits
    member.size = size_bytes * 8  # bits
    member.type = member_tif
    if comment:
        member.cmt = comment
    udt.push_back(member)


def _add_field_to_struct_impl(udt_data: Any, field: StructureFieldInput) -> None:
    """Add a single StructureFieldInput to a udt_type_data_t (IDA 9 / ida_typeinf)."""
    _udt_add_member(udt_data, field.name, field.type, field.offset, field.comment)


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


def _types_sync(
    pattern: str | None = None,
    offset: int = 0,
    limit: int = 500,
) -> list[TypeSummary]:
    """Sync implementation of types — runs on IDA main thread."""
    import ida_typeinf

    if offset < 0:
        raise ToolError('offset must be non-negative')
    if limit <= 0:
        raise ToolError('limit must be positive')

    local_til = ida_typeinf.get_idati()
    if not local_til:
        raise ToolError('Failed to get type library')

    if pattern:
        pattern = pattern.strip('*')

    results: list[TypeSummary] = []
    all_tils = _iter_all_tils(local_til)

    for til, til_name in all_tils:
        try:
            try:
                type_count = ida_typeinf.get_ordinal_limit(til)
            except (AttributeError, TypeError):
                type_count = ida_typeinf.get_ordinal_qty(til) + 1
        except Exception:
            continue

        for ordinal in range(1, type_count):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            name, full_path = _get_type_name_and_path(ordinal, til, til_name)
            if not name:
                continue
            if pattern:
                pl = pattern.lower()
                if pl not in name.lower() and pl not in full_path.lower():
                    continue
            kind = _normalize_type_kind(tif)
            size = _get_type_size(tif)
            results.append(
                TypeSummary(
                    name=name,
                    full_path=full_path,
                    type_string=name,
                    kind=kind,
                    size=size,
                )
            )

    results.sort(key=lambda s: s.name.lower())
    total = len(results)
    end = min(offset + limit, total)
    return results[offset:end]


async def types(
    pattern: str | None = None,
    offset: int = 0,
    limit: int = 500,
) -> list[TypeSummary]:
    """Enumerate and search available types across all type sources. Paginated (not batched).

    RETURNS: list[TypeSummary] with name, full_path, type_string, kind, size

    PARAMETERS:
    - pattern: Substring filter (case-insensitive, strips * characters)
    - offset: Starting index for pagination (default 0)
    - limit: Maximum number of results (default 500)

    USE CASE: Discover available types before setting variable types.

    NOTES:
    - Searches across ALL loaded type libraries (local types + imported TILs like mssdk, gnulnx)
    - full_path includes TIL name for disambiguation (e.g., "mssdk64/HANDLE")

    EXAMPLE:
    - types() -> first 500 types from all loaded TILs
    - types(pattern="stream", limit=100) -> search for stream-related types
    - types(offset=50, limit=50) -> next page of results"""
    return await run_on_ida_main_async(_types_sync, pattern, offset, limit)


async def type_info(
    items: list[str],
) -> list[dict]:
    """Get type details. Batched: accepts list of type names.

    Each item in items is a type name (short name or full path like 'mssdk64/HANDLE').

    RETURNS: list of dicts, each with TypeDetails fields (on success) or
    - target, error: input target and error message (on failure)"""
    results: list[dict] = []
    for type_name in items:
        try:
            details = await run_on_ida_main_async(_get_type_info_one_sync, type_name)
            results.append(details.model_dump())
        except Exception as e:
            results.append({'target': type_name, 'error': str(e)})
    return results


def _get_type_info_one_sync(type_name: str) -> TypeDetails:
    """Get detailed type info for a single type name."""
    import ida_typeinf

    if not type_name or not type_name.strip():
        raise ToolError('type_name cannot be empty')

    local_til = ida_typeinf.get_idati()
    if not local_til:
        raise ToolError('Failed to get type library')

    search_name = type_name
    specific_til_name: str | None = None
    if '/' in type_name:
        parts = type_name.split('/', 1)
        specific_til_name = parts[0]
        search_name = parts[1]

    tif = ida_typeinf.tinfo_t()
    found_til = None
    found_til_name: str | None = None

    all_tils = _iter_all_tils(local_til)
    for til, til_name in all_tils:
        if specific_til_name and til_name != specific_til_name:
            continue
        if tif.get_named_type(til, search_name):
            found_til = til
            found_til_name = til_name
            break
        result = ida_typeinf.parse_decl(tif, til, f'{search_name};', 0)
        if result is not None and tif.is_correct():
            found_til = til
            found_til_name = til_name
            break

    if not found_til:
        if specific_til_name:
            raise ToolError(
                f"Type '{search_name}' not found in type library '{specific_til_name}'"
            )
        raise ToolError(f"Type '{type_name}' not found in any loaded type library")

    name = search_name
    full_path = f'{found_til_name}/{search_name}' if found_til_name else search_name
    kind = _normalize_type_kind(tif)
    size = _get_type_size(tif)

    comment: str | None = None
    try:
        ordinal = ida_typeinf.get_type_ordinal(found_til, search_name)
        if ordinal != 0 and hasattr(ida_typeinf, 'get_numbered_type_cmt'):
            cmt = ida_typeinf.get_numbered_type_cmt(found_til, ordinal)
            if cmt:
                comment = cmt
    except Exception:
        pass

    members: list[MemberInfo] | None = None
    values: list[EnumValue] | None = None
    underlying_type: str | None = None

    if tif.is_struct() or tif.is_union():
        members = _get_struct_members(tif)
    elif tif.is_enum():
        values = _get_enum_values(tif)
    elif hasattr(tif, 'is_typedef') and tif.is_typedef():
        underlying_type = _get_typedef_target(tif)

    return TypeDetails(
        name=name,
        full_path=full_path,
        type_string=name,
        kind=kind,
        size=size,
        comment=comment,
        members=members,
        values=values,
        underlying_type=underlying_type,
    )


def _create_struct_sync(
    name: str,
    size: int = 0,
    fields: list[dict] | None = None,
    packed: bool = False,
) -> StructureCreationResult:
    """Sync implementation of create_struct — runs on IDA main thread."""
    import ida_typeinf

    til = ida_typeinf.get_idati()

    # Check if struct already exists
    existing_tif = ida_typeinf.tinfo_t()
    if existing_tif.get_named_type(til, name) and (
        existing_tif.is_struct() or existing_tif.is_union()
    ):
        existing_size = existing_tif.get_size()
        if existing_size == ida_typeinf.BADSIZE:
            existing_size = 0
        return StructureCreationResult(
            name=name,
            size=existing_size,
            created=False,
            message=f"Structure '{name}' already exists with size {existing_size}",
        )

    # Build UDT from scratch
    udt = ida_typeinf.udt_type_data_t()
    udt.is_union = False
    if packed:
        udt.pack = 1

    # Add caller-supplied fields
    if fields:
        for field_dict in fields:
            field = StructureFieldInput(**field_dict)
            _add_field_to_struct_impl(udt, field)

    tif = ida_typeinf.tinfo_t()
    if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
        raise ToolError(f"Failed to create structure '{name}'")

    ntf_flags = ida_typeinf.NTF_REPLACE
    ret = tif.set_named_type(til, name, ntf_flags)
    if ret != ida_typeinf.TERR_OK:
        raise ToolError(f"Failed to save structure '{name}' to TIL (error {ret})")

    # Determine final size (in bytes)
    final_size = tif.get_size()
    if final_size == ida_typeinf.BADSIZE:
        final_size = 0

    # If caller asked for a larger size, pad with a trailing byte-array field
    if size > 0 and size > final_size:
        pad_bytes = size - final_size
        # Re-fetch the current UDT, add a padding member, recreate
        udt2 = ida_typeinf.udt_type_data_t()
        tif.get_udt_details(udt2)

        pad_member = ida_typeinf.udt_member_t()
        pad_member.name = '_pad'
        pad_member.offset = final_size * 8  # bits
        # Use a byte-array type of the right size
        arr_tif = ida_typeinf.tinfo_t()
        byte_tif = ida_typeinf.tinfo_t()
        byte_tif.create_simple_type(ida_typeinf.BT_INT8)
        arr_data = ida_typeinf.array_type_data_t()
        arr_data.nelems = pad_bytes
        arr_data.elem_type = byte_tif
        arr_tif.create_array(arr_data)
        pad_member.type = arr_tif
        pad_member.size = pad_bytes * 8  # bits
        udt2.push_back(pad_member)

        tif2 = ida_typeinf.tinfo_t()
        if tif2.create_udt(udt2, ida_typeinf.BTF_STRUCT):
            ret2 = tif2.set_named_type(til, name, ntf_flags)
            if ret2 == ida_typeinf.TERR_OK:
                tif = tif2
                final_size = size

    return StructureCreationResult(
        name=name,
        size=final_size,
        created=True,
        message=f"Structure '{name}' created successfully"
        + (' (packed)' if packed else ''),
    )


async def create_struct(
    name: str,
    size: int = 0,
    fields: list[dict] | None = None,
    packed: bool = False,
) -> StructureCreationResult:
    """Create a new structure type in the IDA type database.

    Use this tool to define custom structures that match memory layouts
    discovered during analysis. After creation, use update_vars
    to apply the structure type to variables.

    Returns:
        StructureCreationResult with name, size, created flag, and message.

    Example - Empty struct:
        create_struct(name="NetworkPacket", size=64)

    Example - Struct with fields:
        create_struct(
            name="NetworkPacket",
            fields=[
                {"name": "header_ptr", "type": "void *", "offset": 0},
                {"name": "length", "type": "int", "offset": 8},
                {"name": "flags", "type": "unsigned int", "offset": 12}
            ]
        )

    Example - Packed struct:
        create_struct(name="PackedData", size=16, packed=True)"""
    return await run_on_ida_main_async(_create_struct_sync, name, size, fields, packed)


async def add_field(
    items: list[dict],
) -> list[dict]:
    """Add field(s) to struct(s). Batched: each item {struct_name, field_name, field_type, offset, comment?}.

    If a field already exists at the specified offset, it will be replaced.
    If the structure is not large enough, it will be expanded automatically.

    RETURNS: list of dicts, each with FieldAdditionResult fields."""
    results: list[dict] = []
    for item in items:
        struct_name = item.get('struct_name', '')
        field_name = item.get('field_name', '')
        field_type = item.get('field_type', '')
        offset = item.get('offset', 0)
        comment = item.get('comment', '')
        try:
            result = await run_on_ida_main_async(
                _add_field_one_sync,
                struct_name=struct_name,
                field_name=field_name,
                field_type=field_type,
                offset=offset,
                comment=comment,
            )
            results.append(result.model_dump())
        except Exception as e:
            results.append(
                FieldAdditionResult(
                    struct_name=struct_name,
                    field_name=field_name,
                    offset=offset,
                    size=0,
                    success=False,
                    message=str(e),
                ).model_dump()
            )
    return results


def _add_field_one_sync(
    struct_name: str,
    field_name: str,
    field_type: str,
    offset: int,
    comment: str,
) -> FieldAdditionResult:
    """Add a single field to a struct (must run in IDA main thread)."""
    import ida_typeinf

    til = ida_typeinf.get_idati()

    # Look up the existing struct
    struct_tif = ida_typeinf.tinfo_t()
    if not struct_tif.get_named_type(til, struct_name) or not struct_tif.is_struct():
        return FieldAdditionResult(
            struct_name=struct_name,
            field_name=field_name,
            offset=offset,
            size=0,
            success=False,
            message=f"Structure '{struct_name}' not found",
        )

    # Resolve the field's type
    try:
        member_tif = _resolve_field_type(field_type)
    except ToolError as exc:
        return FieldAdditionResult(
            struct_name=struct_name,
            field_name=field_name,
            offset=offset,
            size=0,
            success=False,
            message=str(exc),
        )

    size_bytes = member_tif.get_size()
    if size_bytes == ida_typeinf.BADSIZE or size_bytes <= 0:
        return FieldAdditionResult(
            struct_name=struct_name,
            field_name=field_name,
            offset=offset,
            size=0,
            success=False,
            message=f"Cannot determine size for type '{field_type}'",
        )

    # Get existing UDT details
    udt_data = ida_typeinf.udt_type_data_t()
    if not struct_tif.get_udt_details(udt_data):
        return FieldAdditionResult(
            struct_name=struct_name,
            field_name=field_name,
            offset=offset,
            size=0,
            success=False,
            message=f"Failed to read UDT details for '{struct_name}'",
        )

    # Remove any existing member that overlaps the target offset (replace semantics)
    offset_bits = offset * 8
    new_members = ida_typeinf.udt_type_data_t()
    for i in range(udt_data.size()):
        m = udt_data[i]
        m_start = m.offset  # bits
        m_end = m.offset + m.size  # bits
        target_end = offset_bits + size_bytes * 8
        # Keep members that do not overlap [offset_bits, target_end)
        if m_end <= offset_bits or m_start >= target_end:
            new_members.push_back(m)

    # Add the new member
    new_member = ida_typeinf.udt_member_t()
    new_member.name = field_name
    new_member.offset = offset_bits
    new_member.size = size_bytes * 8
    new_member.type = member_tif
    if comment:
        new_member.cmt = comment
    new_members.push_back(new_member)

    # Recreate struct with updated members
    new_tif = ida_typeinf.tinfo_t()
    if not new_tif.create_udt(new_members, ida_typeinf.BTF_STRUCT):
        return FieldAdditionResult(
            struct_name=struct_name,
            field_name=field_name,
            offset=offset,
            size=size_bytes,
            success=False,
            message='Failed to rebuild struct UDT after field addition',
        )

    ret = new_tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
    if ret != ida_typeinf.TERR_OK:
        return FieldAdditionResult(
            struct_name=struct_name,
            field_name=field_name,
            offset=offset,
            size=size_bytes,
            success=False,
            message=f"Failed to save updated struct '{struct_name}' to TIL (error {ret})",
        )

    return FieldAdditionResult(
        struct_name=struct_name,
        field_name=field_name,
        offset=offset,
        size=size_bytes,
        success=True,
        message=f"Field '{field_name}' added successfully at offset {offset}",
    )
