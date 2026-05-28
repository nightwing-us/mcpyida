"""CFG extraction and normalization tools."""

from __future__ import annotations

import base64

from mcpyida.models import (
    BasicBlock,
    CFGFeatures,
    CFGResult,
    CallgraphEdge,
    CallgraphNode,
    CallgraphResult,
)


# ---------------------------------------------------------------------------
# Address parsing helper
# ---------------------------------------------------------------------------


def _parse_address(address: str) -> int:
    """Parse a hex address string or function name to an integer EA.

    Accepts both '0x'-prefixed and bare hex strings, or a symbol name that
    IDA can resolve via ``idc.get_name_ea_simple``.

    Raises:
        ValueError: if the string cannot be parsed as a hex integer and cannot
            be resolved as a known name.
    """
    addr_str = address.strip()
    try:
        return int(addr_str, 16)
    except ValueError:
        pass
    # Try as a named symbol.
    import idc

    ea = idc.get_name_ea_simple(addr_str)
    if ea != idc.BADADDR:
        return ea
    raise ValueError(f'Cannot resolve address or name: {address!r}')


# ---------------------------------------------------------------------------
# Thunk-aware name resolution
# ---------------------------------------------------------------------------


def _resolve_name(ea: int) -> str:
    """Return the function name at *ea*, resolving through a thunk chain.

    If IDA marks the function as a thunk (``FUNC_THUNK``), the name of the
    thunk target is returned instead so callers see the real callee name.
    Falls back to the thunk's own name when the target cannot be determined.
    """
    import idaapi
    import ida_funcs

    func = idaapi.get_func(ea)
    if func is not None and (func.flags & idaapi.FUNC_THUNK):
        target = idaapi.calc_thunk_func_target(func)
        if target is not None and target[0] != idaapi.BADADDR:
            resolved = ida_funcs.get_func_name(target[0])
            if resolved:
                return resolved
    return ida_funcs.get_func_name(ea) or hex(ea)


# ---------------------------------------------------------------------------
# CFG extraction
# ---------------------------------------------------------------------------


def cfg_sync(
    address: str,
    normalize: bool = True,
    include_bytes: bool = False,
    include_disassembly: bool = False,
) -> CFGResult:
    """Extract the control flow graph for a function.

    Args:
        address: Hex address string or function name identifying the function.
        normalize: Apply IDA normalization pass (filter zero-size blocks,
            clean dangling successors, sort successors).
        include_bytes: Attach base64-encoded raw bytes to each block.
        include_disassembly: Attach per-instruction disassembly list to each block.

    Returns:
        CFGResult with entry point, block map, and aggregated features.

    Raises:
        ValueError: if address is invalid or no function exists at that address.
    """
    import idaapi
    import ida_bytes
    import ida_ua
    import idautils
    import idc

    ea = _parse_address(address)
    func = idaapi.get_func(ea)
    if func is None:
        raise ValueError(f'No function at {address}')

    entry_hex = hex(func.start_ea)
    blocks: dict[str, BasicBlock] = {}

    for bb in idaapi.FlowChart(func):
        bb_start = bb.start_ea
        bb_end = bb.end_ea
        bb_size = bb_end - bb_start
        addr_hex = hex(bb_start)

        # Collect successor addresses.
        successors: list[str] = [hex(s.start_ea) for s in bb.succs()]

        # Analyse each instruction in the block.
        called_funcs: dict[str, str] = {}
        strings: list[str] = []
        insn_count = 0
        raw_bytes = bytearray()
        instructions_list: list[dict[str, str]] = []

        cur_ea = bb_start
        while cur_ea < bb_end:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, cur_ea)
            if length <= 0:
                # Skip to next head on decode failure.
                next_ea = idaapi.next_head(cur_ea, bb_end)
                if next_ea == idaapi.BADADDR or next_ea <= cur_ea:
                    break
                cur_ea = next_ea
                continue

            insn_count += 1

            # Detect call targets via code cross-references.
            # Only process actual call instructions — skip jumps.
            if idaapi.is_call_insn(cur_ea):
                for ref_ea in idautils.CodeRefsFrom(cur_ea, 0):
                    ref_func = idaapi.get_func(ref_ea)
                    if ref_func is not None and ref_func.start_ea == ref_ea:
                        name = _resolve_name(ref_ea)
                        called_funcs[hex(ref_ea)] = name

            # Collect string references from data cross-references.
            for ref_ea in idautils.DataRefsFrom(cur_ea):
                str_type = idc.get_str_type(ref_ea)
                if str_type is not None and str_type >= 0:
                    s = idc.get_strlit_contents(ref_ea, -1, str_type)
                    if s:
                        strings.append(s.decode('utf-8', errors='replace'))

            # Optionally accumulate raw bytes.
            if include_bytes:
                chunk = ida_bytes.get_bytes(cur_ea, length)
                if chunk:
                    raw_bytes.extend(chunk)

            # Optionally accumulate per-instruction disassembly.
            if include_disassembly:
                mnem = idc.print_insn_mnem(cur_ea)
                op_parts: list[str] = []
                for i in range(len(insn.ops)):
                    if insn.ops[i].type == 0:  # o_void — no more operands
                        break
                    op = idc.print_operand(cur_ea, i)
                    if op:
                        op_parts.append(op)
                operands = ', '.join(op_parts)
                instructions_list.append({
                    'address': hex(cur_ea),
                    'mnemonic': mnem,
                    'operands': operands,
                })

            cur_ea += length

        block = BasicBlock(
            address=addr_hex,
            size=bb_size,
            successors=successors,
            instruction_count=insn_count,
            called_funcs=called_funcs,
            strings=strings,
        )

        if include_bytes:
            block = block.model_copy(
                update={'bytes': base64.b64encode(bytes(raw_bytes)).decode()}
            )
        if include_disassembly:
            block = block.model_copy(update={'instructions': instructions_list})

        blocks[addr_hex] = block

    # Optionally normalise (remove zero-size sink nodes, clean dangling refs).
    if normalize:
        blocks = normalize_ida_cfg(blocks)

    # Aggregate function-level features across all (possibly normalised) blocks.
    all_called_funcs: dict[str, str] = {}
    all_strings: list[str] = []
    total_insns = 0
    for b in blocks.values():
        all_called_funcs.update(b.called_funcs)
        all_strings.extend(b.strings)
        total_insns += b.instruction_count

    return CFGResult(
        entry=entry_hex,
        block_count=len(blocks),
        blocks=blocks,
        features=CFGFeatures(
            instruction_count=total_insns,
            called_funcs=all_called_funcs,
            strings=all_strings,
        ),
    )


async def cfg(
    address: str,
    normalize: bool = True,
    include_bytes: bool = False,
    include_disassembly: bool = False,
) -> CFGResult:
    """Async wrapper for cfg_sync — dispatches to IDA main thread."""
    from mcpyida.mcpserver import run_on_ida_main_async

    return await run_on_ida_main_async(
        cfg_sync, address, normalize, include_bytes, include_disassembly
    )


# ---------------------------------------------------------------------------
# Callgraph traversal
# ---------------------------------------------------------------------------


def callgraph_sync(
    address: str,
    direction: str = 'callees',
    max_depth: int = 5,
    max_nodes: int = 1000,
    max_edges: int = 5000,
) -> CallgraphResult:
    """Build a call graph rooted at the given function.

    Args:
        address: Hex address string or function name identifying the root function.
        direction: One of ``'callees'``, ``'callers'``, or ``'both'``.
        max_depth: Maximum DFS traversal depth (inclusive, 0 = root only).
        max_nodes: Stop adding nodes when this count is reached.
        max_edges: Stop adding edges when this count is reached.

    Returns:
        CallgraphResult with node/edge lists and truncation metadata.

    Raises:
        ValueError: if address is invalid, direction is invalid, or no function
            exists at that address.
    """
    if direction not in ('callees', 'callers', 'both'):
        raise ValueError(
            f"Invalid direction '{direction}', must be 'callees', 'callers', or 'both'"
        )

    import idaapi
    import idautils

    ea = _parse_address(address)
    func = idaapi.get_func(ea)
    if func is None:
        raise ValueError(f'No function at {address}')

    root_addr = hex(func.start_ea)

    nodes: dict[str, CallgraphNode] = {}
    edges: list[CallgraphEdge] = []
    from typing import Literal as _Literal

    edge_set: set[tuple[str, str]] = set()
    visited: set[str] = set()
    truncated = False
    limit_reason: _Literal['depth', 'nodes', 'edges'] | None = None

    def _get_callees(func_ea: int) -> list[int]:
        """Return entry addresses of functions directly called by the function at func_ea."""
        seen: set[int] = set()
        result: list[int] = []
        func_obj = idaapi.get_func(func_ea)
        if func_obj is None:
            return result
        # Iterate all function chunks to handle non-contiguous bodies.
        for chunk_start, chunk_end in idautils.Chunks(func_obj.start_ea):
            for head in idautils.Heads(chunk_start, chunk_end):
                # Only consider actual call instructions, not jumps.
                if not idaapi.is_call_insn(head):
                    continue
                for ref_ea in idautils.CodeRefsFrom(head, 0):
                    ref_func = idaapi.get_func(ref_ea)
                    if ref_func is not None and ref_func.start_ea == ref_ea:
                        if ref_ea not in seen:
                            seen.add(ref_ea)
                            result.append(ref_ea)
        return result

    def _get_callers(func_ea: int) -> list[int]:
        """Return entry addresses of functions that directly call the function at func_ea."""
        seen: set[int] = set()
        result: list[int] = []
        for xref in idautils.CodeRefsTo(func_ea, 0):
            caller_func = idaapi.get_func(xref)
            if caller_func is not None:
                caller_ea = caller_func.start_ea
                if caller_ea not in seen:
                    seen.add(caller_ea)
                    result.append(caller_ea)
        return result

    def traverse(
        func_ea: int,
        depth: int,
        get_related_fn,
        is_callee_direction: bool,
    ) -> None:
        nonlocal truncated, limit_reason

        if truncated:
            return

        addr_hex = hex(func_ea)

        if addr_hex in visited:
            return

        if depth > max_depth:
            truncated = True
            if limit_reason is None:
                limit_reason = 'depth'
            return

        if len(nodes) >= max_nodes:
            truncated = True
            limit_reason = 'nodes'
            return

        visited.add(addr_hex)
        if addr_hex not in nodes:
            nodes[addr_hex] = CallgraphNode(
                addr=addr_hex,
                name=_resolve_name(func_ea),
                depth=depth,
            )

        for related_ea in get_related_fn(func_ea):
            if truncated:
                break

            related_hex = hex(related_ea)

            if len(edges) >= max_edges:
                truncated = True
                limit_reason = 'edges'
                break

            # Normalise edge direction: always from=caller, to=callee.
            if is_callee_direction:
                from_addr, to_addr = addr_hex, related_hex
            else:
                from_addr, to_addr = related_hex, addr_hex

            edge_key = (from_addr, to_addr)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                # Pydantic model uses alias=from/to; populate_by_name=True
                # makes from_addr/to_addr work at runtime, but mypy's pydantic
                # plugin only sees the alias.
                edges.append(CallgraphEdge(from_addr=from_addr, to_addr=to_addr))  # type: ignore[call-arg]

            traverse(related_ea, depth + 1, get_related_fn, is_callee_direction)

    if direction in ('callees', 'both'):
        traverse(func.start_ea, 0, _get_callees, is_callee_direction=True)

    if direction in ('callers', 'both'):
        # For 'both': reset visited to only the root so callers are traversed
        # from the root; previously-discovered callee nodes are kept in the
        # nodes dict but are not re-traversed (visited reset is minimal).
        if direction == 'both':
            visited = {root_addr}
        traverse(func.start_ea, 0, _get_callers, is_callee_direction=False)

    return CallgraphResult(
        root=root_addr,
        direction=direction,
        nodes=list(nodes.values()),
        edges=edges,
        truncated=truncated,
        limit_reason=limit_reason,
    )


async def callgraph(
    address: str,
    direction: str = 'callees',
    max_depth: int = 5,
    max_nodes: int = 1000,
    max_edges: int = 5000,
) -> CallgraphResult:
    """Async wrapper for callgraph_sync — dispatches to IDA main thread."""
    from mcpyida.mcpserver import run_on_ida_main_async

    return await run_on_ida_main_async(
        callgraph_sync, address, direction, max_depth, max_nodes, max_edges
    )


# ---------------------------------------------------------------------------
# CFG normalization
# ---------------------------------------------------------------------------


def normalize_ida_cfg(
    blocks: dict[str, BasicBlock],
) -> dict[str, BasicBlock]:
    """Normalize IDA CFG by filtering zero-size blocks.

    Applies two passes:
    1. Zero-size block filter: remove blocks where size == 0 and
       instruction_count == 0 (IDA emits these as virtual sink nodes at
       external targets).
    2. Dangling successor cleanup: remove successor references to the
       removed blocks from all remaining blocks.
    Successors are sorted after normalization.
    """
    if not blocks:
        return {}

    # Work on a mutable deep copy so callers are not surprised by mutation.
    result: dict[str, BasicBlock] = {
        addr: block.model_copy(deep=True) for addr, block in blocks.items()
    }

    # --- Pass 1: remove zero-size blocks -------------------------------------

    removed: set[str] = {
        addr
        for addr, block in result.items()
        if block.size == 0 and block.instruction_count == 0
    }
    for addr in removed:
        del result[addr]

    # --- Pass 2: clean up dangling successors --------------------------------

    for block in result.values():
        block.successors = [s for s in block.successors if s not in removed]

    # --- Pass 3: sort successors ---------------------------------------------

    for block in result.values():
        block.successors = sorted(block.successors, key=lambda x: int(x, 16))

    return result
