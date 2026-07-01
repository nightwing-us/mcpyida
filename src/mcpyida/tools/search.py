"""Search tools — find_bytes and find_insns.

IDA Pro implementation using ida_bytes and idautils APIs.
"""

from __future__ import annotations

from mcpyida.mcpserver import run_on_ida_main_async
from mcpyida.tools.search_utils import parse_byte_pattern, match_instruction


async def find_bytes(
    patterns: list[str],
    limit: int = 1000,
    offset: int = 0,
) -> list[dict]:
    """Search for byte patterns with wildcard support.

    Each pattern: space-separated hex tokens, '??' for wildcard.
    Example: '48 8B ?? ??'
    """
    return await run_on_ida_main_async(_find_bytes_sync, patterns, limit, offset)


def _find_bytes_sync(
    patterns: list[str],
    limit: int = 1000,
    offset: int = 0,
) -> list[dict]:
    """Sync implementation of find_bytes — runs on IDA main thread."""
    if not isinstance(patterns, list):
        patterns = [patterns]

    results = []
    for pattern_str in patterns:
        try:
            data_bytes, mask_bytes = parse_byte_pattern(pattern_str)
            matches = _search_bytes_ida(data_bytes, mask_bytes, limit + 1, offset)

            has_more = len(matches) > limit
            if has_more:
                matches = matches[:limit]

            results.append({
                'pattern': pattern_str,
                'items': matches,
                'has_more': has_more,
                'error': None,
            })
        except Exception as e:
            results.append({
                'pattern': pattern_str,
                'items': [],
                'has_more': False,
                'error': str(e),
            })
    return results


def _search_bytes_ida(
    data: bytes,
    mask: bytes,
    max_results: int,
    skip: int,
) -> list[dict]:
    """Search using IDA's bin_search with mask arrays."""
    import ida_ida

    start_ea = ida_ida.inf_get_min_ea()
    end_ea = ida_ida.inf_get_max_ea()
    pattern_len = len(data)

    # Build IDA-style search data: bytes where mask is 0xFF, -1 (0x100) as wildcard
    # ida_bytes.bin_search uses a compiled_bin_t
    # For IDA 9+, prefer ida_bytes.find_bytes which accepts a pattern string directly
    pattern_str = _build_ida_pattern_str(data, mask)

    matches = []
    found = 0
    skipped = 0
    ea = start_ea

    while ea < end_ea and found < max_results:
        result_ea = _find_next(ea, end_ea, pattern_str, pattern_len)
        if result_ea is None or result_ea >= end_ea:
            break

        if skipped < skip:
            skipped += 1
        else:
            matched_bytes = _read_bytes_at(result_ea, pattern_len)
            matches.append({
                'addr': f'{result_ea:#x}',
                'bytes': matched_bytes,
            })
            found += 1

        # Advance past this match to search for next occurrence
        ea = result_ea + 1

    return matches


def _build_ida_pattern_str(data: bytes, mask: bytes) -> str:
    """Build a space-separated IDA pattern string (hex bytes, '?' for wildcards).

    IDA's find_bytes / bin_search pattern format: 'AA BB ? CC' where '?' is wildcard.
    """
    tokens = []
    for b, m in zip(data, mask):
        if m == 0x00:
            tokens.append('?')
        else:
            tokens.append(f'{b:02X}')
    return ' '.join(tokens)


def _find_next(
    start_ea: int, end_ea: int, pattern_str: str, pattern_len: int
) -> int | None:
    """Find next match starting from start_ea using IDA's search APIs."""
    import ida_bytes
    import ida_search

    # Try ida_bytes.find_bytes (IDA 9+) first — accepts pattern string directly
    # BADADDR is 0xFFFFFFFFFFFFFFFF in IDA 64-bit; check via idc.BADADDR not
    # ida_bytes.BADADDR (which may not exist in all IDA versions).
    try:
        import idc as _idc

        _BADADDR = _idc.BADADDR
    except Exception:
        _BADADDR = 0xFFFF_FFFF_FFFF_FFFF
    try:
        result = ida_bytes.find_bytes(pattern_str, start_ea, end_ea - start_ea)
        if (
            result is not None
            and result != _BADADDR
            and result != 0xFFFF_FFFF_FFFF_FFFF
        ):
            return result
        return None
    except (AttributeError, TypeError):
        pass

    # Fallback: ida_search.find_binary (available in older IDA)
    try:
        import idc

        BIN_SEARCH_FORWARD = getattr(ida_search, 'BIN_SEARCH_FORWARD', 0)
        BIN_SEARCH_NOSHOW = getattr(ida_search, 'BIN_SEARCH_NOSHOW', 0x10)
        flags = BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW
        result = ida_search.find_binary(start_ea, end_ea, pattern_str, 16, flags)
        if result != idc.BADADDR:
            return result
        return None
    except Exception:
        pass

    return None


def _read_bytes_at(ea: int, length: int) -> str:
    """Read bytes at address and format as hex string."""
    try:
        import ida_bytes

        buf = ida_bytes.get_bytes(ea, length)
        if buf is None:
            return ''
        return ' '.join(f'{b:02X}' for b in buf)
    except Exception:
        return ''


async def find_insns(
    sequences: list[list[dict]],
    limit: int = 1000,
    offset: int = 0,
) -> list[dict]:
    """Search for consecutive instruction sequences.

    Each sequence is a list of {mnemonic, operands} dicts.
    Operands use glob by default, /regex/ for regex.
    """
    return await run_on_ida_main_async(_find_insns_sync, sequences, limit, offset)


def _find_insns_sync(
    sequences: list[list[dict]],
    limit: int = 1000,
    offset: int = 0,
) -> list[dict]:
    """Sync implementation of find_insns — runs on IDA main thread."""
    if not isinstance(sequences, list):
        sequences = [sequences]

    results = []
    for sequence in sequences:
        try:
            matches = _search_insns_ida(sequence, limit + 1, offset)

            has_more = len(matches) > limit
            if has_more:
                matches = matches[:limit]

            results.append({
                'sequence': sequence,
                'items': matches,
                'has_more': has_more,
                'error': None,
            })
        except Exception as e:
            results.append({
                'sequence': sequence,
                'items': [],
                'has_more': False,
                'error': str(e),
            })
    return results


def _search_insns_ida(
    sequence: list[dict],
    max_results: int,
    skip: int,
) -> list[dict]:
    """Search IDA instructions for consecutive sequence match."""
    import idautils  # noqa: F401  # imported for side-effects expected by IDA

    # Collect executable segments for iteration
    exec_ranges = _get_executable_ranges()

    matches = []
    found = 0
    skipped = 0

    for seg_start, seg_end in exec_ranges:
        if found >= max_results:
            break
        for ea in idautils.Heads(seg_start, seg_end):
            if found >= max_results:
                break
            matched_insns = _try_match_sequence(ea, seg_end, sequence)
            if matched_insns is not None:
                if skipped < skip:
                    skipped += 1
                else:
                    matches.append({
                        'addr': f'{ea:#x}',
                        'instructions': matched_insns,
                    })
                    found += 1

    return matches


def _get_executable_ranges() -> list[tuple[int, int]]:
    """Return list of (start_ea, end_ea) for executable segments."""
    import idautils
    import idc

    SEGATTR_PERM = idc.SEGATTR_PERM if hasattr(idc, 'SEGATTR_PERM') else 0x60
    SEG_PERM_EXEC = 1  # execute permission bit in IDA

    ranges = []
    for seg_ea in idautils.Segments():
        perm = idc.get_segm_attr(seg_ea, SEGATTR_PERM)
        if perm & SEG_PERM_EXEC:
            seg_end = idc.get_segm_attr(seg_ea, idc.SEGATTR_END)
            ranges.append((seg_ea, seg_end))

    # Fallback: if no executable segments found, use all segments
    if not ranges:
        for seg_ea in idautils.Segments():
            seg_end = idc.get_segm_attr(seg_ea, idc.SEGATTR_END)
            ranges.append((seg_ea, seg_end))

    return ranges


def _try_match_sequence(
    start_ea: int, seg_end: int, sequence: list[dict]
) -> list[str] | None:
    """Try to match a sequence starting at start_ea. Returns instruction strings or None."""
    import idc
    import idaapi

    if not sequence:
        return None

    matched = []
    ea = start_ea

    for pattern in sequence:
        if ea >= seg_end or ea == idc.BADADDR:
            return None

        insn = idaapi.insn_t()
        if not idaapi.decode_insn(insn, ea):
            return None

        mnemonic = insn.get_canon_mnem()
        # Collect operand strings
        operands = []
        for i in range(8):  # IDA supports up to 8 operands
            op_text = idc.print_operand(ea, i)
            if not op_text:
                break
            operands.append(op_text)

        if not match_instruction(
            pattern.get('mnemonic', '*'),
            pattern.get('operands'),
            mnemonic,
            operands,
        ):
            return None

        matched.append(f'{ea:#x}: {mnemonic} {", ".join(operands)}'.rstrip())
        ea = idaapi.next_head(ea, seg_end)

    return matched
