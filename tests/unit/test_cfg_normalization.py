"""Unit tests for CFG normalization — pure Python, no Ghidra/IDA needed.

These tests exercise the normalization logic with synthetic BasicBlock data.
They are structured for TDD: all tests fail with NotImplementedError until
Task 3 provides the implementation.

Function signatures under test:

    def normalize_ghidra_cfg(
        blocks: dict[str, BasicBlock],
        function_start: int,
        function_end: int,
    ) -> dict[str, BasicBlock]: ...

    def normalize_ida_cfg(
        blocks: dict[str, BasicBlock],
    ) -> dict[str, BasicBlock]: ...
"""
from __future__ import annotations

import pytest

from mcpyida.models import BasicBlock
from mcpyida.tools.cfg import normalize_ida_cfg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _block(
    address: str,
    size: int,
    successors: list[str] | None = None,
    instruction_count: int = 1,
    called_funcs: dict[str, str] | None = None,
    strings: list[str] | None = None,
) -> BasicBlock:
    """Construct a BasicBlock with convenient defaults for tests."""
    return BasicBlock(
        address=address,
        size=size,
        successors=successors or [],
        instruction_count=instruction_count,
        called_funcs=called_funcs or {},
        strings=strings or [],
    )


# ---------------------------------------------------------------------------
# IDA normalization tests
# ---------------------------------------------------------------------------

class TestIdaNormalization:
    """Tests for normalize_ida_cfg."""

    def test_empty_cfg(self):
        """Empty blocks dict returns empty dict."""
        result = normalize_ida_cfg({})
        assert result == {}

    def test_no_zero_size_blocks_unchanged(self):
        """CFG with no zero-size blocks passes through unchanged."""
        blocks = {
            '0x1000': _block('0x1000', size=10, successors=['0x100a'], instruction_count=3),
            '0x100a': _block('0x100a', size=8, successors=[], instruction_count=2),
        }
        result = normalize_ida_cfg(blocks)
        assert len(result) == 2
        assert '0x1000' in result
        assert '0x100a' in result

    def test_remove_zero_size_blocks(self):
        """Blocks with size=0 and instruction_count=0 are removed."""
        blocks = {
            '0x1000': _block('0x1000', size=10, successors=[], instruction_count=3),
            '0x2000': _block('0x2000', size=0, successors=[], instruction_count=0),
        }
        result = normalize_ida_cfg(blocks)
        assert '0x1000' in result
        assert '0x2000' not in result

    def test_keep_blocks_with_instructions_even_if_size_zero(self):
        """Don't remove blocks that have instructions, even if size appears to be 0."""
        blocks = {
            '0x1000': _block('0x1000', size=0, successors=[], instruction_count=1),
        }
        result = normalize_ida_cfg(blocks)
        assert '0x1000' in result

    def test_clean_dangling_successors(self):
        """Successor references to removed zero-size blocks are cleaned up."""
        # A at 0x1000 points to both 0x100a (valid) and 0x2000 (zero-size, will be removed)
        blocks = {
            '0x1000': _block('0x1000', size=10, successors=['0x100a', '0x2000'], instruction_count=3),
            '0x100a': _block('0x100a', size=8, successors=[], instruction_count=2),
            '0x2000': _block('0x2000', size=0, successors=[], instruction_count=0),
        }
        result = normalize_ida_cfg(blocks)
        assert '0x2000' not in result
        assert '0x2000' not in result['0x1000'].successors
        assert '0x100a' in result['0x1000'].successors

    def test_successors_sorted(self):
        """Successors are in ascending address order after normalization."""
        blocks = {
            '0x1000': _block('0x1000', size=10, successors=['0x2000', '0x1010']),
            '0x1010': _block('0x1010', size=8, successors=[]),
            '0x2000': _block('0x2000', size=8, successors=[]),
        }
        result = normalize_ida_cfg(blocks)
        succs = result['0x1000'].successors
        assert succs == sorted(succs, key=lambda x: int(x, 16))


# ---------------------------------------------------------------------------
# Ghidra normalization tests (skipped when mcpyghidra is not importable)
# ---------------------------------------------------------------------------

try:
    from mcpyghidra.tools.cfg import normalize_ghidra_cfg as _normalize_ghidra_cfg  # type: ignore[import]
    from mcpyghidra.models import BasicBlock as _GhidraBasicBlock  # type: ignore[import]
    _GHIDRA_AVAILABLE = True
except ImportError:
    _normalize_ghidra_cfg = None  # type: ignore[assignment]
    _GhidraBasicBlock = BasicBlock  # fall back to IDA model for collection
    _GHIDRA_AVAILABLE = False


def _ghidra_block(
    address: str,
    size: int,
    successors: list[str] | None = None,
    instruction_count: int = 1,
    called_funcs: dict[str, str] | None = None,
    strings: list[str] | None = None,
) -> BasicBlock:
    return _GhidraBasicBlock(  # type: ignore[return-value]
        address=address,
        size=size,
        successors=successors or [],
        instruction_count=instruction_count,
        called_funcs=called_funcs or {},
        strings=strings or [],
    )


_skip_ghidra = pytest.mark.skipif(
    not _GHIDRA_AVAILABLE,
    reason='mcpyghidra not importable from this project — run in MCPyGhidra to execute Ghidra tests',
)


@_skip_ghidra
class TestGhidraNormalization:
    """Tests for normalize_ghidra_cfg (skipped when mcpyghidra is not importable)."""

    def test_empty_cfg_unchanged(self):
        """Empty blocks dict returns empty dict."""
        result = _normalize_ghidra_cfg({}, function_start=0x1000, function_end=0x2000)
        assert result == {}

    def test_single_block_no_change(self):
        """Single block with no successors passes through unchanged."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=20, successors=[], instruction_count=5),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x1014)
        assert len(result) == 1
        assert result['0x1000'].size == 20

    def test_no_change_when_no_merges_needed(self):
        """Blocks with multiple predecessors or non-contiguous successors stay unchanged."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a', '0x2000']),
            '0x100a': _ghidra_block('0x100a', size=10, successors=['0x3000']),
            '0x2000': _ghidra_block('0x2000', size=10, successors=['0x100a']),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x2100)
        assert len(result) == 3

    def test_merge_single_contiguous_successor(self):
        """Block A (size 10) followed immediately by B (size 10, 1 predecessor) merges to size 20."""
        # function_end=0x3000 ensures the external successor 0x2000 is not filtered
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a'], instruction_count=3),
            '0x100a': _ghidra_block('0x100a', size=10, successors=['0x2000'], instruction_count=4),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x3000)
        assert len(result) == 1
        merged = result['0x1000']
        assert merged.size == 20
        assert merged.successors == ['0x2000']

    def test_no_merge_when_successor_has_multiple_predecessors(self):
        """Don't merge when the successor has more than one predecessor."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a']),
            '0x100a': _ghidra_block('0x100a', size=10, successors=['0x3000']),
            '0x2000': _ghidra_block('0x2000', size=10, successors=['0x100a']),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x2100)
        assert len(result) == 3

    def test_no_merge_when_successor_not_contiguous(self):
        """Don't merge if successor address does not immediately follow the block."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x1020']),
            '0x1020': _ghidra_block('0x1020', size=10, successors=[]),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x102a)
        assert len(result) == 2

    def test_no_merge_when_multiple_successors(self):
        """Don't merge when the block has multiple successors (conditional branch)."""
        # function_end=0x4000 ensures neither 0x2000 nor 0x3000 is filtered
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a', '0x2000']),
            '0x100a': _ghidra_block('0x100a', size=10, successors=['0x3000']),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x4000)
        assert len(result) == 2

    def test_recursive_merge_chain(self):
        """Three contiguous single-predecessor blocks A→B→C merge into one block."""
        # function_end=0x3000 ensures the external successor 0x2000 is not filtered
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=5, successors=['0x1005'], instruction_count=2),
            '0x1005': _ghidra_block('0x1005', size=5, successors=['0x100a'], instruction_count=2),
            '0x100a': _ghidra_block('0x100a', size=5, successors=['0x2000'], instruction_count=2),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x3000)
        assert len(result) == 1
        merged = result['0x1000']
        assert merged.size == 15
        assert merged.successors == ['0x2000']
        assert merged.instruction_count == 6

    def test_merge_combines_called_funcs(self):
        """Merged blocks combine their called_funcs dictionaries."""
        blocks = {
            '0x1000': _ghidra_block(
                '0x1000', size=10, successors=['0x100a'],
                called_funcs={'0x4000': 'printf'},
            ),
            '0x100a': _ghidra_block(
                '0x100a', size=10, successors=['0x2000'],
                called_funcs={'0x4010': 'strcmp'},
            ),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x1014)
        assert len(result) == 1
        assert result['0x1000'].called_funcs == {'0x4000': 'printf', '0x4010': 'strcmp'}

    def test_merge_combines_strings(self):
        """Merged blocks combine their strings lists."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a'], strings=['hello']),
            '0x100a': _ghidra_block('0x100a', size=10, successors=[], strings=['world']),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x1014)
        assert len(result) == 1
        merged_strings = result['0x1000'].strings
        assert 'hello' in merged_strings
        assert 'world' in merged_strings

    def test_merge_sums_instruction_counts(self):
        """Merged block instruction_count equals the sum of all absorbed blocks."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=8, successors=['0x1008'], instruction_count=3),
            '0x1008': _ghidra_block('0x1008', size=8, successors=[], instruction_count=5),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x1010)
        assert result['0x1000'].instruction_count == 8

    def test_filter_out_of_function_successors(self):
        """Successors outside [function_start, function_end) are removed."""
        # C at 0x1020 also points to 0x1010 so 0x1010 has 2 predecessors — no merge
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=16, successors=['0x1010', '0x4000']),
            '0x1010': _ghidra_block('0x1010', size=16, successors=[]),
            '0x1020': _ghidra_block('0x1020', size=16, successors=['0x1010']),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x1030)
        assert '0x4000' not in result['0x1000'].successors
        assert '0x1010' in result['0x1000'].successors

    def test_filter_all_out_of_function_successors(self):
        """If all successors are out-of-range they are all removed."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x4000', '0x5000']),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x100a)
        assert result['0x1000'].successors == []

    def test_merge_then_filter_out_of_function_successor(self):
        """After merge, inherited out-of-function successors are already filtered."""
        # A at 0x1000 size 10 -> B at 0x100a size 10, successors=['0x1014', '0x4000']
        # B has 1 predecessor (A)
        # 0x1014 block exists (and has 2 predecessors via D, preventing a second merge)
        # 0x4000 is outside function range [0x1000, 0x1020)
        # After normalization: merged block at 0x1000 size 20, succs=['0x1014']
        # 0x4000 should be filtered (was on B, which got absorbed)
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a'], instruction_count=3),
            '0x100a': _ghidra_block('0x100a', size=10, successors=['0x1014', '0x4000'], instruction_count=4),
            '0x1014': _ghidra_block('0x1014', size=12, successors=[], instruction_count=3),
            # D also jumps to 0x1014, giving it 2 predecessors so it is not absorbed
            '0x1020': _ghidra_block('0x1020', size=10, successors=['0x1014'], instruction_count=2),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x102a)
        # B must have been absorbed into A
        assert '0x100a' not in result
        merged = result['0x1000']
        assert merged.size == 20
        assert merged.instruction_count == 7
        # 0x1014 is in-range so it survives; 0x4000 is out-of-range and must be gone
        assert '0x1014' in merged.successors
        assert '0x4000' not in merged.successors

    def test_call_plus_branch_no_merge_filters_call_target(self):
        """Block with call+PLT successor then fall-through: filter-first enables merge.

        Filter pass removes OOF PLT target 0x4000 from A before the merge pass
        runs.  After filtering A has exactly one successor (the contiguous fall-
        through 0x100a), so the merge pass absorbs B into A — matching IDA
        semantics where the post-call split does not produce a boundary.
        """
        # A at 0x1000 size 10, succs=['0x100a', '0x4000']  (fall-through + PLT call target)
        # B at 0x100a size 10, succs=[]
        # 0x4000 is outside function range [0x1000, 0x1020)
        # Pass 1 (filter): 0x4000 removed from A → A succs=['0x100a']
        # Pass 2 (merge): A has 1 contiguous succ with 1 predecessor → merge
        # Final: single block at 0x1000 size 20
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x100a', '0x4000'], instruction_count=3),
            '0x100a': _ghidra_block('0x100a', size=10, successors=[], instruction_count=4),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x1020)
        # After filter+merge only the absorbing block remains
        assert len(result) == 1
        assert '0x1000' in result
        merged = result['0x1000']
        assert merged.size == 20
        assert merged.instruction_count == 7
        assert merged.successors == []
        # PLT target must be gone
        assert '0x4000' not in merged.successors

    def test_successors_sorted_after_normalization(self):
        """Successors are in ascending address order after normalization."""
        blocks = {
            '0x1000': _ghidra_block('0x1000', size=10, successors=['0x2000', '0x1010']),
            '0x1010': _ghidra_block('0x1010', size=10, successors=[]),
            '0x2000': _ghidra_block('0x2000', size=10, successors=[]),
        }
        result = _normalize_ghidra_cfg(blocks, function_start=0x1000, function_end=0x2100)
        succs = result['0x1000'].successors
        assert succs == sorted(succs, key=lambda x: int(x, 16))
