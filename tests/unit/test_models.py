"""Unit tests for pydantic models in mcpyida.models.

These tests do NOT require IDA Pro or any ida_* runtime — models.py has no
IDA imports so it can be imported directly in any Python environment.
"""
from __future__ import annotations

import pytest

from mcpyida.models import (
    AnalysisState,
    ApplicationInfo,
    ArchitectureInfo,
    BasicBlock,
    BinaryContext,
    CallgraphEdge,
    CallgraphNode,
    CallgraphResult,
    CFGFeatures,
    CFGResult,
    CurrentLocation,
    EnumValue,
    FieldAdditionResult,
    FunctionInfo,
    ListResult,
    MemberInfo,
    MemoryLayout,
    PageInfo,
    page_limit,
    ProgramInfo,
    ResultPageInfo,
    ScriptResult,
    StructureCreationResult,
    SymbolInfo,
    TypeDetails,
    TypeSummary,
)


class TestFunctionInfo:
    def test_required_fields(self):
        fi = FunctionInfo(name='main', entrypoint='0x00401000')
        assert fi.name == 'main'
        assert fi.entrypoint == '0x00401000'

    def test_signature_defaults_none(self):
        fi = FunctionInfo(name='foo', entrypoint='0x1234')
        assert fi.signature is None

    def test_signature_provided(self):
        fi = FunctionInfo(name='foo', entrypoint='0x1234', signature='int foo(void)')
        assert fi.signature == 'int foo(void)'

    def test_missing_name_raises(self):
        with pytest.raises(Exception):
            FunctionInfo(entrypoint='0x1234')  # type: ignore[call-arg]

    def test_missing_entrypoint_raises(self):
        with pytest.raises(Exception):
            FunctionInfo(name='main')  # type: ignore[call-arg]


class TestSymbolInfo:
    def test_required_fields(self):
        si = SymbolInfo(name='main', symbol_type='function')
        assert si.name == 'main'
        assert si.symbol_type == 'function'

    def test_valid_symbol_types(self):
        for stype in ('function', 'code_label', 'global_variable', 'data_label', 'unknown'):
            si = SymbolInfo(name='x', symbol_type=stype)
            assert si.symbol_type == stype

    def test_invalid_symbol_type_raises(self):
        with pytest.raises(Exception):
            SymbolInfo(name='x', symbol_type='not_a_real_type')  # type: ignore[arg-type]


class TestPageInfo:
    def test_defaults(self):
        pi = PageInfo()
        assert pi.offset == 0
        # limit defaults to page_limit (500)
        assert pi.limit == page_limit

    def test_custom_values(self):
        pi = PageInfo(offset=10, limit=50)
        assert pi.offset == 10
        assert pi.limit == 50

    def test_limit_none(self):
        pi = PageInfo(offset=0, limit=None)
        assert pi.limit is None


class TestResultPageInfo:
    def test_construction(self):
        rpi = ResultPageInfo(
            offset=0,
            limit=10,
            num_returned=5,
            total_count=100,
            has_more=True,
            next_offset=10,
        )
        assert rpi.num_returned == 5
        assert rpi.total_count == 100
        assert rpi.has_more is True
        assert rpi.next_offset == 10

    def test_next_offset_defaults_none(self):
        rpi = ResultPageInfo(
            offset=0,
            limit=10,
            num_returned=5,
            total_count=5,
            has_more=False,
        )
        assert rpi.next_offset is None


class TestListResult:
    def test_construction(self):
        rpi = ResultPageInfo(
            offset=0, limit=10, num_returned=1, total_count=1, has_more=False
        )
        lr = ListResult(
            summary='1 function(s)',
            entry_type='function',
            schema_version=1,
            page_info=rpi,
            items=[{'name': 'main', 'entrypoint': '0x00401000'}],
        )
        assert lr.summary == '1 function(s)'
        assert lr.entry_type == 'function'
        assert lr.schema_version == 1
        assert len(lr.items) == 1

    def test_invalid_entry_type_raises(self):
        rpi = ResultPageInfo(
            offset=0, limit=10, num_returned=0, total_count=0, has_more=False
        )
        with pytest.raises(Exception):
            ListResult(
                summary='',
                entry_type='invalid_type',  # type: ignore[arg-type]
                schema_version=1,
                page_info=rpi,
                items=[],
            )

    def test_valid_entry_types(self):
        rpi = ResultPageInfo(
            offset=0, limit=10, num_returned=0, total_count=0, has_more=False
        )
        for etype in ('function', 'memory_segment', 'import', 'export',
                      'string', 'class', 'namespace', 'cross-reference'):
            lr = ListResult(
                summary='',
                entry_type=etype,
                schema_version=1,
                page_info=rpi,
                items=[],
            )
            assert lr.entry_type == etype


class TestTypeSummary:
    def test_required_fields(self):
        ts = TypeSummary(
            name='MyStruct',
            full_path='std::MyStruct',
            type_string='MyStruct',
            kind='struct',
            size=16,
        )
        assert ts.name == 'MyStruct'
        assert ts.full_path == 'std::MyStruct'
        assert ts.type_string == 'MyStruct'
        assert ts.kind == 'struct'
        assert ts.size == 16

    def test_size_can_be_none(self):
        ts = TypeSummary(
            name='void',
            full_path='void',
            type_string='void',
            kind='void',
            size=None,
        )
        assert ts.size is None


class TestMemberInfo:
    def test_construction(self):
        mi = MemberInfo(name='x', type_string='int', offset=0, size=4)
        assert mi.name == 'x'
        assert mi.type_string == 'int'
        assert mi.offset == 0
        assert mi.size == 4

    def test_size_can_be_none(self):
        mi = MemberInfo(name='flex', type_string='char[]', offset=8, size=None)
        assert mi.size is None


class TestEnumValue:
    def test_construction(self):
        ev = EnumValue(name='RED', value=0)
        assert ev.name == 'RED'
        assert ev.value == 0

    def test_negative_value(self):
        ev = EnumValue(name='ERR', value=-1)
        assert ev.value == -1


class TestTypeDetails:
    def test_minimal_construction(self):
        td = TypeDetails(
            name='int',
            full_path='int',
            type_string='int',
            kind='primitive',
            size=4,
            comment=None,
        )
        assert td.name == 'int'
        assert td.members is None
        assert td.values is None
        assert td.underlying_type is None

    def test_struct_with_members(self):
        members = [
            MemberInfo(name='x', type_string='int', offset=0, size=4),
            MemberInfo(name='y', type_string='int', offset=4, size=4),
        ]
        td = TypeDetails(
            name='Point',
            full_path='Point',
            type_string='Point',
            kind='struct',
            size=8,
            comment='2D point',
            members=members,
        )
        assert len(td.members) == 2
        assert td.members[0].name == 'x'

    def test_enum_with_values(self):
        values = [EnumValue(name='A', value=0), EnumValue(name='B', value=1)]
        td = TypeDetails(
            name='Color',
            full_path='Color',
            type_string='Color',
            kind='enum',
            size=4,
            comment=None,
            values=values,
        )
        assert len(td.values) == 2

    def test_typedef_with_underlying(self):
        td = TypeDetails(
            name='size_t',
            full_path='size_t',
            type_string='size_t',
            kind='typedef',
            size=8,
            comment=None,
            underlying_type='unsigned long',
        )
        assert td.underlying_type == 'unsigned long'


class TestStructureCreationResult:
    def test_created_true(self):
        r = StructureCreationResult(
            name='MyStruct',
            size=16,
            created=True,
            message='Structure created successfully',
        )
        assert r.name == 'MyStruct'
        assert r.size == 16
        assert r.created is True

    def test_already_existed(self):
        r = StructureCreationResult(
            name='ExistingStruct',
            size=8,
            created=False,
            message='Structure already exists',
        )
        assert r.created is False


class TestFieldAdditionResult:
    def test_success(self):
        r = FieldAdditionResult(
            struct_name='MyStruct',
            field_name='count',
            offset=0,
            size=4,
            success=True,
            message='Field added',
        )
        assert r.struct_name == 'MyStruct'
        assert r.field_name == 'count'
        assert r.offset == 0
        assert r.size == 4
        assert r.success is True

    def test_failure(self):
        r = FieldAdditionResult(
            struct_name='MyStruct',
            field_name='bad_field',
            offset=0,
            size=0,
            success=False,
            message='Type not found',
        )
        assert r.success is False


class TestBinaryContext:
    """BinaryContext composes all sub-models — test that it round-trips correctly."""

    def _make_context(self) -> BinaryContext:
        return BinaryContext(
            current_location=CurrentLocation(
                addr='0x00401000',
                function=FunctionInfo(name='main', entrypoint='0x00401000'),
            ),
            program=ProgramInfo(
                file_path='/tmp/crackme.elf',
                file_name='crackme.elf',
                file_format='ELF',
                file_size=12345,
                md5='d41d8cd98f00b204e9800998ecf8427e',
            ),
            architecture=ArchitectureInfo(
                processor='x86',
                bitness=64,
                endianness='little',
                compiler='gcc',
            ),
            memory=MemoryLayout(
                image_base='0x00400000',
                entry_point='0x00401000',
                min_address='0x00400000',
                max_address='0x00600000',
            ),
            analysis=AnalysisState(
                database_path='/tmp/crackme.i64',
                function_count=42,
                has_debug_symbols=False,
                has_type_libraries=True,
                analysis_complete=True,
            ),
            application=ApplicationInfo(
                name='IDA Pro',
                version='9.0',
            ),
        )

    def test_construction(self):
        ctx = self._make_context()
        assert ctx.current_location.addr == '0x00401000'
        assert ctx.program.file_name == 'crackme.elf'
        assert ctx.architecture.processor == 'x86'
        assert ctx.memory.image_base == '0x00400000'
        assert ctx.analysis.function_count == 42
        assert ctx.application.name == 'IDA Pro'

    def test_current_location_function_optional(self):
        ctx = BinaryContext(
            current_location=CurrentLocation(addr='0x00401000', function=None),
            program=ProgramInfo(
                file_path=None,
                file_name='test.elf',
                file_format='ELF',
                file_size=None,
            ),
            architecture=ArchitectureInfo(
                processor='x86', bitness=32, endianness='little'
            ),
            memory=MemoryLayout(
                image_base='0x0',
                entry_point='0x0',
                min_address='0x0',
                max_address='0xffff',
            ),
            analysis=AnalysisState(
                database_path='/tmp/x.i64',
                function_count=0,
                has_debug_symbols=False,
                has_type_libraries=False,
            ),
            application=ApplicationInfo(name='IDA Pro', version='9.0'),
        )
        assert ctx.current_location.function is None

    def test_analysis_complete_optional(self):
        ctx = self._make_context()
        # analysis_complete defaults to None when not provided
        ctx2 = BinaryContext(
            current_location=ctx.current_location,
            program=ctx.program,
            architecture=ctx.architecture,
            memory=ctx.memory,
            analysis=AnalysisState(
                database_path='/tmp/x.i64',
                function_count=0,
                has_debug_symbols=False,
                has_type_libraries=False,
            ),
            application=ctx.application,
        )
        assert ctx2.analysis.analysis_complete is None


class TestScriptResult:
    def test_defaults(self):
        sr = ScriptResult()
        assert sr.result is None
        assert sr.stdout == ''
        assert sr.stderr == ''
        assert sr.output == ''
        assert sr.success is True
        assert sr.error is None
        assert sr.error_traceback is None

    def test_success_with_result(self):
        sr = ScriptResult(result='42', stdout='hello\n', output='hello\n')
        assert sr.result == '42'
        assert sr.stdout == 'hello\n'
        assert sr.output == 'hello\n'
        assert sr.success is True

    def test_failure_fields(self):
        sr = ScriptResult(
            success=False,
            error='NameError: name x is not defined',
            error_traceback='Traceback (most recent call last):\n  ...\nNameError: name x is not defined',
            stderr='Traceback (most recent call last):\n  ...\nNameError: name x is not defined',
            output='Traceback (most recent call last):\n  ...\nNameError: name x is not defined',
        )
        assert sr.success is False
        assert sr.error == 'NameError: name x is not defined'
        assert sr.error_traceback is not None
        assert 'NameError' in sr.error_traceback

    def test_result_none_on_no_expression(self):
        sr = ScriptResult(stdout='side effect only\n', output='side effect only\n')
        assert sr.result is None
        assert sr.stdout == 'side effect only\n'

    def test_stderr_separate_from_stdout(self):
        sr = ScriptResult(
            stdout='out\n',
            stderr='err\n',
            output='out\nerr\n',
        )
        assert sr.stdout == 'out\n'
        assert sr.stderr == 'err\n'
        assert sr.output == 'out\nerr\n'


class TestBasicBlock:
    def test_minimal_construction(self):
        bb = BasicBlock(address='0x401000', size=16)
        assert bb.address == '0x401000'
        assert bb.size == 16
        assert bb.successors == []
        assert bb.instruction_count == 0
        assert bb.called_funcs == {}
        assert bb.strings == []
        assert bb.bytes is None
        assert bb.instructions is None

    def test_full_construction(self):
        bb = BasicBlock(
            address='0x401000',
            size=32,
            successors=['0x401020', '0x401040'],
            instruction_count=8,
            called_funcs={'0x402000': 'malloc'},
            strings=['hello'],
            bytes='AQIDBA==',
            instructions=[{'addr': '0x401000', 'mnem': 'push', 'op': 'rbp'}],
        )
        assert bb.successors == ['0x401020', '0x401040']
        assert bb.instruction_count == 8
        assert bb.called_funcs == {'0x402000': 'malloc'}
        assert bb.strings == ['hello']
        assert bb.bytes == 'AQIDBA=='
        assert bb.instructions is not None
        assert len(bb.instructions) == 1

    def test_missing_required_fields_raises(self):
        with pytest.raises(Exception):
            BasicBlock(size=16)  # type: ignore[call-arg]

        with pytest.raises(Exception):
            BasicBlock(address='0x401000')  # type: ignore[call-arg]


class TestCFGFeatures:
    def test_defaults(self):
        f = CFGFeatures()
        assert f.instruction_count == 0
        assert f.called_funcs == {}
        assert f.strings == []

    def test_full_construction(self):
        f = CFGFeatures(
            instruction_count=42,
            called_funcs={'0x402000': 'printf', '0x403000': 'malloc'},
            strings=['format string', 'error message'],
        )
        assert f.instruction_count == 42
        assert len(f.called_funcs) == 2
        assert len(f.strings) == 2


class TestCFGResult:
    def test_minimal_construction(self):
        result = CFGResult(entry='0x401000')
        assert result.entry == '0x401000'
        assert result.block_count == 0
        assert result.blocks == {}
        assert result.features.instruction_count == 0

    def test_with_blocks(self):
        bb0 = BasicBlock(address='0x401000', size=16, successors=['0x401010'], instruction_count=4)
        bb1 = BasicBlock(address='0x401010', size=8, instruction_count=2)
        result = CFGResult(
            entry='0x401000',
            block_count=2,
            blocks={
                '0x401000': bb0,
                '0x401010': bb1,
            },
            features=CFGFeatures(instruction_count=6),
        )
        assert result.block_count == 2
        assert len(result.blocks) == 2
        assert result.blocks['0x401000'].successors == ['0x401010']
        assert result.features.instruction_count == 6

    def test_nested_block_features(self):
        bb = BasicBlock(
            address='0x401000',
            size=20,
            instruction_count=5,
            called_funcs={'0x402000': 'puts'},
            strings=['hello world'],
        )
        result = CFGResult(
            entry='0x401000',
            block_count=1,
            blocks={'0x401000': bb},
            features=CFGFeatures(
                instruction_count=5,
                called_funcs={'0x402000': 'puts'},
                strings=['hello world'],
            ),
        )
        assert result.blocks['0x401000'].called_funcs == {'0x402000': 'puts'}
        assert result.features.called_funcs == {'0x402000': 'puts'}

    def test_missing_entry_raises(self):
        with pytest.raises(Exception):
            CFGResult()  # type: ignore[call-arg]


class TestCallgraphNode:
    def test_construction(self):
        node = CallgraphNode(addr='0x401000', name='main', depth=0)
        assert node.addr == '0x401000'
        assert node.name == 'main'
        assert node.depth == 0

    def test_nested_depth(self):
        node = CallgraphNode(addr='0x402000', name='helper', depth=3)
        assert node.depth == 3

    def test_missing_fields_raise(self):
        with pytest.raises(Exception):
            CallgraphNode(name='main', depth=0)  # type: ignore[call-arg]


class TestCallgraphEdge:
    def test_construction_with_alias(self):
        edge = CallgraphEdge(**{'from': '0x401000', 'to': '0x402000'})
        assert edge.from_addr == '0x401000'
        assert edge.to_addr == '0x402000'

    def test_construction_with_field_name(self):
        edge = CallgraphEdge(from_addr='0x401000', to_addr='0x402000')
        assert edge.from_addr == '0x401000'
        assert edge.to_addr == '0x402000'

    def test_serialization_uses_alias(self):
        edge = CallgraphEdge(**{'from': '0x401000', 'to': '0x402000'})
        data = edge.model_dump(by_alias=True)
        assert 'from' in data
        assert 'from_addr' not in data
        assert data['from'] == '0x401000'
        assert data['to'] == '0x402000'
        assert 'to_addr' not in data

    def test_serialization_without_alias(self):
        edge = CallgraphEdge(**{'from': '0x401000', 'to': '0x402000'})
        data = edge.model_dump()
        assert 'from_addr' in data
        assert data['from_addr'] == '0x401000'
        assert 'to_addr' in data
        assert data['to_addr'] == '0x402000'

    def test_callgraph_result_full_serialization(self):
        """Full result serialization produces correct edge keys."""
        result = CallgraphResult(
            root='0x401000',
            direction='callees',
            nodes=[CallgraphNode(addr='0x401000', name='main', depth=0)],
            edges=[CallgraphEdge(from_addr='0x401000', to_addr='0x402000')],
        )
        data = result.model_dump(by_alias=True)
        edge = data['edges'][0]
        assert 'from' in edge, 'Edge should serialize from_addr as "from"'
        assert 'to' in edge, 'Edge should serialize to_addr as "to"'
        assert 'from_addr' not in edge
        assert 'to_addr' not in edge

    def test_callgraph_edge_json_roundtrip(self):
        """Edge can be reconstructed from its own JSON."""
        edge = CallgraphEdge(from_addr='0x401000', to_addr='0x402000')
        json_str = edge.model_dump_json(by_alias=True)
        reconstructed = CallgraphEdge.model_validate_json(json_str)
        assert reconstructed.from_addr == '0x401000'
        assert reconstructed.to_addr == '0x402000'


class TestCallgraphResult:
    def test_minimal_construction(self):
        result = CallgraphResult(root='0x401000', direction='callees')
        assert result.root == '0x401000'
        assert result.direction == 'callees'
        assert result.nodes == []
        assert result.edges == []
        assert result.truncated is False
        assert result.limit_reason is None

    def test_full_construction(self):
        nodes = [
            CallgraphNode(addr='0x401000', name='main', depth=0),
            CallgraphNode(addr='0x402000', name='helper', depth=1),
        ]
        edges = [
            CallgraphEdge(**{'from': '0x401000', 'to': '0x402000'}),
        ]
        result = CallgraphResult(
            root='0x401000',
            direction='callees',
            nodes=nodes,
            edges=edges,
            truncated=True,
            limit_reason='nodes',
        )
        assert len(result.nodes) == 2
        assert len(result.edges) == 1
        assert result.truncated is True
        assert result.limit_reason == 'nodes'

    def test_callers_direction(self):
        result = CallgraphResult(root='0x402000', direction='callers')
        assert result.direction == 'callers'

    def test_missing_required_fields_raise(self):
        with pytest.raises(Exception):
            CallgraphResult(direction='callees')  # type: ignore[call-arg]

        with pytest.raises(Exception):
            CallgraphResult(root='0x401000')  # type: ignore[call-arg]
