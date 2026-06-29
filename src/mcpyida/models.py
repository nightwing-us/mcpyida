"""Pydantic models for MCPyIDA.

This module contains only pydantic BaseModel subclasses and the Literal type
aliases they depend on.  It has NO IDA/ida_* imports, so it can be imported
in any Python environment (tests, tooling, etc.) without a running IDA Pro
instance.
"""

from __future__ import annotations

import sys
from typing import (
    Dict,
    List,
    Literal,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

if sys.version_info >= (3, 12):
    from .custom_types_312 import JsonValueTypes
else:
    from .custom_types_p312 import JsonValueTypes


# ---------------------------------------------------------------------------
# Literal type aliases
# ---------------------------------------------------------------------------

EntryTypes = Literal[
    'function',
    'memory_segment',
    'import',
    'export',
    'string',
    'class',
    'namespace',
    'cross-reference',
    'type',
]

SymbolTypes = Literal[
    'function',
    'code_label',
    'global_variable',
    'data_label',
    'unknown',
]


# ---------------------------------------------------------------------------
# Pagination models
# ---------------------------------------------------------------------------

page_limit = 500


class PageInfo(BaseModel):
    offset: int = Field(0, description='Starting position for pagination.')
    limit: int | None = Field(
        page_limit, description='Maximum results to return. None for no limit.'
    )

    def __str__(self) -> str:
        return f'offset={self.offset}, limit={self.limit}'


class ResultPageInfo(PageInfo):
    num_returned: int
    total_count: int
    has_more: bool
    next_offset: int | None = None


class ListResult(BaseModel):
    summary: str
    entry_type: EntryTypes
    schema_version: Literal[1]
    page_info: ResultPageInfo
    items: List[Dict[str, JsonValueTypes]]


# ---------------------------------------------------------------------------
# Function / location models
# ---------------------------------------------------------------------------


class FunctionInfo(BaseModel):
    name: str
    entrypoint: str = Field(description='The hex entry point of the function')
    signature: str | None = None


class CurrentLocation(BaseModel):
    addr: str = Field(description='Hex address of the current location')
    function: FunctionInfo | None = None


# ---------------------------------------------------------------------------
# Binary context models
# ---------------------------------------------------------------------------


class ProgramInfo(BaseModel):
    """Information about the binary file being analyzed."""

    file_path: str | None = Field(description='Full path to the original binary file')
    file_name: str = Field(description='Base name of the binary file')
    file_format: str = Field(description='Binary format (PE, ELF, Mach-O, COFF, etc.)')
    file_size: int | None = Field(description='File size in bytes, None if unavailable')
    md5: str | None = Field(description='MD5 hash of the binary', default=None)


class ArchitectureInfo(BaseModel):
    """Architecture and platform information."""

    processor: str = Field(description='Processor type (x86, ARM, MIPS, etc.)')
    bitness: int = Field(description='Address size in bits (16, 32, 64)')
    endianness: str = Field(description='Byte order (little, big)')
    compiler: str | None = Field(
        description='Detected compiler if available', default=None
    )


class MemoryLayout(BaseModel):
    """Memory address space layout."""

    image_base: str = Field(description='Base address where binary is loaded (hex)')
    entry_point: str = Field(description='Program entry point address (hex)')
    min_address: str = Field(description='Lowest address in address space (hex)')
    max_address: str = Field(description='Highest address in address space (hex)')


class AnalysisState(BaseModel):
    """Current state of binary analysis."""

    database_path: str = Field(description='Path to the analysis database/project file')
    function_count: int = Field(description='Total number of functions identified')
    has_debug_symbols: bool = Field(description='Whether debug symbols are present')
    has_type_libraries: bool = Field(description='Whether type libraries are loaded')
    analysis_complete: bool | None = Field(
        description='Whether auto-analysis is complete', default=None
    )


class ApplicationInfo(BaseModel):
    """Information about the RE application."""

    name: str = Field(description="Application name (e.g., 'IDA Pro')")
    version: str = Field(description='Application version')


class BinaryContext(BaseModel):
    """Complete context about the currently open binary."""

    current_location: CurrentLocation = Field(
        description='Current cursor position and function'
    )
    program: ProgramInfo = Field(description='Binary file information')
    architecture: ArchitectureInfo = Field(
        description='Architecture and platform details'
    )
    memory: MemoryLayout = Field(description='Memory address space layout')
    analysis: AnalysisState = Field(description='Analysis progress and state')
    application: ApplicationInfo = Field(description='RE application info')


# ---------------------------------------------------------------------------
# Symbol model
# ---------------------------------------------------------------------------


class SymbolInfo(BaseModel):
    name: str
    symbol_type: SymbolTypes


# ---------------------------------------------------------------------------
# Type discovery models
# ---------------------------------------------------------------------------


class TypeSummary(BaseModel):
    name: str = Field(description="Short name (e.g., 'istream')")
    full_path: str = Field(description="Full path (e.g., 'std::istream')")
    type_string: str = Field(description='Exact string to pass to type-setting tools')
    kind: str = Field(description='Normalized type kind')
    size: int | None = Field(description='Size in bytes, None if unknown/variable')


class MemberInfo(BaseModel):
    name: str = Field(description='Member name')
    type_string: str = Field(description='Member type')
    offset: int = Field(description='Byte offset within struct/union')
    size: int | None = Field(description='Member size in bytes')


class EnumValue(BaseModel):
    name: str = Field(description='Enum member name')
    value: int = Field(description='Enum member value')


class TypeDetails(BaseModel):
    name: str = Field(description='Short name')
    full_path: str = Field(description='Full path')
    type_string: str = Field(description='Exact string to pass to type-setting tools')
    kind: str = Field(description='Normalized type kind')
    size: int | None = Field(description='Size in bytes, None if unknown/variable')
    comment: str | None = Field(description='Type comment/documentation')
    members: list[MemberInfo] | None = Field(
        description='Struct/union members', default=None
    )
    values: list[EnumValue] | None = Field(description='Enum values', default=None)
    underlying_type: str | None = Field(
        description='Underlying type for typedefs', default=None
    )


# ---------------------------------------------------------------------------
# Structure mutation models
# ---------------------------------------------------------------------------


class StructureFieldInput(BaseModel):
    """Input specification for a structure field."""

    name: str = Field(description='Field name')
    type: str = Field(description="C type string (e.g., 'int', 'char *')")
    offset: int = Field(description='Byte offset within structure')
    comment: str = Field(default='', description='Optional field comment')


class StructureCreationResult(BaseModel):
    """Result of structure creation."""

    name: str = Field(description='Structure name')
    size: int = Field(description='Structure size in bytes')
    created: bool = Field(description='True if newly created, False if already existed')
    message: str = Field(description='Status message')


class FieldAdditionResult(BaseModel):
    """Result of adding a field to a structure."""

    struct_name: str = Field(description='Structure name')
    field_name: str = Field(description='Field name added')
    offset: int = Field(description='Byte offset of field')
    size: int = Field(description='Size of field in bytes')
    success: bool = Field(description='True if field was added successfully')
    message: str = Field(description='Status message or error description')


# ---------------------------------------------------------------------------
# Elicitation models
# ---------------------------------------------------------------------------


class ConfirmAction(BaseModel):
    """Schema for elicitation confirmation prompts."""

    confirm: bool = Field(description='Confirm this action')
    apply_to_all: bool = Field(
        default=False,
        description='Apply this choice to all remaining items in this batch',
    )


# ---------------------------------------------------------------------------
# Script execution models
# ---------------------------------------------------------------------------


class ScriptResult(BaseModel):
    """Result from pyghidra/idapython script execution."""

    result: str | None = Field(
        default=None, description='Last expression value (Jupyter-style eval)'
    )
    stdout: str = Field(default='', description='Captured stdout output')
    stderr: str = Field(default='', description='Captured stderr output')
    output: str = Field(
        default='', description='Interleaved stdout+stderr in execution order'
    )
    success: bool = Field(default=True, description='False if an exception occurred')
    error: str | None = Field(default=None, description='Exception message if failed')
    error_traceback: str | None = Field(
        default=None, description='Full traceback if failed'
    )


# ---------------------------------------------------------------------------
# CFG models
# ---------------------------------------------------------------------------


class BasicBlock(BaseModel):
    """A single basic block in a control flow graph."""

    address: str
    size: int
    successors: list[str] = Field(default_factory=list)
    instruction_count: int = 0
    called_funcs: dict[str, str] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)
    bytes: str | None = Field(
        default=None,
        description='Base64-encoded raw bytes (only when include_bytes=True)',
    )
    instructions: list[dict[str, str]] | None = Field(
        default=None,
        description='Instruction list (only when include_disassembly=True)',
    )


class CFGFeatures(BaseModel):
    """Function-level aggregated features from all blocks."""

    instruction_count: int = 0
    called_funcs: dict[str, str] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)


class CFGResult(BaseModel):
    """Complete control flow graph for a single function."""

    entry: str
    block_count: int = 0
    blocks: dict[str, BasicBlock] = Field(default_factory=dict)
    features: CFGFeatures = Field(default_factory=CFGFeatures)


# ---------------------------------------------------------------------------
# Callgraph models
# ---------------------------------------------------------------------------


class CallgraphNode(BaseModel):
    """A function node in a call graph."""

    addr: str
    name: str
    depth: int


class CallgraphEdge(BaseModel):
    """A call edge in a call graph."""

    model_config = ConfigDict(populate_by_name=True)

    from_addr: str = Field(alias='from', description='Caller address (hex)')
    to_addr: str = Field(alias='to', description='Callee address (hex)')


class CallgraphResult(BaseModel):
    """Result of a call graph traversal."""

    root: str
    direction: str
    nodes: list[CallgraphNode] = Field(default_factory=list)
    edges: list[CallgraphEdge] = Field(default_factory=list)
    truncated: bool = False
    limit_reason: Literal['depth', 'nodes', 'edges'] | None = None
