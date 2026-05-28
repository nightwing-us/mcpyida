"""Tests for structure creation and modification tools."""
import pytest
from pydantic import ValidationError

from mcpyida.models import (
    FieldAdditionResult,
    StructureCreationResult,
    StructureFieldInput,
)


class TestCreateStruct:
    """Tests for create_struct MCP tool."""

    def test_create_struct_returns_creation_result(self):
        """create_struct should return StructureCreationResult with correct fields."""
        result = StructureCreationResult(
            name="TestStruct",
            size=16,
            created=True,
            message="Structure created successfully"
        )

        assert result.name == "TestStruct"
        assert result.size == 16
        assert result.created is True

    def test_structure_field_input_validation(self):
        """StructureFieldInput should validate required fields."""
        field = StructureFieldInput(
            name="test_field",
            type="int",
            offset=8
        )

        assert field.name == "test_field"
        assert field.type == "int"
        assert field.offset == 8
        assert field.comment == ""  # Default

    def test_structure_field_input_rejects_missing_offset(self):
        """StructureFieldInput should require offset."""
        with pytest.raises(ValidationError):
            StructureFieldInput(name="test", type="int")  # Missing offset


class TestAddStructField:
    """Tests for add_struct_field MCP tool."""

    def test_field_addition_result_model(self):
        """FieldAdditionResult should have correct fields."""
        result = FieldAdditionResult(
            struct_name="TestStruct",
            field_name="new_field",
            offset=16,
            size=4,
            success=True,
            message="Field added successfully"
        )

        assert result.struct_name == "TestStruct"
        assert result.field_name == "new_field"
        assert result.offset == 16
        assert result.size == 4
        assert result.success is True
