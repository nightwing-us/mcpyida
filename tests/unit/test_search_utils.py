"""Unit tests for search utilities — no runtime required."""
import pytest
from mcpyida.tools.search_utils import parse_byte_pattern, match_operand


class TestParseBytePattern:
    def test_exact_bytes(self):
        data, mask = parse_byte_pattern('48 8B 05')
        assert data == bytes([0x48, 0x8B, 0x05])
        assert mask == bytes([0xFF, 0xFF, 0xFF])

    def test_wildcards(self):
        data, mask = parse_byte_pattern('48 ?? 05')
        assert data == bytes([0x48, 0x00, 0x05])
        assert mask == bytes([0xFF, 0x00, 0xFF])

    def test_all_wildcards(self):
        data, mask = parse_byte_pattern('?? ?? ??')
        assert mask == bytes([0x00, 0x00, 0x00])

    def test_single_byte(self):
        data, mask = parse_byte_pattern('90')
        assert data == bytes([0x90])
        assert mask == bytes([0xFF])

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_byte_pattern('')

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            parse_byte_pattern('GG')

    def test_case_insensitive(self):
        data, mask = parse_byte_pattern('4a Bc')
        assert data == bytes([0x4A, 0xBC])

    def test_extra_whitespace(self):
        data, mask = parse_byte_pattern('  48   8B   05  ')
        assert data == bytes([0x48, 0x8B, 0x05])


class TestMatchOperand:
    def test_wildcard(self):
        assert match_operand('*', 'RAX') is True

    def test_exact_match(self):
        assert match_operand('RAX', 'RAX') is True
        assert match_operand('RAX', 'RBX') is False

    def test_case_insensitive(self):
        assert match_operand('rax', 'RAX') is True

    def test_glob_star(self):
        assert match_operand('R*', 'RAX') is True
        assert match_operand('R*', 'RBP') is True
        assert match_operand('R*', 'EAX') is False

    def test_glob_question(self):
        assert match_operand('R?X', 'RAX') is True
        assert match_operand('R?X', 'RBX') is True
        assert match_operand('R?X', 'RBP') is False

    def test_regex(self):
        assert match_operand('/.*0xDEAD.*/', 'dword ptr [0xDEADBEEF]') is True
        assert match_operand('/.*0xDEAD.*/', 'RAX') is False

    def test_regex_case_insensitive(self):
        assert match_operand('/r[a-d]x/', 'RAX') is True
        assert match_operand('/r[a-d]x/', 'RCX') is True

    def test_memory_glob(self):
        assert match_operand('[*]', '[RBP + -0x4]') is True
