"""Pattern parsing and matching utilities for search tools.

No platform-specific imports — pure Python.
"""

from __future__ import annotations

import fnmatch
import re


def parse_byte_pattern(pattern: str) -> tuple[bytes, bytes]:
    """Parse a byte pattern string into (data, mask) tuples.

    Pattern format: space-separated hex tokens, '??' for wildcard.
    Example: '48 8B ?? 05' -> (b'\\x48\\x8b\\x00\\x05', b'\\xff\\xff\\x00\\xff')
    """
    tokens = pattern.strip().split()
    if not tokens:
        raise ValueError('Empty byte pattern')

    data = bytearray()
    mask = bytearray()
    for token in tokens:
        if token in ('??', '?'):
            data.append(0x00)
            mask.append(0x00)
        else:
            try:
                val = int(token, 16)
                if val < 0 or val > 0xFF:
                    raise ValueError(f'Byte value out of range: {token}')
                data.append(val)
                mask.append(0xFF)
            except ValueError:
                raise ValueError(f'Invalid byte token: {token!r}')

    return bytes(data), bytes(mask)


def _glob_to_regex(pattern: str) -> str:
    """Translate a glob pattern to a regex string.

    Treats '[' and ']' as literals (not character classes), so patterns like
    '[*]' match bracket-enclosed content rather than acting as fnmatch char classes.
    """
    parts = []
    for ch in pattern:
        if ch == '*':
            parts.append('.*')
        elif ch == '?':
            parts.append('.')
        elif ch in r'\.+^${}|()\[\]':
            parts.append(re.escape(ch))
        else:
            parts.append(ch)
    return ''.join(parts)


def match_operand(pattern: str, actual: str) -> bool:
    """Match an operand string against a pattern.

    Patterns:
    - '*' matches anything
    - '/regex/' uses regex (case-insensitive)
    - Otherwise glob matching (case-insensitive); '[' and ']' are treated as
      literals so patterns like '[*]' match bracket-enclosed memory operands.
    """
    if pattern == '*':
        return True
    if pattern.startswith('/') and pattern.endswith('/') and len(pattern) > 2:
        try:
            return bool(re.match(pattern[1:-1], actual, re.IGNORECASE))
        except re.error:
            return False
    regex = _glob_to_regex(pattern.upper()) + '$'
    return bool(re.match(regex, actual.upper(), re.IGNORECASE))


def match_instruction(
    mnemonic_pattern: str,
    operand_patterns: list[str] | None,
    actual_mnemonic: str,
    actual_operands: list[str],
) -> bool:
    """Match an instruction against mnemonic + operand patterns."""
    # Check mnemonic
    if mnemonic_pattern != '*':
        if not fnmatch.fnmatch(actual_mnemonic.upper(), mnemonic_pattern.upper()):
            return False

    # Check operands
    if operand_patterns:
        for i, pat in enumerate(operand_patterns):
            if pat == '*':
                continue
            if i >= len(actual_operands):
                return False
            if not match_operand(pat, actual_operands[i]):
                return False

    return True
