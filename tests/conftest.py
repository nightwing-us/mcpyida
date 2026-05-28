"""Shared pytest configuration and markers."""
import os

import pytest


def _can_import(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


requires_ida = pytest.mark.skipif(
    not _can_import('idapro'),
    reason='idalib not available (install idapro pip package)',
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')
CRACKME_ELF = os.path.join(FIXTURES_DIR, 'crackme.elf')
TYPED_FIXTURE_ELF = os.path.join(FIXTURES_DIR, 'typed_fixture.elf')
STRUCT_TEST_ELF = os.path.join(FIXTURES_DIR, 'struct_test.elf')
