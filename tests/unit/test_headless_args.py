"""Unit tests for mcpyida.headless argument handling.

These exercise the argparse-level validation that runs BEFORE the (expensive,
IDA-only) idalib import, so they need neither idapro nor a running IDA.
"""
from __future__ import annotations

import sys

import pytest

import mcpyida.headless as headless
from tests.conftest import CRACKME_ELF


def test_idb_path_with_whitespace_is_rejected(monkeypatch, capsys):
    """--idb-path containing whitespace fails fast (IDA splits -o on spaces)."""
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'mcpyida-headless',
            '--binary',
            CRACKME_ELF,
            '--idb-path',
            '/tmp/has space/db.i64',
        ],
    )
    with pytest.raises(SystemExit) as exc:
        headless.main()

    # argparse parser.error() exits with code 2.
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert '--idb-path' in err
    assert 'whitespace' in err


def test_missing_binary_is_rejected(monkeypatch, capsys):
    """A non-existent --binary fails before any idalib work."""
    monkeypatch.setattr(
        sys,
        'argv',
        ['mcpyida-headless', '--binary', '/no/such/binary.elf'],
    )
    with pytest.raises(SystemExit) as exc:
        headless.main()

    assert exc.value.code == 1
    assert 'binary not found' in capsys.readouterr().err
