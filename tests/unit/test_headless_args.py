"""Unit tests for mcpyida.headless argument handling.

These exercise validation that runs BEFORE the (expensive, IDA-only) idalib
import, so they need neither idapro nor a running IDA.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

import mcpyida.headless as headless
from tests.conftest import CRACKME_ELF


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, 'argv', argv)
    with pytest.raises(SystemExit) as exc:
        headless.main()
    return exc.value.code


def test_binary_is_positional_flag_form_rejected(monkeypatch, capsys):
    # --binary no longer exists; passing it is an argparse error (exit 2).
    code = _run(monkeypatch, ['mcpyida-headless', '--binary', CRACKME_ELF])
    assert code == 2
    assert 'unrecognized arguments' in capsys.readouterr().err


def test_missing_binary_emits_structured_error(monkeypatch, capsys):
    code = _run(monkeypatch, ['mcpyida-headless', '/no/such/binary.elf'])
    out = capsys.readouterr().out
    assert json.loads(out)['reason'] == 'binary_not_found'
    assert code == 3


def test_invalid_port_emits_structured_error(monkeypatch, capsys):
    code = _run(monkeypatch, ['mcpyida-headless', CRACKME_ELF, '--port', 'abc'])
    out = capsys.readouterr().out
    assert json.loads(out)['reason'] == 'bad_port'
    assert code == 5


def test_idb_path_whitespace_is_argparse_error(monkeypatch, capsys):
    code = _run(
        monkeypatch,
        ['mcpyida-headless', CRACKME_ELF, '--idb-path', '/tmp/has space/db.i64'],
    )
    # Pure usage error -> argparse exit 2 (unchanged).
    assert code == 2
    err = capsys.readouterr().err
    assert '--idb-path' in err and 'whitespace' in err


def test_bad_ida_dir_emits_missing_install_dir(monkeypatch, capsys):
    code = _run(
        monkeypatch,
        ['mcpyida-headless', CRACKME_ELF, '--ida-dir', '/no/such/ida/dir'],
    )
    out = capsys.readouterr().out
    assert json.loads(out)['reason'] == 'missing_install_dir'
    assert code == 4


def test_good_ida_dir_sets_idadir(monkeypatch, tmp_path, capsys):
    # A dir that contains libidalib.so passes the up-front check and sets IDADIR.
    # Force `import idapro` to fail DETERMINISTICALLY (None in sys.modules) so the
    # test is independent of whether idalib is installed in this env — CI's unit
    # image HAS idapro, a dev box may not. Without this, main() would run real
    # idalib calls against the fake --ida-dir (hang / no SystemExit).
    (tmp_path / 'libidalib.so').write_bytes(b'')
    monkeypatch.delenv('IDADIR', raising=False)
    monkeypatch.setitem(sys.modules, 'idapro', None)
    code = _run(
        monkeypatch,
        ['mcpyida-headless', CRACKME_ELF, '--ida-dir', str(tmp_path)],
    )
    # IDADIR was set (before the import); then `import idapro` fails ->
    # structured missing_install_dir, exit 4.
    assert os.environ.get('IDADIR') == str(tmp_path)
    assert code == 4
    assert json.loads(capsys.readouterr().out)['reason'] == 'missing_install_dir'
