"""Unit tests for the structured headless status/error contract (no IDA)."""
import json

import pytest

from mcpyida.cli_status import EXIT_CODES, emit_error, emit_ready


def test_emit_ready_prints_ready_json(capsys):
    emit_ready('127.0.0.1', 6150, '/path/to/bin')
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload == {
        'status': 'ready',
        'host': '127.0.0.1',
        'port': 6150,
        'binary': '/path/to/bin',
    }


def test_emit_error_prints_error_json_to_stdout_and_returns_code(capsys):
    code = emit_error('binary_not_found', 'binary not found: /x')
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == {
        'status': 'error',
        'reason': 'binary_not_found',
        'detail': 'binary not found: /x',
    }
    assert code == 3


def test_emit_error_remediation_goes_to_stderr(capsys):
    emit_error('bad_port', 'bad', remediation='use N, N-M, or 0')
    captured = capsys.readouterr()
    assert 'use N, N-M, or 0' in captured.err
    assert 'use N, N-M, or 0' not in captured.out  # remediation is NOT in the JSON


def test_unknown_reason_maps_to_one(capsys):
    assert emit_error('totally_unknown', 'x') == 1


@pytest.mark.parametrize(
    'reason,code',
    [
        ('binary_not_found', 3),
        ('missing_install_dir', 4),
        ('bad_port', 5),
        ('port_unavailable', 6),
        ('open_failed', 7),
        ('jvm_not_found', 8),
        ('internal', 1),
    ],
)
def test_exit_code_map(reason, code):
    assert EXIT_CODES[reason] == code
