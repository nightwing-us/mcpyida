"""Unit tests for portspec: --port parsing + parallel-safe socket binding.

Pure (no IDA): real sockets, no idalib. Proves parallel headless/GUI instances
land on distinct, actually-bindable ports in a configured range.
"""
import socket

import pytest

from mcpyida.portspec import (
    DEFAULT_PORT_RANGE,
    bind_listen_socket,
    parse_port_spec,
    resolve_port_spec,
)


# --- parse_port_spec ---------------------------------------------------------

def test_parse_range():
    assert parse_port_spec('6150-6159') == list(range(6150, 6160))


def test_parse_single_str_and_int():
    assert parse_port_spec('6150') == [6150]
    assert parse_port_spec(6150) == [6150]


def test_parse_zero_is_os_assign_sentinel():
    assert parse_port_spec('0') == [0]
    assert parse_port_spec(0) == [0]


def test_parse_strips_whitespace():
    assert parse_port_spec('  6150-6159 ') == list(range(6150, 6160))


def test_default_range_constant_parses():
    assert parse_port_spec(DEFAULT_PORT_RANGE) == list(range(6150, 6160))


@pytest.mark.parametrize('bad', ['abc', '6159-6150', '0-70000', '', '70000', '-5'])
def test_parse_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_port_spec(bad)


# --- bind_listen_socket ------------------------------------------------------

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_binds_requested_port_when_free():
    p = _free_port()
    sock, port = bind_listen_socket('127.0.0.1', [p])
    try:
        assert port == p
    finally:
        sock.close()


def test_skips_busy_port_to_next():
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    occupied.bind(('127.0.0.1', 0))
    occupied.listen(1)
    busy = occupied.getsockname()[1]
    try:
        sock, port = bind_listen_socket(
            '127.0.0.1', [busy, busy + 1, busy + 2, busy + 3]
        )
        try:
            assert port != busy
            assert port in (busy + 1, busy + 2, busy + 3)
        finally:
            sock.close()
    finally:
        occupied.close()


def test_exclude_skips_port():
    p = _free_port()
    sock, port = bind_listen_socket(
        '127.0.0.1', [p, p + 1, p + 2, p + 3], exclude={p}
    )
    try:
        assert port != p
    finally:
        sock.close()


def test_zero_os_assigns_a_real_port():
    sock, port = bind_listen_socket('127.0.0.1', [0])
    try:
        assert port > 0
    finally:
        sock.close()


def test_raises_when_all_candidates_busy():
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    occupied.bind(('127.0.0.1', 0))
    occupied.listen(1)
    busy = occupied.getsockname()[1]
    try:
        with pytest.raises(OSError):
            bind_listen_socket('127.0.0.1', [busy])  # strict single, busy
    finally:
        occupied.close()


# resolve_port_spec: the single source of the default, shared by GUI + headless.

def test_resolve_defaults_to_range_when_unset():
    # GUI path: McpServer() (port=None) then start() with no port -> range.
    assert resolve_port_spec(None, None) == DEFAULT_PORT_RANGE


def test_resolve_explicit_arg_wins():
    # Headless path: start(host, args.port) passes an explicit spec.
    assert resolve_port_spec('6150-6159', None) == '6150-6159'
    assert resolve_port_spec(7000, 6150) == 7000
    # Explicit "0" (auto-assign) must be honored, not overridden by the default.
    assert resolve_port_spec(0, None) == 0


def test_resolve_falls_back_to_configured_port():
    assert resolve_port_spec(None, 6155) == 6155
