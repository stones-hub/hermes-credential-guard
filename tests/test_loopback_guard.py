from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

SUPPORT = Path(__file__).resolve().parent / "support"
sys.path.insert(0, str(SUPPORT))

import hermes_loopback_launcher as guard  # noqa: E402


DOCUMENTATION_TARGETS = [
    ("203.0.113.1", 9),
    ("2001:db8::1", 9),
]


def _ipv6_loopback_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.bind(("::1", 0))
            return True
        finally:
            s.close()
    except OSError:
        return False


@pytest.fixture()
def installed_guard(monkeypatch):
    # Reset attempt log between tests.
    monkeypatch.setattr(guard, "_ATTEMPTS", [])
    guard.install_guards()
    guard.assert_guards_installed()
    yield
    # Leave patched for process; other tests re-install as needed.


@pytest.fixture()
def fail_on_call_spies(monkeypatch, installed_guard):
    """Replace _ORIG_* with spies that fail if ever invoked (proves no real I/O)."""
    counts = {
        "connect": 0,
        "connect_ex": 0,
        "create_connection": 0,
        "sendto": 0,
        "sendmsg": 0,
    }

    def _boom(name):
        def boom(*_a, **_k):
            counts[name] += 1
            raise AssertionError(f"original {name} must not be called for non-loopback")

        return boom

    monkeypatch.setattr(guard, "_ORIG_CONNECT", _boom("connect"))
    monkeypatch.setattr(guard, "_ORIG_CONNECT_EX", _boom("connect_ex"))
    monkeypatch.setattr(guard, "_ORIG_CREATE_CONNECTION", _boom("create_connection"))
    monkeypatch.setattr(guard, "_ORIG_SENDTO", _boom("sendto"))
    if guard._ORIG_SENDMSG is not None:
        monkeypatch.setattr(guard, "_ORIG_SENDMSG", _boom("sendmsg"))
    return counts


def test_guards_installed_on_all_target_methods(installed_guard):
    guard.assert_guards_installed()
    assert socket.socket.connect is guard._guard_connect
    assert socket.socket.connect_ex is guard._guard_connect_ex
    assert socket.create_connection is guard._guard_create_connection
    assert socket.socket.sendto is guard._guard_sendto
    if guard._ORIG_SENDMSG is not None:
        assert socket.socket.sendmsg is guard._guard_sendmsg


@pytest.mark.parametrize("host,port", DOCUMENTATION_TARGETS)
def test_connect_blocks_documentation_hosts(fail_on_call_spies, host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError, match="net guard blocked"):
            sock.connect((host, port))
    finally:
        sock.close()
    assert any(h == host for h, _ in guard._ATTEMPTS)
    assert fail_on_call_spies["connect"] == 0


@pytest.mark.parametrize("host,port", DOCUMENTATION_TARGETS)
def test_connect_ex_blocks_documentation_hosts(fail_on_call_spies, host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        err = sock.connect_ex((host, port))
        assert err != 0
    finally:
        sock.close()
    assert any(h == host for h, _ in guard._ATTEMPTS)
    assert fail_on_call_spies["connect_ex"] == 0


@pytest.mark.parametrize("host,port", DOCUMENTATION_TARGETS)
def test_create_connection_blocks_documentation_hosts(fail_on_call_spies, host, port):
    with pytest.raises(OSError, match="net guard blocked"):
        socket.create_connection((host, port), timeout=0.2)
    assert any(h == host for h, _ in guard._ATTEMPTS)
    assert fail_on_call_spies["create_connection"] == 0


@pytest.mark.parametrize("host,port", DOCUMENTATION_TARGETS)
def test_sendto_blocks_documentation_hosts(fail_on_call_spies, host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        with pytest.raises(OSError, match="net guard blocked"):
            sock.sendto(b"x", (host, port))
    finally:
        sock.close()
    assert any(h == host for h, _ in guard._ATTEMPTS)
    assert fail_on_call_spies["sendto"] == 0


@pytest.mark.parametrize("host,port", DOCUMENTATION_TARGETS)
def test_sendmsg_blocks_documentation_hosts(fail_on_call_spies, host, port):
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        with pytest.raises(OSError, match="net guard blocked"):
            sock.sendmsg([b"x"], [], 0, (host, port))
    finally:
        sock.close()
    assert any(h == host for h, _ in guard._ATTEMPTS)
    assert fail_on_call_spies["sendmsg"] == 0


def test_sendmsg_blocks_before_orig_even_with_default_ancdata(fail_on_call_spies):
    """Non-loopback sendmsg([b'x'], address=...) must reject with zero orig calls."""
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(OSError, match="net guard blocked"):
            sock.sendmsg([b"x"], None, 0, ("203.0.113.1", 9))
    finally:
        sock.close()
    assert fail_on_call_spies["sendmsg"] == 0
    assert any(h == "203.0.113.1" for h, _ in guard._ATTEMPTS)


def test_ipv4_loopback_connect(installed_guard):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        conn, _ = listener.accept()
        conn.close()
    finally:
        client.close()
        listener.close()
    assert any(h in {"127.0.0.1", "localhost"} for h, _ in guard._ATTEMPTS)


def test_ipv4_loopback_connect_ex(installed_guard):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        assert client.connect_ex((host, port)) == 0
        conn, _ = listener.accept()
        conn.close()
    finally:
        client.close()
        listener.close()


def test_ipv4_loopback_create_connection(installed_guard):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    try:
        client = socket.create_connection((host, port), timeout=1.0)
        conn, _ = listener.accept()
        conn.close()
        client.close()
    finally:
        listener.close()


def test_ipv4_loopback_sendto(installed_guard):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    host, port = server.getsockname()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.sendto(b"ping", (host, port))
        data, _ = server.recvfrom(16)
        assert data == b"ping"
    finally:
        client.close()
        server.close()
    assert any(h == "127.0.0.1" for h, _ in guard._ATTEMPTS)


def test_ipv4_loopback_sendmsg(installed_guard):
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    host, port = server.getsockname()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Standard one-arg form — must not TypeError on ancdata=None.
        client.sendmsg([b"x"], [], 0, (host, port))
        data, _ = server.recvfrom(16)
        assert data == b"x"
    finally:
        client.close()
        server.close()
    assert any(h == "127.0.0.1" for h, _ in guard._ATTEMPTS)


def test_sendmsg_omitted_ancdata_compatible(installed_guard):
    """sendmsg([b'x']) must work: None ancdata → empty iterable for native call."""
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    a, b = socket.socketpair()
    try:
        a.sendmsg([b"x"])
        data, _ = b.recvfrom(16)
        assert data == b"x"
    finally:
        a.close()
        b.close()


def test_sendmsg_explicit_ancdata_flags_address(installed_guard):
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    host, port = server.getsockname()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        n = client.sendmsg([b"ab"], [], 0, (host, port))
        assert n == 2
        data, _ = server.recvfrom(16)
        assert data == b"ab"
    finally:
        client.close()
        server.close()


def test_af_unix_connect(installed_guard):
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cgunix-") as shallow:
        path = str(Path(shallow) / "s")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(path)
            conn, _ = server.accept()
            conn.close()
        finally:
            client.close()
            server.close()


def test_af_unix_sendmsg(installed_guard):
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        a.sendmsg([b"unix"])
        assert b.recv(16) == b"unix"
    finally:
        a.close()
        b.close()


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="IPv6 ::1 unavailable")
def test_ipv6_loopback_connect(installed_guard):
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::1", 0))
    listener.listen(1)
    host, port = listener.getsockname()[:2]
    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        conn, _ = listener.accept()
        conn.close()
    finally:
        client.close()
        listener.close()


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="IPv6 ::1 unavailable")
def test_ipv6_loopback_connect_ex(installed_guard):
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::1", 0))
    listener.listen(1)
    host, port = listener.getsockname()[:2]
    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        assert client.connect_ex((host, port)) == 0
        conn, _ = listener.accept()
        conn.close()
    finally:
        client.close()
        listener.close()
    assert any(h == "::1" for h, _ in guard._ATTEMPTS)


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="IPv6 ::1 unavailable")
def test_ipv6_loopback_create_connection(installed_guard):
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::1", 0))
    listener.listen(1)
    host, port = listener.getsockname()[:2]
    try:
        client = socket.create_connection((host, port), timeout=1.0)
        conn, _ = listener.accept()
        conn.close()
        client.close()
    finally:
        listener.close()
    assert any(h == "::1" for h, _ in guard._ATTEMPTS)


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="IPv6 ::1 unavailable")
def test_ipv6_loopback_sendto(installed_guard):
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.bind(("::1", 0))
    host, port = server.getsockname()[:2]
    client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        client.sendto(b"v6", (host, port))
        data, _ = server.recvfrom(16)
        assert data == b"v6"
    finally:
        client.close()
        server.close()


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="IPv6 ::1 unavailable")
def test_ipv6_loopback_sendmsg(installed_guard):
    if guard._ORIG_SENDMSG is None:
        pytest.skip("sendmsg not available on this platform")
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.bind(("::1", 0))
    host, port = server.getsockname()[:2]
    client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        client.sendmsg([b"v6"], [], 0, (host, port))
        data, _ = server.recvfrom(16)
        assert data == b"v6"
    finally:
        client.close()
        server.close()


def test_remaining_bypass_notes_documented():
    notes = guard.remaining_bypass_notes()
    assert any("ctypes" in n for n in notes)
    assert any("subprocess" in n for n in notes)
    # Documentation must keep framing as Python conventional socket guard, not OS sandbox.
    assert "NOT an OS sandbox" in guard.__doc__ or "not an OS sandbox" in guard.__doc__.lower()
