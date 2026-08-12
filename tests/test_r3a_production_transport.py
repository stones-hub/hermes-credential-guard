"""R3A B1/B2: production HTTPS transport seams — no fake transport override."""

from __future__ import annotations

import ssl
import urllib.request
from typing import Any, Dict, List, Optional

import pytest

from credential_guard.adapters import http as http_adapter


def _base_request(**over: Any) -> Dict[str, Any]:
    req = {
        "method": "GET",
        "url": "https://svc.example.test:443/v1",
        "headers": {"Authorization": "Bearer x"},
        "allow_redirects": False,
        "trust_env": False,
        "verify": True,
        "connect_timeout_seconds": 2,
        "total_timeout_seconds": 5,
        "max_response_body_bytes": 4096,
    }
    req.update(over)
    return req


def _mint_loopback_tls(cert_dir):
    """Create ephemeral CA + server cert for 127.0.0.1 in tmp_path only."""
    import subprocess
    from pathlib import Path

    cert_dir = Path(cert_dir)
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "ca.key"
    ca_pem = cert_dir / "ca.pem"
    server_key = cert_dir / "server.key"
    server_csr = cert_dir / "server.csr"
    server_pem = cert_dir / "server.pem"
    ext = cert_dir / "ext.cnf"
    ext.write_text(
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_pem),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=CG-SYNTHETIC-CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(server_key),
            "-out",
            str(server_csr),
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_pem),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_pem),
            "-days",
            "1",
            "-extfile",
            str(ext),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return ca_pem, server_pem, server_key


def test_b1_open_must_not_receive_context_kwarg(monkeypatch):
    """RED/GREEN: OpenerDirector.open rejects context= — TLS must live on HTTPSHandler."""
    seen_open_kwargs: List[Dict[str, Any]] = []
    seen_handlers: List[List[Any]] = []
    https_contexts: List[Optional[ssl.SSLContext]] = []

    real_build = urllib.request.build_opener

    def _capture_build(*handlers):
        opener = real_build(*handlers)
        seen_handlers.append(list(opener.handlers))
        for h in opener.handlers:
            if isinstance(h, urllib.request.HTTPSHandler):
                https_contexts.append(getattr(h, "_context", None))
        real_open = opener.open

        def _open(fullurl, data=None, timeout=None, **kwargs):
            seen_open_kwargs.append(dict(kwargs))
            if "context" in kwargs:
                raise TypeError("open() got an unexpected keyword argument 'context'")
            # Do not network — raise controlled failure after recording.
            raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")

        opener.open = _open  # type: ignore[method-assign]
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", _capture_build)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")

    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(_base_request())

    assert seen_open_kwargs, "production transport must call opener.open"
    assert all("context" not in kw for kw in seen_open_kwargs)

    assert seen_handlers, "production transport must build an opener"
    handlers = seen_handlers[0]
    # No env-imported proxy URL may remain on any ProxyHandler.
    for h in handlers:
        if isinstance(h, urllib.request.ProxyHandler):
            for url in (h.proxies or {}).values():
                assert url in ("", None) or not url
                assert "127.0.0.1:9" not in str(url)
    proxy_urls = []
    for h in handlers:
        if isinstance(h, urllib.request.ProxyHandler):
            proxy_urls.extend((h.proxies or {}).values())
    assert "http://127.0.0.1:9" not in proxy_urls

    https_handlers = [h for h in handlers if isinstance(h, urllib.request.HTTPSHandler)]
    assert https_handlers, "TLS context must be installed via HTTPSHandler"
    assert https_contexts and https_contexts[0] is not None

    redirect_handlers = [
        h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
    ]
    assert redirect_handlers, "NoRedirect handler must be installed"
    # redirect_request must refuse follow (return None).
    rh = redirect_handlers[0]
    assert rh.redirect_request(None, None, 302, "Found", {}, "https://x") is None


def test_b1_verify_true_required_cannot_disable():
    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(_base_request(verify=False))
    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(_base_request(trust_env=True))
    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(_base_request(allow_redirects=True))


def test_b1_mutation_context_kwarg_on_open_is_rejected_by_seam(monkeypatch):
    """Mutation: if open again receives context=, the seam test must see it and fail intent."""
    opener = urllib.request.build_opener()
    req = urllib.request.Request("https://127.0.0.1/", method="GET")
    with pytest.raises(TypeError, match="context"):
        opener.open(req, timeout=1, context=ssl.create_default_context())


def test_b1_mutation_source_forbids_open_context_and_requires_https_handler_context():
    """Load-bearing source gate: context= on open, or missing HTTPSHandler context, is RED."""
    from pathlib import Path

    src = Path(http_adapter.__file__).read_text(encoding="utf-8")
    assert "opener.open(" in src
    open_idx = src.find("opener.open(")
    open_chunk = src[open_idx : open_idx + 120]
    assert "context=" not in open_chunk
    assert "super().__init__(context=ctx)" in src or "HTTPSHandler(context=" in src
    assert "ProxyHandler({})" in src
    assert "build_opener(_NoRedirect)" not in src


def test_b1_loopback_tls_uses_production_transport(tmp_path, monkeypatch):
    """Isolation path: real _default_transport against loopback TLS — no transport= override."""
    import http.server
    import socket
    import threading
    import time

    ca_pem, server_pem, server_key = _mint_loopback_tls(tmp_path / "tls")

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: A003
            return

    ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_server.load_cert_chain(str(server_pem), str(server_key))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(5)
    ssock = ctx_server.wrap_socket(sock, server_side=True)
    server = http.server.HTTPServer(("127.0.0.1", port), _Handler, bind_and_activate=False)
    server.socket = ssock
    threading.Thread(target=server.handle_request, daemon=True).start()
    time.sleep(0.05)

    real_cdc = ssl.create_default_context

    def _trust_tmp_ca():
        c = real_cdc()
        c.load_verify_locations(cafile=str(ca_pem))
        return c

    monkeypatch.setattr(ssl, "create_default_context", _trust_tmp_ca)
    out = http_adapter._default_transport(
        _base_request(
            url=f"https://127.0.0.1:{port}/v1",
            connect_timeout_seconds=2,
            total_timeout_seconds=5,
        )
    )
    server.server_close()
    assert out["status"] == 200
    assert b"ok" in out["body"]


def test_b2_connect_timeout_used_on_connection_seam(monkeypatch):
    """connect_timeout_seconds must enter the connection-establishment timeout."""
    seen: Dict[str, Any] = {}

    def _boom(*_a, **_k):
        raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")

    def _wrap(ctx, *, connect_timeout, deadline):
        seen["connect_timeout"] = float(connect_timeout)
        seen["has_deadline"] = deadline > 0
        return type("O", (), {"open": staticmethod(_boom), "handlers": []})()

    monkeypatch.setattr(http_adapter, "_build_production_opener", _wrap)

    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(
            _base_request(connect_timeout_seconds=3, total_timeout_seconds=9)
        )
    assert seen.get("connect_timeout") == 3.0
    assert seen.get("has_deadline") is True


def test_b2_total_deadline_blocks_slow_httperror_body(monkeypatch):
    """HTTPError/302 slow-drip body must hit monotonic total deadline (not only pre-read check)."""
    import time
    import urllib.error
    from email.message import Message

    clock = {"t": 1000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["t"])

    class _SlowDripFP:
        """Deterministic drip: each read returns few bytes and advances past deadline."""

        def __init__(self) -> None:
            self._reads = 0

        def read(self, n: int = -1) -> bytes:  # noqa: A003
            self._reads += 1
            # Advance wall past total_timeout (1.0) during sustained body drip.
            clock["t"] += 0.4
            if self._reads > 8:
                return b""
            size = 4 if n < 0 else min(4, max(1, n))
            return b"x" * size

        def close(self) -> None:
            return None

    def _raise_httperror(_fullurl, data=None, timeout=None, **_kwargs):
        hdrs = Message()
        hdrs["content-type"] = "text/plain"
        raise urllib.error.HTTPError(
            "https://svc.example.test:443/v1",
            302,
            "Found",
            hdrs,
            _SlowDripFP(),
        )

    def _wrap(ctx, *, connect_timeout, deadline):
        return type("O", (), {"open": staticmethod(_raise_httperror), "handlers": []})()

    monkeypatch.setattr(http_adapter, "_build_production_opener", _wrap)

    with pytest.raises(http_adapter.HttpAdapterError) as ei:
        http_adapter._default_transport(
            _base_request(
                total_timeout_seconds=1,
                connect_timeout_seconds=5,
                max_response_body_bytes=4096,
            )
        )
    assert ei.value.code == "HTTP_ADAPTER_FAILED"
    assert "svc.example" not in repr(ei.value)
    assert "302" not in repr(ei.value)
    assert "Found" not in repr(ei.value)


def test_b2_mutation_httperror_body_without_post_deadline_returns_status(monkeypatch):
    """Mutation: dropping post-read deadline checks must incorrectly return 302 past deadline."""
    import time
    import urllib.error
    from email.message import Message

    clock = {"t": 2000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["t"])
    real_reader = http_adapter._read_body_with_deadline

    class _SlowOversizeFP:
        """One read returns max_body+1 bytes and jumps past deadline (exits loop without re-pre-check)."""

        def read(self, n: int = -1) -> bytes:  # noqa: A003
            clock["t"] += 5.0
            size = 64 if n < 0 else max(1, n)
            return b"y" * size

        def close(self) -> None:
            return None

    def _raise_httperror(_fullurl, data=None, timeout=None, **_kwargs):
        hdrs = Message()
        hdrs["content-type"] = "text/plain"
        raise urllib.error.HTTPError(
            "https://svc.example.test:443/v1",
            302,
            "Found",
            hdrs,
            _SlowOversizeFP(),
        )

    def _wrap(ctx, *, connect_timeout, deadline):
        return type("O", (), {"open": staticmethod(_raise_httperror), "handlers": []})()

    # Same bounded loop as production, but post-read / post-loop deadline checks deleted.
    def _mutated_read(reader, *, max_body: int, deadline: float) -> bytes:
        if reader is None:
            return b""
        chunks: list[bytes] = []
        total = 0
        while total <= max_body:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")
            piece = reader.read(min(8192, max_body + 1 - total))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
            # mutation: no post-read deadline check
        # mutation: no post-loop deadline check
        return b"".join(chunks)

    monkeypatch.setattr(http_adapter, "_build_production_opener", _wrap)
    monkeypatch.setattr(http_adapter, "_read_body_with_deadline", _mutated_read)

    out = http_adapter._default_transport(
        _base_request(
            total_timeout_seconds=1,
            connect_timeout_seconds=5,
            max_response_body_bytes=16,
        )
    )
    # Under mutation the contract is violated: status returned after deadline.
    assert out["status"] == 302
    assert out["body"]

    # Control: production helper with the same FP must still timeout (post-check load-bearing).
    clock["t"] = 3000.0
    monkeypatch.setattr(http_adapter, "_read_body_with_deadline", real_reader)
    with pytest.raises(http_adapter.HttpAdapterError) as ei:
        http_adapter._default_transport(
            _base_request(
                total_timeout_seconds=1,
                connect_timeout_seconds=5,
                max_response_body_bytes=16,
            )
        )
    assert ei.value.code == "HTTP_ADAPTER_FAILED"


def _nested_httperror_body_shape(sock, *, clock=None, drip_advance: float = 0.0):
    """Real urllib shape: HTTPError.fp -> HTTPResponse-like -> fp.raw._sock (not flat FP)."""

    class _Raw:
        def __init__(self, s) -> None:
            self._sock = s

    class _InnerBuffered:
        """HTTPResponse.fp — BufferedReader-like with raw._sock."""

        def __init__(self, s) -> None:
            self.raw = _Raw(s)

        def read(self, n: int = -1) -> bytes:  # noqa: A003
            raise AssertionError("inner buffered read must not be called directly")

        def close(self) -> None:
            return None

    class _HTTPResponseLike:
        """Mirrors http.client.HTTPResponse used as HTTPError.fp (has .fp, no .raw)."""

        def __init__(self, s) -> None:
            self.fp = _InnerBuffered(s)
            self._reads = 0

        def read(self, n: int = -1) -> bytes:  # noqa: A003
            self._reads += 1
            if clock is not None and drip_advance:
                clock["t"] += drip_advance
            size = 4 if n < 0 else min(4, max(1, n))
            if self._reads > 6:
                return b""
            return b"x" * size

        def close(self) -> None:
            return None

    return _HTTPResponseLike(sock)


class _ObsSock:
    """Observable stand-in for the leaf socket under raw._sock."""

    def __init__(self) -> None:
        self.settimeout_calls: List[float] = []

    def settimeout(self, value: float) -> None:
        self.settimeout_calls.append(float(value))

    def fileno(self) -> int:
        return -1


def test_b2_httperror_nested_response_pushes_remaining_deadline_to_socket(monkeypatch):
    """HTTPError real nesting must set socket timeout before each blocking body read."""
    import time
    import urllib.error
    from email.message import Message

    clock = {"t": 8000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["t"])
    sock = _ObsSock()
    nested = _nested_httperror_body_shape(sock, clock=clock, drip_advance=0.15)

    def _raise_httperror(_fullurl, data=None, timeout=None, **_kwargs):
        hdrs = Message()
        hdrs["content-type"] = "text/plain"
        raise urllib.error.HTTPError(
            "https://svc.example.test:443/v1",
            302,
            "Found",
            hdrs,
            nested,
        )

    def _wrap(ctx, *, connect_timeout, deadline):
        return type("O", (), {"open": staticmethod(_raise_httperror), "handlers": []})()

    monkeypatch.setattr(http_adapter, "_build_production_opener", _wrap)

    wall0 = time.perf_counter()
    # May finish under deadline or raise — contract is pre-read socket deadline push.
    try:
        out = http_adapter._default_transport(
            _base_request(
                total_timeout_seconds=1,
                connect_timeout_seconds=5,
                max_response_body_bytes=4096,
            )
        )
        assert out["status"] == 302
    except http_adapter.HttpAdapterError as ei:
        assert ei.code == "HTTP_ADAPTER_FAILED"
    wall_elapsed = time.perf_counter() - wall0
    # Contract: remaining total deadline must reach the nested socket before reads.
    assert len(sock.settimeout_calls) > 0
    assert all(v > 0 for v in sock.settimeout_calls)
    assert wall_elapsed < 2.5


def test_b2_mutation_httperror_nested_shallow_unwrap_skips_socket_deadline(monkeypatch):
    """Mutation: one-level fp.raw._sock only — nested HTTPResponse shape must miss socket."""
    import time
    import urllib.error
    from email.message import Message

    clock = {"t": 9000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["t"])
    sock = _ObsSock()
    nested = _nested_httperror_body_shape(sock, clock=clock, drip_advance=0.15)
    real_reader = http_adapter._read_body_with_deadline

    def _raise_httperror(_fullurl, data=None, timeout=None, **_kwargs):
        hdrs = Message()
        hdrs["content-type"] = "text/plain"
        raise urllib.error.HTTPError(
            "https://svc.example.test:443/v1",
            302,
            "Found",
            hdrs,
            nested,
        )

    def _wrap(ctx, *, connect_timeout, deadline):
        return type("O", (), {"open": staticmethod(_raise_httperror), "handlers": []})()

    def _shallow_read(reader, *, max_body: int, deadline: float) -> bytes:
        """Old one-level unwrap: HTTPError.fp.raw._sock — misses HTTPResponse.fp.raw._sock."""
        if reader is None:
            return b""
        chunks: list[bytes] = []
        total = 0
        while total <= max_body:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")
            try:
                fp = getattr(reader, "fp", reader)
                raw = getattr(fp, "raw", None)
                leaf = getattr(raw, "_sock", None) if raw is not None else None
                if leaf is not None:
                    leaf.settimeout(remaining)
            except Exception:
                pass
            piece = reader.read(min(8192, max_body + 1 - total))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
            if time.monotonic() > deadline:
                raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")
        body = b"".join(chunks)
        if time.monotonic() > deadline:
            raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")
        return body

    monkeypatch.setattr(http_adapter, "_build_production_opener", _wrap)
    monkeypatch.setattr(http_adapter, "_read_body_with_deadline", _shallow_read)

    # Under shallow mutation: nested socket never receives remaining deadline.
    try:
        http_adapter._default_transport(
            _base_request(
                total_timeout_seconds=1,
                connect_timeout_seconds=5,
                max_response_body_bytes=4096,
            )
        )
    except http_adapter.HttpAdapterError:
        pass
    assert sock.settimeout_calls == []

    # Control: production reader must push settimeout on the same nested shape.
    clock["t"] = 10000.0
    sock2 = _ObsSock()
    nested2 = _nested_httperror_body_shape(sock2, clock=clock, drip_advance=0.15)

    def _raise2(_fullurl, data=None, timeout=None, **_kwargs):
        hdrs = Message()
        hdrs["content-type"] = "text/plain"
        raise urllib.error.HTTPError(
            "https://svc.example.test:443/v1",
            302,
            "Found",
            hdrs,
            nested2,
        )

    monkeypatch.setattr(
        http_adapter,
        "_build_production_opener",
        lambda ctx, *, connect_timeout, deadline: type(
            "O", (), {"open": staticmethod(_raise2), "handlers": []}
        )(),
    )
    monkeypatch.setattr(http_adapter, "_read_body_with_deadline", real_reader)
    try:
        http_adapter._default_transport(
            _base_request(
                total_timeout_seconds=1,
                connect_timeout_seconds=5,
                max_response_body_bytes=4096,
            )
        )
    except http_adapter.HttpAdapterError:
        pass
    assert len(sock2.settimeout_calls) > 0
    assert all(v > 0 for v in sock2.settimeout_calls)


def test_b2_ok_response_nested_fp_raw_sock_also_gets_deadline(monkeypatch):
    """Normal HTTPResponse shape (fp.raw._sock) must still receive remaining deadline."""
    import time

    sock = _ObsSock()

    class _Raw:
        def __init__(self, s) -> None:
            self._sock = s

    class _OkResp:
        """HTTPResponse-like: reader itself has .fp.raw._sock (one level, not HTTPError)."""

        def __init__(self, s) -> None:
            self.fp = type("FP", (), {"raw": _Raw(s)})()
            self.status = 200
            self.headers = {"content-type": "text/plain"}
            self._reads = 0

        def getcode(self) -> int:
            return 200

        def read(self, n: int = -1) -> bytes:  # noqa: A003
            self._reads += 1
            if self._reads > 2:
                return b""
            size = 4 if n < 0 else min(4, max(1, n))
            return b"z" * size

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _open(_fullurl, data=None, timeout=None, **_kwargs):
        return _OkResp(sock)

    def _wrap(ctx, *, connect_timeout, deadline):
        return type("O", (), {"open": staticmethod(_open), "handlers": []})()

    monkeypatch.setattr(http_adapter, "_build_production_opener", _wrap)
    t0 = time.monotonic()
    out = http_adapter._default_transport(
        _base_request(
            total_timeout_seconds=5,
            connect_timeout_seconds=2,
            max_response_body_bytes=4096,
        )
    )
    elapsed = time.monotonic() - t0
    assert out["status"] == 200
    assert len(sock.settimeout_calls) > 0
    assert all(v > 0 for v in sock.settimeout_calls)
    assert elapsed < 2.0


def test_b2_total_deadline_blocks_slow_body(monkeypatch, tmp_path):
    """Slow sustained body reads must hit monotonic total deadline (not only socket timeout)."""
    import http.server
    import socket
    import threading
    import time

    ca_pem, server_pem, server_key = _mint_loopback_tls(tmp_path / "tls-slow")

    class _Slow(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            for _ in range(200):
                try:
                    self.wfile.write(b"x" * 1000)
                    self.wfile.flush()
                except Exception:
                    break
                time.sleep(0.05)

        def log_message(self, fmt, *args):  # noqa: A003
            return

    ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_server.load_cert_chain(str(server_pem), str(server_key))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(5)
    ssock = ctx_server.wrap_socket(sock, server_side=True)
    server = http.server.HTTPServer(("127.0.0.1", port), _Slow, bind_and_activate=False)
    server.socket = ssock
    threading.Thread(target=server.handle_request, daemon=True).start()
    time.sleep(0.05)

    real_cdc = ssl.create_default_context

    def _trust():
        c = real_cdc()
        c.load_verify_locations(cafile=str(ca_pem))
        return c

    monkeypatch.setattr(ssl, "create_default_context", _trust)
    t0 = time.monotonic()
    with pytest.raises(http_adapter.HttpAdapterError) as ei:
        http_adapter._default_transport(
            _base_request(
                url=f"https://127.0.0.1:{port}/slow",
                connect_timeout_seconds=5,
                total_timeout_seconds=1,
                max_response_body_bytes=2_000_000,
            )
        )
    elapsed = time.monotonic() - t0
    server.server_close()
    assert ei.value.code == "HTTP_ADAPTER_FAILED"
    assert elapsed < 3.5
    assert "127.0.0.1" not in repr(ei.value)
    assert "slow" not in repr(ei.value)


def test_b2_schema_rejects_max_response_header_bytes_field(tmp_path):
    """Honest narrowing: network header-byte limit removed from R3A config Schema."""
    import json
    import os
    from credential_guard.config import CONFIG_FILENAME, CredentialGuardConfig, ConfigError

    doc = {
        "version": 2,
        "credentials": {"t": {"type": "token", "value": "CG_SYNTHETIC_DECOY_deadbeef"}},
        "bindings": {
            "b": {
                "type": "http",
                "credential_ref": "t",
                "target": {"scheme": "https", "host": "svc.example.test", "port": 443},
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/v1"],
                    "max_response_header_bytes": 8192,
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }
    path = tmp_path / CONFIG_FILENAME
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code == "CONFIG_SCHEMA"


def test_b2_output_headers_are_allowlist_bounded_not_wire_parse_limit():
    """Remaining header bound is model-output allowlist, not urllib parse-time limit."""
    from pathlib import Path

    body = Path(http_adapter.__file__).read_text(encoding="utf-8")
    # Production must not read max_response_header_bytes as a wire/parse limit.
    assert "max_response_header_bytes" not in body
    assert "_filter_response_headers" in body
    assert "_SAFE_RESPONSE_HEADERS" in body
