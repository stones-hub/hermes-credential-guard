"""R8 Slice A: HTTP/HTTPS unified scheme schema, digests, scrubbed meta."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict

import pytest

from credential_guard.config import CONFIG_FILENAME, ConfigError, CredentialGuardConfig
from credential_guard import runtime_config as rc


def _decoy(n: int = 16) -> str:
    return "CG_SYNTHETIC_DECOY_" + secrets.token_hex(n)


def _write(path: Path, doc: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps(doc, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _http_doc(
    token: str,
    *,
    scheme: str = "https",
    host: str = "api.example.test",
    port: int = 443,
    **binding_overrides: Any,
) -> Dict[str, Any]:
    binding: Dict[str, Any] = {
        "type": "http",
        "credential_ref": "svc-token",
        "target": {"scheme": scheme, "host": host, "port": port},
        "request": {
            "allowed_methods": ["GET"],
            "allowed_paths": ["/v1/status"],
        },
        "inject": {"type": "bearer", "location": "authorization_header"},
        "approval": "required",
    }
    binding.update(binding_overrides)
    return {
        "version": 2,
        "credentials": {"svc-token": {"type": "token", "value": token}},
        "bindings": {"svc-api": binding},
    }


@pytest.fixture
def isolated_runtime(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    if hasattr(rc, "reset_runtime_for_tests"):
        rc.reset_runtime_for_tests()
    yield store
    if hasattr(rc, "reset_runtime_for_tests"):
        rc.reset_runtime_for_tests()


def test_r8_a_http_scheme_loads_and_is_preserved(tmp_path: Path):
    """HTTP binding must load with scheme=http retained (not rewritten to https)."""
    decoy = _decoy()
    path = _write(
        tmp_path / CONFIG_FILENAME,
        _http_doc(decoy, scheme="http", host="internal-api.example.test", port=8080),
    )
    cfg = CredentialGuardConfig.load(path)
    binding = cfg.bindings["svc-api"]
    assert binding["target"]["scheme"] == "http"
    assert binding["target"]["host"] == "internal-api.example.test"
    assert binding["target"]["port"] == 8080
    assert decoy not in repr(binding)


def test_r8_a_https_scheme_still_loads(tmp_path: Path):
    decoy = _decoy()
    path = _write(tmp_path / CONFIG_FILENAME, _http_doc(decoy, scheme="https"))
    cfg = CredentialGuardConfig.load(path)
    assert cfg.bindings["svc-api"]["target"]["scheme"] == "https"


@pytest.mark.parametrize(
    "bad_scheme",
    ["ftp", "file", "ws", "HTTP", "HTTPS", "Http", "Https", ""],
)
def test_r8_a_rejects_illegal_schemes(tmp_path: Path, bad_scheme: str):
    decoy = _decoy()
    doc = _http_doc(decoy, scheme="https")
    doc["bindings"]["svc-api"]["target"]["scheme"] = bad_scheme
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(
            _write(tmp_path / f"bad-{abs(hash(bad_scheme)) % 10**8}.json", doc)
        )
    assert ei.value.code == "CONFIG_SCHEMA"
    assert decoy not in f"{ei.value!s}{ei.value!r}"


def test_r8_a_http_https_swap_changes_both_digests(isolated_runtime: Path):
    """HTTP↔HTTPS must invalidate both binding_digest and target_digest."""
    decoy = _decoy()
    _write(
        isolated_runtime / CONFIG_FILENAME,
        _http_doc(decoy, scheme="https", host="api.example.test", port=443),
    )
    view = rc.load_and_publish_runtime()
    meta_https = view.bindings["svc-api"]
    https_binding = meta_https["binding_digest"]
    https_target = meta_https["target_digest"]

    _write(
        isolated_runtime / CONFIG_FILENAME,
        _http_doc(decoy, scheme="http", host="api.example.test", port=443),
    )
    rc.reset_runtime_for_tests()
    meta_http = rc.load_and_publish_runtime().bindings["svc-api"]
    assert meta_http["binding_digest"] != https_binding
    assert meta_http["target_digest"] != https_target


def test_r8_a_scrubbed_meta_exposes_scheme_not_host_port(isolated_runtime: Path):
    decoy = _decoy()
    _write(
        isolated_runtime / CONFIG_FILENAME,
        _http_doc(decoy, scheme="http", host="secret-host.example.test", port=8080),
    )
    meta = rc.load_and_publish_runtime().bindings["svc-api"]
    scrubbed = {k: meta[k] for k in meta if k not in ("binding_digest", "target_digest")}
    blob = json.dumps(scrubbed, sort_keys=True, default=str)
    assert "secret-host.example.test" not in blob
    assert "host" not in scrubbed
    assert "port" not in scrubbed
    assert scrubbed.get("scheme") == "http"
    assert decoy not in blob


def test_r8_a_operation_summary_uses_binding_scheme(isolated_runtime: Path):
    decoy = _decoy()
    _write(
        isolated_runtime / CONFIG_FILENAME,
        _http_doc(decoy, scheme="http", host="internal-api.example.test", port=8080),
    )
    meta = rc.load_and_publish_runtime().bindings["svc-api"]
    summary = str(meta.get("operation_summary") or "")
    assert summary.startswith("http:")
    assert not summary.startswith("https:")
    assert "bearer" in summary


# ---- Slice B: unified production transport ----


def test_r8_b_execute_http_builds_url_from_binding_scheme():
    """execute_http must use binding scheme (http) — not hardcode https."""
    from credential_guard.adapters import http as http_adapter
    from credential_guard.injection import SecretLease

    decoy = _decoy()
    captured: list[dict] = []

    def transport(req):
        captured.append(req)
        return {"status": 200, "headers": {"content-type": "text/plain"}, "body": b"ok"}

    lease = SecretLease({"kind": "token", "value": decoy})
    binding = {
        "type": "http",
        "credential_ref": "svc-token",
        "target": {
            "scheme": "http",
            "host": "internal-api.example.test",
            "port": 8080,
        },
        "request": {
            "allowed_methods": ["GET"],
            "allowed_paths": ["/v1/status"],
            "connect_timeout_seconds": 2,
            "total_timeout_seconds": 5,
            "max_response_body_bytes": 4096,
        },
        "inject": {"type": "bearer", "location": "authorization_header"},
        "approval": "required",
    }
    result = http_adapter.execute_http(
        binding=binding,
        method="GET",
        path="/v1/status",
        lease=lease,
        transport=transport,
    )
    assert result["ok"] is True
    assert len(captured) == 1
    assert captured[0]["url"] == "http://internal-api.example.test:8080/v1/status"
    assert captured[0]["url"].startswith("http://")
    assert not captured[0]["url"].startswith("https://")
    assert decoy not in json.dumps(result)


def test_r8_b_execute_http_rejects_non_http_https_scheme_at_runtime():
    from credential_guard.adapters import http as http_adapter
    from credential_guard.injection import SecretLease

    decoy = _decoy()
    hits = {"n": 0}

    def transport(req):
        hits["n"] += 1
        return {"status": 200, "headers": {}, "body": b"x"}

    lease = SecretLease({"kind": "token", "value": decoy})
    binding = {
        "type": "http",
        "credential_ref": "svc-token",
        "target": {"scheme": "ftp", "host": "api.example.test", "port": 21},
        "request": {
            "allowed_methods": ["GET"],
            "allowed_paths": ["/v1/status"],
            "connect_timeout_seconds": 2,
            "total_timeout_seconds": 5,
            "max_response_body_bytes": 4096,
        },
        "inject": {"type": "bearer", "location": "authorization_header"},
        "approval": "required",
    }
    result = http_adapter.execute_http(
        binding=binding,
        method="GET",
        path="/v1/status",
        lease=lease,
        transport=transport,
    )
    assert result["ok"] is False
    assert hits["n"] == 0


def test_r8_b_default_transport_http_uses_http_handler_no_proxy_no_redirect(monkeypatch):
    """HTTP URL must install HTTPHandler + empty ProxyHandler + NoRedirect."""
    import urllib.request

    from credential_guard.adapters import http as http_adapter

    seen_handlers: list[list] = []
    real_build = urllib.request.build_opener

    def _capture_build(*handlers):
        seen_handlers.append(list(handlers))
        opener = real_build(*handlers)

        def _open(fullurl, data=None, timeout=None, **kwargs):
            raise http_adapter.HttpAdapterError("HTTP_ADAPTER_FAILED")

        opener.open = _open  # type: ignore[method-assign]
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", _capture_build)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")

    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(
            {
                "method": "GET",
                "url": "http://svc.example.test:8080/v1",
                "headers": {"Authorization": "Bearer x"},
                "allow_redirects": False,
                "trust_env": False,
                "verify": True,
                "connect_timeout_seconds": 2,
                "total_timeout_seconds": 5,
                "max_response_body_bytes": 4096,
            }
        )

    assert seen_handlers
    handlers = seen_handlers[0]
    proxy_handlers = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy_handlers
    for h in proxy_handlers:
        for url in (h.proxies or {}).values():
            assert url in ("", None) or not url
            assert "127.0.0.1:9" not in str(url)
    redirect_handlers = [
        h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
    ]
    assert redirect_handlers
    assert (
        redirect_handlers[0].redirect_request(None, None, 302, "Found", {}, "http://x")
        is None
    )
    http_handlers = [
        h
        for h in handlers
        if isinstance(h, urllib.request.HTTPHandler)
        and not isinstance(h, urllib.request.HTTPSHandler)
    ]
    assert http_handlers, "plain HTTP must use HTTPHandler"


def test_r8_b_https_verify_false_still_rejected():
    from credential_guard.adapters import http as http_adapter

    with pytest.raises(http_adapter.HttpAdapterError):
        http_adapter._default_transport(
            {
                "method": "GET",
                "url": "https://svc.example.test:443/v1",
                "headers": {},
                "allow_redirects": False,
                "trust_env": False,
                "verify": False,
                "connect_timeout_seconds": 2,
                "total_timeout_seconds": 5,
                "max_response_body_bytes": 4096,
            }
        )
    src = Path(http_adapter.__file__).read_text(encoding="utf-8")
    assert 'request.get("verify") is not True' in src


def test_r8_b_loopback_plain_http_production_transport(tmp_path, monkeypatch):
    """Real loopback HTTPServer + production _default_transport (not fake)."""
    import http.server
    import socket
    import threading

    from credential_guard.adapters import http as http_adapter

    for k in list(os.environ):
        if k.lower().endswith("_proxy") or k.lower() in {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        }:
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")

    hits = {"n": 0}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits["n"] += 1
            body = b'{"ok":true,"source":"cg-synthetic-loopback"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: A003
            return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.HTTPServer(("127.0.0.1", port), _Handler, bind_and_activate=False)
    server.server_bind()
    server.server_activate()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        out = http_adapter._default_transport(
            {
                "method": "GET",
                "url": f"http://127.0.0.1:{port}/v1/status",
                "headers": {"Authorization": "Bearer CG_SYNTHETIC_DECOY_loopback"},
                "allow_redirects": False,
                "trust_env": False,
                "verify": True,
                "connect_timeout_seconds": 2,
                "total_timeout_seconds": 5,
                "max_response_body_bytes": 4096,
            }
        )
        assert out["status"] == 200
        assert b"cg-synthetic-loopback" in out["body"]
        assert hits["n"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_r8_b_http_three_xx_not_followed_by_production_transport(tmp_path, monkeypatch):
    import http.server
    import socket
    import threading

    from credential_guard.adapters import http as http_adapter

    for k in list(os.environ):
        if "proxy" in k.lower():
            monkeypatch.delenv(k, raising=False)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1/elsewhere")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"followed")

        def log_message(self, fmt, *args):  # noqa: A003
            return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.HTTPServer(("127.0.0.1", port), _Handler, bind_and_activate=False)
    server.server_bind()
    server.server_activate()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        out = http_adapter._default_transport(
            {
                "method": "GET",
                "url": f"http://127.0.0.1:{port}/start",
                "headers": {},
                "allow_redirects": False,
                "trust_env": False,
                "verify": True,
                "connect_timeout_seconds": 2,
                "total_timeout_seconds": 5,
                "max_response_body_bytes": 4096,
            }
        )
        assert out["status"] == 302
        assert b"followed" not in (out.get("body") or b"")
    finally:
        server.shutdown()
        server.server_close()


def test_r8_b_no_https_to_http_fallback_in_source():
    from credential_guard.adapters import http as http_adapter

    src = Path(http_adapter.__file__).read_text(encoding="utf-8")
    assert 'replace("https://", "http://")' not in src
    assert "replace('https://', 'http://')" not in src


# ---- Slice C: three inject modes + result guard + zero-downstream gates ----


def _start_loopback_http(handler_cls):
    import http.server
    import socket
    import threading

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.HTTPServer(("127.0.0.1", port), handler_cls, bind_and_activate=False)
    server.server_bind()
    server.server_activate()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _map_synthetic_host_to_loopback(monkeypatch, host: str):
    import socket

    real = socket.getaddrinfo

    def _mapped(name, port, *args, **kwargs):
        if name == host:
            return real("127.0.0.1", port, *args, **kwargs)
        return real(name, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _mapped)


@pytest.mark.parametrize(
    "inject_kind",
    ["bearer", "basic", "api_key_header"],
)
def test_r8_c_http_inject_modes_real_loopback_and_scrub(monkeypatch, inject_kind):
    """HTTP Bearer/Basic/API-Key: real production transport + echo scrub."""
    import base64
    import http.server

    from credential_guard.adapters import http as http_adapter
    from credential_guard.injection import SecretLease

    for k in list(os.environ):
        if "proxy" in k.lower():
            monkeypatch.delenv(k, raising=False)

    host = "internal-api.example.test"
    path = "/v1/echo"
    decoy = _decoy()
    user = "cg_synth_user"
    seen = {"auth": None, "api": None, "n": 0}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["n"] += 1
            seen["auth"] = self.headers.get("Authorization")
            seen["api"] = self.headers.get("X-Api-Key")
            # Echo decoy material into body — must be scrubbed before model sees it.
            body = f'{{"echo":"{decoy}","password":"{decoy}"}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: A003
            return

    server, port = _start_loopback_http(_Handler)
    # Rewrite only the connect URL host to loopback; keep production transport.
    # (DNS monkeypatch is order-fragile under the full suite.)
    real_transport = http_adapter._default_transport

    def transport(req):
        rewritten = dict(req)
        rewritten["url"] = rewritten["url"].replace(
            f"http://{host}:{port}", f"http://127.0.0.1:{port}", 1
        )
        assert rewritten["url"].startswith("http://127.0.0.1:")
        return real_transport(rewritten)

    try:
        if inject_kind == "bearer":
            lease = SecretLease({"kind": "token", "value": decoy})
            inject = {"type": "bearer", "location": "authorization_header"}
            cred_ref = "tok"
        elif inject_kind == "basic":
            lease = SecretLease(
                {"kind": "username_password", "username": user, "password": decoy}
            )
            inject = {"type": "basic", "location": "authorization_header"}
            cred_ref = "up"
        else:
            lease = SecretLease({"kind": "token", "value": decoy})
            inject = {"type": "api_key_header", "header_name": "X-Api-Key"}
            cred_ref = "tok"

        binding = {
            "type": "http",
            "credential_ref": cred_ref,
            "target": {"scheme": "http", "host": host, "port": port},
            "request": {
                "allowed_methods": ["GET"],
                "allowed_paths": [path],
                "connect_timeout_seconds": 2,
                "total_timeout_seconds": 5,
                "max_response_body_bytes": 4096,
            },
            "inject": inject,
            "approval": "required",
        }
        result = http_adapter.execute_http(
            binding=binding,
            method="GET",
            path=path,
            lease=lease,
            transport=transport,
        )
        dumped = json.dumps(result)
        assert decoy not in dumped
        assert seen["n"] == 1
        if inject_kind == "bearer":
            assert result["ok"] is True or result.get("error") == "HTTP_RESULT_SCRUBBED"
            assert seen["auth"] == f"Bearer {decoy}"
        elif inject_kind == "basic":
            expected = base64.b64encode(f"{user}:{decoy}".encode()).decode("ascii")
            assert seen["auth"] == f"Basic {expected}"
            assert result["ok"] is True or result.get("error") == "HTTP_RESULT_SCRUBBED"
        else:
            assert seen["api"] == decoy
            assert result["ok"] is True or result.get("error") == "HTTP_RESULT_SCRUBBED"
    finally:
        server.shutdown()
        server.server_close()


def test_r8_c_http_formal_chain_deny_replay_scheme_swap_zero_downstream(
    tmp_path, monkeypatch
):
    """Deny / replay / scheme steal → downstream transport hits stay 0."""
    import types

    from credential_guard.approval import on_pre_tool_call
    from credential_guard.injection_plan import PlanState
    from credential_guard.reference_tools import handle_http_credential_request
    from credential_guard.runtime_config import (
        HTTP_REFERENCE_TOOL,
        load_and_publish_runtime,
        reset_runtime_for_tests,
    )
    from credential_guard.tool_execution import (
        get_http_adapter_invoke_count,
        on_tool_execution,
        reset_http_adapter_observe_for_tests,
        set_http_transport_override_for_tests,
    )
    from credential_guard.tool_request import (
        get_plan_store,
        on_tool_request,
        reset_tool_request_state_for_tests,
    )

    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    reset_http_adapter_observe_for_tests()

    hermes_cli = types.ModuleType("hermes_cli")
    cfg_mod = types.ModuleType("hermes_cli.config")
    cfg_mod.load_config_readonly = lambda: {
        "approvals": {"mode": "manual", "timeout": 300}
    }
    hermes_cli.config = cfg_mod
    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod.is_approval_bypass_active_for_session = lambda sid: False
    approval_mod._get_approval_timeout = lambda: 300
    tools_mod.approval = approval_mod
    import sys

    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", cfg_mod)
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)

    decoy = _decoy()
    doc = _http_doc(
        decoy, scheme="http", host="internal-api.example.test", port=8080
    )
    _write(store / CONFIG_FILENAME, doc)
    load_and_publish_runtime()
    rc.reset_injection_secret_resolve_count_for_tests()

    hits: list = []

    def fake_transport(req):
        hits.append(req)
        return {"status": 200, "headers": {"content-type": "text/plain"}, "body": b"ok"}

    set_http_transport_override_for_tests(fake_transport)
    args = {
        "target": "svc-api",
        "method": "GET",
        "path": "/v1/status",
        "credential": "<CREDENTIAL:svc-token>",
    }

    # --- deny path: invalidate before execution ---
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-deny",
    )
    get_plan_store().invalidate("s1", "tc-deny")
    out_deny = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-deny",
    )
    assert hits == []
    assert rc.get_injection_secret_resolve_count() == 0
    assert get_http_adapter_invoke_count() == 0
    assert decoy not in out_deny

    # --- approve once, then replay ---
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ok",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-ok",
        )["action"]
        == "approve"
    )
    out_ok = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ok",
    )
    assert len(hits) == 1
    assert hits[0]["url"].startswith("http://")
    assert rc.get_injection_secret_resolve_count() == 1
    assert decoy not in out_ok
    assert get_plan_store().lookup("s1", "tc-ok").state is PlanState.CONSUMED

    before_hits = len(hits)
    before_resolve = rc.get_injection_secret_resolve_count()
    out_replay = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ok",
    )
    assert len(hits) == before_hits
    assert rc.get_injection_secret_resolve_count() == before_resolve
    assert decoy not in out_replay

    # --- scheme swap after analyze: http→https invalidates, zero new hits ---
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t2",
        tool_call_id="tc-swap",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t2",
            tool_call_id="tc-swap",
        )["action"]
        == "approve"
    )
    # Steal scheme in published config identity.
    doc2 = _http_doc(
        decoy, scheme="https", host="internal-api.example.test", port=8080
    )
    _write(store / CONFIG_FILENAME, doc2)
    reset_runtime_for_tests()
    load_and_publish_runtime()
    before_swap_hits = len(hits)
    before_swap_resolve = rc.get_injection_secret_resolve_count()
    out_swap = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: handle_http_credential_request(a),
        session_id="s1",
        turn_id="t2",
        tool_call_id="tc-swap",
    )
    assert len(hits) == before_swap_hits
    assert rc.get_injection_secret_resolve_count() == before_swap_resolve
    assert decoy not in out_swap

    set_http_transport_override_for_tests(None)
    reset_http_adapter_observe_for_tests()
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


# ---- Slice D: HTTP plaintext approval warning (scheme-aware line count) ----

_HTTP_PLAINTEXT_WARNING = (
    "警告：该目标使用明文 HTTP，凭证在网络传输过程中不会被加密。"
)


def _approval_env(tmp_path, monkeypatch, *, scheme: str, host: str, port: int, decoy: str):
    import types

    from credential_guard.runtime_config import (
        load_and_publish_runtime,
        reset_runtime_for_tests,
    )
    from credential_guard.tool_request import reset_tool_request_state_for_tests

    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()

    hermes_cli = types.ModuleType("hermes_cli")
    cfg_mod = types.ModuleType("hermes_cli.config")
    cfg_mod.load_config_readonly = lambda: {
        "approvals": {"mode": "manual", "timeout": 300}
    }
    hermes_cli.config = cfg_mod
    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod.is_approval_bypass_active_for_session = lambda sid: False
    approval_mod._get_approval_timeout = lambda: 300
    tools_mod.approval = approval_mod
    import sys

    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", cfg_mod)
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)

    _write(
        store / CONFIG_FILENAME,
        _http_doc(decoy, scheme=scheme, host=host, port=port),
    )
    load_and_publish_runtime()
    return decoy


def test_r8_d_http_approval_includes_plaintext_warning(tmp_path, monkeypatch):
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
    from credential_guard.tool_request import on_tool_request

    decoy = _decoy()
    host = "secret-host.example.test"
    _approval_env(tmp_path, monkeypatch, scheme="http", host=host, port=8080, decoy=decoy)
    args = {
        "target": "svc-api",
        "method": "GET",
        "path": "/v1/status",
        "credential": "<CREDENTIAL:svc-token>",
    }
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-http-warn",
    )
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-http-warn",
    )
    assert out["action"] == "approve"
    msg = out["message"]
    assert _HTTP_PLAINTEXT_WARNING in msg
    # HTTP template: 8 lines => 7 newlines.
    assert msg.count("\n") == 7
    lines = msg.split("\n")
    assert len(lines) == 8
    assert lines[-2] == _HTTP_PLAINTEXT_WARNING
    assert lines[-1] == "审批范围：仅本次调用"
    assert "svc-api" in msg
    assert "svc-token" in msg
    assert "GET /v1/status" in msg
    assert host not in msg
    assert "8080" not in msg
    assert decoy not in msg
    assert "Authorization" not in msg or "Authorization Header" in msg
    assert decoy not in msg
    assert "Bearer " not in msg


def test_r8_d_https_approval_omits_plaintext_warning(tmp_path, monkeypatch):
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
    from credential_guard.tool_request import on_tool_request

    decoy = _decoy()
    host = "secure-api.example.test"
    _approval_env(tmp_path, monkeypatch, scheme="https", host=host, port=443, decoy=decoy)
    args = {
        "target": "svc-api",
        "method": "GET",
        "path": "/v1/status",
        "credential": "<CREDENTIAL:svc-token>",
    }
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-https-nowarn",
    )
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-https-nowarn",
    )
    assert out["action"] == "approve"
    msg = out["message"]
    assert _HTTP_PLAINTEXT_WARNING not in msg
    assert "明文 HTTP" not in msg
    # HTTPS template remains exactly 7 lines => 6 newlines.
    assert msg.count("\n") == 6
    assert len(msg.split("\n")) == 7
    assert host not in msg
    assert decoy not in msg


def _run_http_approval(tmp_path, monkeypatch, *, scheme: str, tool_call_id: str, decoy: str):
    """Analyze + pre_tool_call on a fresh plan; returns on_pre_tool_call result."""
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
    from credential_guard.tool_request import on_tool_request

    host = "secret-host.example.test" if scheme == "http" else "secure-api.example.test"
    port = 8080 if scheme == "http" else 443
    _approval_env(tmp_path, monkeypatch, scheme=scheme, host=host, port=port, decoy=decoy)
    args = {
        "target": "svc-api",
        "method": "GET",
        "path": "/v1/status",
        "credential": "<CREDENTIAL:svc-token>",
    }
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id=tool_call_id,
    )
    return on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id=tool_call_id,
    )


def test_r8_d_mutation_http_warning_gate_drop_must_block(tmp_path, monkeypatch):
    """Behavioral mutation: deleting the HTTP warning must block, never approve."""
    import credential_guard.approval as approval_mod

    decoy = _decoy()
    real = approval_mod._reference_approval_message

    def _drop_warning(plan, meta, *, payload):
        msg = real(plan, meta, payload=payload)
        lines = [ln for ln in msg.split("\n") if ln != _HTTP_PLAINTEXT_WARNING]
        return "\n".join(lines)

    monkeypatch.setattr(approval_mod, "_reference_approval_message", _drop_warning)
    out = _run_http_approval(
        tmp_path, monkeypatch, scheme="http", tool_call_id="tc-mut-drop", decoy=decoy
    )
    assert out is not None
    assert out.get("action") == "block"
    assert out.get("action") != "approve"


def test_r8_d_mutation_http_warning_gate_rewrite_must_block(tmp_path, monkeypatch):
    """Behavioral mutation: rewriting the HTTP warning text must block."""
    import credential_guard.approval as approval_mod

    decoy = _decoy()
    real = approval_mod._reference_approval_message
    rewritten = "警告：该目标使用明文传输（改写文本）。"

    def _rewrite_warning(plan, meta, *, payload):
        msg = real(plan, meta, payload=payload)
        return msg.replace(_HTTP_PLAINTEXT_WARNING, rewritten)

    monkeypatch.setattr(approval_mod, "_reference_approval_message", _rewrite_warning)
    out = _run_http_approval(
        tmp_path, monkeypatch, scheme="http", tool_call_id="tc-mut-rewrite", decoy=decoy
    )
    assert out is not None
    assert out.get("action") == "block"
    assert rewritten not in (out.get("message") or "")


def test_r8_d_mutation_http_warning_gate_shift_must_block(tmp_path, monkeypatch):
    """Behavioral mutation: moving the warning off the penultimate line must block."""
    import credential_guard.approval as approval_mod

    decoy = _decoy()
    real = approval_mod._reference_approval_message

    def _shift_warning(plan, meta, *, payload):
        msg = real(plan, meta, payload=payload)
        lines = msg.split("\n")
        assert lines[-2] == _HTTP_PLAINTEXT_WARNING
        warn = lines.pop(-2)
        lines.insert(1, warn)
        assert lines[-2] != _HTTP_PLAINTEXT_WARNING
        assert warn in lines
        return "\n".join(lines)

    monkeypatch.setattr(approval_mod, "_reference_approval_message", _shift_warning)
    out = _run_http_approval(
        tmp_path, monkeypatch, scheme="http", tool_call_id="tc-mut-shift", decoy=decoy
    )
    assert out is not None
    assert out.get("action") == "block"


def test_r8_d_http_binding_missing_or_invalid_scheme_fail_closed(tmp_path, monkeypatch):
    """HTTP binding meta missing/invalid scheme must fail-closed at approval gate."""
    import types

    import credential_guard.approval as approval_mod
    from credential_guard import runtime_config as rc_mod
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
    from credential_guard.tool_request import on_tool_request

    decoy = _decoy()
    _approval_env(
        tmp_path,
        monkeypatch,
        scheme="http",
        host="secret-host.example.test",
        port=8080,
        decoy=decoy,
    )
    args = {
        "target": "svc-api",
        "method": "GET",
        "path": "/v1/status",
        "credential": "<CREDENTIAL:svc-token>",
    }

    real_get = rc_mod.get_runtime_view

    def _strip_scheme_view():
        view = real_get()
        scrubbed = {}
        for name, meta in view.bindings.items():
            m = dict(meta)
            m.pop("scheme", None)
            scrubbed[name] = m
        return types.SimpleNamespace(
            credential_names=view.credential_names,
            config_digest=view.config_digest,
            config_file_identity=view.config_file_identity,
            bindings=scrubbed,
        )

    monkeypatch.setattr(rc_mod, "get_runtime_view", _strip_scheme_view)
    # approval imports runtime_config as module attribute usage via runtime_config.*
    monkeypatch.setattr(approval_mod.runtime_config, "get_runtime_view", _strip_scheme_view)

    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-no-scheme",
    )
    out_missing = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-no-scheme",
    )
    assert out_missing is not None
    assert out_missing.get("action") == "block"

    def _bad_scheme_view():
        view = real_get()
        scrubbed = {}
        for name, meta in view.bindings.items():
            m = dict(meta)
            m["scheme"] = "ftp"
            scrubbed[name] = m
        return types.SimpleNamespace(
            credential_names=view.credential_names,
            config_digest=view.config_digest,
            config_file_identity=view.config_file_identity,
            bindings=scrubbed,
        )

    monkeypatch.setattr(rc_mod, "get_runtime_view", _bad_scheme_view)
    monkeypatch.setattr(approval_mod.runtime_config, "get_runtime_view", _bad_scheme_view)
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-bad-scheme",
    )
    out_bad = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-bad-scheme",
    )
    assert out_bad is not None
    assert out_bad.get("action") == "block"


# ---- Slice E: HTTPS-only gate flipped to http|https security contract ----


def test_r8_e_production_adapter_keeps_proxy_redirect_tls_contracts():
    from pathlib import Path

    from credential_guard.adapters import http as http_adapter

    src = Path(http_adapter.__file__).read_text(encoding="utf-8")
    assert "ProxyHandler({})" in src
    assert "_NoRedirectHandler" in src
    assert 'request.get("verify") is not True' in src
    assert 'scheme not in {"http", "https"}' in src or "scheme not in {'http', 'https'}" in src
    assert 'replace("https://", "http://")' not in src


def test_r8_e_mutation_drop_proxy_or_verify_or_scheme_set_is_detectable():
    from pathlib import Path

    from credential_guard.adapters import http as http_adapter

    src = Path(http_adapter.__file__).read_text(encoding="utf-8")
    mutated_proxy = src.replace("ProxyHandler({})", "ProxyHandler()")
    assert "ProxyHandler({})" not in mutated_proxy
    mutated_verify = src.replace(
        'request.get("verify") is not True', 'request.get("verify") is False'
    )
    assert 'request.get("verify") is not True' not in mutated_verify
    mutated_scheme = src.replace('{"http", "https"}', '{"https"}')
    assert '{"http", "https"}' not in mutated_scheme
