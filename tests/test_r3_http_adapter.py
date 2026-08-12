"""R3A Slice A3: structured HTTP adapter with fake transport."""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from credential_guard.config import CONFIG_FILENAME, CredentialGuardConfig
from credential_guard.injection import SecretLease, resolve_one_for_execution
from credential_guard.injection_plan import InjectionPlan, PlanState
from credential_guard import runtime_config as rc


def _decoy(n: int = 16) -> str:
    return "CG_SYNTHETIC_DECOY_" + secrets.token_hex(n)


def _write(path: Path, doc: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps(doc, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _http_doc(token: str, **req_over: Any) -> Dict[str, Any]:
    request = {
        "allowed_methods": ["POST"],
        "allowed_paths": ["/job/project-x/build"],
    }
    request.update(req_over)
    return {
        "version": 2,
        "credentials": {"jenkins-token": {"type": "token", "value": token}},
        "bindings": {
            "jenkins-production": {
                "type": "http",
                "credential_ref": "jenkins-token",
                "target": {
                    "scheme": "https",
                    "host": "jenkins.example.test",
                    "port": 443,
                },
                "request": request,
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
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
    # Block proxy env influence.
    for k in list(os.environ):
        if k.lower().endswith("_proxy") or k.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            monkeypatch.delenv(k, raising=False)
    rc.reset_runtime_for_tests()
    yield store
    rc.reset_runtime_for_tests()


def _consumed_plan() -> InjectionPlan:
    return InjectionPlan(
        session_id="s1",
        turn_id="t1",
        tool_call_id="c1",
        tool_name="http_credential_request",
        args_digest="a" * 64,
        reference_arg_path=("credential",),
        credential_name="jenkins-token",
        target_name="jenkins-production",
        binding_name="jenkins-production",
        binding_type="http",
        config_digest="b" * 64,
        binding_digest="c" * 64,
        target_digest="d" * 64,
        config_file_identity={"path": "x", "sha256": "e" * 64, "size": 1},
        nonce="f" * 32,
        created_monotonic=0.0,
        expires_monotonic=999999.0,
        state=PlanState.CONSUMED,
    )


def test_a3_bearer_inject_via_fake_transport(isolated_runtime: Path):
    """Minimal A3 RED: adapter builds URL from binding + relative path and injects Bearer."""
    from credential_guard.adapters import http as http_adapter

    decoy = _decoy()
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    view = rc.load_and_publish_runtime()
    cfg = CredentialGuardConfig.load(isolated_runtime / CONFIG_FILENAME)
    binding = dict(cfg.bindings["jenkins-production"])
    lease = resolve_one_for_execution(_consumed_plan(), view)

    captured: List[Dict[str, Any]] = []

    def fake_transport(request: Dict[str, Any]) -> Dict[str, Any]:
        captured.append(request)
        return {
            "status": 201,
            "headers": {
                "content-type": "application/json",
                "set-cookie": "session=evil",
                "authorization": "should-not-return",
            },
            "body": b'{"queued":true}',
        }

    result = http_adapter.execute_http(
        binding=binding,
        method="POST",
        path="/job/project-x/build",
        lease=lease,
        transport=fake_transport,
    )
    lease.close()
    assert result["ok"] is True
    assert result["status"] == 201
    assert result["truncated"] is False
    assert result["headers"].get("content-type") == "application/json"
    assert "set-cookie" not in {k.lower() for k in result["headers"]}
    assert "authorization" not in {k.lower() for k in result["headers"]}
    assert decoy not in json.dumps(result)

    assert len(captured) == 1
    req = captured[0]
    assert req["method"] == "POST"
    assert req["url"] == "https://jenkins.example.test:443/job/project-x/build"
    assert req["headers"]["Authorization"] == f"Bearer {decoy}"
    assert req["allow_redirects"] is False
    assert req["trust_env"] is False
    assert req["verify"] is True


def _run(isolated_runtime, decoy, method="POST", path="/job/project-x/build", transport=None, doc=None):
    from credential_guard.adapters import http as http_adapter

    _write(isolated_runtime / CONFIG_FILENAME, doc or _http_doc(decoy))
    view = rc.load_and_publish_runtime()
    cfg = CredentialGuardConfig.load(isolated_runtime / CONFIG_FILENAME)
    binding = dict(cfg.bindings["jenkins-production"])
    # unfreeze nested mappingproxies for adapter
    binding["target"] = dict(binding["target"])
    binding["request"] = dict(binding["request"])
    binding["inject"] = dict(binding["inject"])
    lease = resolve_one_for_execution(_consumed_plan(), view)
    try:
        return http_adapter.execute_http(
            binding=binding,
            method=method,
            path=path,
            lease=lease,
            transport=transport
            or (
                lambda r: {
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body": b"{}",
                }
            ),
        )
    finally:
        lease.close()


@pytest.mark.parametrize(
    "path",
    [
        "//evil",
        "/job/../etc/passwd",
        "/job/%2e%2e/secret",
        "/job/x?q=1",
        "/job/x#frag",
        "/job/x\\y",
        "http://jenkins.example.test/job/x",
        "/job/\nX",
    ],
)
def test_a3_rejects_dangerous_paths(isolated_runtime: Path, path: str):
    decoy = _decoy()
    result = _run(isolated_runtime, decoy, path=path)
    assert result["ok"] is False
    assert result["error"] in {"HTTP_REQUEST_REJECTED", "HTTP_PATH_REJECTED", "HTTP_ADAPTER_FAILED"}
    assert decoy not in json.dumps(result)


def test_a3_rejects_method_outside_allowlist(isolated_runtime: Path):
    decoy = _decoy()
    result = _run(isolated_runtime, decoy, method="DELETE")
    assert result["ok"] is False
    assert result["error"] == "HTTP_REQUEST_REJECTED"


def test_a3_three_xx_does_not_follow(isolated_runtime: Path):
    decoy = _decoy()
    calls = []

    def transport(req):
        calls.append(req)
        return {
            "status": 302,
            "headers": {"location": "https://evil.example.test/steal", "content-type": "text/plain"},
            "body": b"redirect",
        }

    result = _run(isolated_runtime, decoy, transport=transport)
    assert result["ok"] is True
    assert result["status"] == 302
    assert len(calls) == 1
    assert calls[0]["allow_redirects"] is False
    assert "location" not in result["headers"]  # not in safe allowlist
    assert decoy not in json.dumps(result)


def test_a3_scrubs_decoy_from_body(isolated_runtime: Path):
    decoy = _decoy()

    def transport(req):
        return {
            "status": 200,
            "headers": {"content-type": "text/plain"},
            "body": f"token={decoy}".encode(),
        }

    result = _run(isolated_runtime, decoy, transport=transport)
    dumped = json.dumps(result)
    assert decoy not in dumped
    assert result["ok"] is True or result.get("error") == "HTTP_RESULT_SCRUBBED"


def test_a3_basic_and_api_key_header_inject(isolated_runtime: Path):
    from credential_guard.adapters import http as http_adapter

    password = _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "svc": {
                "type": "username_password",
                "username": "cg_readonly",
                "password": password,
            },
            "tok": {"type": "token", "value": password + "tok"},
        },
        "bindings": {
            "svc-basic": {
                "type": "http",
                "credential_ref": "svc",
                "target": {
                    "scheme": "https",
                    "host": "svc.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/v1"],
                },
                "inject": {
                    "type": "basic",
                    "location": "authorization_header",
                },
                "approval": "required",
            },
            "api": {
                "type": "http",
                "credential_ref": "tok",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/v1"],
                },
                "inject": {"type": "api_key_header", "header_name": "X-Api-Key"},
                "approval": "required",
            },
        },
    }
    _write(isolated_runtime / CONFIG_FILENAME, doc)
    view = rc.load_and_publish_runtime()
    cfg = CredentialGuardConfig.load(isolated_runtime / CONFIG_FILENAME)

    captured = []

    def transport(req):
        captured.append(req)
        return {"status": 200, "headers": {"content-type": "text/plain"}, "body": b"ok"}

    # basic
    lease = resolve_one_for_execution(
        InjectionPlan(
            **{**_consumed_plan().__dict__, "credential_name": "svc", "binding_name": "svc-basic", "target_name": "svc-basic"}
        ),
        view,
    )
    binding = {k: (dict(v) if hasattr(v, "keys") else v) for k, v in dict(cfg.bindings["svc-basic"]).items()}
    http_adapter.execute_http(binding=binding, method="GET", path="/v1", lease=lease, transport=transport)
    lease.close()
    expected = "Basic " + base64.b64encode(b"cg_readonly:" + password.encode()).decode()
    assert captured[0]["headers"]["Authorization"] == expected

    # api key
    lease2 = resolve_one_for_execution(
        InjectionPlan(
            **{**_consumed_plan().__dict__, "credential_name": "tok", "binding_name": "api", "target_name": "api", "tool_call_id": "c2"}
        ),
        view,
    )
    binding2 = {k: (dict(v) if hasattr(v, "keys") else v) for k, v in dict(cfg.bindings["api"]).items()}
    http_adapter.execute_http(binding=binding2, method="GET", path="/v1", lease=lease2, transport=transport)
    lease2.close()
    assert captured[1]["headers"]["X-Api-Key"] == password + "tok"
    assert password not in json.dumps({"h": {k: ("***" if k in ("Authorization", "X-Api-Key") else v) for k, v in captured[1]["headers"].items()}})
