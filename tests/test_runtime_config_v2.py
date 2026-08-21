"""R1B: formal runtime switches to credential-guard.json only (strict TDD)."""

from __future__ import annotations

import ast
import base64
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from credential_guard.config import CONFIG_FILENAME
from credential_guard.middleware import SAFE_BLOCK_MESSAGE, is_blocked_response_content, on_llm_execution, on_llm_request
from credential_guard.models import make_token_id
from credential_guard.state import get_egress_registry_snapshot, get_registry


def _decoy(n: int = 16) -> str:
    return "CG_R1B_" + secrets.token_hex(n)


def _chmod700(path: Path) -> None:
    os.chmod(path, 0o700)


def _chmod600(path: Path) -> None:
    os.chmod(path, 0o600)


def _write_json(path: Path, doc: Any, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod700(path.parent)
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, mode)
    return path


def _v2_token(token: str, *, name: str = "internal_api_token") -> Dict[str, Any]:
    return {
        "version": 2,
        "credentials": {name: {"type": "token", "value": token}},
        "bindings": {
            "internal-api": {
                "type": "http",
                "credential_ref": name,
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }


def _v2_userpass(
    password: str,
    *,
    name: str = "svc_user",
    username: str = "cg_readonly",
) -> Dict[str, Any]:
    return {
        "version": 2,
        "credentials": {
            name: {
                "type": "username_password",
                "username": username,
                "password": password,
            }
        },
        "bindings": {
            "svc-basic": {
                "type": "http",
                "credential_ref": name,
                "target": {
                    "scheme": "https",
                    "host": "svc.example.test",
                    "port": 8443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "basic", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }


def _v1_creds(password: str, cred_id: str = "mysql_canary_credential") -> Dict[str, Any]:
    return {
        "version": 1,
        "credentials": {
            cred_id: {
                "type": "mysql",
                "username": "cg_readonly",
                "password": password,
            }
        },
    }


def _v1_targets() -> Dict[str, Any]:
    return {"version": 1, "targets": {}}


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir(mode=0o700)
    _chmod700(store)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()
    # Reset runtime publish state between tests.
    try:
        from credential_guard import runtime_config as rc

        if hasattr(rc, "reset_runtime_for_tests"):
            rc.reset_runtime_for_tests()
    except ImportError:
        pass
    return hermes, store


def _assert_exec_blocked(canary: str) -> None:
    calls: List[Any] = []

    def fake_next(req):
        calls.append(req)
        return {"ok": True}

    blocked = on_llm_execution(
        request={"messages": [{"role": "user", "content": f"x={canary}"}]},
        next_call=fake_next,
    )
    assert calls == []
    assert getattr(blocked, "model", "") == "credential-guard-blocked"
    assert is_blocked_response_content(blocked.choices[0].message.content)
    blob = str(blocked)
    assert canary not in blob
    assert "Traceback" not in blob
    # Product guidance may mention the config basename; forbid raw exception names.
    assert "RuntimeConfigError" not in blob
    assert "/Users/" not in blob
    assert "CG-CONFIG-UNAVAILABLE" in blocked.choices[0].message.content


# ---------------------------------------------------------------------------
# A. Formal source switch
# ---------------------------------------------------------------------------


def test_a1_only_v2_loads_and_redacts(isolated_home):
    from credential_guard.runtime_config import (
        get_runtime_view,
        load_and_publish_runtime,
    )

    hermes, store = isolated_home
    token = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(token))
    view = load_and_publish_runtime()
    assert view.config_digest
    assert "internal-api" in view.binding_names
    assert "internal_api_token" in view.binding_credential_refs
    reg = get_egress_registry_snapshot()
    expected = f"<SECRET:{make_token_id('internal_api_token', 'value')}>"
    assert any(v.token == expected for v in reg.values())

    captured = []
    on_llm_execution(
        request={"messages": [{"content": token}]},
        next_call=lambda r: captured.append(r) or {"ok": True},
    )
    assert len(captured) == 1
    wire = json.dumps(captured[0])
    assert wire.count(token) == 0
    assert expected in wire
    published = get_runtime_view()
    assert published.config_digest == view.config_digest


def test_a2_only_legacy_dual_files_fail_closed_no_fallback(isolated_home):
    from credential_guard.runtime_config import RuntimeConfigError, load_and_publish_runtime

    hermes, store = isolated_home
    legacy = _decoy()
    _write_json(store / "credentials.json", _v1_creds(legacy))
    _write_json(store / "targets.json", _v1_targets())
    with pytest.raises(RuntimeConfigError) as ei:
        load_and_publish_runtime()
    assert ei.value.code == "RUNTIME_CONFIG_NOT_FOUND"
    blob = f"{ei.value!s}{ei.value!r}"
    assert legacy not in blob
    assert str(store) not in blob
    _assert_exec_blocked(legacy)


def test_a3_both_present_only_v2_used_legacy_decoy_absent(isolated_home):
    hermes, store = isolated_home
    v2_token = _decoy()
    legacy = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(v2_token))
    _write_json(store / "credentials.json", _v1_creds(legacy))
    _write_json(store / "targets.json", _v1_targets())

    captured = []
    on_llm_execution(
        request={
            "messages": [
                {"content": f"v2={v2_token}"},
                {"content": f"legacy={legacy}"},
            ]
        },
        next_call=lambda r: captured.append(r) or {"ok": True},
    )
    assert len(captured) == 1
    wire = json.dumps(captured[0])
    assert wire.count(v2_token) == 0
    # Legacy decoy must not be treated as registered secret (still plaintext
    # on wire is OK for unregistered text); must NOT become a SECRET token
    # from the dual-file id.
    legacy_token = f"<SECRET:{make_token_id('mysql_canary_credential', 'password')}>"
    assert legacy_token not in wire
    v2_tok = f"<SECRET:{make_token_id('internal_api_token', 'value')}>"
    assert v2_tok in wire
    # Ensure dual-file secret was not ingested: registry must not contain it.
    reg = get_egress_registry_snapshot()
    secrets_set = {v.secret for v in reg.values()}
    assert legacy not in secrets_set
    assert v2_token in secrets_set


def test_a4_invalid_v2_plus_valid_legacy_no_fallback(isolated_home):
    from credential_guard.runtime_config import RuntimeConfigError, load_and_publish_runtime

    hermes, store = isolated_home
    legacy = _decoy()
    _write_json(store / CONFIG_FILENAME, {"version": 2, "credentials": {}, "extra": 1})
    _write_json(store / "credentials.json", _v1_creds(legacy))
    _write_json(store / "targets.json", _v1_targets())
    with pytest.raises(RuntimeConfigError) as ei:
        load_and_publish_runtime()
    assert ei.value.code in {"RUNTIME_CONFIG_INVALID", "RUNTIME_CONFIG_UNAVAILABLE"}
    _assert_exec_blocked(legacy)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "mode_0644",
        "symlink",
        "parent_0755",
        "duplicate_key",
        "unknown_field",
    ],
)
def test_a5_v2_security_and_schema_faults(isolated_home, tmp_path, fault):
    from credential_guard.runtime_config import RuntimeConfigError, load_and_publish_runtime

    hermes, store = isolated_home
    decoy = _decoy()
    path = store / CONFIG_FILENAME
    if fault == "missing":
        pass
    elif fault == "mode_0644":
        _write_json(path, _v2_token(decoy), mode=0o644)
    elif fault == "symlink":
        real = tmp_path / "real.json"
        _write_json(real, _v2_token(decoy))
        path.symlink_to(real)
    elif fault == "parent_0755":
        _write_json(path, _v2_token(decoy))
        os.chmod(store, 0o755)
    elif fault == "duplicate_key":
        # Hand-crafted JSON with duplicate top-level key.
        path.write_text(
            '{"version":2,"credentials":{},"bindings":{},"credentials":{}}',
            encoding="utf-8",
        )
        _chmod600(path)
    elif fault == "unknown_field":
        _write_json(
            path,
            {
                "version": 2,
                "credentials": {},
                "bindings": {},
                "unexpected": True,
            },
        )
    with pytest.raises(RuntimeConfigError) as ei:
        load_and_publish_runtime()
    assert ei.value.code in {
        "RUNTIME_CONFIG_NOT_FOUND",
        "RUNTIME_CONFIG_INVALID",
        "RUNTIME_CONFIG_UNAVAILABLE",
    }
    blob = f"{ei.value!s}{ei.value!r}{getattr(ei.value, 'code', '')}"
    assert decoy not in blob
    assert str(path) not in blob
    _assert_exec_blocked(decoy)


def test_a6_static_call_graph_hooks_state_middleware_no_dual_loader():
    root = Path(__file__).resolve().parents[1] / "credential_guard"
    forbidden_names = {
        "build_redaction_registry_snapshot",
        "_load_credentials_document",
        "_load_targets_document",
        "FileCredentialBackend",
        "TargetMetadataBackend",
    }
    forbidden_literals = {"credentials.json", "targets.json"}
    for rel in ("hooks.py", "middleware.py", "state.py"):
        src = (root / rel).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                assert name not in forbidden_names, f"{rel} calls {name}"
            if isinstance(node, ast.ImportFrom):
                if node.module and "file_backend" in node.module:
                    imported = {a.name for a in node.names}
                    assert not (imported & forbidden_names), f"{rel} imports {imported}"
        for lit in forbidden_literals:
            # Allow comments/docs only if absent from string constants used as paths.
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    assert lit not in node.value, f"{rel} string literal {lit}"


# ---------------------------------------------------------------------------
# B. Atomic registry
# ---------------------------------------------------------------------------


def test_b1_multiple_credentials_built_atomically(isolated_home):
    from credential_guard.runtime_config import load_and_publish_runtime

    hermes, store = isolated_home
    t1, t2 = _decoy(), _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "token_a": {"type": "token", "value": t1},
            "token_b": {"type": "token", "value": t2},
        },
        "bindings": {
            "bind-a": {
                "type": "http",
                "credential_ref": "token_a",
                "target": {
                    "scheme": "https",
                    "host": "a.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
            "bind-b": {
                "type": "http",
                "credential_ref": "token_b",
                "target": {
                    "scheme": "https",
                    "host": "b.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
        },
    }
    _write_json(store / CONFIG_FILENAME, doc)
    view = load_and_publish_runtime()
    reg = get_egress_registry_snapshot()
    secrets_set = {v.secret for v in reg.values()}
    assert t1 in secrets_set and t2 in secrets_set
    assert set(view.binding_names) == {"bind-a", "bind-b"}


def test_b2_fault_injection_mid_build_does_not_publish_partial(isolated_home, monkeypatch):
    from credential_guard import runtime_config as rc
    from credential_guard.registry import CredentialRegistry

    hermes, store = isolated_home
    t1, t2 = _decoy(), _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "token_a": {"type": "token", "value": t1},
            "token_b": {"type": "token", "value": t2},
        },
        "bindings": {
            "bind-a": {
                "type": "http",
                "credential_ref": "token_a",
                "target": {
                    "scheme": "https",
                    "host": "a.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
            "bind-b": {
                "type": "http",
                "credential_ref": "token_b",
                "target": {
                    "scheme": "https",
                    "host": "b.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
        },
    }
    _write_json(store / CONFIG_FILENAME, doc)
    # Publish a known-good empty generation first.
    empty = {
        "version": 2,
        "credentials": {},
        "bindings": {},
    }
    _write_json(store / CONFIG_FILENAME, empty)
    good = rc.load_and_publish_runtime()
    assert good.generation >= 1
    old_digest = good.config_digest

    _write_json(store / CONFIG_FILENAME, doc)
    real_register = CredentialRegistry.register
    state = {"n": 0}

    def flaky(self, key, field, secret):
        state["n"] += 1
        if state["n"] >= 2:
            raise ValueError("injected build fault")
        return real_register(self, key, field, secret)

    monkeypatch.setattr(CredentialRegistry, "register", flaky)
    with pytest.raises(rc.RuntimeConfigError):
        rc.load_and_publish_runtime()
    # Published view must remain previous complete generation (or unavailable).
    # Fail-closed default: unavailable → protected request blocked.
    _assert_exec_blocked(t1)
    _assert_exec_blocked(t2)
    # If a view remains, it must be the old digest without partial secrets.
    try:
        view = rc.get_runtime_view()
        assert view.config_digest == old_digest
        secrets_set = {v.secret for v in view.egress_registry.values()}
        assert t1 not in secrets_set and t2 not in secrets_set
    except rc.RuntimeConfigError as exc:
        assert exc.code == "RUNTIME_CONFIG_UNAVAILABLE"


def test_b3_reload_success_same_generation_trio(isolated_home):
    from credential_guard.runtime_config import load_and_publish_runtime, reload_runtime

    hermes, store = isolated_home
    t1 = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(t1, name="tok_one"))
    v1 = load_and_publish_runtime()
    t2 = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(t2, name="tok_two"))
    v2 = reload_runtime()
    assert v2.generation > v1.generation
    assert v2.config_digest != v1.config_digest
    # Same-generation consistency across registry / digest / binding view.
    assert v2.config_digest == v2.binding_view_digest
    assert v2.config_digest == v2.egress_registry_digest_marker
    assert "tok_two" in v2.binding_credential_refs or "internal-api" in v2.binding_names
    reg = get_egress_registry_snapshot()
    assert t2 in {v.secret for v in reg.values()}
    assert t1 not in {v.secret for v in reg.values()}


def test_b4_reload_failure_fail_closed(isolated_home):
    from credential_guard.runtime_config import load_and_publish_runtime, reload_runtime

    hermes, store = isolated_home
    token = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(token))
    load_and_publish_runtime()
    # Corrupt config.
    (store / CONFIG_FILENAME).write_text("{not-json", encoding="utf-8")
    _chmod600(store / CONFIG_FILENAME)
    with pytest.raises(Exception):
        reload_runtime()
    _assert_exec_blocked(token)


def test_b5_concurrent_readers_see_full_generations_only(isolated_home):
    from credential_guard.runtime_config import load_and_publish_runtime, reload_runtime

    hermes, store = isolated_home
    digests_seen = []
    errors = []
    stop = threading.Event()

    t_a = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(t_a, name="tok_a"))
    load_and_publish_runtime()

    def reader():
        from credential_guard import runtime_config as rc

        while not stop.is_set():
            try:
                view = rc.get_runtime_view()
                digests_seen.append(view.config_digest)
                secrets_set = {v.secret for v in view.egress_registry.values()}
                # Never a mix of both generations' secrets under one digest.
                if t_a in secrets_set and getattr(reader, "t_b", None) in secrets_set:
                    errors.append("mixed_generation")
            except rc.RuntimeConfigError:
                pass
            time.sleep(0.001)

    reader.t_b = None  # type: ignore[attr-defined]
    threads = [threading.Thread(target=reader) for _ in range(4)]
    for th in threads:
        th.start()
    time.sleep(0.02)
    t_b = _decoy()
    reader.t_b = t_b  # type: ignore[attr-defined]
    _write_json(store / CONFIG_FILENAME, _v2_token(t_b, name="tok_b"))
    reload_runtime()
    time.sleep(0.05)
    stop.set()
    for th in threads:
        th.join(timeout=2)
    assert errors == []
    assert digests_seen


def test_b6_canonical_copy_mutation_does_not_affect_runtime(isolated_home):
    from credential_guard.runtime_config import load_and_publish_runtime

    hermes, store = isolated_home
    token = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(token))
    view = load_and_publish_runtime()
    canonical = view.to_canonical_dict()
    canonical["credentials"]["internal_api_token"]["value"] = "MUTATED_" + token
    # Runtime registry must still hold original.
    reg = get_egress_registry_snapshot()
    secrets_set = {v.secret for v in reg.values()}
    assert token in secrets_set
    assert ("MUTATED_" + token) not in secrets_set


# ---------------------------------------------------------------------------
# C. Egress zero-leak
# ---------------------------------------------------------------------------


def test_c_token_and_password_and_nested_and_variants(isolated_home):
    hermes, store = isolated_home
    token = _decoy()
    password = _decoy()
    username = "cg_u_" + secrets.token_hex(3)
    doc = {
        "version": 2,
        "credentials": {
            "api_tok": {"type": "token", "value": token},
            "svc_up": {
                "type": "username_password",
                "username": username,
                "password": password,
            },
        },
        "bindings": {
            "b1": {
                "type": "http",
                "credential_ref": "api_tok",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
            "b2": {
                "type": "http",
                "credential_ref": "svc_up",
                "target": {
                    "scheme": "https",
                    "host": "svc.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "basic", "location": "authorization_header"},
                "approval": "required",
            },
        },
    }
    _write_json(store / CONFIG_FILENAME, doc)
    combo = f"{username}:{password}"
    b64 = base64.b64encode(combo.encode()).decode("ascii")
    nested = {
        "messages": [
            {"content": token},
            {"content": password},
            {"list": [token, {"p": password}]},
            {"tuple_like": (combo,)},
            {"basic": b64},
        ]
    }
    # tuple becomes list via json; pass object graph to middleware.
    captured = []
    on_llm_execution(
        request=nested,
        next_call=lambda r: captured.append(r) or {"ok": True},
    )
    assert len(captured) == 1
    wire = json.dumps(captured[0], ensure_ascii=False)
    assert wire.count(token) == 0
    assert wire.count(password) == 0
    assert wire.count(combo) == 0
    assert wire.count(b64) == 0

    from credential_guard.hooks import on_transform_tool_result

    tool_out = on_transform_tool_result(
        result=json.dumps({"token": token, "password": password}),
        tool_name="terminal",
        arguments={},
    )
    assert token not in tool_out and password not in tool_out


def test_c_loader_exception_provider_calls_zero(isolated_home, monkeypatch):
    from credential_guard import runtime_config as rc

    hermes, store = isolated_home
    token = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(token))

    def boom(*_a, **_k):
        raise rc.RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE", "configuration error")

    monkeypatch.setattr(rc, "build_file_egress_registry", boom)
    _assert_exec_blocked(token)


def test_c_ssh_config_runtime_load_is_rejected(isolated_home):
    """R5: the formal runtime refuses ssh_config credentials and bindings."""
    from credential_guard.runtime_config import (
        RuntimeConfigError,
        load_and_publish_runtime,
    )

    hermes, store = isolated_home
    doc = {
        "version": 2,
        "credentials": {"jump_box": {"type": "ssh_config", "alias": "JumpHost"}},
        "bindings": {
            "jump_box": {
                "type": "ssh_config",
                "credential_ref": "jump_box",
                "approval": "required",
            }
        },
    }
    _write_json(store / CONFIG_FILENAME, doc)
    with pytest.raises(RuntimeConfigError):
        load_and_publish_runtime()


def test_c_require_runtime_adapter_removed(isolated_home):
    """C8: dead R1B stub is gone; adapters are real, not 'not ready'."""
    import credential_guard.runtime_config as rc

    hermes, store = isolated_home
    token = _decoy()
    _write_json(store / CONFIG_FILENAME, _v2_token(token))
    rc.load_and_publish_runtime()
    assert not hasattr(rc, "require_runtime_adapter")
    assert "RUNTIME_ADAPTER_NOT_READY" not in Path(rc.__file__).read_text(encoding="utf-8")
    assert token  # keep canary in scope for hygiene


# ---------------------------------------------------------------------------
# D. Path protection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "basename",
    [
        "credential-guard.json",
        "credentials.json",
        "targets.json",
        "credentials.json.v1.bak",
        "targets.json.v1.bak",
        ".cg-migrate.journal",
        ".cg-migrate.lock",
        ".credential-guard.runtime.lock",
        ".cg-migrate-new-abc.tmp",
    ],
)
def test_d_store_artifacts_blocked_for_read_search_terminal(
    isolated_home, basename
):
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.hooks import on_transform_tool_result
    from credential_guard.sensitive_paths import path_is_protected

    hermes, store = isolated_home
    # Minimal valid v2 so egress path is healthy for non-path tests.
    _write_json(store / CONFIG_FILENAME, {"version": 2, "credentials": {}, "bindings": {}})
    target = store / basename
    if not target.exists():
        target.write_text("{}", encoding="utf-8")
        try:
            _chmod600(target)
        except OSError:
            pass
    assert path_is_protected(str(target))

    blocked = on_pre_tool_call(
        tool_name="read_file", args={"path": str(target)}
    )
    assert isinstance(blocked, dict) and blocked.get("action") == "block"

    search = on_pre_tool_call(
        tool_name="search_files", args={"path": str(store), "pattern": "*"}
    )
    assert isinstance(search, dict) and search.get("action") == "block"

    term = on_pre_tool_call(
        tool_name="terminal", args={"command": f"cat {target}"}
    )
    assert isinstance(term, dict) and term.get("action") == "block"

    code = on_pre_tool_call(
        tool_name="execute_code",
        args={"code": f"open({str(target)!r}).read()"},
    )
    assert isinstance(code, dict) and code.get("action") == "block"

    # Secondary tool-result gate for execute_code (must not depend on registry).
    code_out = on_transform_tool_result(
        result="secret-file-body-execute-code-canary",
        tool_name="execute_code",
        args={"code": f"from pathlib import Path\nPath({str(target)!r}).read_text()"},
    )
    assert "blocked" in code_out
    assert "secret-file-body-execute-code-canary" not in code_out

    # Secondary tool-result gate.
    out = on_transform_tool_result(
        result="secret-file-body",
        tool_name="read_file",
        args={"path": str(target)},
    )
    assert "blocked" in out and "secret-file-body" not in out


def test_d_ordinary_dot_lock_not_blocked(isolated_home):
    """Similar ordinary ``.lock`` files outside the store must not be false-positive."""
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.sensitive_paths import path_is_protected

    hermes, store = isolated_home
    # Place outside credential-guard store (store contents are wholly sensitive).
    ordinary = hermes / "app.lock"
    ordinary.write_text("not-a-protocol-lock", encoding="utf-8")
    assert not path_is_protected(str(ordinary))
    assert (
        on_pre_tool_call(tool_name="read_file", args={"path": str(ordinary)}) is None
    )
    assert (
        on_pre_tool_call(
            tool_name="terminal", args={"command": f"cat {ordinary}"}
        )
        is None
    )
    assert (
        on_pre_tool_call(
            tool_name="execute_code",
            args={"code": f"open({str(ordinary)!r}).read()"},
        )
        is None
    )


def test_d_relative_and_dotdot_variants(isolated_home, monkeypatch):
    from credential_guard.sensitive_paths import path_is_protected

    hermes, store = isolated_home
    _write_json(store / CONFIG_FILENAME, {"version": 2, "credentials": {}, "bindings": {}})
    monkeypatch.chdir(hermes)
    assert path_is_protected("credential-guard/credential-guard.json")
    assert path_is_protected(str(Path("credential-guard") / ".." / "credential-guard" / CONFIG_FILENAME))


# ---------------------------------------------------------------------------
# E. Non-interference
# ---------------------------------------------------------------------------


def test_e_ordinary_chat_and_file_unaffected(isolated_home, tmp_path):
    from credential_guard.sensitive_paths import path_is_protected

    hermes, store = isolated_home
    _write_json(store / CONFIG_FILENAME, {"version": 2, "credentials": {}, "bindings": {}})
    ordinary = "hello ordinary chat without secrets"
    captured = []
    on_llm_execution(
        request={"messages": [{"content": ordinary}]},
        next_call=lambda r: captured.append(r) or {"ok": True},
    )
    assert len(captured) == 1
    assert ordinary in json.dumps(captured[0])
    note = tmp_path / "notes.txt"
    note.write_text("ok", encoding="utf-8")
    assert not path_is_protected(str(note))


# ---------------------------------------------------------------------------
# F. Profile boundary static
# ---------------------------------------------------------------------------


def test_f_no_real_worker_profile_strings_in_runtime_module():
    root = Path(__file__).resolve().parents[1] / "credential_guard"
    banned = (
        "profiles/worker",
        "profiles/default",
        "hermes -p worker",
        "hermes -p default",
    )
    for rel in ("runtime_config.py", "state.py", "hooks.py", "middleware.py"):
        path = root / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for b in banned:
            assert b not in text
