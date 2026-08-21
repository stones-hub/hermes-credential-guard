"""R1B: production credential-guard.json must feed egress redaction (TDD)."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import pytest

from credential_guard.config import CONFIG_FILENAME
from credential_guard.middleware import SAFE_BLOCK_MESSAGE, is_blocked_response_content, on_llm_execution
from credential_guard.models import make_token_id
from credential_guard.state import get_registry


def _runtime_canary() -> str:
    return "cg_canary_" + secrets.token_hex(16)


def _v2_userpass(
    cred_id: str,
    password: str,
    *,
    username: str = "cg_readonly",
) -> dict:
    return {
        "version": 2,
        "credentials": {
            cred_id: {
                "type": "username_password",
                "username": username,
                "password": password,
            }
        },
        "bindings": {},
    }


def _write_secure_store(
    root: Path,
    *,
    document: dict,
    dir_mode: int = 0o700,
    file_mode: int = 0o600,
) -> Path:
    store = root / "credential-guard"
    store.mkdir(mode=dir_mode, parents=True, exist_ok=True)
    os.chmod(store, dir_mode)
    cfg_path = store / CONFIG_FILENAME
    cfg_path.write_text(json.dumps(document), encoding="utf-8")
    os.chmod(cfg_path, file_mode)
    return store


@pytest.fixture
def isolated_hermes_home(tmp_path, monkeypatch):
    hermes_home = tmp_path / "hermes_home"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    get_registry().clear()
    try:
        from credential_guard.runtime_config import reset_runtime_for_tests

        reset_runtime_for_tests()
    except Exception:
        pass
    return hermes_home


def test_t1_file_secret_redacted_before_provider_without_manual_register(
    isolated_hermes_home,
):
    """File canary must be replaced; must not rely on get_registry().register()."""
    canary = _runtime_canary()
    cred_id = "mysql_canary_credential"
    _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary)
    )
    assert get_registry().values() == []

    captured = []

    def fake_next(req):
        captured.append(req)
        return {"ok": True}

    result = on_llm_execution(
        request={"messages": [{"role": "user", "content": f"password is {canary}"}]},
        next_call=fake_next,
    )
    assert result == {"ok": True}
    assert len(captured) == 1
    wire = json.dumps(captured[0], ensure_ascii=False)
    assert canary not in wire
    expected_token = f"<SECRET:{make_token_id(cred_id, 'password')}>"
    assert expected_token in wire
    assert wire.count(canary) == 0


def _assert_exec_fail_closed(canary: str) -> None:
    calls = []

    def fake_next(req):
        calls.append(req)
        return {"ok": True}

    blocked = on_llm_execution(
        request={"messages": [{"role": "user", "content": f"password is {canary}"}]},
        next_call=fake_next,
    )
    assert calls == []
    assert getattr(blocked, "model", "") == "credential-guard-blocked"
    assert is_blocked_response_content(blocked.choices[0].message.content)
    blob = str(blocked)
    assert canary not in blob
    # Actionable guidance may name the config basename; forbid internals/paths.
    assert "Traceback" not in blob
    assert "FileBackendError" not in blob
    assert "credential store" not in blob.lower()
    assert "/Users/" not in blob
    assert "CG-CONFIG-UNAVAILABLE" in blocked.choices[0].message.content


def test_t2_missing_unified_config_fail_closed(isolated_hermes_home):
    canary = _runtime_canary()
    store = isolated_hermes_home / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    # Legacy dual files only — must not fall back.
    legacy = store / "credentials.json"
    legacy.write_text(
        json.dumps(
            {
                "version": 1,
                "credentials": {
                    "mysql_canary_credential": {
                        "type": "mysql",
                        "username": "cg_readonly",
                        "password": canary,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    os.chmod(legacy, 0o600)
    tgt = store / "targets.json"
    tgt.write_text(json.dumps({"version": 1, "targets": {}}), encoding="utf-8")
    os.chmod(tgt, 0o600)
    _assert_exec_fail_closed(canary)


def test_t2_config_mode_0644_fail_closed(isolated_hermes_home):
    canary = _runtime_canary()
    _write_secure_store(
        isolated_hermes_home,
        document=_v2_userpass("mysql_canary_credential", canary),
        file_mode=0o644,
    )
    _assert_exec_fail_closed(canary)


def test_t2_config_symlink_fail_closed(isolated_hermes_home, tmp_path):
    canary = _runtime_canary()
    real = tmp_path / "real_cfg.json"
    real.write_text(
        json.dumps(_v2_userpass("mysql_canary_credential", canary)), encoding="utf-8"
    )
    os.chmod(real, 0o600)
    store = isolated_hermes_home / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    link = store / CONFIG_FILENAME
    link.symlink_to(real)
    _assert_exec_fail_closed(canary)


def test_t2_invalid_json_fail_closed(isolated_hermes_home):
    canary = _runtime_canary()
    store = isolated_hermes_home / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    bad = store / CONFIG_FILENAME
    bad.write_text("{not-json", encoding="utf-8")
    os.chmod(bad, 0o600)
    _assert_exec_fail_closed(canary)


def test_t2_schema_error_fail_closed(isolated_hermes_home):
    canary = _runtime_canary()
    bad_schema = {
        "version": 2,
        "credentials": {
            "mysql_canary_credential": {
                "type": "username_password",
                "username": "cg_readonly",
                "password": canary,
                "extra": "nope",
            }
        },
        "bindings": {},
    }
    _write_secure_store(isolated_hermes_home, document=bad_schema)
    _assert_exec_fail_closed(canary)


def test_t2_short_password_fail_closed(isolated_hermes_home):
    canary = "short1"  # < MIN_SECRET_LENGTH (8); still must not appear in response
    short_doc = _v2_userpass("mysql_canary_credential", canary)
    _write_secure_store(isolated_hermes_home, document=short_doc)
    _assert_exec_fail_closed(canary)


def test_t2_duplicate_secret_fail_closed(isolated_hermes_home):
    canary = _runtime_canary()
    dup = {
        "version": 2,
        "credentials": {
            "mysql_canary_credential": {
                "type": "username_password",
                "username": "cg_readonly",
                "password": canary,
            },
            "mysql_other_credential": {
                "type": "username_password",
                "username": "cg_other",
                "password": canary,
            },
        },
        "bindings": {},
    }
    _write_secure_store(isolated_hermes_home, document=dup)
    _assert_exec_fail_closed(canary)


def test_t2_identity_conflict_with_base_registry_fail_closed(isolated_hermes_home):
    canary_file = _runtime_canary()
    canary_base = _runtime_canary()
    cred_id = "mysql_canary_credential"
    _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary_file)
    )
    get_registry().register(cred_id, "password", canary_base)
    calls = []

    def fake_next(req):
        calls.append(req)
        return {"ok": True}

    blocked = on_llm_execution(
        request={
            "messages": [
                {"role": "user", "content": f"a={canary_file} b={canary_base}"}
            ]
        },
        next_call=fake_next,
    )
    assert calls == []
    blob = str(blocked)
    assert canary_file not in blob
    assert canary_base not in blob
    assert is_blocked_response_content(blocked.choices[0].message.content)


def test_t3_tool_result_text_and_json_use_file_snapshot(isolated_hermes_home):
    from credential_guard.hooks import on_transform_tool_result

    canary = _runtime_canary()
    cred_id = "mysql_canary_credential"
    _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary)
    )
    assert get_registry().values() == []
    # C9: tool-result reflux uses the same registry token as llm_request.
    secret_token = f"<SECRET:{make_token_id(cred_id, 'password')}>"

    text_out = on_transform_tool_result(
        result=f"found {canary} in output", tool_name="terminal", arguments={}
    )
    assert canary not in text_out
    assert secret_token in text_out
    assert f"<CREDENTIAL:{cred_id}>" not in text_out

    json_out = on_transform_tool_result(
        result=json.dumps({"password": canary}, ensure_ascii=False),
        tool_name="terminal",
        arguments={},
    )
    assert canary not in json_out
    parsed = json.loads(json_out)
    assert parsed["password"] == secret_token


def test_t3_tool_result_snapshot_failure_returns_safe_json(isolated_hermes_home):
    from credential_guard.hooks import on_transform_tool_result
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    canary = _runtime_canary()
    store = isolated_hermes_home / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    bad = store / CONFIG_FILENAME
    bad.write_text("{broken", encoding="utf-8")
    os.chmod(bad, 0o600)
    out = on_transform_tool_result(
        result=f"leak {canary}", tool_name="terminal", arguments={}
    )
    assert canary not in out
    assert out == RESULT_GUARD_FAIL_TEXT
    assert out.count(canary) == 0
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_t3_tool_result_uses_registry_secret_token(isolated_hermes_home):
    """C9: tool reflux must use registry <SECRET:cg_...> (not usable <CREDENTIAL:name>)."""
    from credential_guard.hooks import on_transform_tool_result

    canary = _runtime_canary()
    cred_id = "mysql_canary_credential"
    _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary)
    )
    secret_token = f"<SECRET:{make_token_id(cred_id, 'password')}>"
    text_out = on_transform_tool_result(
        result=f"found {canary} in output", tool_name="terminal", arguments={}
    )
    assert secret_token in text_out
    assert f"<CREDENTIAL:{cred_id}>" not in text_out


def test_t4_llm_request_redacts_file_canary_without_mutating_original(
    isolated_hermes_home,
):
    from credential_guard.middleware import on_llm_request

    canary = _runtime_canary()
    cred_id = "mysql_canary_credential"
    _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary)
    )
    assert get_registry().values() == []
    token = f"<SECRET:{make_token_id(cred_id, 'password')}>"
    original = {"messages": [{"role": "user", "content": f"password is {canary}"}]}
    out = on_llm_request(request=original)
    assert original["messages"][0]["content"] == f"password is {canary}"
    wire = json.dumps(out, ensure_ascii=False)
    assert canary not in wire
    assert token in out["request"]["messages"][0]["content"]


def test_t4_llm_request_backend_failure_returns_fixed_safe_request(
    isolated_hermes_home,
):
    from credential_guard.middleware import on_llm_request

    canary = _runtime_canary()
    store = isolated_hermes_home / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    bad = store / CONFIG_FILENAME
    bad.write_text("{broken", encoding="utf-8")
    os.chmod(bad, 0o600)
    original = {"messages": [{"role": "user", "content": f"password is {canary}"}]}
    out = on_llm_request(request=original)
    assert original["messages"][0]["content"] == f"password is {canary}"
    wire = json.dumps(out, ensure_ascii=False)
    assert canary not in wire
    assert out["request"]["messages"][0]["content"] == SAFE_BLOCK_MESSAGE
    assert out["reason"] == "redaction failed closed"


def test_t5_check_reports_egress_registry_ready(isolated_hermes_home, monkeypatch, capsys):
    from credential_guard.cli import run_check
    from tests.test_plugin_registration import _complete_mgr, _install_fake_mgr

    canary = _runtime_canary()
    cred_id = "mysql_canary_credential"
    store = _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary)
    )
    _install_fake_mgr(monkeypatch, _complete_mgr())
    code = run_check()
    out = capsys.readouterr().out
    assert code == 0
    assert "egress_registry=ready" in out
    assert "egress_opaque_count=2" in out
    assert canary not in out
    assert "cg_readonly" not in out  # username must not appear
    assert str(store.resolve()) not in out
    assert str(isolated_hermes_home.resolve()) not in out
    assert CONFIG_FILENAME not in out


def test_t5_check_reports_egress_registry_unavailable(
    isolated_hermes_home, monkeypatch, capsys
):
    from credential_guard.cli import run_check
    from tests.test_plugin_registration import _complete_mgr, _install_fake_mgr

    # No unified config under HERMES_HOME store.
    store = isolated_hermes_home / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    _install_fake_mgr(monkeypatch, _complete_mgr())
    code = run_check()
    out = capsys.readouterr().out
    assert "egress_registry=unavailable" in out
    assert "egress_opaque_count=" in out
    assert str(store.resolve()) not in out
    assert CONFIG_FILENAME not in out
    assert code != 0 or "egress_registry=unavailable" in out


def test_t5_register_path_uses_production_bridge(isolated_hermes_home):
    """After register(ctx), production middleware redacts file canary."""
    from credential_guard import register
    from credential_guard.middleware import on_llm_execution

    class FakeCtx:
        def __init__(self):
            self.middlewares = []
            self.hooks = []
            self.cli = []
            self.tools = []

        def register_middleware(self, kind, callback):
            self.middlewares.append((kind, callback))

        def register_hook(self, name, callback):
            self.hooks.append((name, callback))

        def register_cli_command(self, **kwargs):
            self.cli.append(kwargs)

        def register_tool(self, **kwargs):
            self.tools.append(kwargs)

    canary = _runtime_canary()
    cred_id = "mysql_canary_credential"
    _write_secure_store(
        isolated_hermes_home, document=_v2_userpass(cred_id, canary)
    )
    ctx = FakeCtx()
    register(ctx)
    exec_cbs = [cb for kind, cb in ctx.middlewares if kind == "llm_execution"]
    assert exec_cbs
    production_exec = exec_cbs[0]
    assert production_exec is on_llm_execution

    captured = []
    production_exec(
        request={"messages": [{"content": canary}]},
        next_call=lambda req: captured.append(req) or {"ok": True},
    )
    assert len(captured) == 1
    assert canary not in json.dumps(captured[0])
    token = f"<SECRET:{make_token_id(cred_id, 'password')}>"
    assert token in json.dumps(captured[0])


def test_t4_basic_auth_combo_redacted_via_file_snapshot(
    isolated_hermes_home, monkeypatch, capsys
):
    """base64(username:password) must not reach Provider; check hides username."""
    import base64

    from credential_guard.cli import run_check
    from tests.test_plugin_registration import _complete_mgr, _install_fake_mgr

    password = _runtime_canary()
    username = "cg_user_" + secrets.token_hex(4)
    combo = f"{username}:{password}"
    basic_b64 = base64.b64encode(combo.encode("utf-8")).decode("ascii")
    cred_id = "mysql_basic_cred"
    _write_secure_store(
        isolated_hermes_home,
        document=_v2_userpass(cred_id, password, username=username),
    )

    captured = []

    def fake_next(req):
        captured.append(req)
        return {"ok": True}

    result = on_llm_execution(
        request={
            "messages": [
                {"role": "user", "content": f"pass={password}"},
                {"role": "user", "content": f"combo={combo}"},
                {"role": "user", "content": f"basic={basic_b64}"},
            ]
        },
        next_call=fake_next,
    )
    assert result == {"ok": True}
    assert len(captured) == 1
    wire = json.dumps(captured[0], ensure_ascii=False)
    assert wire.count(password) == 0
    assert wire.count(combo) == 0
    assert wire.count(basic_b64) == 0
    pwd_token = f"<SECRET:{make_token_id(cred_id, 'password')}>"
    basic_token = f"<SECRET:{make_token_id(cred_id, 'basic_auth')}>"
    assert pwd_token in wire
    assert basic_token in wire

    _install_fake_mgr(monkeypatch, _complete_mgr())
    code = run_check()
    out = capsys.readouterr().out
    assert code == 0
    assert "egress_registry=ready" in out
    # password + basic_auth = 2 opaque identities
    assert "egress_opaque_count=2" in out
    assert username not in out
    assert password not in out
    assert basic_b64 not in out
