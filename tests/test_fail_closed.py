from __future__ import annotations

import json
import os

import pytest

from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import SAFE_BLOCK_MESSAGE, is_blocked_response_content, on_llm_execution, on_llm_request
from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT
from credential_guard.state import get_registry


DECOY = "decoy_fail_closed_secret_9"


@pytest.fixture(autouse=True)
def _isolated_empty_store(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()


def test_llm_request_get_registry_failure_returns_safe_copy_without_original(monkeypatch):
    get_registry().register("db", "password", DECOY)
    original = {"messages": [{"content": DECOY}], "model": "m"}

    def boom():
        raise RuntimeError(f"registry boom {DECOY}")

    monkeypatch.setattr(
        "credential_guard.middleware.get_egress_registry_snapshot", boom
    )
    out = on_llm_request(request=original)
    assert DECOY not in json.dumps(out)
    assert out["request"]["messages"][0]["content"] == SAFE_BLOCK_MESSAGE
    assert original["messages"][0]["content"] == DECOY


def test_llm_request_redactor_failure_returns_safe_copy(monkeypatch):
    get_registry().register("db", "password", DECOY)

    def boom(*_a, **_k):
        raise RuntimeError(f"redactor {DECOY}")

    monkeypatch.setattr("credential_guard.middleware.redact_payload", boom)
    out = on_llm_request(request={"messages": [{"content": DECOY}]})
    assert DECOY not in json.dumps(out)
    assert out["reason"] == "redaction failed closed"


def test_llm_request_values_iteration_failure_returns_safe_copy(monkeypatch):
    reg = get_registry()
    reg.register("db", "password", DECOY)

    def boom():
        raise RuntimeError(f"values {DECOY}")

    # Snapshot copies via values(); break base registry values to fail closed.
    monkeypatch.setattr(reg, "values", boom)
    out = on_llm_request(request={"messages": [{"content": DECOY}]})
    assert DECOY not in json.dumps(out)


def test_llm_execution_get_registry_failure_does_not_call_next(monkeypatch):
    get_registry().register("db", "password", DECOY)
    calls = []

    def boom():
        raise RuntimeError(f"registry {DECOY}")

    monkeypatch.setattr(
        "credential_guard.middleware.get_egress_registry_snapshot", boom
    )
    blocked = on_llm_execution(
        request={"messages": [{"content": DECOY}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert getattr(blocked, "model", "") == "credential-guard-blocked"
    assert is_blocked_response_content(blocked.choices[0].message.content)
    assert blocked.choices[0].message.tool_calls is None
    assert DECOY not in str(blocked)


def test_llm_execution_serialization_style_failure_blocks_downstream(monkeypatch):
    get_registry().register("db", "password", DECOY)
    calls = []

    def boom(*_a, **_k):
        raise TypeError(f"cannot serialize {DECOY}")

    monkeypatch.setattr("credential_guard.middleware.contains_plain_secret", boom)
    blocked = on_llm_execution(
        request={"messages": [{"content": "<SECRET:cg_x>"}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert getattr(blocked, "model", "") == "credential-guard-blocked"


def test_llm_execution_contains_failure_and_key_collision_fail_closed(monkeypatch):
    get_registry().register("db", "password", DECOY)
    calls = []

    def boom(*_a, **_k):
        raise RuntimeError(f"collision {DECOY}")

    monkeypatch.setattr("credential_guard.middleware.redact_payload", boom)
    blocked = on_llm_execution(
        request={"messages": [{"content": DECOY}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert DECOY not in str(blocked)


def test_tool_hook_get_registry_failure_returns_safe_json_without_secret(monkeypatch):
    get_registry().register("db", "password", DECOY)

    def boom():
        raise RuntimeError(f"registry {DECOY}")

    monkeypatch.setattr("credential_guard.hooks.get_egress_registry_snapshot", boom)
    out = on_transform_tool_result(result=f"leak {DECOY}", tool_name="t", arguments={})
    assert out == RESULT_GUARD_FAIL_TEXT
    assert DECOY not in out
    assert out.count(DECOY) == 0


def test_tool_hook_result_guard_failure_returns_fixed_fail_text(monkeypatch):
    get_registry().register("db", "password", DECOY)

    def boom(*_a, **_k):
        raise RuntimeError(f"guard boom {DECOY}")

    monkeypatch.setattr("credential_guard.result_guard.guard_tool_result", boom)
    out = on_transform_tool_result(result='{"a":1}', tool_name="t", arguments={})
    assert out == RESULT_GUARD_FAIL_TEXT
    assert DECOY not in out
    assert "guard boom" not in out


def test_tool_hook_result_guard_mutation_old_json_error_is_red(monkeypatch):
    """Mutation: returning legacy SAFE JSON must not satisfy R4 fail-closed."""
    get_registry().register("db", "password", DECOY)

    def boom():
        raise RuntimeError(f"registry {DECOY}")

    monkeypatch.setattr("credential_guard.hooks.get_egress_registry_snapshot", boom)
    out = on_transform_tool_result(result=f"leak {DECOY}", tool_name="t", arguments={})
    legacy = json.dumps(
        {"error": "tool result blocked by credential-guard"}, ensure_ascii=False
    )
    assert out != legacy
    assert out == RESULT_GUARD_FAIL_TEXT


def test_fail_closed_logging_never_includes_decoy(caplog, monkeypatch):
    import logging

    get_registry().register("db", "password", DECOY)
    caplog.set_level(logging.WARNING, logger="credential_guard")

    def boom(*_a, **_k):
        raise RuntimeError(f"explode with {DECOY}")

    monkeypatch.setattr("credential_guard.middleware.redact_payload", boom)
    on_llm_request(request={"messages": [{"content": DECOY}]})
    on_llm_execution(
        request={"messages": [{"content": DECOY}]},
        next_call=lambda r: r,
    )
    joined = "\n".join(r.message for r in caplog.records)
    assert DECOY not in joined
    assert "failed closed" in joined
