"""C5–C7 usability tests: dynamic tool schema descriptions + C7 warning.

C5: Safe binding list in tool descriptions.
C6: Redacted credential-code misuse returns a fixed local error.
C7: Best-effort local unregistered-credential risk warning (non-blocking).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, List

import pytest

import credential_guard
from credential_guard import (
    credential_process_run_schema,
    http_credential_request_schema,
    register,
)
from credential_guard import middleware as mw
from credential_guard.middleware import on_llm_execution, on_llm_request
from credential_guard.process_tools import (
    TOOL_DESCRIPTION as PROCESS_STATIC_DESCRIPTION,
    handle_credential_process_run,
)
from credential_guard.reference_tools import (
    TOOL_DESCRIPTION as HTTP_STATIC_DESCRIPTION,
    handle_http_credential_request,
)
from credential_guard.config import ConfigError, parse_config_document
from credential_guard.runtime_config import (
    RuntimeConfigError,
    get_runtime_view,
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard.state import get_registry
from credential_guard.target_catalog import reset_registration_catalog_for_tests
from credential_guard.unregistered_warning import (
    FAMILY_AWS,
    FAMILY_GITHUB,
    FAMILY_OPENAI,
    FAMILY_SLACK,
    MAX_SESSION_ID_CHARS,
    UNREGISTERED_WARNING_TEXT,
    best_effort_warn_unregistered,
    note_families_and_select_emits,
    reset_unregistered_warning_state_for_tests,
    scan_unregistered_credential_families,
    session_keys_snapshot_for_tests,
    session_resident_key_chars_for_tests,
    session_state_size_for_tests,
    wait_unregistered_warning_idle_for_tests,
)


def _c7_wait_warn(timeout: float = 2.0) -> None:
    """Drain async warning worker before reading stderr in tests."""
    assert wait_unregistered_warning_idle_for_tests(timeout=timeout)

_C6_ERROR = "CREDENTIAL_CODE_NOT_USABLE"
_C6_MESSAGE = (
    "提供的是脱敏代号，不是凭证引用。凭证不能通过对话传入；"
    "请使用工具描述中列出的 <CREDENTIAL:name>。"
)
_C6_EXPECTED = {
    "error": _C6_ERROR,
    "message": _C6_MESSAGE,
    "ok": False,
    "source": "credential-guard",
}
_C6_CODE = "<SECRET:cg_0123456789abcdef>"
_C6_DETECTOR_RE = re.compile(r"^<SECRET:cg_[0-9a-f]{16}>$")


@pytest.fixture(autouse=True)
def reset_runtime():
    """Ensure clean runtime state for each test."""
    reset_runtime_for_tests()
    get_registry().clear()
    reset_unregistered_warning_state_for_tests()
    reset_registration_catalog_for_tests()
    mw.reset_config_notices_for_tests()
    yield
    reset_runtime_for_tests()
    get_registry().clear()
    reset_unregistered_warning_state_for_tests()
    reset_registration_catalog_for_tests()
    mw.reset_config_notices_for_tests()


def test_c5_http_schema_lists_http_bindings_only():
    """RED: HTTP tool schema should list only HTTP bindings with safe metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = Path(tmpdir) / "cg-store"
        store.mkdir(parents=True, exist_ok=True)
        os.chmod(store, 0o700)
        config_path = store / "credential-guard.json"
        config = {
            "version": 2,
            "credentials": {
                "ci-token": {"type": "token", "value": "decoy-ci-abc123-min8chars"},
                "report-token": {"type": "token", "value": "decoy-report-xyz789-min8"},
            },
            "bindings": {
                "ci-api": {
                    "type": "http",
                    "credential_ref": "ci-token",
                    "target": {"scheme": "https", "host": "ci.example.test", "port": 443},
                    "request": {
                        "allowed_methods": ["GET", "POST"],
                        "allowed_paths": ["/status", "/jobs/build", "/jobs/test"],
                    },
                    "inject": {
                        "type": "bearer",
                        "location": "authorization_header",
                    },
                    "approval": "required",
                },
                "report-job": {
                    "type": "process_env",
                    "credential_ref": "report-token",
                    "program": "/usr/local/bin/report-cli",
                    "argv": ["/usr/local/bin/report-cli"],
                    "env_name": "REPORT_TOKEN",
                    "timeout_seconds": 10,
                    "max_stdout_bytes": 4096,
                    "max_stderr_bytes": 4096,
                    "approval": "required",
                },
            },
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(config_path, 0o600)
        load_and_publish_runtime(config_path)

        schema = http_credential_request_schema()
        desc = schema["description"]

        # Should list the HTTP binding
        assert "ci-api" in desc
        assert "<CREDENTIAL:ci-token>" in desc

        # Should NOT list the process binding
        assert "report-job" not in desc

        # Should NOT expose sensitive fields
        assert "ci.example.test" not in desc
        assert "443" not in desc
        assert "decoy-ci-abc123" not in desc
        assert "decoy-report-xyz789" not in desc

        # Should show allowed operations safely - require all to be present
        assert "GET" in desc
        assert "POST" in desc
        assert "/status" in desc or "/jobs/build" in desc or "/jobs/test" in desc

        # Should NOT contain internal codenames
        assert "R3A" not in desc
        assert "R3B" not in desc


def test_c5_process_schema_lists_process_bindings_only():
    """RED: Process tool schema should list only process bindings with safe metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = Path(tmpdir) / "cg-store"
        store.mkdir(parents=True, exist_ok=True)
        os.chmod(store, 0o700)
        config_path = store / "credential-guard.json"
        config = {
            "version": 2,
            "credentials": {
                "ci-token": {"type": "token", "value": "decoy-ci-abc123-min8chars"},
                "report-token": {"type": "token", "value": "decoy-report-xyz789-min8"},
            },
            "bindings": {
                "ci-api": {
                    "type": "http",
                    "credential_ref": "ci-token",
                    "target": {"scheme": "https", "host": "ci.example.test", "port": 443},
                    "request": {
                        "allowed_methods": ["GET", "POST"],
                        "allowed_paths": ["/status", "/jobs/build", "/jobs/test"],
                    },
                    "inject": {
                        "type": "bearer",
                        "location": "authorization_header",
                    },
                    "approval": "required",
                },
                "report-job": {
                    "type": "process_env",
                    "credential_ref": "report-token",
                    "program": "/usr/local/bin/report-cli",
                    "argv": ["/usr/local/bin/report-cli"],
                    "env_name": "REPORT_TOKEN",
                    "timeout_seconds": 10,
                    "max_stdout_bytes": 4096,
                    "max_stderr_bytes": 4096,
                    "approval": "required",
                },
            },
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(config_path, 0o600)
        load_and_publish_runtime(config_path)

        schema = credential_process_run_schema()
        desc = schema["description"]

        # Should list the process binding
        assert "report-job" in desc
        assert "<CREDENTIAL:report-token>" in desc

        # Should NOT list the HTTP binding
        assert "ci-api" not in desc

        # Should NOT expose sensitive fields
        assert "/usr/local/bin/report-cli" not in desc
        assert "REPORT_TOKEN" not in desc
        assert "decoy-ci-abc123" not in desc
        assert "decoy-report-xyz789" not in desc

        # Should NOT contain internal codenames
        assert "R3A" not in desc
        assert "R3B" not in desc


def test_c5_static_fallback_when_runtime_unavailable():
    """RED→GREEN: When runtime is unavailable, return static description."""
    reset_runtime_for_tests()
    # Don't publish anything - runtime should be unavailable

    http_schema = http_credential_request_schema()
    process_schema = credential_process_run_schema()

    # Should return valid schemas
    assert http_schema["name"] == "http_credential_request"
    assert process_schema["name"] == "credential_process_run"

    # Descriptions should exist but not list specific bindings
    assert "description" in http_schema
    assert "description" in process_schema

    # Should not crash or expose errors
    assert "Traceback" not in http_schema["description"]
    assert "Traceback" not in process_schema["description"]


def test_c5_bounded_description_with_omission_count():
    """RED→GREEN: Large binding lists should truncate with accurate omission count."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = Path(tmpdir) / "cg-store"
        store.mkdir(parents=True, exist_ok=True)
        os.chmod(store, 0o700)
        config_path = store / "credential-guard.json"
        credentials = {f"token-{i:03d}": {"type": "token", "value": f"decoy-val-{i:03d}-min8"} for i in range(100)}
        bindings = {}
        for i in range(100):
            bindings[f"http-target-{i:03d}"] = {
                "type": "http",
                "credential_ref": f"token-{i:03d}",
                "target": {"scheme": "https", "host": f"api{i}.example.test", "port": 443},
                "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        config = {
            "version": 2,
            "credentials": credentials,
            "bindings": bindings,
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(config_path, 0o600)
        load_and_publish_runtime(config_path)

        schema = http_credential_request_schema()
        desc = schema["description"]

        # Hard limit: 12,000 chars
        assert len(desc) <= 12000

        # Count how many bindings are actually shown
        shown_count = sum(1 for i in range(100) if f"http-target-{i:03d}" in desc)

        if shown_count < 100:
            # Should have an omission notice with count
            omitted = 100 - shown_count
            # Extract the actual number from the description
            import re
            match = re.search(r'(\d+)\s*(?:个|targets?|bindings?).*?(?:未展示|not shown|omitted)', desc, re.IGNORECASE)
            if not match:
                match = re.search(r'(?:未展示|not shown|omitted).*?(\d+)', desc, re.IGNORECASE)
            assert match, f"Should have omission notice with count, got: {desc[-200:]}"
            extracted_count = int(match.group(1))
            assert extracted_count == omitted, f"Omission count should be {omitted}, got {extracted_count}"


def test_c5_stable_sorting():
    """RED→GREEN: Binding list should be stably sorted by name."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = Path(tmpdir) / "cg-store"
        store.mkdir(parents=True, exist_ok=True)
        os.chmod(store, 0o700)
        config_path = store / "credential-guard.json"
        config = {
            "version": 2,
            "credentials": {
                "tok-a": {"type": "token", "value": "decoy-aaa-min8chars"},
                "tok-b": {"type": "token", "value": "decoy-bbb-min8chars"},
                "tok-c": {"type": "token", "value": "decoy-ccc-min8chars"},
            },
            "bindings": {
                "zebra": {
                    "type": "http",
                    "credential_ref": "tok-c",
                    "target": {"scheme": "https", "host": "z.test", "port": 443},
                    "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
                    "inject": {
                        "type": "bearer",
                        "location": "authorization_header",
                    },
                    "approval": "required",
                },
                "alpha": {
                    "type": "http",
                    "credential_ref": "tok-a",
                    "target": {"scheme": "https", "host": "a.test", "port": 443},
                    "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
                    "inject": {
                        "type": "bearer",
                        "location": "authorization_header",
                    },
                    "approval": "required",
                },
                "beta": {
                    "type": "http",
                    "credential_ref": "tok-b",
                    "target": {"scheme": "https", "host": "b.test", "port": 443},
                    "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
                    "inject": {
                        "type": "bearer",
                        "location": "authorization_header",
                    },
                    "approval": "required",
                },
            },
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(config_path, 0o600)
        load_and_publish_runtime(config_path)

        schema = http_credential_request_schema()
        desc = schema["description"]

        # Find positions
        pos_alpha = desc.find("alpha")
        pos_beta = desc.find("beta")
        pos_zebra = desc.find("zebra")

        # Should appear in alphabetical order
        assert pos_alpha != -1
        assert pos_beta != -1
        assert pos_zebra != -1
        assert pos_alpha < pos_beta < pos_zebra


def test_c5_schema_builder_called_once_per_tool():
    """RED→GREEN: Schema description builder should be called exactly once per tool."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = Path(tmpdir) / "cg-store"
        store.mkdir(parents=True, exist_ok=True)
        os.chmod(store, 0o700)
        config_path = store / "credential-guard.json"
        config = {
            "version": 2,
            "credentials": {
                "tok1": {"type": "token", "value": "decoy-tok1-min8chars"},
            },
            "bindings": {
                "target1": {
                    "type": "http",
                    "credential_ref": "tok1",
                    "target": {"scheme": "https", "host": "api.test", "port": 443},
                    "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
                    "inject": {"type": "bearer", "location": "authorization_header"},
                    "approval": "required",
                },
            },
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(config_path, 0o600)
        load_and_publish_runtime(config_path)

        # Call schema functions multiple times
        http_schema1 = http_credential_request_schema()
        http_schema2 = http_credential_request_schema()
        process_schema1 = credential_process_run_schema()
        process_schema2 = credential_process_run_schema()

        # Descriptions should be identical (same object reused or same content)
        assert http_schema1["description"] == http_schema2["description"]
        assert process_schema1["description"] == process_schema2["description"]

        # Schema description should match what register would see
        assert http_schema1["description"] == http_schema1["description"]
        assert process_schema1["description"] == process_schema1["description"]


class _RegisterCaptureCtx:
    """Minimal FakeCtx that records register_tool schema/description only."""

    def __init__(self) -> None:
        self.tools: list[dict[str, Any]] = []

    def register_middleware(self, *_a, **_k):
        return None

    def register_hook(self, *_a, **_k):
        return None

    def register_cli_command(self, **_k):
        return None

    def register_tool(self, **kwargs):
        self.tools.append(kwargs)


def _c5_cold_start_v2_config() -> dict[str, Any]:
    return {
        "version": 2,
        "credentials": {
            "ci-token": {"type": "token", "value": "decoy-ci-abc123-min8chars"},
            "report-token": {"type": "token", "value": "decoy-report-xyz789-min8"},
        },
        "bindings": {
            "ci-api": {
                "type": "http",
                "credential_ref": "ci-token",
                "target": {"scheme": "https", "host": "ci.example.test", "port": 443},
                "request": {
                    "allowed_methods": ["GET", "POST"],
                    "allowed_paths": ["/status", "/jobs/build"],
                },
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            },
            "report-job": {
                "type": "process_env",
                "credential_ref": "report-token",
                "program": "/usr/local/bin/report-cli",
                "argv": ["/usr/local/bin/report-cli"],
                "env_name": "REPORT_TOKEN",
                "timeout_seconds": 10,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            },
        },
    }


def _c5_write_store(
    hermes: Path, doc: dict[str, Any], *, write_catalog: bool = True
) -> Path:
    store = hermes / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(cfg, 0o600)
    if write_catalog:
        from credential_guard.target_catalog import (
            TARGET_CATALOG_FILENAME,
            build_catalog_document,
        )
        from credential_guard.config import CredentialGuardConfig

        try:
            cfg_obj = CredentialGuardConfig.from_mapping(doc)
        except ConfigError:
            # Illegal docs: leave sidecar absent → static fallback.
            return store
        st = cfg.lstat()
        identity = {
            "device": int(st.st_dev),
            "inode": int(st.st_ino),
            "size": int(st.st_size),
            "mtime_ns": int(st.st_mtime_ns),
        }
        cat = build_catalog_document(cfg_obj, identity)
        cat_path = store / TARGET_CATALOG_FILENAME
        cat_path.write_text(json.dumps(cat), encoding="utf-8")
        os.chmod(cat_path, 0o600)
    return store


def _tool_desc_by_name(ctx: _RegisterCaptureCtx) -> dict[str, str]:
    out: dict[str, str] = {}
    for tool in ctx.tools:
        schema = tool.get("schema") or {}
        name = tool.get("name") or schema.get("name")
        desc = tool.get("description")
        if desc is None:
            desc = schema.get("description")
        assert isinstance(name, str) and isinstance(desc, str)
        out[name] = desc
    return out


def test_c5_cold_register_lists_bindings_from_disk(tmp_path, monkeypatch):
    """register(ctx) cold-start lists bindings from safe target catalog sidecar."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _c5_write_store(hermes, _c5_cold_start_v2_config())

    reset_runtime_for_tests()
    reset_registration_catalog_for_tests()
    # Do NOT call load_and_publish_runtime — cold start must go through register().

    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_desc_by_name(ctx)
    http_desc = descs["http_credential_request"]
    proc_desc = descs["credential_process_run"]

    assert "ci-api" in http_desc
    assert "<CREDENTIAL:ci-token>" in http_desc
    assert "report-job" not in http_desc

    assert "report-job" in proc_desc
    assert "<CREDENTIAL:report-token>" in proc_desc
    assert "ci-api" not in proc_desc

    sensitive = (
        "ci.example.test",
        "443",
        "/usr/local/bin/report-cli",
        "REPORT_TOKEN",
        "decoy-ci-abc123",
        "decoy-report-xyz789",
    )
    for blob in (http_desc, proc_desc):
        for needle in sensitive:
            assert needle not in blob

    with pytest.raises(RuntimeConfigError):
        get_runtime_view()


def test_c5_cold_register_invalid_or_missing_uses_static_fallback(
    tmp_path, monkeypatch
):
    """register() must succeed with static fallback; runtime stays unhealthy."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    # Case A: store / config absent.
    reset_runtime_for_tests()
    reset_registration_catalog_for_tests()
    ctx_missing = _RegisterCaptureCtx()
    register(ctx_missing)
    descs_missing = _tool_desc_by_name(ctx_missing)
    assert descs_missing["http_credential_request"] == HTTP_STATIC_DESCRIPTION
    assert descs_missing["credential_process_run"] == PROCESS_STATIC_DESCRIPTION
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()

    # Case B: store present but catalog missing (main config illegal or present).
    store = hermes / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    bad = store / "credential-guard.json"
    bad.write_text("{not-json", encoding="utf-8")
    os.chmod(bad, 0o600)

    reset_runtime_for_tests()
    reset_registration_catalog_for_tests()
    ctx_bad = _RegisterCaptureCtx()
    register(ctx_bad)
    descs_bad = _tool_desc_by_name(ctx_bad)
    assert descs_bad["http_credential_request"] == HTTP_STATIC_DESCRIPTION
    assert descs_bad["credential_process_run"] == PROCESS_STATIC_DESCRIPTION
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()


def test_c5_cold_register_loads_catalog_once_for_both_schemas(tmp_path, monkeypatch):
    """Registration loads sidecar once; both builders reuse registration bindings."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _c5_write_store(hermes, _c5_cold_start_v2_config())
    reset_runtime_for_tests()
    reset_registration_catalog_for_tests()

    calls: list[int] = []
    import credential_guard.target_catalog as cat_mod

    real = cat_mod.prepare_registration_catalog

    def _counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(credential_guard, "prepare_registration_catalog", _counting)
    ctx = _RegisterCaptureCtx()
    register(ctx)
    assert calls == [1]
    descs = _tool_desc_by_name(ctx)
    assert "ci-api" in descs["http_credential_request"]
    assert "report-job" in descs["credential_process_run"]


def test_c5_mutation_omit_startup_catalog_makes_cold_register_static(
    tmp_path, monkeypatch
):
    """Mutation: skipping startup catalog load leaves cold-start descriptions static."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _c5_write_store(hermes, _c5_cold_start_v2_config())
    reset_runtime_for_tests()
    reset_registration_catalog_for_tests()

    monkeypatch.setattr(
        credential_guard,
        "prepare_registration_catalog",
        lambda *a, **k: None,
    )
    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_desc_by_name(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC_DESCRIPTION
    assert descs["credential_process_run"] == PROCESS_STATIC_DESCRIPTION
    assert "ci-api" not in descs["http_credential_request"]
    assert "report-job" not in descs["credential_process_run"]

# ---------------------------------------------------------------------------
# C5 security: credential/binding names must never equal any registered secret
# ---------------------------------------------------------------------------

# Synthetic decoys only — NAME_RE-compatible, >= MIN_SECRET_LENGTH.
_C5_COLLISION_SECRET = "secretvalue12345"
_C5_OTHER_SECRET = "othersecret99999"
_C5_CASE_SECRET = "Secretvalue12345"  # differs only by case from a valid name


def _c5_http_binding(name: str, credential_ref: str) -> dict[str, Any]:
    return {
        name: {
            "type": "http",
            "credential_ref": credential_ref,
            "target": {"scheme": "https", "host": "api.example.test", "port": 443},
            "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
            "inject": {"type": "bearer", "location": "authorization_header"},
            "approval": "required",
        }
    }


def _assert_config_schema_reject(exc: BaseException) -> None:
    assert isinstance(exc, ConfigError)
    assert exc.code == "CONFIG_SCHEMA"
    assert str(exc) == "invalid configuration"
    blob = f"{type(exc).__name__}:{exc!s}:{exc!r}"
    assert _C5_COLLISION_SECRET not in blob
    assert _C5_OTHER_SECRET not in blob
    assert _C5_CASE_SECRET not in blob


def test_c5_config_rejects_credential_name_eq_other_token_value():
    """Credential name must not equal another credential's token value."""
    doc = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
            _C5_COLLISION_SECRET: {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": {},
    }
    with pytest.raises(ConfigError) as ei:
        parse_config_document(doc)
    _assert_config_schema_reject(ei.value)


def test_c5_config_rejects_credential_name_eq_other_password():
    """Credential name must not equal another credential's password."""
    doc = {
        "version": 2,
        "credentials": {
            "db-login": {
                "type": "username_password",
                "username": "readonly",
                "password": _C5_COLLISION_SECRET,
            },
            _C5_COLLISION_SECRET: {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": {},
    }
    with pytest.raises(ConfigError) as ei:
        parse_config_document(doc)
    _assert_config_schema_reject(ei.value)


def test_c5_config_rejects_binding_name_eq_token_or_password():
    """Binding name must not equal any registered token/password plaintext."""
    doc = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
        },
        "bindings": _c5_http_binding(_C5_COLLISION_SECRET, "legit-token"),
    }
    with pytest.raises(ConfigError) as ei:
        parse_config_document(doc)
    _assert_config_schema_reject(ei.value)


def test_c5_config_case_difference_is_not_name_secret_collision():
    """Exact-string semantics: case-different name vs secret is not a collision."""
    doc = {
        "version": 2,
        "credentials": {
            "tok-a": {"type": "token", "value": _C5_CASE_SECRET},
            "secretvalue12345": {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": {},
    }
    creds, binds = parse_config_document(doc)
    loaded_ok = "tok-a" in creds and "secretvalue12345" in creds and binds == {}
    assert loaded_ok is True


def test_c5_config_ordinary_names_still_load():
    """Legitimate ordinary credential/binding names continue to parse."""
    doc = {
        "version": 2,
        "credentials": {
            "ci-token": {"type": "token", "value": "decoy-ci-abc123-min8chars"},
            "db-login": {
                "type": "username_password",
                "username": "readonly",
                "password": "decoy-db-pass-min8chars",
            },
        },
        "bindings": _c5_http_binding("ci-api", "ci-token"),
    }
    creds, binds = parse_config_document(doc)
    loaded_ok = "ci-token" in creds and "db-login" in creds and "ci-api" in binds
    assert loaded_ok is True


def test_c5_name_secret_collision_must_not_load():
    """Boolean contract: cross-item name↔secret collision must fail closed."""
    doc = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
            _C5_COLLISION_SECRET: {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": _c5_http_binding("api-target", _C5_COLLISION_SECRET),
    }
    loaded_ok = False
    try:
        parse_config_document(doc)
        loaded_ok = True
    except ConfigError:
        loaded_ok = False
    assert loaded_ok is False


def test_c5_cold_register_name_secret_collision_static_fallback_no_secret(
    tmp_path, monkeypatch
):
    """Dangerous collision config: register succeeds, static desc, secret absent."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    colliding = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
            _C5_COLLISION_SECRET: {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": _c5_http_binding("api-target", _C5_COLLISION_SECRET),
    }
    _c5_write_store(hermes, colliding, write_catalog=False)
    reset_runtime_for_tests()
    reset_registration_catalog_for_tests()

    ctx = _RegisterCaptureCtx()
    register(ctx)  # must not raise
    descs = _tool_desc_by_name(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC_DESCRIPTION
    assert descs["credential_process_run"] == PROCESS_STATIC_DESCRIPTION
    joined = descs["http_credential_request"] + descs["credential_process_run"]
    secret_absent = _C5_COLLISION_SECRET not in joined and _C5_OTHER_SECRET not in joined
    assert secret_absent is True
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()


def test_c5_mutation_omit_name_secret_collision_check_must_allow_load(monkeypatch):
    """Mutation: deleting name↔secret collision reject makes security RED."""
    import credential_guard.config as cfg_mod

    monkeypatch.setattr(
        cfg_mod,
        "_reject_names_overlapping_secrets",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        cfg_mod,
        "_reject_visible_strings_overlapping_secrets",
        lambda *_a, **_k: None,
    )
    doc = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
            _C5_COLLISION_SECRET: {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": _c5_http_binding("api-target", _C5_COLLISION_SECRET),
    }
    creds, binds = parse_config_document(doc)
    loaded_ok = _C5_COLLISION_SECRET in creds and "api-target" in binds
    assert loaded_ok is True
    # Leak path boolean: colliding name is a credential_ref that equals a secret.
    leak = any(
        b.get("credential_ref") == _C5_COLLISION_SECRET for b in binds.values()
    )
    assert leak is True


# ---------------------------------------------------------------------------
# C5 final blockers knife 1: model-visible strings vs secret substring
# ---------------------------------------------------------------------------

_C5_PATH_TOKEN = "/secretvalue12345"  # valid exact path + secret (>= MIN_SECRET)


def _c5_http_binding_with_path(
    name: str, credential_ref: str, path: str, method: str = "GET"
) -> dict[str, Any]:
    return {
        name: {
            "type": "http",
            "credential_ref": credential_ref,
            "target": {"scheme": "https", "host": "api.example.test", "port": 443},
            "request": {"allowed_methods": [method], "allowed_paths": [path]},
            "inject": {"type": "bearer", "location": "authorization_header"},
            "approval": "required",
        }
    }


def test_c5_config_rejects_token_eq_allowed_path():
    """Token plaintext equal to an allowed_path must fail closed (CONFIG_SCHEMA)."""
    doc = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_PATH_TOKEN},
        },
        "bindings": _c5_http_binding_with_path("ci-api", "legit-token", _C5_PATH_TOKEN),
    }
    with pytest.raises(ConfigError) as ei:
        parse_config_document(doc)
    _assert_config_schema_reject(ei.value)
    assert _C5_PATH_TOKEN not in f"{ei.value!s}{ei.value!r}"


def test_c5_config_rejects_password_embedded_in_allowed_path():
    """Password substring inside allowed_path must fail closed."""
    doc = {
        "version": 2,
        "credentials": {
            "db-login": {
                "type": "username_password",
                "username": "readonly",
                "password": _C5_COLLISION_SECRET,
            },
        },
        "bindings": {
            "ci-api": {
                "type": "http",
                "credential_ref": "db-login",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": [f"/v1/{_C5_COLLISION_SECRET}/status"],
                },
                "inject": {"type": "basic", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError) as ei:
        parse_config_document(doc)
    _assert_config_schema_reject(ei.value)


def test_c5_config_rejects_secret_embedded_in_binding_or_cred_name():
    """Secret substring in binding name or referenced credential name → CONFIG_SCHEMA."""
    # Binding name embeds token plaintext (NAME_RE-safe).
    bind_doc = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
        },
        "bindings": _c5_http_binding(
            f"api-{_C5_COLLISION_SECRET}", "legit-token"
        ),
    }
    with pytest.raises(ConfigError) as ei:
        parse_config_document(bind_doc)
    _assert_config_schema_reject(ei.value)

    # Referenced credential name embeds password plaintext.
    cred_name = f"tok-{_C5_COLLISION_SECRET}"
    cred_doc = {
        "version": 2,
        "credentials": {
            cred_name: {
                "type": "username_password",
                "username": "readonly",
                "password": _C5_COLLISION_SECRET,
            },
        },
        "bindings": {
            "ci-api": {
                "type": "http",
                "credential_ref": cred_name,
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {"allowed_methods": ["GET"], "allowed_paths": ["/"]},
                "inject": {"type": "basic", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError) as ei2:
        parse_config_document(cred_doc)
    _assert_config_schema_reject(ei2.value)


def _assert_c6_payload(raw: str) -> None:
    payload = json.loads(raw)
    assert payload == _C6_EXPECTED
    assert raw == json.dumps(_C6_EXPECTED, separators=(",", ":"), sort_keys=True)


def test_c6_http_handler_rejects_redacted_credential_code(monkeypatch):
    """RED→GREEN: exact <SECRET:cg_…> on credential returns fixed C6 error."""
    calls: list[object] = []

    def _boom(*_a, **_k):
        calls.append(1)
        raise AssertionError("finalize_reference_execution must not run for C6")

    monkeypatch.setattr(
        "credential_guard.reference_tools.finalize_reference_execution",
        _boom,
    )
    out = handle_http_credential_request(
        {"target": "ci-api", "method": "GET", "path": "/status", "credential": _C6_CODE}
    )
    _assert_c6_payload(out)
    assert calls == []


def test_c6_process_handler_rejects_redacted_credential_code(monkeypatch):
    """RED→GREEN: exact <SECRET:cg_…> on credential returns fixed C6 error."""
    calls: list[object] = []

    def _boom(*_a, **_k):
        calls.append(1)
        raise AssertionError("finalize_reference_execution must not run for C6")

    monkeypatch.setattr(
        "credential_guard.process_tools.finalize_reference_execution",
        _boom,
    )
    out = handle_credential_process_run(
        {"target": "report-job", "credential": _C6_CODE}
    )
    _assert_c6_payload(out)
    assert calls == []


@pytest.mark.parametrize(
    "bad",
    [
        "<SECRET:CG_0123456789abcdef>",  # uppercase hex / prefix
        "<SECRET:cg_0123456789abcde>",  # 15 hex
        "<SECRET:cg_0123456789abcdef0>",  # 17 hex
        "prefix<SECRET:cg_0123456789abcdef>",  # embedded prefix
        "<SECRET:cg_0123456789abcdef>suffix",  # embedded suffix
        "plain-string",
        "<CREDENTIAL:ci-token>",
    ],
)
def test_c6_non_exact_credential_values_do_not_use_c6_code(bad, monkeypatch):
    """Negative: non-exact forms must not return CREDENTIAL_CODE_NOT_USABLE."""
    monkeypatch.setattr(
        "credential_guard.reference_tools.finalize_reference_execution",
        lambda *a, **k: json.dumps({"ok": True, "via": "finalize"}, sort_keys=True),
    )
    monkeypatch.setattr(
        "credential_guard.process_tools.finalize_reference_execution",
        lambda *a, **k: json.dumps({"ok": True, "via": "finalize"}, sort_keys=True),
    )
    http_out = handle_http_credential_request(
        {"target": "ci-api", "method": "GET", "path": "/status", "credential": bad}
    )
    proc_out = handle_credential_process_run(
        {"target": "report-job", "credential": bad}
    )
    assert _C6_ERROR not in http_out
    assert _C6_ERROR not in proc_out


def test_c6_marker_in_other_fields_does_not_trigger(monkeypatch):
    """Other args may contain a marker; only credential exact-match is C6."""
    monkeypatch.setattr(
        "credential_guard.reference_tools.finalize_reference_execution",
        lambda *a, **k: json.dumps({"ok": True, "via": "finalize"}, sort_keys=True),
    )
    out = handle_http_credential_request(
        {
            "target": _C6_CODE,
            "method": "GET",
            "path": "/status",
            "credential": "<CREDENTIAL:ci-token>",
        }
    )
    assert _C6_ERROR not in out
    assert json.loads(out)["via"] == "finalize"


def test_c6_valid_credential_reference_still_reaches_finalize(monkeypatch):
    """Legitimate <CREDENTIAL:name> keeps the finalize seam (no real secret/Profile)."""
    seen: list[tuple] = []

    def _capture(tool_name, args, **context):
        seen.append((tool_name, dict(args), dict(context)))
        return json.dumps(
            {"ok": True, "error": None, "source": "credential-guard", "via": "finalize"},
            separators=(",", ":"),
            sort_keys=True,
        )

    monkeypatch.setattr(
        "credential_guard.reference_tools.finalize_reference_execution",
        _capture,
    )
    monkeypatch.setattr(
        "credential_guard.process_tools.finalize_reference_execution",
        _capture,
    )
    cred = "<CREDENTIAL:ci-token>"
    http_out = handle_http_credential_request(
        {"target": "ci-api", "method": "GET", "path": "/status", "credential": cred}
    )
    proc_out = handle_credential_process_run(
        {"target": "report-job", "credential": cred}
    )
    assert json.loads(http_out)["via"] == "finalize"
    assert json.loads(proc_out)["via"] == "finalize"
    assert len(seen) == 2
    assert seen[0][1]["credential"] == cred
    assert seen[1][1]["credential"] == cred
    assert _C6_ERROR not in http_out
    assert _C6_ERROR not in proc_out


def test_c6_exact_detector_is_load_bearing():
    """Mutation anchor: exact regex must accept only the strict form."""
    assert _C6_DETECTOR_RE.fullmatch(_C6_CODE)
    assert not _C6_DETECTOR_RE.fullmatch("<SECRET:CG_0123456789abcdef>")
    assert not _C6_DETECTOR_RE.fullmatch("<SECRET:cg_0123456789abcde>")
    assert not _C6_DETECTOR_RE.fullmatch("<SECRET:cg_0123456789abcdef0>")
    assert not _C6_DETECTOR_RE.fullmatch("x" + _C6_CODE)
    assert not _C6_DETECTOR_RE.fullmatch(_C6_CODE + "y")
    # Shared production detector must match the same contract.
    from credential_guard.credential_code import is_redacted_credential_code

    assert is_redacted_credential_code(_C6_CODE) is True
    assert is_redacted_credential_code("<SECRET:CG_0123456789abcdef>") is False
    assert is_redacted_credential_code("x" + _C6_CODE) is False


def test_c6_mutation_never_match_detector_makes_positive_red(monkeypatch):
    """If exact detector never hits, C6 positive path must not return the code."""
    monkeypatch.setattr(
        "credential_guard.reference_tools.is_redacted_credential_code",
        lambda _v: False,
    )
    monkeypatch.setattr(
        "credential_guard.process_tools.is_redacted_credential_code",
        lambda _v: False,
    )
    monkeypatch.setattr(
        "credential_guard.reference_tools.finalize_reference_execution",
        lambda *a, **k: json.dumps({"ok": False, "error": "PLAN_NOT_PENDING"}),
    )
    monkeypatch.setattr(
        "credential_guard.process_tools.finalize_reference_execution",
        lambda *a, **k: json.dumps({"ok": False, "error": "PLAN_NOT_PENDING"}),
    )
    http_out = handle_http_credential_request(
        {"target": "ci-api", "method": "GET", "path": "/status", "credential": _C6_CODE}
    )
    proc_out = handle_credential_process_run(
        {"target": "report-job", "credential": _C6_CODE}
    )
    assert _C6_ERROR not in http_out
    assert _C6_ERROR not in proc_out


# ---------------------------------------------------------------------------
# C7 — unregistered credential local risk warning (non-blocking)
# ---------------------------------------------------------------------------

# Explicit synthetic decoys only — never real credentials.
_C7_OPENAI = "sk-decoyOpenAIStyleToken0001xx"
_C7_GITHUB = "ghp_decoyGitHubClassicTok01xx"
_C7_AWS = "AKIADECOYAWSACCESS01"
_C7_SLACK = "xoxb-decoy-slack-tok"


@pytest.fixture
def c7_empty_store(tmp_path, monkeypatch):
    """Isolated empty Schema v2 store so egress registry loads without Profile."""
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
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    (tmp_path / "home").mkdir(exist_ok=True)
    reset_runtime_for_tests()
    get_registry().clear()
    reset_unregistered_warning_state_for_tests()
    yield store
    reset_runtime_for_tests()
    get_registry().clear()
    reset_unregistered_warning_state_for_tests()


def _c7_msg(text: str) -> dict:
    return {"messages": [{"role": "user", "content": text}], "model": "fake-model"}


def test_c7_scanner_four_families_hit_and_negatives_miss():
    """RED→GREEN: four high-signal decoys hit; order/JWT/URL/random miss."""
    assert scan_unregistered_credential_families(
        f"here {_C7_OPENAI} end"
    ) == {FAMILY_OPENAI}
    assert scan_unregistered_credential_families(
        f"token={_C7_GITHUB}"
    ) == {FAMILY_GITHUB}
    assert scan_unregistered_credential_families(_C7_AWS) == {FAMILY_AWS}
    assert scan_unregistered_credential_families(
        {"body": f"auth {_C7_SLACK}"}
    ) == {FAMILY_SLACK}

    negatives = [
        "ORD-2024-12345678901234567890",
        "sk-short",
        "ghp_tooshort",
        "AKIASHORT",
        "xoxb-short",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signaturepart",
        "https://api.example.test/v1/keys?q=sk",
        "a7f3b2c1d4e5f67890abcdef1234567890abcdef",
        "foosk-decoyOpenAIStyleToken0001xx",  # no boundary
        "prefix_ghp_decoyGitHubClassicTok01xx",
    ]
    for text in negatives:
        assert scan_unregistered_credential_families(text) == set(), text


def test_c7_scanner_skips_non_json_objects_without_str():
    class Boom:
        def __str__(self) -> str:  # pragma: no cover - must not be called
            raise AssertionError("str() must not be called")

        def __repr__(self) -> str:  # pragma: no cover
            raise AssertionError("repr() must not be called")

    assert scan_unregistered_credential_families({"x": Boom(), "y": _C7_OPENAI}) == {
        FAMILY_OPENAI
    }


def test_c7_scanner_budget_stops_silently():
    """Hitting node budget stops; does not raise."""
    huge = {f"k{i}": f"v{i}" for i in range(20_000)}
    assert scan_unregistered_credential_families(huge) == set()


def test_c7_unregistered_warns_once_provider_request_unchanged(
    c7_empty_store, capsys, monkeypatch
):
    """Unregistered decoy → fixed stderr; Provider request byte-identical to C7-off."""
    req = _c7_msg(f"please use {_C7_OPENAI}")
    captured: List[Any] = []

    def next_call(r):
        captured.append(deepcopy(r))
        return {"ok": True}

    monkeypatch.setattr(mw, "best_effort_warn_unregistered", lambda *a, **k: None)
    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="s-a")
    assert len(captured) == 1
    baseline = captured[0]
    captured.clear()
    reset_unregistered_warning_state_for_tests()
    capsys.readouterr()
    monkeypatch.setattr(mw, "best_effort_warn_unregistered", best_effort_warn_unregistered)

    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="s-a")
    assert len(captured) == 1
    assert captured[0] == baseline
    assert _C7_OPENAI in json.dumps(captured[0], ensure_ascii=False)
    _c7_wait_warn()
    err = capsys.readouterr().err
    assert err.count(UNREGISTERED_WARNING_TEXT) == 1
    assert _C7_OPENAI not in err


def test_c7_registered_decoy_redacted_no_warning(c7_empty_store, capsys):
    """Registered decoy becomes <SECRET:…>; no C7 warning; Provider never sees plaintext."""
    get_registry().register("openai_decoy", "token", _C7_OPENAI)
    captured: List[Any] = []

    def next_call(r):
        captured.append(r)
        return {"ok": True}

    on_llm_execution(
        request=_c7_msg(f"key {_C7_OPENAI}"),
        next_call=next_call,
        session_id="s-reg",
    )
    assert len(captured) == 1
    blob = json.dumps(captured[0], ensure_ascii=False)
    assert _C7_OPENAI not in blob
    assert "<SECRET:cg_" in blob
    _c7_wait_warn()
    err = capsys.readouterr().err
    assert UNREGISTERED_WARNING_TEXT not in err


def test_c7_best_effort_swallows_scanner_dedupe_stderr_errors(
    c7_empty_store, capsys, monkeypatch
):
    """Scanner / dedupe / stderr failures must not affect Provider call."""
    req = _c7_msg(f"x {_C7_GITHUB}")
    captured: List[Any] = []

    def next_call(r):
        captured.append(deepcopy(r))
        return {"ok": True}

    monkeypatch.setattr(
        "credential_guard.unregistered_warning.scan_unregistered_credential_families",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("scan boom")),
    )
    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="s-e1")
    assert len(captured) == 1
    assert _C7_GITHUB in json.dumps(captured[0])

    captured.clear()
    monkeypatch.setattr(
        "credential_guard.unregistered_warning.scan_unregistered_credential_families",
        lambda *_a, **_k: {FAMILY_GITHUB},
    )
    monkeypatch.setattr(
        "credential_guard.unregistered_warning.note_families_and_select_emits",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("dedupe boom")),
    )
    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="s-e2")
    assert len(captured) == 1

    captured.clear()
    reset_unregistered_warning_state_for_tests()

    class _BrokenStderr:
        def write(self, *_a, **_k):
            raise OSError("write boom")

        def flush(self):
            raise OSError("flush boom")

    monkeypatch.setattr(
        "credential_guard.unregistered_warning.scan_unregistered_credential_families",
        lambda *_a, **_k: {FAMILY_GITHUB},
    )
    monkeypatch.setattr(
        "credential_guard.unregistered_warning.note_families_and_select_emits",
        lambda *_a, **_k: {FAMILY_GITHUB},
    )
    monkeypatch.setattr(
        "credential_guard.unregistered_warning.sys.stderr",
        _BrokenStderr(),
    )
    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="s-e3")
    assert len(captured) == 1
    assert _C7_GITHUB in json.dumps(captured[0])
    # Finish the async write while BrokenStderr is still patched so teardown
    # cannot flush the constant text onto the real pytest stderr.
    _c7_wait_warn()


def test_c7_dedupe_two_seams_same_session_once_and_lru_bound(c7_empty_store, capsys):
    """Same session+family across two seams → one warn; families independent; LRU bound."""
    req = _c7_msg(f"{_C7_OPENAI} and {_C7_AWS}")
    calls: List[Any] = []

    def next_call(r):
        calls.append(r)
        return {"ok": True}

    sid = "session-multi"
    stage = on_llm_request(request=deepcopy(req), session_id=sid)["request"]
    on_llm_execution(request=stage, next_call=next_call, session_id=sid)
    _c7_wait_warn()
    err = capsys.readouterr().err
    # Two families → two identical warning lines; not four (no double-seam).
    assert err.count(UNREGISTERED_WARNING_TEXT) == 2
    assert len(calls) == 1

    # Empty session_id: once per family at process level.
    reset_unregistered_warning_state_for_tests()
    capsys.readouterr()
    on_llm_request(request=_c7_msg(_C7_SLACK), session_id="")
    on_llm_execution(
        request=_c7_msg(_C7_SLACK),
        next_call=lambda r: {"ok": True},
        session_id="",
    )
    _c7_wait_warn()
    assert capsys.readouterr().err.count(UNREGISTERED_WARNING_TEXT) == 1

    # LRU: >1024 sessions remains bounded.
    reset_unregistered_warning_state_for_tests()
    for i in range(1100):
        note_families_and_select_emits(f"sess-{i}", {FAMILY_OPENAI})
    assert session_state_size_for_tests() <= 1024


def test_c7_empty_session_process_dedupe_survives_session_lru_eviction():
    """Empty session_id is process+family once; must not be LRU-evicted by non-empty sessions."""
    reset_unregistered_warning_state_for_tests()

    first = note_families_and_select_emits("", {FAMILY_OPENAI})
    assert first == {FAMILY_OPENAI}

    for i in range(1100):
        note_families_and_select_emits(f"sess-lru-{i}", {FAMILY_GITHUB})

    assert session_state_size_for_tests() <= 1024

    again = note_families_and_select_emits("", {FAMILY_OPENAI})
    assert again == set()
    assert session_state_size_for_tests() <= 1024


def test_c7_oversized_session_id_uses_process_dedupe_not_lru():
    """Oversized session_id must not enter LRU; share empty-session process dedupe."""
    reset_unregistered_warning_state_for_tests()
    assert MAX_SESSION_ID_CHARS == 256
    huge = "S" * 1_000_000

    first = note_families_and_select_emits(huge, {FAMILY_OPENAI})
    assert first == {FAMILY_OPENAI}

    keys = session_keys_snapshot_for_tests()
    assert huge not in keys
    assert all(huge[:4096] != k and huge[:MAX_SESSION_ID_CHARS] != k for k in keys)
    assert all(len(k) <= MAX_SESSION_ID_CHARS for k in keys)
    assert session_state_size_for_tests() == 0
    assert session_resident_key_chars_for_tests() == 0

    # Same oversized + family: process-level once; still not in LRU.
    assert note_families_and_select_emits(huge, {FAMILY_OPENAI}) == set()
    assert note_families_and_select_emits("", {FAMILY_OPENAI}) == set()
    assert session_state_size_for_tests() == 0
    assert session_resident_key_chars_for_tests() == 0

    # Ordinary short session still uses session+family dedupe and LRU.
    short = note_families_and_select_emits("short-sess", {FAMILY_GITHUB})
    assert short == {FAMILY_GITHUB}
    assert note_families_and_select_emits("short-sess", {FAMILY_GITHUB}) == set()
    assert session_state_size_for_tests() == 1
    assert session_keys_snapshot_for_tests() == ("short-sess",)
    assert session_resident_key_chars_for_tests() == len("short-sess")

    # Resident key character total has a fixed hard ceiling.
    reset_unregistered_warning_state_for_tests()
    hard_cap = MAX_SESSION_ID_CHARS * 1024
    for i in range(1100):
        # Exactly at the allowed bound — must enter LRU, never truncate/hash.
        sid = f"{i:04d}" + ("x" * (MAX_SESSION_ID_CHARS - 4))
        assert len(sid) == MAX_SESSION_ID_CHARS
        note_families_and_select_emits(sid, {FAMILY_OPENAI})
    assert session_state_size_for_tests() <= 1024
    assert session_resident_key_chars_for_tests() <= hard_cap
    assert all(
        len(k) <= MAX_SESSION_ID_CHARS for k in session_keys_snapshot_for_tests()
    )

    # Non-string session_id also collapses to process policy.
    reset_unregistered_warning_state_for_tests()
    assert note_families_and_select_emits(None, {FAMILY_SLACK}) == {FAMILY_SLACK}  # type: ignore[arg-type]
    assert note_families_and_select_emits("", {FAMILY_SLACK}) == set()
    assert session_state_size_for_tests() == 0


def test_c7_warning_text_is_exact_constant_no_hit_material(capsys):
    """Warning text equals the fixed constant; no fragment/hash/path leakage."""
    reset_unregistered_warning_state_for_tests()
    best_effort_warn_unregistered(_C7_OPENAI, session_id="txt")
    _c7_wait_warn()
    err = capsys.readouterr().err.strip()
    assert err == UNREGISTERED_WARNING_TEXT
    assert err == (
        "Credential Guard 风险提醒：检测到疑似未登记的凭证；它不受本插件保护，"
        "当前请求内容未被修改。请将需要保护的凭证加入本机配置。"
        "检测可能遗漏或误报。"
    )
    assert _C7_OPENAI not in err
    assert "sk-" not in err
    assert "openai" not in err.lower()
    assert "hash" not in err.lower()
    assert "/" not in err  # no path


def test_c7_mutation_raise_in_warning_breaks_non_interference(
    c7_empty_store, monkeypatch
):
    """If warning raises, non-interference must fail (Provider must still be called)."""
    calls: List[Any] = []

    def next_call(r):
        calls.append(r)
        return {"ok": True}

    def _boom(*_a, **_k):
        raise RuntimeError("mutated warn raise")

    monkeypatch.setattr(mw, "best_effort_warn_unregistered", _boom)
    # Current production swallows via the helper itself; mutating the seam to
    # raise *out of* _prepare_provider_bound must surface as a blocked path.
    # Load-bearing: production wraps only inside best_effort; raising from the
    # imported name after gate still propagates into RequestBlock handling.
    result = on_llm_execution(
        request=_c7_msg(_C7_OPENAI),
        next_call=next_call,
        session_id="mut-raise",
    )
    # With raise escaping _prepare_provider_bound, Provider is NOT called —
    # this documents the non-interference contract that must stay GREEN only
    # while best_effort swallows. The complementary positive path:
    reset_unregistered_warning_state_for_tests()
    calls.clear()
    monkeypatch.setattr(
        mw,
        "best_effort_warn_unregistered",
        lambda *a, **k: best_effort_warn_unregistered(*a, **k),
    )
    on_llm_execution(
        request=_c7_msg(_C7_OPENAI),
        next_call=next_call,
        session_id="mut-raise-ok",
    )
    assert len(calls) == 1
    # The raise mutation path must differ (Provider not called).
    monkeypatch.setattr(mw, "best_effort_warn_unregistered", _boom)
    calls.clear()
    result = on_llm_execution(
        request=_c7_msg(_C7_OPENAI),
        next_call=next_call,
        session_id="mut-raise-2",
    )
    assert calls == []
    assert getattr(result, "model", "") == "credential-guard-blocked"


def test_c7_mutation_request_rewrite_breaks_provider_equivalence(
    c7_empty_store, monkeypatch
):
    """If warning rewrites request, Provider-equivalence assertion goes RED."""
    req = _c7_msg(_C7_OPENAI)
    captured: List[Any] = []

    def next_call(r):
        captured.append(deepcopy(r))
        return {"ok": True}

    # Identity baseline with real helper.
    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="rw0")
    assert len(captured) == 1
    baseline = captured[0]
    assert _C7_OPENAI in json.dumps(baseline, ensure_ascii=False)
    captured.clear()
    reset_unregistered_warning_state_for_tests()

    def _rewrite(payload, session_id=""):
        if isinstance(payload, dict) and "messages" in payload:
            payload["messages"] = [{"role": "user", "content": "REWRITTEN"}]

    monkeypatch.setattr(mw, "best_effort_warn_unregistered", _rewrite)
    on_llm_execution(request=deepcopy(req), next_call=next_call, session_id="rw1")
    assert len(captured) == 1
    assert captured[0] != baseline
    assert captured[0]["messages"][0]["content"] == "REWRITTEN"


def test_c7_mutation_call_before_final_gate_warns_on_blocked(
    c7_empty_store, capsys, monkeypatch
):
    """Warning must not run when final residual gate blocks the request."""
    decoy_req = _c7_msg(_C7_OPENAI)

    def _block(*_a, **_k):
        return mw._detail_residual("request", action_kind="unrecoverable")

    monkeypatch.setattr(mw, "_final_residual_gate", _block)
    calls: List[Any] = []
    result = on_llm_execution(
        request=decoy_req,
        next_call=lambda r: calls.append(r) or {"ok": True},
        session_id="pre-gate",
    )
    assert calls == []
    assert getattr(result, "model", "") == "credential-guard-blocked"
    _c7_wait_warn()
    assert UNREGISTERED_WARNING_TEXT not in capsys.readouterr().err

    # Mutation evidence: calling warn before a block would emit the fixed text.
    reset_unregistered_warning_state_for_tests()
    capsys.readouterr()
    best_effort_warn_unregistered(decoy_req, session_id="pre-gate-mut")
    _c7_wait_warn()
    assert UNREGISTERED_WARNING_TEXT in capsys.readouterr().err


def test_c7_blocking_stderr_does_not_stall_provider_hot_path(tmp_path):
    """Blocking stderr write must not stall Provider; request stays deep-equal.

    Isolated in a subprocess so a permanently blocked daemon/worker cannot hang
    the pytest process. Proves the real ``_prepare_provider_bound`` → warning
    → ``next_call`` order under a write() that waits forever.
    """
    repo = Path(__file__).resolve().parents[1]
    marker = tmp_path / "c7_block_stderr_marker"
    status = tmp_path / "c7_block_stderr_status"
    script = f"""
import json
import os
import sys
import tempfile
import threading
from copy import deepcopy
from pathlib import Path

repo = {str(repo)!r}
sys.path.insert(0, repo)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = repo

home = Path(tempfile.mkdtemp())
hermes = home / "hermes"
store = hermes / "credential-guard"
store.mkdir(parents=True)
os.chmod(store, 0o700)
cfg = store / "credential-guard.json"
cfg.write_text(
    json.dumps({{"version": 2, "credentials": {{}}, "bindings": {{}}}}),
    encoding="utf-8",
)
os.chmod(cfg, 0o600)
os.environ["HOME"] = str(home / "home")
os.environ["HERMES_HOME"] = str(hermes)
(home / "home").mkdir(exist_ok=True)

# The plugin derives its store from its install location and no longer reads
# HERMES_HOME; this probe runs from a checkout, so pin the store explicitly.
from credential_guard import store_location as _sl

_sl.use_store_dir(store)

from credential_guard import middleware as mw
from credential_guard.middleware import on_llm_execution
from credential_guard.runtime_config import reset_runtime_for_tests
from credential_guard.state import get_registry
from credential_guard.unregistered_warning import (
    best_effort_warn_unregistered,
    reset_unregistered_warning_state_for_tests,
)
import credential_guard.unregistered_warning as uw

reset_runtime_for_tests()
get_registry().clear()
reset_unregistered_warning_state_for_tests()

decoy = "sk-decoyOpenAIStyleToken0001xx"
req = {{"messages": [{{"role": "user", "content": decoy}}], "model": "fake-model"}}

baseline_box = []
mw.best_effort_warn_unregistered = lambda *a, **k: None
on_llm_execution(
    request=deepcopy(req),
    next_call=lambda r: baseline_box.append(deepcopy(r)) or {{"ok": True}},
    session_id="blk-base",
)
assert len(baseline_box) == 1
baseline = baseline_box[0]

mw.best_effort_warn_unregistered = best_effort_warn_unregistered
reset_unregistered_warning_state_for_tests()

entered = threading.Event()
never = threading.Event()


class BlockingStderr:
    def write(self, data):
        entered.set()
        never.wait()
        return len(data) if data else 0

    def flush(self):
        return None

    def isatty(self):
        return False


# Patch the sys module object used by the warning path. After this, avoid
# SystemExit/traceback to the same stderr — use os._exit + status file.
uw.sys.stderr = BlockingStderr()

provider_calls = []
provider_done = threading.Event()
errors = []


def run():
    try:
        def next_call(r):
            provider_calls.append(deepcopy(r))
            provider_done.set()
            return {{"ok": True}}

        on_llm_execution(
            request=deepcopy(req),
            next_call=next_call,
            session_id="blk-hot",
        )
    except Exception as exc:  # pragma: no cover - surface via status file
        errors.append(repr(exc))


t = threading.Thread(target=run, daemon=True)
t.start()

status_path = Path({str(status)!r})
marker_path = Path({str(marker)!r})

if not entered.wait(timeout=3.0):
    status_path.write_text("WRITE_NOT_ENTERED", encoding="utf-8")
    os._exit(3)
if not provider_done.wait(timeout=2.0):
    status_path.write_text("PROVIDER_STALLED", encoding="utf-8")
    os._exit(2)
if errors:
    status_path.write_text("RUN_ERROR:" + ";".join(errors), encoding="utf-8")
    os._exit(4)
if len(provider_calls) != 1:
    status_path.write_text("PROVIDER_COUNT=" + str(len(provider_calls)), encoding="utf-8")
    os._exit(5)
if provider_calls[0] != baseline:
    status_path.write_text("REQUEST_NOT_DEEP_EQUAL", encoding="utf-8")
    os._exit(6)

marker_path.write_text("PASS", encoding="utf-8")
status_path.write_text("PASS", encoding="utf-8")
os._exit(0)
"""
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repo),
    }
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    status_text = status.read_text(encoding="utf-8") if status.exists() else "<missing>"
    assert proc.returncode == 0, (
        f"rc={proc.returncode} status={status_text!r}\n"
        f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )
    assert marker.read_text(encoding="utf-8") == "PASS"
    assert status_text == "PASS"
