"""R3B Slice B1: process_env/stdin binding schema — fixed local program, no shell tools."""

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


def _program(tmp_path: Path, name: str = "cg-synth-helper") -> str:
    """Absolute path string for schema tests — file need not exist yet (identity is B2)."""
    return str((tmp_path / name).resolve())


def _process_env_doc(token: str, program: str, **overrides: Any) -> Dict[str, Any]:
    binding: Dict[str, Any] = {
        "type": "process_env",
        "credential_ref": "cli_token",
        "program": program,
        "argv": [program, "status"],
        "env_name": "MY_API_TOKEN",
        "timeout_seconds": 30,
        "max_stdout_bytes": 65536,
        "max_stderr_bytes": 65536,
        "approval": "required",
    }
    binding.update(overrides)
    return {
        "version": 2,
        "credentials": {"cli_token": {"type": "token", "value": token}},
        "bindings": {"cli-env": binding},
    }


def _stdin_doc(token: str, program: str, **overrides: Any) -> Dict[str, Any]:
    binding: Dict[str, Any] = {
        "type": "stdin",
        "credential_ref": "cli_token",
        "program": program,
        "argv": [program, "ingest"],
        "stdin_format": "raw",
        "timeout_seconds": 30,
        "max_stdout_bytes": 65536,
        "max_stderr_bytes": 65536,
        "approval": "required",
    }
    binding.update(overrides)
    return {
        "version": 2,
        "credentials": {"cli_token": {"type": "token", "value": token}},
        "bindings": {"cli-stdin": binding},
    }


def test_b1_process_env_accepts_fixed_program_schema(tmp_path: Path):
    """Minimal GREEN target: fixed program/argv/env_name/limits; no model tool fields."""
    decoy = _decoy()
    program = _program(tmp_path)
    path = _write(tmp_path / CONFIG_FILENAME, _process_env_doc(decoy, program))
    cfg = CredentialGuardConfig.load(path)
    binding = cfg.bindings["cli-env"]
    assert binding["type"] == "process_env"
    assert binding["program"] == program
    assert list(binding["argv"]) == [program, "status"]
    assert binding["env_name"] == "MY_API_TOKEN"
    assert 0 < binding["timeout_seconds"] <= 120
    assert 0 < binding["max_stdout_bytes"] <= 8_388_608
    assert 0 < binding["max_stderr_bytes"] <= 8_388_608
    assert "tool" not in binding
    assert "arg_path" not in binding
    assert len(cfg.config_digest) == 64
    assert decoy not in f"{cfg!r}"


def test_b1_stdin_accepts_fixed_program_schema(tmp_path: Path):
    decoy = _decoy()
    program = _program(tmp_path)
    cfg = CredentialGuardConfig.load(
        _write(tmp_path / CONFIG_FILENAME, _stdin_doc(decoy, program, stdin_format="line"))
    )
    binding = cfg.bindings["cli-stdin"]
    assert binding["type"] == "stdin"
    assert binding["stdin_format"] == "line"
    assert binding["program"] == program
    assert "env_name" not in binding
    assert "tool" not in binding
    assert "arg_path" not in binding


@pytest.mark.parametrize(
    "legacy",
    [
        {
            "type": "process_env",
            "credential_ref": "cli_token",
            "tool": "terminal",
            "env_name": "MY_API_TOKEN",
            "approval": "required",
        },
        {
            "type": "stdin",
            "credential_ref": "cli_token",
            "tool": "execute_code",
            "arg_path": ["stdin"],
            "approval": "required",
        },
        {
            "type": "process_env",
            "credential_ref": "cli_token",
            "tool": "terminal",
            "program": "/opt/cg/helper",
            "argv": ["/opt/cg/helper"],
            "env_name": "MY_API_TOKEN",
            "timeout_seconds": 30,
            "max_stdout_bytes": 65536,
            "max_stderr_bytes": 65536,
            "approval": "required",
        },
    ],
)
def test_b1_rejects_legacy_terminal_execute_code_schema(tmp_path: Path, legacy: Dict[str, Any]):
    decoy = _decoy()
    doc = {
        "version": 2,
        "credentials": {"cli_token": {"type": "token", "value": decoy}},
        "bindings": {"legacy": legacy},
    }
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"
    assert decoy not in f"{ei.value!s}{ei.value!r}"


@pytest.mark.parametrize(
    "bad_program",
    [
        "relative/helper",
        "./helper",
        "~/helper",
        "/usr/bin/bash",
        "/usr/bin/python3",
        "/usr/bin/env",
        "/opt/bin/python3.11",
        "/tmp/../usr/bin/helper",
        "/opt/$HOME/helper",
        "/opt/helper\n",
    ],
)
def test_b1_rejects_unsafe_program_paths(tmp_path: Path, bad_program: str):
    decoy = _decoy()
    # Keep argv[0] aligned so failure is specifically program validation.
    doc = _process_env_doc(decoy, bad_program, argv=[bad_program, "x"])
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / f"p-{abs(hash(bad_program)) % 10**8}.json", doc))
    assert ei.value.code == "CONFIG_SCHEMA"


@pytest.mark.parametrize("flag", ["-c", "--command", "-e", "--eval"])
def test_b1_rejects_secondary_interpretation_argv(tmp_path: Path, flag: str):
    decoy = _decoy()
    program = _program(tmp_path)
    doc = _process_env_doc(decoy, program, argv=[program, flag, "echo hi"])
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"


def test_b1_rejects_argv0_mismatch(tmp_path: Path):
    decoy = _decoy()
    program = _program(tmp_path)
    doc = _process_env_doc(decoy, program, argv=["other-name", "status"])
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"


@pytest.mark.parametrize(
    "env_name",
    ["PATH", "HOME", "HERMES_HOME", "LD_PRELOAD", "PYTHONPATH", "BASH_ENV", "HTTP_PROXY", "path", "1BAD"],
)
def test_b1_rejects_forbidden_or_illegal_env_name(tmp_path: Path, env_name: str):
    decoy = _decoy()
    program = _program(tmp_path)
    doc = _process_env_doc(decoy, program, env_name=env_name)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"


@pytest.mark.parametrize(
    "overrides",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 121},
        {"timeout_seconds": -1},
        {"timeout_seconds": 1.5},
        {"timeout_seconds": True},
        {"max_stdout_bytes": 0},
        {"max_stdout_bytes": 9_000_000},
        {"max_stderr_bytes": 100},
        {"stdin_format": "json"},  # only on stdin docs — applied via helper below
    ],
)
def test_b1_rejects_illegal_timeout_limits_or_format(tmp_path: Path, overrides: Dict[str, Any]):
    decoy = _decoy()
    program = _program(tmp_path)
    if "stdin_format" in overrides:
        doc = _stdin_doc(decoy, program, **overrides)
    else:
        doc = _process_env_doc(decoy, program, **overrides)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"


def test_b1_rejects_unknown_fields(tmp_path: Path):
    decoy = _decoy()
    program = _program(tmp_path)
    doc = _process_env_doc(decoy, program, cwd="/tmp", command="x")
    # unknown fields via update still present — helper puts them in binding
    binding = doc["bindings"]["cli-env"]
    binding["cwd"] = "/tmp"
    binding["shell"] = True
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"


def test_b1_rejects_username_password_for_process_bindings(tmp_path: Path):
    decoy = _decoy()
    program = _program(tmp_path)
    for factory in (_process_env_doc, _stdin_doc):
        doc = factory(decoy, program)
        doc["credentials"]["cli_token"] = {
            "type": "username_password",
            "username": "u",
            "password": decoy,
        }
        with pytest.raises(ConfigError) as ei:
            CredentialGuardConfig.load(
                _write(tmp_path / f"up-{factory.__name__}.json", doc)
            )
        assert ei.value.code == "CONFIG_SCHEMA"


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


def test_b1_digests_cover_execution_fields_and_scrub_hides_program(
    isolated_runtime: Path, tmp_path: Path
):
    """Digests bind program/argv/env/limits; scrubbed meta must not leak them."""
    decoy = _decoy()
    program = _program(tmp_path)
    _write(isolated_runtime / CONFIG_FILENAME, _process_env_doc(decoy, program))
    view = rc.load_and_publish_runtime()
    meta = view.bindings["cli-env"]
    blob = json.dumps(
        {k: meta[k] for k in meta if k not in ("binding_digest", "target_digest")},
        sort_keys=True,
        default=str,
    )
    assert program not in blob
    assert "MY_API_TOKEN" not in blob
    assert "env_name" not in meta
    assert "program" not in meta
    assert "argv" not in meta
    assert meta.get("allowed_tools") == ("credential_process_run",)
    assert tuple(meta.get("reference_arg_path") or ()) == ("credential",)
    assert "fixed local program" in str(meta.get("operation_summary") or "").lower() or (
        "fixed local program" in str(meta.get("process_summary") or "").lower()
    ) or meta.get("inject_mode") in {"process_env", "env"}

    base_binding = meta["binding_digest"]
    base_target = meta["target_digest"]
    assert len(base_binding) == 64 and len(base_target) == 64

    # Mutate env_name → binding_digest must change.
    doc2 = _process_env_doc(decoy, program, env_name="OTHER_TOKEN")
    _write(isolated_runtime / CONFIG_FILENAME, doc2)
    rc.reset_runtime_for_tests()
    meta2 = rc.load_and_publish_runtime().bindings["cli-env"]
    assert meta2["binding_digest"] != base_binding

    # Mutate argv → binding_digest must change.
    doc3 = _process_env_doc(decoy, program, argv=[program, "other"])
    _write(isolated_runtime / CONFIG_FILENAME, doc3)
    rc.reset_runtime_for_tests()
    meta3 = rc.load_and_publish_runtime().bindings["cli-env"]
    assert meta3["binding_digest"] != base_binding

    # Mutate program → both digests must change (program identity is target).
    other = _program(tmp_path, "cg-synth-other")
    doc4 = _process_env_doc(decoy, other, argv=[other, "status"])
    _write(isolated_runtime / CONFIG_FILENAME, doc4)
    rc.reset_runtime_for_tests()
    meta4 = rc.load_and_publish_runtime().bindings["cli-env"]
    assert meta4["binding_digest"] != base_binding
    assert meta4["target_digest"] != base_target


def test_b1_mutation_scrub_must_not_expose_program_or_env(
    isolated_runtime: Path, tmp_path: Path, monkeypatch
):
    """Deleting scrub of program/env_name must turn the hygiene contract RED."""
    decoy = _decoy()
    program = _program(tmp_path)
    _write(isolated_runtime / CONFIG_FILENAME, _process_env_doc(decoy, program))
    real = rc._freeze_binding_meta

    def leaky_freeze(bindings):
        frozen = real(bindings)
        # Mutate: re-introduce absolute program + env_name into scrubbed view.
        out = {}
        for name, meta in frozen.items():
            raw = bindings[name]
            leaked = dict(meta)
            leaked["program"] = raw.get("program")
            leaked["env_name"] = raw.get("env_name")
            leaked["argv"] = list(raw.get("argv") or ())
            out[name] = leaked
        from types import MappingProxyType

        return MappingProxyType({k: MappingProxyType(v) for k, v in out.items()})

    monkeypatch.setattr(rc, "_freeze_binding_meta", leaky_freeze)
    rc.reset_runtime_for_tests()
    meta = rc.load_and_publish_runtime().bindings["cli-env"]
    blob = json.dumps(dict(meta), sort_keys=True, default=str)
    # Under mutation the leak is present — this is the RED signal of the gate.
    assert program in blob
    assert "MY_API_TOKEN" in blob
    monkeypatch.setattr(rc, "_freeze_binding_meta", real)
    rc.reset_runtime_for_tests()
    meta_ok = rc.load_and_publish_runtime().bindings["cli-env"]
    blob_ok = json.dumps(
        {k: meta_ok[k] for k in meta_ok if k not in ("binding_digest", "target_digest")},
        sort_keys=True,
        default=str,
    )
    assert program not in blob_ok
    assert "MY_API_TOKEN" not in blob_ok
