"""R3A Slice A1: HTTP binding schema — allowed_methods/paths + digests."""

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


def _http_doc(token: str, **binding_overrides: Any) -> Dict[str, Any]:
    binding: Dict[str, Any] = {
        "type": "http",
        "credential_ref": "jenkins-token",
        "target": {"scheme": "https", "host": "jenkins.example.test", "port": 443},
        "request": {
            "allowed_methods": ["POST"],
            "allowed_paths": ["/job/project-x/build"],
        },
        "inject": {"type": "bearer", "location": "authorization_header"},
        "approval": "required",
    }
    binding.update(binding_overrides)
    return {
        "version": 2,
        "credentials": {"jenkins-token": {"type": "token", "value": token}},
        "bindings": {"jenkins-production": binding},
    }


def test_a1_http_binding_accepts_exact_allowed_methods_and_paths(tmp_path: Path):
    """Minimal GREEN target for A1: request allowlists are first-class schema."""
    decoy = _decoy()
    path = _write(tmp_path / CONFIG_FILENAME, _http_doc(decoy))
    cfg = CredentialGuardConfig.load(path)
    binding = cfg.bindings["jenkins-production"]
    assert binding["type"] == "http"
    assert binding["request"]["allowed_methods"] == ("POST",)
    assert binding["request"]["allowed_paths"] == ("/job/project-x/build",)
    # Safe defaults present and finite.
    req = binding["request"]
    assert 0 < req["connect_timeout_seconds"] <= 60
    assert 0 < req["total_timeout_seconds"] <= 120
    assert "max_response_header_bytes" not in req
    assert 0 < req["max_response_body_bytes"] <= 8_388_608
    # Canonical digest material must not surface the decoy value in errors/repr of digest APIs.
    assert len(cfg.config_digest) == 64


def test_a1_rejects_empty_allowed_paths(tmp_path: Path):
    decoy = _decoy()
    doc = _http_doc(decoy)
    doc["bindings"]["jenkins-production"]["request"]["allowed_paths"] = []
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"
    assert decoy not in f"{ei.value!s}{ei.value!r}"


def test_a1_rejects_regex_or_wildcard_paths(tmp_path: Path):
    decoy = _decoy()
    for bad in ("/job/.*/build", "/job/*/build", "/job/(x|y)/build", "/job/?/build"):
        doc = _http_doc(decoy)
        doc["bindings"]["jenkins-production"]["request"]["allowed_paths"] = [bad]
        with pytest.raises(ConfigError) as ei:
            CredentialGuardConfig.load(_write(tmp_path / f"c-{abs(hash(bad)) % 10**8}.json", doc))
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


def test_a1_binding_and_target_digests_cover_execution_fields(isolated_runtime: Path):
    """Digests must bind real target + allowlists + inject + limits; meta must scrub host."""
    decoy = _decoy()
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    view = rc.load_and_publish_runtime()
    meta = view.bindings["jenkins-production"]
    # Safety: host never appears in scrubbed meta keys/values exposed for match/approval.
    blob = json.dumps(
        {k: meta[k] for k in meta if k not in ("binding_digest", "target_digest")},
        sort_keys=True,
        default=str,
    )
    assert "jenkins.example.test" not in blob
    assert "host" not in meta

    base_binding = meta["binding_digest"]
    base_target = meta["target_digest"]
    assert len(base_binding) == 64 and len(base_target) == 64

    # Mutate host → target_digest must change.
    doc2 = _http_doc(decoy)
    doc2["bindings"]["jenkins-production"]["target"]["host"] = "other.example.test"
    _write(isolated_runtime / CONFIG_FILENAME, doc2)
    rc.reset_runtime_for_tests()
    meta2 = rc.load_and_publish_runtime().bindings["jenkins-production"]
    assert meta2["target_digest"] != base_target

    # Mutate allowed_paths → binding_digest must change.
    doc3 = _http_doc(decoy)
    doc3["bindings"]["jenkins-production"]["request"]["allowed_paths"] = [
        "/job/other/build"
    ]
    _write(isolated_runtime / CONFIG_FILENAME, doc3)
    rc.reset_runtime_for_tests()
    meta3 = rc.load_and_publish_runtime().bindings["jenkins-production"]
    assert meta3["binding_digest"] != base_binding

    # Mutate inject type → binding_digest must change.
    doc4 = {
        "version": 2,
        "credentials": {"jenkins-token": {"type": "token", "value": decoy}},
        "bindings": {
            "jenkins-production": {
                "type": "http",
                "credential_ref": "jenkins-token",
                "target": {
                    "scheme": "https",
                    "host": "jenkins.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["POST"],
                    "allowed_paths": ["/job/project-x/build"],
                },
                "inject": {"type": "api_key_header", "header_name": "X-Api-Key"},
                "approval": "required",
            }
        },
    }
    _write(isolated_runtime / CONFIG_FILENAME, doc4)
    rc.reset_runtime_for_tests()
    meta4 = rc.load_and_publish_runtime().bindings["jenkins-production"]
    assert meta4["binding_digest"] != base_binding


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["bindings"]["jenkins-production"].__setitem__("extra", 1),
        lambda d: d["bindings"]["jenkins-production"]["target"].__setitem__(
            "scheme", "ftp"
        ),
        lambda d: d["bindings"]["jenkins-production"]["target"].__setitem__(
            "host", "127.0.0.1"
        ),
        lambda d: d["bindings"]["jenkins-production"]["target"].__setitem__(
            "host", "user@jenkins.example.test"
        ),
        lambda d: d["bindings"]["jenkins-production"]["target"].__setitem__(
            "host", "*.example.test"
        ),
        lambda d: d["bindings"]["jenkins-production"]["target"].__setitem__(
            "port", 0
        ),
        lambda d: d["bindings"]["jenkins-production"]["target"].__setitem__(
            "port", 70000
        ),
        lambda d: d["bindings"]["jenkins-production"]["request"].__setitem__(
            "allowed_methods", []
        ),
        lambda d: d["bindings"]["jenkins-production"]["request"].__setitem__(
            "allowed_methods", ["POST", "TRACE"]
        ),
        lambda d: d["bindings"]["jenkins-production"]["request"].__setitem__(
            "connect_timeout_seconds", -1
        ),
        lambda d: d["bindings"]["jenkins-production"]["request"].__setitem__(
            "max_response_body_bytes", 10**12
        ),
        lambda d: d["bindings"]["jenkins-production"]["inject"].__setitem__(
            "header_name", "Authorization"
        )
        if False
        else d["bindings"]["jenkins-production"].update(
            {
                "inject": {"type": "api_key_header", "header_name": "Authorization"},
            }
        ),
    ],
)
def test_a1_rejects_dangerous_or_unknown_http_fields(tmp_path: Path, mutate):
    decoy = _decoy()
    doc = _http_doc(decoy)
    mutate(doc)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"
    assert decoy not in f"{ei.value!s}{ei.value!r}"


def test_a1_rejects_type_mismatch_bearer_needs_token(tmp_path: Path):
    password = _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "svc": {
                "type": "username_password",
                "username": "u",
                "password": password,
            }
        },
        "bindings": {
            "b": {
                "type": "http",
                "credential_ref": "svc",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/v1"],
                },
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write(tmp_path / CONFIG_FILENAME, doc))
    assert ei.value.code == "CONFIG_SCHEMA"


def test_a1_mutation_dropping_target_host_from_digest_would_fail(
    isolated_runtime: Path, monkeypatch
):
    """Negative/mutation: if target_digest ignores host, host swap becomes invisible."""
    decoy = _decoy()
    import hashlib
    import json
    from types import MappingProxyType

    real = rc._freeze_binding_meta

    def weak_freeze(bindings):
        view = real(bindings)
        rebuilt = {}
        for name, meta in view.items():
            weak = dict(meta)
            payload = {
                "name": name,
                "credential_ref": meta.get("credential_ref"),
                "type": meta.get("type"),
            }
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            weak["target_digest"] = hashlib.sha256(raw.encode()).hexdigest()
            rebuilt[name] = MappingProxyType(weak)
        return MappingProxyType(rebuilt)

    monkeypatch.setattr(rc, "_freeze_binding_meta", weak_freeze)
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    meta1 = rc.load_and_publish_runtime().bindings["jenkins-production"]
    rc.reset_runtime_for_tests()
    doc2 = _http_doc(decoy)
    doc2["bindings"]["jenkins-production"]["target"]["host"] = "other.example.test"
    _write(isolated_runtime / CONFIG_FILENAME, doc2)
    meta2 = rc.load_and_publish_runtime().bindings["jenkins-production"]
    # Weakened gate: host swap does not change target_digest.
    assert meta2["target_digest"] == meta1["target_digest"]
    # Production gate still distinguishes (control).
    monkeypatch.setattr(rc, "_freeze_binding_meta", real)
    rc.reset_runtime_for_tests()
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    prod1 = rc.load_and_publish_runtime().bindings["jenkins-production"]["target_digest"]
    rc.reset_runtime_for_tests()
    _write(isolated_runtime / CONFIG_FILENAME, doc2)
    prod2 = rc.load_and_publish_runtime().bindings["jenkins-production"]["target_digest"]
    assert prod1 != prod2
