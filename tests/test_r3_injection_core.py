"""R3A Slice A2: SecretLease + one-shot injection resolve core."""

from __future__ import annotations

import copy
import json
import os
import pickle
import secrets
from pathlib import Path
from typing import Any, Dict

import pytest

from credential_guard.config import CONFIG_FILENAME
from credential_guard import runtime_config as rc
from credential_guard.injection_plan import InjectionPlan, PlanState


def _decoy(n: int = 16) -> str:
    return "CG_SYNTHETIC_DECOY_" + secrets.token_hex(n)


def _write(path: Path, doc: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps(doc, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _http_doc(token: str) -> Dict[str, Any]:
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
                "request": {
                    "allowed_methods": ["POST"],
                    "allowed_paths": ["/job/project-x/build"],
                },
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
    rc.reset_runtime_for_tests()
    yield store
    rc.reset_runtime_for_tests()


def _consumed_plan(*, credential_name: str = "jenkins-token") -> InjectionPlan:
    return InjectionPlan(
        session_id="s1",
        turn_id="t1",
        tool_call_id="c1",
        tool_name="http_credential_request",
        args_digest="a" * 64,
        reference_arg_path=("credential",),
        credential_name=credential_name,
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


def test_a2_resolve_one_token_notes_injection_not_registry_count(isolated_runtime: Path):
    """First A2 RED: resolve_one_for_execution must exist and count injection resolves separately."""
    from credential_guard import injection as inj

    decoy = _decoy()
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    view = rc.load_and_publish_runtime()
    registry_count = rc.get_execution_secret_resolve_count()
    assert registry_count >= 1  # egress build already resolved for redaction
    before_inj = rc.get_injection_secret_resolve_count()
    assert before_inj == 0

    lease = inj.resolve_one_for_execution(_consumed_plan(), view)
    assert rc.get_injection_secret_resolve_count() == before_inj + 1
    # Registry/egress counter must not be used as the injection evidence.
    assert rc.get_execution_secret_resolve_count() == registry_count

    material = lease.read_for_adapter()
    assert material["kind"] == "token"
    assert material["value"] == decoy
    lease.close()
    with pytest.raises(inj.InjectionError) as ei:
        lease.read_for_adapter()
    assert ei.value.code == "INJECTION_LEASE_CLOSED"
    assert decoy not in f"{ei.value!s}{ei.value!r}{lease!r}{lease!s}"


def test_a2_secret_lease_blocks_repr_pickle_copy_json(isolated_runtime: Path):
    from credential_guard import injection as inj

    decoy = _decoy()
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    view = rc.load_and_publish_runtime()
    lease = inj.resolve_one_for_execution(_consumed_plan(), view)
    assert decoy not in repr(lease)
    assert decoy not in str(lease)
    with pytest.raises(Exception):
        json.dumps(lease)  # type: ignore[arg-type]
    with pytest.raises(inj.InjectionError) as ei:
        copy.copy(lease)
    assert ei.value.code == "INJECTION_LEASE_COPY_FORBIDDEN"
    with pytest.raises(inj.InjectionError):
        copy.deepcopy(lease)
    with pytest.raises(inj.InjectionError) as ej:
        pickle.dumps(lease)
    assert ej.value.code == "INJECTION_LEASE_SERIALIZE_FORBIDDEN"
    lease.close()


def test_a2_rejects_non_consumed_plan(isolated_runtime: Path):
    from credential_guard import injection as inj

    decoy = _decoy()
    _write(isolated_runtime / CONFIG_FILENAME, _http_doc(decoy))
    view = rc.load_and_publish_runtime()
    pending = InjectionPlan(
        **{
            **_consumed_plan().__dict__,
            "state": PlanState.APPROVAL_PENDING,
        }
    )
    before = rc.get_injection_secret_resolve_count()
    with pytest.raises(inj.InjectionError) as ei:
        inj.resolve_one_for_execution(pending, view)
    assert ei.value.code == "INJECTION_RESOLVE_FAILED"
    assert rc.get_injection_secret_resolve_count() == before
    assert decoy not in f"{ei.value!s}{ei.value!r}"


def test_a2_resolve_basic_username_password(isolated_runtime: Path):
    from credential_guard import injection as inj

    password = _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "svc": {
                "type": "username_password",
                "username": "cg_readonly",
                "password": password,
            }
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
            }
        },
    }
    _write(isolated_runtime / CONFIG_FILENAME, doc)
    view = rc.load_and_publish_runtime()
    plan = _consumed_plan(credential_name="svc")
    lease = inj.resolve_one_for_execution(plan, view)
    material = lease.read_for_adapter()
    assert material["kind"] == "username_password"
    assert material["username"] == "cg_readonly"
    assert material["password"] == password
    lease.close()
