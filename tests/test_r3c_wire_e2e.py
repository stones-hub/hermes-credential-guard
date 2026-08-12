"""R3C C1: three adapters on one public AIAgent wire E2E.

Candidate evidence only — does not claim R3/R3C PASS.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WIRE_SCRIPT = REPO / "scripts" / "run_r3c_wire_e2e.py"
HERMES_SPIKE_PYTHON = Path(
    os.environ.get(
        "HERMES_SPIKE_PYTHON",
        "/tmp/credential-guard-r2-hermes-venv/bin/python",
    )
)

_FULL_APPROVE_ORDER = [
    "tool_request",
    "tool_execution",
    "pre_tool_call",
    "approval_gate",
    "handler",
    "consume",
    "resolve",
    "adapter",
]


# R3-era frozen fact. ``scripts/run_r3c_wire_e2e.py`` is AST-frozen (digest
# pinned in tests/test_r3c_evidence_authenticity_gate.py) and may not be edited,
# so its ``_FORMAL_PROVIDED_TOOLS`` still names the four tools that existed at
# R3C sign-off. The A2-retired tests below compare against this historical
# tuple instead of against the live R5 registration set.
_R3_HISTORICAL_PROVIDED_TOOLS = (
    "mysql_credential_action",
    "ssh_credential_action",
    "http_credential_request",
    "credential_process_run",
)


@pytest.fixture(scope="module")
def wire_module():
    """Load the frozen R3 carrier for historical-fact assertions (no run_all)."""
    assert WIRE_SCRIPT.is_file(), "missing scripts/run_r3c_wire_e2e.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3c_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _assert_r3_historical_toolset(mod) -> None:
    """The frozen carrier must still pin the R3 four-tool set, byte for byte."""
    assert tuple(mod._FORMAL_PROVIDED_TOOLS) == _R3_HISTORICAL_PROVIDED_TOOLS


@pytest.fixture(scope="module")
def wire_results():
    assert WIRE_SCRIPT.is_file(), "missing scripts/run_r3c_wire_e2e.py (RED until GREEN harness)"
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3c_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    work = Path(tempfile.mkdtemp(prefix="r3c-wire-test-"))
    try:
        results = mod.run_all(work)
        yield results
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _assert_zero_secrets(r: dict) -> None:
    assert r["wire_secret_count"] == 0
    assert r["token_in_provider_raw"] == 0
    assert r["token_in_approval_raw"] == 0
    assert r["token_in_result"] == 0
    assert r["trace_secret_count"] == 0
    assert isinstance(r["trace_artifact_count"], int)
    assert isinstance(r["trace_dirs_scanned"], list)
    assert len(r["trace_dirs_scanned"]) >= 1


def _assert_approve_common(r: dict, *, adapter: str) -> None:
    assert r["order"] == _FULL_APPROVE_ORDER
    assert r["counts"]["consume"] == 1
    assert r["counts"]["resolve"] == 1
    assert r["counts"]["adapter"] == 1
    assert r["injection_resolve_delta"] == 1
    _assert_zero_secrets(r)
    assert r["used_environ_copy"] is False
    assert r["loopback_only"] is True
    assert r["raw_http_has_request_line"] >= 1
    assert r["raw_http_has_headers"] >= 1
    assert r["raw_http_has_body"] >= 1
    assert r["approval_raw_count"] >= 1
    assert r["approval_raw_has_reason"] is True
    assert r["identity_unchanged"] is True
    assert r["provider_logical_turns"] >= 2
    assert r["http_transport_override_calls"] == 0
    if adapter == "http":
        assert r["http_target_evidence_layer"] == (
            "production_default_transport_loopback_tls"
        )
        assert r["http_adapter_delta"] == 1
        assert r["process_start_delta"] == 0
        assert r["http_target_hits"] == 1
        assert r["http_target_auth_applied"] == 1
        assert r["http_target_echoed_secret"] == 0
        assert r["default_transport_enter_count"] == 1
        assert r["http_tls_verify"] is True
        assert r["http_tls_loopback"] is True
    elif adapter == "env":
        assert r["process_start_delta"] == 1
        assert r["http_adapter_delta"] == 0
        assert r["http_target_hits"] == 0
        assert r["default_transport_enter_count"] == 0
        assert r["marker_ok"] is True
        assert r["parent_env_secret_count"] == 0
        assert r["cg_probe_in_parent"] is False
        assert r["followup_child_status"] == "absent"
        assert r["followup_child_secret_count"] == 0
    elif adapter == "stdin":
        assert r["process_start_delta"] == 1
        assert r["http_adapter_delta"] == 0
        assert r["http_target_hits"] == 0
        assert r["default_transport_enter_count"] == 0
        assert r["marker_ok"] is True


def _assert_deny_closed(r: dict) -> None:
    assert r["injection_resolve_delta"] == 0
    assert r["http_adapter_delta"] == 0
    assert r["process_start_delta"] == 0
    assert r.get("http_target_hits", 0) == 0
    assert r.get("default_transport_enter_count", 0) == 0
    assert r.get("http_transport_override_calls", 0) == 0
    _assert_zero_secrets(r)
    assert r["approval_raw_count"] >= 1


def _assert_timeout_distinct(r: dict, deny_r: dict) -> None:
    _assert_deny_closed(r)
    assert r["approval_is_timeout"] is True
    assert r["approval_timeout_branch"] is True
    assert r["approval_outcome"] == "timeout"
    assert r["await_gateway_call_count"] > 0
    assert r["host_approval_raw_intact"] is True
    assert isinstance(r.get("host_approval_raw"), dict)
    host_msg = str(r["host_approval_raw"].get("message") or "")
    assert "timed out without user response" in host_msg
    assert "Silence is not consent" in host_msg
    assert deny_r["approval_outcome"] == "denied"
    assert r["approval_message"] != deny_r["approval_message"]
    assert (
        "timed out" in r["approval_message"].lower()
        or "timeout" in r["approval_message"].lower()
        or "silence is not consent" in r["approval_message"].lower()
    )
    assert "DENIED" in deny_r["approval_message"] or deny_r[
        "approval_outcome"
    ] == "denied"
    # R3C wire covers approval-timeout; R3A/R3B retain separate adapter-timeout sign-off.
    assert r["counts"]["resolve"] == 0
    assert r["counts"]["adapter"] == 0


def _assert_replay(r: dict, *, adapter: str) -> None:
    assert r["injection_resolve_delta"] == 1
    assert r["counts"]["resolve"] == 1
    assert r["counts"]["adapter"] == 1
    assert r["counts"]["tool_request"] >= 2
    assert r["run_conversation_calls"] == 1
    assert r["replay_identity_same"] is True
    ids = r["tool_request_identities"]
    assert len(ids) >= 2
    for key in ("session_id", "turn_id", "tool_call_id", "args_digest"):
        assert ids[0][key] == ids[1][key]
        assert ids[0][key]
    assert r["second_resolve_delta"] == 0
    assert r["second_adapter_delta"] == 0
    assert r["second_start_delta"] == 0
    assert r["replay_closed"] is True
    assert "RUNTIME_ADAPTER_NOT_READY" in (r.get("result2_preview") or "")
    _assert_zero_secrets(r)
    assert r["http_transport_override_calls"] == 0
    if adapter == "http":
        assert r["http_adapter_delta"] == 1
        assert r["process_start_delta"] == 0
        assert r["http_target_hits"] == 1
        assert r["second_http_target_delta"] == 0
        assert r["default_transport_enter_count"] == 1
        assert r["http_target_evidence_layer"] == (
            "production_default_transport_loopback_tls"
        )
    else:
        assert r["process_start_delta"] == 1
        assert r["http_adapter_delta"] == 0
    assert r["manifest_bytes_identical"] is True
    # A2 retirement: ``manifest_registry_tools_match`` compares the installed
    # manifest against the LIVE registration set and is asserted no longer.
    # The callers assert the R3 historical tool set instead.


def _assert_mutate_closed(r: dict) -> None:
    assert r["injection_resolve_delta"] == 0
    assert r["http_adapter_delta"] == 0
    assert r["process_start_delta"] == 0
    assert r.get("http_target_hits", 0) == 0
    assert r.get("default_transport_enter_count", 0) == 0
    assert r.get("http_transport_override_calls", 0) == 0
    _assert_zero_secrets(r)


def test_r3c_wire_http_approve(wire_results):
    r = wire_results["http_approve"]
    _assert_approve_common(r, adapter="http")
    assert r["provider_raw_request_count"] >= 2


def test_r3c_wire_provider_raw_request_count_present(wire_results):
    for name in ("http_approve", "env_approve", "stdin_approve"):
        assert wire_results[name]["provider_raw_request_count"] >= 2


def test_r3c_wire_env_approve(wire_results):
    _assert_approve_common(wire_results["env_approve"], adapter="env")


def test_r3c_wire_stdin_approve(wire_results):
    _assert_approve_common(wire_results["stdin_approve"], adapter="stdin")


def test_r3c_wire_http_deny(wire_results):
    _assert_deny_closed(wire_results["http_deny"])


def test_r3c_wire_env_deny(wire_results):
    _assert_deny_closed(wire_results["env_deny"])


def test_r3c_wire_stdin_deny(wire_results):
    _assert_deny_closed(wire_results["stdin_deny"])


def test_r3c_wire_http_timeout_distinct_from_deny(wire_results):
    _assert_timeout_distinct(
        wire_results["http_timeout"], wire_results["http_deny"]
    )


def test_r3c_wire_env_timeout_distinct_from_deny(wire_results):
    _assert_timeout_distinct(
        wire_results["env_timeout"], wire_results["env_deny"]
    )


def test_r3c_wire_stdin_timeout_distinct_from_deny(wire_results):
    _assert_timeout_distinct(
        wire_results["stdin_timeout"], wire_results["stdin_deny"]
    )


def test_r3c_wire_http_replay_closed(wire_results, wire_module):
    """RETIRED to R3 historical scope — R5 A2 decision (HTTP adapter).

    Why retired: ``_assert_replay`` used to require
    ``manifest_registry_tools_match``, i.e. the installed manifest's tool list
    had to equal the LIVE registry's. R5 Slice C reduced the live registration
    set to two tools, while the carrier ``scripts/run_r3c_wire_e2e.py`` is
    AST-frozen (digest pinned in
    ``tests/test_r3c_evidence_authenticity_gate.py``) and still pins the R3
    four-tuple. The carrier may not be edited, so that one comparison now
    contradicts R5 reality and is dropped; the R3 historical tuple is asserted
    instead. Every behavioural replay assertion still runs against the live
    wire.

    Live equivalent of the dropped comparison (and the full 3×5 replay matrix)
    now lives on the 0.4.0 installed-ZIP path:
    ``tests/r6_installed_zip_wire_matrix.py`` (opt-in via
    ``scripts/run_r6_installed_zip_tests.py``), closed out by
    ``tests/test_r5_wire_e2e.py::test_r5_wire_full_main_chain_matrix_closed``.
    This test remains RETIRED historical evidence and must not be flipped live.
    """
    _assert_replay(wire_results["http_replay"], adapter="http")
    _assert_r3_historical_toolset(wire_module)


def test_r3c_wire_env_replay_closed(wire_results, wire_module):
    """RETIRED to R3 historical scope — R5 A2 decision (process env adapter).

    Same reason as :func:`test_r3c_wire_http_replay_closed`. Live equivalent
    coverage: ``tests/r6_installed_zip_wire_matrix.py`` (0.4.0 installed ZIP),
    closed by
    ``tests/test_r5_wire_e2e.py::test_r5_wire_full_main_chain_matrix_closed``.
    Remains RETIRED; do not flip live.
    """
    _assert_replay(wire_results["env_replay"], adapter="env")
    _assert_r3_historical_toolset(wire_module)


def test_r3c_wire_stdin_replay_closed(wire_results, wire_module):
    """RETIRED to R3 historical scope — R5 A2 decision (process stdin adapter).

    Same reason as :func:`test_r3c_wire_http_replay_closed`. Live equivalent
    coverage: ``tests/r6_installed_zip_wire_matrix.py`` (0.4.0 installed ZIP),
    closed by
    ``tests/test_r5_wire_e2e.py::test_r5_wire_full_main_chain_matrix_closed``.
    Remains RETIRED; do not flip live.
    """
    _assert_replay(wire_results["stdin_replay"], adapter="stdin")
    _assert_r3_historical_toolset(wire_module)


def test_r3c_wire_http_mutate_closed(wire_results):
    _assert_mutate_closed(wire_results["http_mutate"])


def test_r3c_wire_env_mutate_closed(wire_results):
    _assert_mutate_closed(wire_results["env_mutate"])


def test_r3c_wire_stdin_mutate_closed(wire_results):
    _assert_mutate_closed(wire_results["stdin_mutate"])


def test_r3c_wire_ordinary_public_agent_non_interference(wire_results):
    r = wire_results["ordinary_tool"]
    assert r["ordinary_evidence_layer"] == "public_AIAgent"
    assert r["injection_resolve_delta"] == 0
    assert r["http_adapter_delta"] == 0
    assert r["process_start_delta"] == 0
    assert r["counts"].get("resolve", 0) == 0
    assert r["counts"].get("adapter", 0) == 0
    assert r["counts"].get("approval_gate", 0) == 0
    _assert_zero_secrets(r)


def test_r3c_wire_trace_and_parent_env_metrics_present(wire_results):
    for name in ("http_approve", "env_approve", "stdin_approve"):
        r = wire_results[name]
        assert "trace_artifact_count" in r
        assert "trace_kinds" in r
        assert "trace_dirs_scanned" in r
        assert "trace_inventory" in r
        assert isinstance(r["trace_inventory"], list)
        assert r["trace_secret_count"] == 0
        assert r["manifest_bytes_identical"] is True
    ea = wire_results["env_approve"]
    assert ea["parent_env_secret_count"] == 0
    assert ea["cg_probe_in_parent"] is False
    assert ea["followup_child_status"] == "absent"


def test_r3c_wire_trace_sidecars_full_scan_includes_db_wal_shm():
    """Synthetic state.db / .db-wal / .db-shm + session JSONL must all enter scan."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3c_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    decoys = (mod.DECOY_HTTP, mod.DECOY_ENV, mod.DECOY_STDIN)
    work = Path(tempfile.mkdtemp(prefix="r3c-trace-scan-"))
    try:
        hermes = work / "hermes"
        home = work / "home"
        (hermes / "sessions").mkdir(parents=True)
        (home / "tmp").mkdir(parents=True)
        (hermes / "state.db").write_bytes(b"sqlite-header-synthetic")
        (hermes / "state.db-wal").write_bytes(b"wal-synthetic")
        (hermes / "state.db-shm").write_bytes(b"shm-synthetic")
        (hermes / "sessions" / "turn.jsonl").write_text(
            '{"role":"tool","content":"ok"}\n', encoding="utf-8"
        )
        # Secret store must be excluded exactly, not scanned as carrier body claim.
        store = hermes / "credential-guard"
        store.mkdir(parents=True)
        (store / "credential-guard.json").write_text(
            '{"v":"%s"}' % decoys[0], encoding="utf-8"
        )
        clean = mod.enumerate_runtime_carriers(
            [hermes, home], decoys=decoys
        )
        paths = {row["path"] for row in clean["trace_inventory"]}
        assert "state.db" in paths
        assert "state.db-wal" in paths
        assert "state.db-shm" in paths
        assert any(p.endswith("turn.jsonl") for p in paths)
        assert "credential-guard/credential-guard.json" not in paths
        assert clean["trace_secret_count"] == 0
        # Implant canary into a scanned sidecar → predicate RED (secret_count > 0).
        (hermes / "state.db-wal").write_bytes(decoys[1].encode("utf-8"))
        polluted = mod.enumerate_runtime_carriers([hermes, home], decoys=decoys)
        assert polluted["trace_secret_count"] > 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_r3c_wire_parent_env_full_scan_canary_mutation_red():
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3c_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    decoy = mod.DECOY_HTTP
    key = "CG_R3C_MUTATION_ARBITRARY_PARENT_KEY"
    assert mod.parent_env_secret_count((decoy,)) == 0 or key not in os.environ
    before = mod.parent_env_secret_count((decoy,))
    os.environ[key] = "prefix-" + decoy + "-suffix"
    try:
        after = mod.parent_env_secret_count((decoy,))
        assert after > before
        assert after >= 1
    finally:
        os.environ.pop(key, None)


def test_r3c_wire_manifest_byte_identical_and_tools_match_registry(wire_module):
    """RETIRED to R3 historical scope — R5 A2 decision.

    Why retired: this test compared ``formal_manifest_tool_names()`` (which
    reads the LIVE ``plugin.yaml``) against the carrier's
    ``_FORMAL_PROVIDED_TOOLS``. Slice C left two live tools while the AST-frozen
    carrier (``scripts/run_r3c_wire_e2e.py``, digest pinned in
    ``tests/test_r3c_evidence_authenticity_gate.py``) still pins the R3
    four-tuple, and the carrier may not be edited. The tool-set comparison and
    the tool-name content assertions on the live manifest are therefore
    dropped. What remains is historical/mechanical and still load-bearing: the
    carrier's frozen four-tuple, and that ``_install_plugin`` copies
    ``plugin.yaml`` byte-identically.

    Live equivalent of the dropped manifest↔registry comparison now runs on
    the 0.4.0 installed-ZIP path:
    ``tests/r6_installed_zip_wire_matrix.py::test_manifest_registry_equal_on_installed_zip``
    (opt-in). This test remains RETIRED historical evidence and must not be
    flipped live.
    """
    mod = wire_module
    _assert_r3_historical_toolset(mod)
    work = Path(tempfile.mkdtemp(prefix="r3c-manifest-"))
    try:
        hermes = work / "hermes"
        hermes.mkdir()
        mod._install_plugin(hermes)
        src = (REPO / "plugin.yaml").read_bytes()
        dst = (hermes / "plugins" / "credential-guard" / "plugin.yaml").read_bytes()
        assert src == dst
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_r3c_wire_mutation_temp_manifest_patch_is_red():
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    assert validate_r3c_evidence_source(src, "wire_script") == []
    mutated = src.replace(
        "shutil.copy2(REPO / \"plugin.yaml\", root / \"plugin.yaml\")",
        "shutil.copy2(REPO / \"plugin.yaml\", root / \"plugin.yaml\")\n"
        "    man = (root / \"plugin.yaml\").read_text(encoding=\"utf-8\")\n"
        "    if \"credential_process_run\" not in man:\n"
        "        (root / \"plugin.yaml\").write_text("
        "man.rstrip() + \"\\n  - credential_process_run\\n\", encoding=\"utf-8\")\n",
    )
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("temp_manifest_patch" in x or "manifest" in x for x in v)


def test_r3c_wire_mutation_two_conversation_replay_is_red():
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    mutated = src + "\nresult2 = agent.run_conversation('again')\n"
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("two_conversation_replay" in x for x in v)


def test_r3c_wire_mutation_setdefault_timeout_is_red():
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    mutated = src + '\ndecision.setdefault("outcome", "timeout")\n'
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("setdefault_timeout_outcome" in x for x in v)


def test_r3c_wire_mutation_delete_identity_record_is_red():
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    for token in (
        "tool_request_identities",
        "replay_identity_same",
        "host_approval_raw",
        "trace_inventory",
        "manifest_bytes_identical",
    ):
        mutated = src.replace(token, "TOKEN_ABSENT")
        assert token not in mutated
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"deleting {token} must violate"


def test_r3c_wire_script_cli_entrypoint(wire_module):
    """RETIRED to R3 historical scope — R5 A2 decision.

    Why retired: this test executed the carrier as a CLI subprocess against the
    LIVE workspace and required exit code 0. ``run_all()`` internally requires
    the installed manifest to agree with the carrier's frozen
    ``_FORMAL_PROVIDED_TOOLS`` four-tuple; Slice C left two live tools, so the
    subprocess now exits 1. The carrier ``scripts/run_r3c_wire_e2e.py`` is
    AST-frozen (digest pinned in
    ``tests/test_r3c_evidence_authenticity_gate.py``) and may not be edited to
    accommodate R5, so the live subprocess run is dropped. What remains asserts
    R3 historical source facts: the frozen four-tuple, a real ``__main__`` CLI
    entry point, and the R3 evidence tokens the carrier must still emit.

    Live equivalent wire execution against the 0.4.0 installed ZIP is
    ``tests/r6_installed_zip_wire_matrix.py`` (opt-in via
    ``scripts/run_r6_installed_zip_tests.py``), closed by
    ``tests/test_r5_wire_e2e.py::test_r5_wire_full_main_chain_matrix_closed``.
    This CLI subprocess remains RETIRED; do not flip live.
    """
    _assert_r3_historical_toolset(wire_module)
    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in src
    assert "def main(" in src
    assert "wire_secret_count" in src
    assert "http_credential_request" in src
    assert "credential_process_run" in src
    assert "http_replay" in src
    assert "trace_artifact_count" in src
    assert "approval_timeout_branch" in src


def test_r3c_wire_mutation_drop_adapter_evidence_is_red():
    """Source mutation: delete one adapter scenario → authenticity predicate RED."""
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    assert validate_r3c_evidence_source(src, "wire_script") == []
    for scenario in ("http_approve", "env_approve", "stdin_approve"):
        mutated = src.replace(scenario, "TOKEN_ABSENT")
        assert scenario not in mutated
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"deleting {scenario} must violate authenticity predicate"


def test_r3c_wire_mutation_remove_raw_or_approval_is_red():
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    for token in ("raw_requests", "approval_raw", "sys.setprofile"):
        mutated = src.replace(token, "TOKEN_ABSENT")
        assert token not in mutated
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"removing {token} must violate authenticity predicate"


def test_r3c_wire_mutation_parent_env_pollution_is_red():
    from tests.test_r3c_evidence_authenticity_gate import validate_r3c_evidence_source

    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    # Construct forbidden patterns without embedding them as live source tokens.
    polluted = (
        src
        + "\nos.environ['CG_PROBE_ENV'] = 'pollute'\n"
        + "env = os.environ"
        + ".copy()\n"
    )
    v = validate_r3c_evidence_source(polluted, "wire_script")
    assert v
    assert any("environ" in x or "copy" in x for x in v)


def test_r3c_wire_raw_http_mechanical_shape_required():
    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    assert "raw_http_has_request_line" in src
    assert "raw_http_has_headers" in src
    assert "raw_http_has_body" in src
    assert 'b"POST "' in src or "startswith(b\"POST \")" in src
    assert "_bomb_connect" in src
    assert "_guard_connect" in src
    assert "raw_requests.append(body)" not in src
    assert "http_target_evidence_layer" in src
    assert "production_default_transport_loopback_tls" in src
    assert "R3A_signed_transport_override_in_R3C_wire" not in src
    assert "set_http_transport_override_for_tests(" not in src
    assert "_fake_http_target" not in src
    assert "_default_transport" in src
    assert "create_default_context" in src
    assert "load_verify_locations" in src
    assert "subjectAltName=DNS:svc.example.test,IP:127.0.0.1" in src
    # Round4 load-bearing: explicit first-identity Names reused by second replay payload.
    assert "first_tool_call_id = tc_id" in src
    assert "first_serialized_args = args" in src
    assert 'approval_mod._await_gateway_decision, "_await_gateway_decision"' in src
    assert "await_gateway_call_count > 0" in src
    assert "host_timeout_text" in src


def test_r3c_wire_mutation_guard_disabled_hits_bomb_runtime():
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3c_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    work = Path(tempfile.mkdtemp(prefix="r3c-wire-mut-guard-"))
    try:
        healthy = mod.run_net_probe(work, guard_enabled=True)
        assert healthy["non_loopback_original_calls"] == 0
        assert healthy["net_violations"] >= 1
        assert healthy["loopback_only"] is True
        mutated = mod.run_net_probe(work, guard_enabled=False)
        assert mutated["guard_enabled"] is False
        assert mutated["non_loopback_original_calls"] > 0
        assert mutated["loopback_only"] is False
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_r3c_wire_mutation_remove_net_guard_is_red():
    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    mutated = src
    for old, new in (
        ("socket.socket.connect = _guard_connect", "pass  # mutated-drop-guard-connect"),
        ("socket.socket.connect_ex = _guard_connect_ex", "pass  # mutated-drop-guard-connect_ex"),
        (
            "socket.create_connection = _guard_create_connection",
            "pass  # mutated-drop-guard-create",
        ),
    ):
        mutated = mutated.replace(old, new)
    install_hits = len(
        re.findall(
            r"socket\.(?:socket\.connect|create_connection)\s*=\s*_guard_", mutated
        )
    )
    assert install_hits < 2
    assert "_bomb_connect" in src
