from __future__ import annotations

import base64
import importlib.util
from pathlib import Path
from urllib.parse import quote, quote_plus

from credential_guard.middleware import SAFE_BLOCK_MESSAGE
from tests.hermes_e2e_helpers import DECOY_SECRET, opaque_token


def _load_canary_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_canary_e2e.py"
    spec = importlib.util.spec_from_file_location("run_canary_e2e", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DECOY_USERNAME = "cg_readonly"
DECOY_BASIC_COMBO = f"{DECOY_USERNAME}:{DECOY_SECRET}"
DECOY_BASIC_TOKEN = opaque_token("db", "basic_auth")


def _wire_forms() -> dict:
    raw = DECOY_SECRET.encode("utf-8")
    combo_raw = DECOY_BASIC_COMBO.encode("utf-8")
    return {
        "plain": DECOY_SECRET,
        "percent": quote(DECOY_SECRET, safe=""),
        "quote_plus": quote_plus(DECOY_SECRET),
        "base64": base64.b64encode(raw).decode("ascii"),
        "urlsafe_base64": base64.urlsafe_b64encode(raw).decode("ascii"),
        "basic_auth": base64.b64encode(combo_raw).decode("ascii"),
        "basic_auth_plain": DECOY_BASIC_COMBO,
    }


def _passing_summary(**overrides):
    base = {
        "check_exit": 0,
        "chat_exit": 0,
        "captured_chat_requests": 1,
        "plain_secret_count": 0,
        "wire_percent_count": 0,
        "wire_quote_plus_count": 0,
        "wire_base64_count": 0,
        "wire_urlsafe_base64_count": 0,
        "wire_basic_auth_count": 0,
        "stable_ref_count": 1,
        "tools_in_request": False,
        "fail_closed_llm_execution_exit": 0,
        "fail_closed_llm_execution_extra_chat_requests": 0,
        "fail_closed_llm_execution_stdout_has_block_msg": True,
        "fail_closed_llm_execution_has_decoy": False,
        "fail_closed_llm_request_exit": 0,
        "fail_closed_llm_request_extra_chat_requests": 0,
        "fail_closed_llm_request_stdout_has_block_msg": True,
        "fail_closed_llm_request_plain_secret_count": 0,
        "fail_closed_llm_request_has_decoy": False,
        # Accepted residual — must NOT drive gate.
        "accepted_local_residual": {"agent_log": 1, "state_db": 1},
        "run_id": "diagnostic-only",
        "python_note": "diagnostic",
    }
    base.update(overrides)
    return base


def test_evaluate_canary_gates_passes_when_complete():
    mod = _load_canary_module()
    assert mod.evaluate_canary_gates(_passing_summary()) == 0
    assert SAFE_BLOCK_MESSAGE  # fixed message still defined


def test_evaluate_canary_gates_fails_without_block_message():
    mod = _load_canary_module()
    code = mod.evaluate_canary_gates(
        _passing_summary(fail_closed_llm_execution_stdout_has_block_msg=False)
    )
    assert code == 3


def test_evaluate_canary_gates_fails_when_exec_stdout_has_decoy():
    mod = _load_canary_module()
    code = mod.evaluate_canary_gates(
        _passing_summary(fail_closed_llm_execution_has_decoy=True)
    )
    assert code == 3


def test_evaluate_canary_gates_fails_when_req_stdout_has_decoy():
    mod = _load_canary_module()
    code = mod.evaluate_canary_gates(
        _passing_summary(fail_closed_llm_request_has_decoy=True)
    )
    assert code == 8


def test_evaluate_canary_gates_mutates_every_security_field():
    mod = _load_canary_module()
    assert mod.evaluate_canary_gates(_passing_summary()) == 0
    mutations = {
        "check_exit": 1,
        "chat_exit": 1,
        "captured_chat_requests": 0,
        "plain_secret_count": 1,
        "wire_percent_count": 1,
        "wire_quote_plus_count": 1,
        "wire_base64_count": 1,
        "wire_urlsafe_base64_count": 1,
        "wire_basic_auth_count": 1,
        "stable_ref_count": 0,
        "tools_in_request": True,
        "fail_closed_llm_execution_exit": 1,
        "fail_closed_llm_execution_extra_chat_requests": 1,
        "fail_closed_llm_execution_stdout_has_block_msg": False,
        "fail_closed_llm_execution_has_decoy": True,
        "fail_closed_llm_request_exit": 1,
        "fail_closed_llm_request_extra_chat_requests": 1,
        "fail_closed_llm_request_stdout_has_block_msg": False,
        "fail_closed_llm_request_plain_secret_count": 1,
        "fail_closed_llm_request_has_decoy": True,
    }
    for key, bad_val in mutations.items():
        code = mod.evaluate_canary_gates(_passing_summary(**{key: bad_val}))
        assert code != 0, key


def test_evaluate_canary_gates_ignores_diagnostic_and_accepted_residual():
    """Diagnostic / accepted residual fields must not flip the gate alone."""
    mod = _load_canary_module()
    assert (
        mod.evaluate_canary_gates(
            _passing_summary(
                accepted_local_residual={"agent_log": 99, "wal": 99},
                run_id="anything",
                python_note="noise",
                isolation={"all_temp": False},
                net_attempts=[{"host": "diag"}],
                worker_delta={"status": "unchanged", "worker_live": True},
            )
        )
        == 0
    )


def test_canary_wire_forms_cover_required_encodings():
    forms = _wire_forms()
    assert forms["plain"] == DECOY_SECRET
    assert forms["base64"] != forms["plain"]
    assert forms["basic_auth"] != forms["base64"]
    assert DECOY_BASIC_TOKEN.startswith("<SECRET:")
