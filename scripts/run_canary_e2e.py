#!/usr/bin/env python3
"""Runnable real Hermes CLI E2E against a local fake OpenAI-compatible provider.

Uses the host hermes Python 3.11 runtime with a process-level loopback net guard.
Does not inherit provider keys. Never touches the worker profile.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, quote_plus

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from credential_guard.middleware import SAFE_BLOCK_MESSAGE
from tests.fake_provider import FakeProvider
from tests.hermes_e2e_helpers import (
    DECOY_SECRET,
    DECOY_TOKEN,
    WORKER_PROFILE,
    assert_all_loopback,
    assert_loopback_guards_present,
    assert_worker_evidence,
    classify_worker_delta,
    content_fingerprint,
    count_decoy_in_paths,
    detect_worker_live,
    opaque_token,
    prepare_isolated_hermes,
    read_net_audit,
    request_has_tools,
    run_hermes,
    temp_isolation_evidence,
)

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


def evaluate_canary_gates(summary: dict) -> int:
    """Pure acceptance function for canary summary. Returns 0 on pass, else gate code.

    Exit 0 additionally requires:
      - llm_execution stdout contains the fixed block message;
      - llm_execution stdout/stderr contain no decoy plaintext;
      - llm_request fallback stdout/stderr contain no decoy plaintext;
      - provider wire counts for plain + common encodings are all 0;
    Accepted local residual counts (agent.log / WAL) do not drive this gate.
    """
    if summary.get("check_exit") != 0:
        return 1
    if summary.get("chat_exit") != 0:
        return 6
    bodies = summary.get("captured_chat_requests", 0)
    plain = summary.get("plain_secret_count", -1)
    refs = summary.get("stable_ref_count", 0)
    tools = summary.get("tools_in_request", True)
    wire_keys = (
        "wire_percent_count",
        "wire_quote_plus_count",
        "wire_base64_count",
        "wire_urlsafe_base64_count",
        "wire_basic_auth_count",
    )
    if not bodies or plain != 0 or refs < 1 or tools:
        return 2
    for key in wire_keys:
        if summary.get(key, -1) != 0:
            return 2
    if (
        summary.get("fail_closed_llm_execution_extra_chat_requests") != 0
        or summary.get("fail_closed_llm_execution_exit") != 0
    ):
        return 3
    if not summary.get("fail_closed_llm_execution_stdout_has_block_msg"):
        return 3
    if summary.get("fail_closed_llm_execution_has_decoy"):
        return 3
    if (
        summary.get("fail_closed_llm_request_exit") != 0
        or summary.get("fail_closed_llm_request_extra_chat_requests") != 0
        or not summary.get("fail_closed_llm_request_stdout_has_block_msg")
        or summary.get("fail_closed_llm_request_plain_secret_count", -1) != 0
    ):
        return 8
    if summary.get("fail_closed_llm_request_has_decoy"):
        return 8
    return 0


def main() -> int:
    before_fp = content_fingerprint(WORKER_PROFILE)
    worker_live = detect_worker_live(WORKER_PROFILE)
    forms = _wire_forms()
    provider = FakeProvider()
    provider.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cg-canary-e2e-") as tmp:
            iso = prepare_isolated_hermes(Path(tmp), provider.base_url)
            isolation = temp_isolation_evidence(iso)
            assert_loopback_guards_present()
            check = run_hermes(iso, ["credential-guard", "check"])
            prompt = (
                "Reply with ok only. "
                f"password is {forms['plain']}; "
                f"pct={forms['percent']}; "
                f"qp={forms['quote_plus']}; "
                f"b64={forms['base64']}; "
                f"url={forms['urlsafe_base64']}; "
                f"basic={forms['basic_auth']}; "
                f"combo={forms['basic_auth_plain']}"
            )
            chat = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    prompt,
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                timeout=180,
            )
            bodies_after_chat = list(provider.chat_completion_bodies)
            fail_exec = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    f"password is {DECOY_SECRET}",
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                extra_env={"CREDENTIAL_GUARD_TEST_INJECT_FAILURE": "file_backend"},
                timeout=180,
            )
            bodies_after_fail_exec = list(provider.chat_completion_bodies)
            fail_exec_extra = len(bodies_after_fail_exec) - len(bodies_after_chat)

            fail_req = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    f"password is {DECOY_SECRET}",
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                extra_env={"CREDENTIAL_GUARD_TEST_INJECT_FAILURE": "llm_request"},
                timeout=180,
            )
            bodies_after_fail_req = list(provider.chat_completion_bodies)
            fail_req_extra = len(bodies_after_fail_req) - len(bodies_after_fail_exec)
            # R7: llm_request fail-closed terminates locally — zero provider bodies.
            fail_req_joined = b"".join(bodies_after_fail_req[len(bodies_after_fail_exec) :])

            def _sum_count(needle: str) -> int:
                raw = needle.encode("utf-8")
                return sum(b.count(raw) for b in bodies_after_chat)

            plain = _sum_count(forms["plain"])
            # When percent/quote-plus equal plain, do not double-count plain as
            # a distinct encoding hit after redaction (both are 0).
            wire_percent = (
                _sum_count(forms["percent"])
                if forms["percent"] != forms["plain"]
                else 0
            )
            wire_qp = (
                _sum_count(forms["quote_plus"])
                if forms["quote_plus"] not in {forms["plain"], forms["percent"]}
                else 0
            )
            wire_b64 = _sum_count(forms["base64"])
            wire_url = (
                _sum_count(forms["urlsafe_base64"])
                if forms["urlsafe_base64"] != forms["base64"]
                else wire_b64
            )
            wire_basic = _sum_count(forms["basic_auth"]) + _sum_count(
                forms["basic_auth_plain"]
            )
            refs = _sum_count(DECOY_TOKEN) + _sum_count(DECOY_BASIC_TOKEN)
            tools_present = any(request_has_tools(b) for b in bodies_after_chat)
            split = count_decoy_in_paths(
                iso.hermes_home,
                DECOY_SECRET,
                [
                    "logs/agent.log",
                    "state.db",
                    "state.db-wal",
                    "state.db-shm",
                    "sessions",
                ],
            )
            audit = read_net_audit(iso)
            after_fp = content_fingerprint(WORKER_PROFILE)
            delta = classify_worker_delta(
                before_fp, after_fp, worker_live=worker_live
            )
            exec_has_block = SAFE_BLOCK_MESSAGE in fail_exec.stdout
            exec_has_decoy = (
                DECOY_SECRET in fail_exec.stdout or DECOY_SECRET in fail_exec.stderr
            )
            req_has_decoy = (
                DECOY_SECRET in fail_req.stdout or DECOY_SECRET in fail_req.stderr
            )
            req_has_block = SAFE_BLOCK_MESSAGE in fail_req.stdout
            summary = {
                "check_exit": check.returncode,
                "chat_exit": chat.returncode,
                "fail_closed_llm_execution_exit": fail_exec.returncode,
                "fail_closed_llm_execution_stdout_has_block_msg": exec_has_block,
                "fail_closed_llm_execution_has_decoy": exec_has_decoy,
                "fail_closed_llm_execution_extra_chat_requests": fail_exec_extra,
                "fail_closed_llm_request_exit": fail_req.returncode,
                "fail_closed_llm_request_extra_chat_requests": fail_req_extra,
                "fail_closed_llm_request_stdout_has_block_msg": req_has_block,
                "fail_closed_llm_request_plain_secret_count": fail_req_joined.count(
                    DECOY_SECRET.encode("utf-8")
                ),
                "fail_closed_llm_request_has_decoy": req_has_decoy,
                "captured_chat_requests": len(bodies_after_chat),
                "plain_secret_count": plain,
                "wire_percent_count": wire_percent,
                "wire_quote_plus_count": wire_qp,
                "wire_base64_count": wire_b64,
                "wire_urlsafe_base64_count": wire_url,
                "wire_basic_auth_count": wire_basic,
                "stable_ref_count": refs,
                "tools_in_request": tools_present,
                # AC8/AC9 accepted residual — diagnostic only, not a provider gate.
                "accepted_local_residual": split,
                "local_persisted_split": split,  # backward-compatible alias
                "net_attempts": audit.get("attempts"),
                "worker_delta": {
                    "status": delta["status"],
                    "stable": delta["stable"],
                    "unchanged": delta["unchanged"],
                    "config_plugins_sessions_unchanged": delta[
                        "config_plugins_sessions_unchanged"
                    ],
                    "natural_or_live_noise_count": len(delta["natural_or_live_noise"]),
                    "unexpected_changes": [
                        c["path"] for c in delta["unexpected_changes"]
                    ],
                    "worker_live": worker_live,
                },
                "isolation": isolation,
                "python_note": (
                    "hermes CLI uses its own Python 3.11; project .venv may be 3.9"
                ),
                "stable_token_example": DECOY_TOKEN,
                # backward-compatible aliases
                "fail_closed_exit": fail_exec.returncode,
                "fail_closed_stdout_has_block_msg": exec_has_block,
                "fail_closed_extra_chat_requests": fail_exec_extra,
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            print("check_stdout:", check.stdout.strip())
            print("fail_exec_stdout_tail:", fail_exec.stdout[-500:])
            print("fail_req_stdout_tail:", fail_req.stdout[-500:])
            try:
                assert_all_loopback(audit)
            except AssertionError as exc:
                print("net_guard_failed:", exc)
                return 5
            try:
                assert_worker_evidence(delta, isolation)
            except AssertionError as exc:
                print("worker_evidence_failed:", exc)
                return 4
            return evaluate_canary_gates(summary)
    finally:
        provider.stop()


if __name__ == "__main__":
    raise SystemExit(main())
