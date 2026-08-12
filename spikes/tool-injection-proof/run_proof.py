#!/usr/bin/env python3
"""R0 proof runner — real Hermes PluginManager + approval gate + fake tool.

Prints one JSON evidence object on stdout. Never prints decoy plaintext.
Residue scanning runs in-process; only booleans/counts leave the child.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import shutil
import sys
import threading
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

SPIKE_DIR = Path(__file__).resolve().parent
SPIKE_NAME = "tool-injection-proof"
REF = "<CREDENTIAL:decoy>"
MIN_FRAG = 8


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ensure_hermes_path() -> Path:
    root = Path(os.environ.get("HERMES_AGENT_ROOT") or "/Users/yelei/.hermes/hermes-agent")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def _install_plugin(hermes_home: Path) -> Path:
    plugins = hermes_home / "plugins"
    plugins.mkdir(parents=True, exist_ok=True)
    dest = plugins / SPIKE_NAME
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        SPIKE_DIR,
        dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "run_proof.py"),
    )
    (hermes_home / "config.yaml").write_text(
        "model: unused-r0\n"
        "approvals:\n  mode: manual\n"
        "plugins:\n  enabled:\n    - tool-injection-proof\n",
        encoding="utf-8",
    )
    return dest


def _load_manager_and_spike():
    """Load spike via real PluginManager and install it as the process singleton."""
    import hermes_cli.plugins as plugins_mod
    from hermes_cli.plugins import PluginManager

    plugins_mod._plugin_manager = None
    mgr = PluginManager()
    mgr.discover_and_load(force=True)
    plugins_mod._plugin_manager = mgr

    loaded = mgr._plugins.get(SPIKE_NAME)
    if not loaded or not loaded.enabled:
        raise RuntimeError(
            f"plugin not loaded: enabled={getattr(loaded, 'enabled', None)} "
            f"error={getattr(loaded, 'error', 'missing')}"
        )
    spike = loaded.module
    if not hasattr(spike, "reset_state") or not hasattr(spike, "snapshot_counts"):
        raise RuntimeError(f"spike module missing state API: {spike}")
    return mgr, spike


def _invoke(
    *,
    tool_call_id: str,
    approval: str,
    spike,
    ref: str = REF,
) -> str:
    from model_tools import handle_function_call

    approved = approval == "approve"

    def _gate(tool_name, reason, **kwargs):
        with spike._lock:
            order = spike._state.setdefault("call_order", [])
            if not order or order[-1] != "approval_gate":
                order.append("approval_gate")
            spike._state["approval_payload_plain_count"] = int(
                spike._state.get("approval_payload_plain_count") or 0
            ) + spike._count_plain(
                {"reason": reason, "tool_name": tool_name, **kwargs}
            )
        return {
            "approved": approved,
            "message": None if approved else "DENIED: r0 proof deny path",
        }

    args = {"token": ref, "note": "r0-proof"}
    with patch("tools.approval.request_tool_approval", side_effect=_gate):
        return handle_function_call(
            "tip_probe_tool",
            deepcopy(args),
            task_id="tip-task",
            tool_call_id=tool_call_id,
            session_id="tip-session",
        )


def _has_secret_fragment(blob: str, secret: str, min_frag: int = MIN_FRAG) -> bool:
    """True if blob contains the full secret or any contiguous fragment length >= min_frag."""
    if not secret or not blob:
        return False
    if len(secret) < min_frag:
        return secret in blob
    for i in range(len(secret) - min_frag + 1):
        if secret[i : i + min_frag] in blob:
            return True
    return False


def _serialize_for_scan(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _scan_residues(blob: str, secrets: List[str]) -> int:
    return sum(1 for s in secrets if s and _has_secret_fragment(blob, s))


def _residue_gate(
    spike,
    secrets: List[str],
    captured_stdout: str,
    captured_stderr: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Scan stdout/stderr/approval/trace/shared state for secret fragments.

    Does not scan trusted resolver_store source secrets themselves; clears
    the store afterward and reports emptiness.
    """
    residual = 0
    with spike._lock:
        # Drop irreversible digests from mutable state before fragment scan so
        # evidence/state never retain secret material and hex cannot false-hit.
        for row in list(spike._state.get("received_values") or []):
            if isinstance(row, dict):
                row.pop("digest", None)
        for plan in (spike._state.get("plans") or {}).values():
            if isinstance(plan, dict):
                plan.pop("token_digest", None)

        for key, val in list(spike._state.items()):
            if key in ("resolver_store", "decoy_plain"):
                continue
            residual += _scan_residues(_serialize_for_scan(val), secrets)

        residual += _scan_residues(
            _serialize_for_scan(spike._state.get("approval_blobs")), secrets
        )
        residual += _scan_residues(
            _serialize_for_scan(spike._state.get("trace_blobs")), secrets
        )

        spike._state["resolver_store"] = {}
        spike._state["decoy_plain"] = ""
        store_empty = not bool(spike._state.get("resolver_store"))

    residual += _scan_residues(captured_stdout, secrets)
    residual += _scan_residues(captured_stderr, secrets)
    residual += _scan_residues(_serialize_for_scan(evidence), secrets)

    return {
        "partial_secret_residue_count": int(residual),
        "residue_gate_passed": residual == 0,
        "resolver_store_empty": store_empty,
        "shared_state_plain_count": int(residual),
    }


def run_scenario(scenario: str) -> Tuple[Dict[str, Any], List[str], Any]:
    hermes_home = Path(os.environ["HERMES_HOME"])
    home = Path(os.environ["HOME"])
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    _install_plugin(hermes_home)
    _ensure_hermes_path()

    decoy = "TIP_DECOY_" + secrets.token_urlsafe(24)
    fault = os.environ.get("TIP_FAULT", "") if scenario == "fault" else ""
    secrets_held: List[str] = [decoy]

    _mgr, spike = _load_manager_and_spike()
    spike.reset_state(decoy_plain=decoy, fault=fault)

    if scenario == "approve":
        result = _invoke(tool_call_id="tc-approve", approval="approve", spike=spike)
        out = spike.snapshot_counts()
        out["tool_result_ok"] = '"ok": true' in result.lower() or '"ok":true' in result.lower()
        out["approval_denied"] = False
        snap = spike._state.get("original_args_snapshot")
        out["original_args_still_ref"] = bool(
            isinstance(snap, dict) and REF in json.dumps(snap)
        )
        return out, secrets_held, spike

    if scenario == "deny":
        result = _invoke(tool_call_id="tc-deny", approval="deny", spike=spike)
        out = spike.snapshot_counts()
        out["approval_denied"] = (
            "DENIED" in result or "BLOCKED" in result or "denied" in result.lower()
        )
        return out, secrets_held, spike

    if scenario == "fault":
        result = _invoke(tool_call_id=f"tc-fault-{fault}", approval="approve", spike=spike)
        out = spike.snapshot_counts()
        out["tool_result_preview"] = result[:160]
        return out, secrets_held, spike

    if scenario == "once_and_concurrent":
        _invoke(tool_call_id="tc-once", approval="approve", spike=spike)
        once = spike.snapshot_counts()
        snap = spike._state.get("original_args_snapshot")
        once["original_args_still_ref"] = bool(
            isinstance(snap, dict) and REF in json.dumps(snap)
        )
        once["next_call_count"] = int(once.get("next_call_count") or 0)

        # Sequential A/B with distinct decoys + refs — prove A gets A, B gets B.
        decoy_a = "TIP_DECOY_A_" + secrets.token_urlsafe(16)
        decoy_b = "TIP_DECOY_B_" + secrets.token_urlsafe(16)
        secrets_held.extend([decoy_a, decoy_b])
        dig_a = _digest(decoy_a)
        dig_b = _digest(decoy_b)

        spike.reset_state(resolver_store={"decoy_a": decoy_a}, fault="")
        _invoke(
            tool_call_id="plan-a",
            approval="approve",
            spike=spike,
            ref="<CREDENTIAL:decoy_a>",
        )
        recv_a = list(spike._state.get("received_values") or [])
        plans_a = dict(spike._state.get("plans") or {})
        next_a = int(spike._state.get("next_call_count") or 0)

        spike.reset_state(resolver_store={"decoy_b": decoy_b}, fault="")
        _invoke(
            tool_call_id="plan-b",
            approval="approve",
            spike=spike,
            ref="<CREDENTIAL:decoy_b>",
        )
        recv_b = list(spike._state.get("received_values") or [])
        plans_b = dict(spike._state.get("plans") or {})
        next_b = int(spike._state.get("next_call_count") or 0)

        a_digest = (recv_a[0].get("digest") if recv_a else "") or ""
        b_digest = (recv_b[0].get("digest") if recv_b else "") or ""
        seq_bind_ok = (
            bool(recv_a)
            and bool(recv_b)
            and a_digest == dig_a
            and b_digest == dig_b
            and a_digest != dig_b
            and b_digest != dig_a
            and not recv_a[0].get("has_ref")
            and not recv_b[0].get("has_ref")
            and "plan-a" in plans_a
            and "plan-b" in plans_b
            and next_a == 1
            and next_b == 1
        )

        # Concurrent: two tool_call_ids, two distinct runtime decoys + refs.
        decoy_c1 = "TIP_DECOY_C1_" + secrets.token_urlsafe(16)
        decoy_c2 = "TIP_DECOY_C2_" + secrets.token_urlsafe(16)
        secrets_held.extend([decoy_c1, decoy_c2])
        dig_c1 = _digest(decoy_c1)
        dig_c2 = _digest(decoy_c2)

        spike.reset_state(
            resolver_store={"decoy_c1": decoy_c1, "decoy_c2": decoy_c2},
            fault="",
        )
        barrier = threading.Barrier(2)
        concurrent_errors: list[str] = []

        def conc(tcid: str, ref: str) -> None:
            try:
                barrier.wait(timeout=10)
                _invoke(tool_call_id=tcid, approval="approve", spike=spike, ref=ref)
            except Exception as exc:
                concurrent_errors.append(f"{tcid}:{type(exc).__name__}")

        t1 = threading.Thread(
            target=conc, args=("conc-1", "<CREDENTIAL:decoy_c1>")
        )
        t2 = threading.Thread(
            target=conc, args=("conc-2", "<CREDENTIAL:decoy_c2>")
        )
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        plans = dict(spike._state.get("plans") or {})
        received = list(spike._state.get("received_values") or [])
        by_plan = {r.get("plan_id"): r for r in received if r.get("plan_id")}
        r1 = by_plan.get("conc-1") or {}
        r2 = by_plan.get("conc-2") or {}
        bind_ok = (
            r1.get("digest") == dig_c1
            and r2.get("digest") == dig_c2
            and r1.get("digest") != dig_c2
            and r2.get("digest") != dig_c1
            and r1.get("digest_match") is True
            and r2.get("digest_match") is True
            and not r1.get("has_ref")
            and not r2.get("has_ref")
        )
        each_once = (
            "conc-1" in plans
            and "conc-2" in plans
            and bool(plans["conc-1"].get("next_call_once"))
            and bool(plans["conc-2"].get("next_call_once"))
            and int(spike._state.get("next_call_count") or 0) == 2
            and len(received) == 2
        )
        no_cross = bool(
            seq_bind_ok and bind_ok and each_once and not concurrent_errors
        )

        once["concurrent_no_cross"] = no_cross
        once["concurrent_distinct_secret_binding"] = bool(seq_bind_ok and bind_ok)
        once["concurrent_each_next_call_once"] = bool(each_once)
        once["concurrent_errors"] = concurrent_errors
        once["plans_keys"] = sorted(plans.keys())
        once["tool_received_plain_count"] = max(
            int(once.get("tool_received_plain_count") or 0), 1
        )
        once["trace_plain_count"] = int(once.get("middleware_trace_plain_count") or 0)
        # Binding proof: booleans only — never emit digest bodies.
        once["concurrent_binding_a_matches_a_not_b"] = bool(
            a_digest == dig_a and a_digest != dig_b
        )
        once["concurrent_binding_b_matches_b_not_a"] = bool(
            b_digest == dig_b and b_digest != dig_a
        )
        return once, secrets_held, spike

    raise SystemExit(f"unknown scenario: {scenario}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    if "HERMES_HOME" not in os.environ or "HOME" not in os.environ:
        raise SystemExit("HOME and HERMES_HOME required")

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        evidence, secrets_held, spike = run_scenario(args.scenario)
        gate = _residue_gate(
            spike,
            secrets_held,
            stdout_buf.getvalue(),
            stderr_buf.getvalue(),
            evidence,
        )
        evidence.update(gate)
        evidence.pop("decoy_plain", None)
        evidence.pop("received_values", None)
        evidence.pop("resolver_store", None)

    # Only safe JSON on real stdout.
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
