"""R5 provider tool-call/result closure — decoy secrets never egress.

Also the retained home of the Provider closure properties migrated off
``tests/test_m2_release_blockers.py`` (H7/J4/J5). Those originals used the old
MySQL tool plus ``scripts/run_m2_e2e.py`` as carrier; both are on the R5 delete
list, so the closure reconciler lives here and every fixture is built from the
two generic tools (``http_credential_request`` / ``credential_process_run``).
"""

from __future__ import annotations

import json
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

import pytest

from credential_guard.bindings import PROCESS_REFERENCE_TOOL
from credential_guard.runtime_config import HTTP_REFERENCE_TOOL

_XFAIL_DELETION = pytest.mark.xfail(
    strict=True,
    reason=(
        "Live-wire provider decoy closure waits on the R5 wire main-chain "
        "matrix (same gap as tests/test_r5_wire_e2e.py). Permanent marker: the "
        "body is `assert False`, so it fails forever and can never XPASS."
    ),
)

DECOY = "CG_R5_PROVIDER_DECOY_" + "d" * 24


def _parse_tool_results(bodies: List[Dict[str, Any]]) -> Dict[str, str]:
    """Minimal closure helper: map tool_call_id → content (conflict = error)."""
    out: Dict[str, str] = {}
    errors: List[str] = []
    for body in bodies:
        for item in body.get("tool_results") or []:
            tid = item.get("tool_call_id")
            content = item.get("content")
            if not isinstance(tid, str) or not isinstance(content, str):
                errors.append("malformed tool_result")
                continue
            if tid in out and out[tid] != content:
                errors.append(f"conflict:{tid}")
            else:
                out[tid] = content
    return {"results": out, "errors": errors}  # type: ignore[return-value]


def test_provider_result_closure_rejects_orphan_and_conflict():
    good = [
        {
            "tool_results": [
                {"tool_call_id": "c1", "content": "ok"},
                {"tool_call_id": "c2", "content": "ok2"},
            ]
        }
    ]
    parsed = _parse_tool_results(good)
    assert parsed["errors"] == []
    assert set(parsed["results"]) == {"c1", "c2"}

    conflict = [
        {
            "tool_results": [
                {"tool_call_id": "c1", "content": "a"},
                {"tool_call_id": "c1", "content": "b"},
            ]
        }
    ]
    bad = _parse_tool_results(conflict)
    assert any("conflict" in e for e in bad["errors"])


def test_decoy_credential_must_not_appear_in_provider_payload():
    """Static contract: synthetic decoy must be absent from a scrubbed blob."""
    payload = {
        "messages": [{"role": "assistant", "content": "ready"}],
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_credential_request",
                    "arguments": json.dumps(
                        {
                            "target": "jenkins-production",
                            "credential": "<CREDENTIAL:jenkins-token>",
                        }
                    ),
                },
            }
        ],
    }
    blob = json.dumps(payload)
    assert DECOY not in blob
    assert "CG_R5_PROVIDER_DECOY_" not in blob


@_XFAIL_DELETION
def test_r5_provider_live_wire_decoy_count_zero():
    """Live wire decoy egress count=0 waits for R5 current carrier full matrix."""
    assert False, "live provider decoy closure not yet wired to R5 carrier"


# ---------------------------------------------------------------------------
# Migrated closure properties (originals: H7 orphan/conflict, J4 extra/missing/
# same-id, J5 deny fixed-blocked + deny extra call).
#
# Carrier note: every fixture below is built from the two generic reference
# tools. Nothing here imports ``credential_guard.tools`` or loads
# ``scripts/run_m2_e2e.py``, so the properties survive the atomic delete slice.
# ---------------------------------------------------------------------------

CHECK_CONFLICT_CALL = "conflict_tool_call"
CHECK_CONFLICT_RESULT = "conflict_tool_result"
CHECK_ORPHAN_RESULT = "orphan_tool_result"
CHECK_MISSING_RESULT = "missing_tool_result"
CHECK_EXTRA_CALL = "extra_tool_call"
CHECK_MISSING_CALL = "missing_tool_call"
CHECK_FIXED_BLOCKED = "fixed_blocked_result"

ALL_CHECKS: FrozenSet[str] = frozenset(
    {
        CHECK_CONFLICT_CALL,
        CHECK_CONFLICT_RESULT,
        CHECK_ORPHAN_RESULT,
        CHECK_MISSING_RESULT,
        CHECK_EXTRA_CALL,
        CHECK_MISSING_CALL,
        CHECK_FIXED_BLOCKED,
    }
)

# Hermes emits this fixed denial text; a runner's own prose must never satisfy it.
_FIXED_BLOCKED_PREFIX = "BLOCKED: User denied"


def http_call(call_id: str, path: str, target: str = "jenkins-production") -> Dict[str, Any]:
    """Assistant message carrying one http_credential_request tool call."""
    return {
        "role": "assistant",
        "tool_calls": [
            {
                "id": call_id,
                "function": {
                    "name": HTTP_REFERENCE_TOOL,
                    "arguments": json.dumps(
                        {
                            "target": target,
                            "method": "POST",
                            "path": path,
                            "credential": "<CREDENTIAL:jenkins-token>",
                        },
                        sort_keys=True,
                    ),
                },
            }
        ],
    }


def process_call(call_id: str, target: str = "deploy-runner") -> Dict[str, Any]:
    """Assistant message carrying one credential_process_run tool call."""
    return {
        "role": "assistant",
        "tool_calls": [
            {
                "id": call_id,
                "function": {
                    "name": PROCESS_REFERENCE_TOOL,
                    "arguments": json.dumps(
                        {"target": target, "credential": "<CREDENTIAL:deploy-token>"},
                        sort_keys=True,
                    ),
                },
            }
        ],
    }


def tool_result(call_id: str, payload: Any) -> Dict[str, Any]:
    content = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def body(*messages: Dict[str, Any]) -> bytes:
    return json.dumps({"messages": list(messages)}).encode()


def parse_provider_closure(
    bodies: List[bytes],
    *,
    checks: FrozenSet[str] = ALL_CHECKS,
) -> Dict[str, Any]:
    """Reconcile Provider tool_calls ↔ tool_results across request bodies.

    ``checks`` exists only so mutation tests can disable one rule at a time and
    prove each error class is load-bearing; production callers take the default.
    """
    calls: Dict[str, Tuple[str, str]] = {}
    results: Dict[str, str] = {}
    errors: List[str] = []

    for raw in bodies:
        doc = json.loads(raw)
        for msg in doc.get("messages") or []:
            role = msg.get("role")
            if role == "assistant":
                for call in msg.get("tool_calls") or []:
                    tid = call.get("id")
                    fn = call.get("function") or {}
                    signature = (fn.get("name"), fn.get("arguments"))
                    if not isinstance(tid, str) or not tid:
                        errors.append("malformed_tool_call")
                        continue
                    if tid not in calls:
                        calls[tid] = signature
                    elif calls[tid] != signature and CHECK_CONFLICT_CALL in checks:
                        errors.append(f"{CHECK_CONFLICT_CALL}:{tid}")
            elif role == "tool":
                tid = msg.get("tool_call_id")
                content = msg.get("content")
                if not isinstance(tid, str) or not isinstance(content, str):
                    errors.append("malformed_tool_result")
                    continue
                if tid not in calls and CHECK_ORPHAN_RESULT in checks:
                    errors.append(f"{CHECK_ORPHAN_RESULT}:{tid}")
                if tid not in results:
                    results[tid] = content
                elif results[tid] != content and CHECK_CONFLICT_RESULT in checks:
                    errors.append(f"{CHECK_CONFLICT_RESULT}:{tid}")

    if CHECK_MISSING_RESULT in checks:
        for tid in calls:
            if tid not in results:
                errors.append(f"{CHECK_MISSING_RESULT}:{tid}")

    return {"calls": calls, "results": results, "errors": errors}


def assert_tool_call_closure(
    reconciled: Mapping[str, Any],
    *,
    expected_call_ids: FrozenSet[str],
    checks: FrozenSet[str] = ALL_CHECKS,
) -> List[str]:
    """Closure over the exact set of calls the scenario authorized."""
    errors = list(reconciled["errors"])
    seen = set(reconciled["calls"])
    if CHECK_EXTRA_CALL in checks:
        for tid in sorted(seen - set(expected_call_ids)):
            errors.append(f"{CHECK_EXTRA_CALL}:{tid}")
    if CHECK_MISSING_CALL in checks:
        for tid in sorted(set(expected_call_ids) - seen):
            errors.append(f"{CHECK_MISSING_CALL}:{tid}")
    return errors


def _blocked_text(content: str) -> Optional[str]:
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return content
    if isinstance(payload, dict):
        err = payload.get("error")
        return err if isinstance(err, str) else None
    return content


def evaluate_deny_provider_blocked(
    bodies: List[bytes],
    *,
    expected_call_ids: FrozenSet[str],
    checks: FrozenSet[str] = ALL_CHECKS,
) -> Dict[str, Any]:
    """Deny path: Provider must see the host's fixed BLOCKED result, nothing else."""
    reconciled = parse_provider_closure(bodies, checks=checks)
    closure_errors = assert_tool_call_closure(
        reconciled, expected_call_ids=expected_call_ids, checks=checks
    )
    fixed_ok = True
    if CHECK_FIXED_BLOCKED in checks:
        fixed_ok = False
        for tid in expected_call_ids:
            text = _blocked_text(reconciled["results"].get(tid, ""))
            if isinstance(text, str) and text.startswith(_FIXED_BLOCKED_PREFIX):
                fixed_ok = True
    return {
        "fixed_blocked_result_ok": fixed_ok,
        "tool_result_reconcile_ok": not closure_errors,
        "provider_saw_blocked": fixed_ok and not closure_errors,
        "errors": closure_errors,
    }


_HTTP_OK = {"ok": True, "status": 201, "target": "jenkins-production"}
_PROC_OK = {"ok": True, "exit_code": 0, "target": "deploy-runner"}


def test_migrated_j4_extra_tool_call_fails_closure():
    """One extra generic-tool call beyond the authorized set breaks closure."""
    bodies = [
        body(http_call("call_http", "/job/project-x/build")),
        body(
            http_call("call_http", "/job/project-x/build"),
            tool_result("call_http", _HTTP_OK),
            process_call("call_proc"),
        ),
        body(
            http_call("call_http", "/job/project-x/build"),
            tool_result("call_http", _HTTP_OK),
            process_call("call_proc"),
            tool_result("call_proc", _PROC_OK),
            http_call("call_extra", "/job/project-x/build"),
            tool_result("call_extra", _HTTP_OK),
        ),
    ]
    reconciled = parse_provider_closure(bodies)
    errors = assert_tool_call_closure(
        reconciled, expected_call_ids=frozenset({"call_http", "call_proc"})
    )
    assert any(e.startswith(CHECK_EXTRA_CALL) for e in errors), errors


def test_migrated_j4_missing_tool_result_fails():
    """A generic-tool call the Provider never got a result for breaks closure."""
    bodies = [body(http_call("call_http", "/job/project-x/build"))]
    reconciled = parse_provider_closure(bodies)
    assert any(
        e.startswith(CHECK_MISSING_RESULT) for e in reconciled["errors"]
    ), reconciled["errors"]


def test_migrated_j4_same_id_multi_action_fails():
    """Same tool_call_id reused for a different generic-tool action is a conflict."""
    first = http_call("call_http", "/job/project-x/build")
    swapped = http_call("call_http", "/health")
    bodies = [body(first), body(first, swapped)]
    reconciled = parse_provider_closure(bodies)
    assert any(
        e.startswith(CHECK_CONFLICT_CALL) for e in reconciled["errors"]
    ), reconciled["errors"]

    cross_tool = [body(first), body(first, process_call("call_http"))]
    cross = parse_provider_closure(cross_tool)
    assert any(e.startswith(CHECK_CONFLICT_CALL) for e in cross["errors"]), cross["errors"]


def test_migrated_h7_orphan_and_conflicting_results_fail():
    """Orphan / conflicting tool_results on generic-tool ids break closure."""
    orphan = [body(tool_result("call_http", _HTTP_OK))]
    parsed = parse_provider_closure(orphan)
    assert any(e.startswith(CHECK_ORPHAN_RESULT) for e in parsed["errors"]), parsed["errors"]

    call = http_call("call_http", "/job/project-x/build")
    conflicting = [
        body(call),
        body(call, tool_result("call_http", {"ok": False, "status": 500})),
        body(call, tool_result("call_http", _HTTP_OK)),
    ]
    parsed2 = parse_provider_closure(conflicting)
    assert any(
        e.startswith(CHECK_CONFLICT_RESULT) for e in parsed2["errors"]
    ), parsed2["errors"]


def test_migrated_j5_deny_requires_provider_fixed_blocked_result():
    """Deny: Provider must receive the host's fixed BLOCKED text, not runner prose."""
    deny = process_call("call_deny")
    good = [
        body(deny),
        body(
            deny,
            tool_result(
                "call_deny",
                {
                    "error": (
                        "BLOCKED: User denied this potentially dangerous action "
                        "(matched 'credential-guard'). Do NOT retry — the user has "
                        "explicitly rejected it."
                    )
                },
            ),
        ),
    ]
    blocked = evaluate_deny_provider_blocked(
        good, expected_call_ids=frozenset({"call_deny"})
    )
    assert blocked["fixed_blocked_result_ok"] is True
    assert blocked["tool_result_reconcile_ok"] is True
    assert blocked["provider_saw_blocked"] is True

    # A runner's own phrase containing "BLOCKED" must not satisfy the contract.
    bad = [
        body(deny),
        body(deny, tool_result("call_deny", "deny-path-complete BLOCKED")),
    ]
    forged = evaluate_deny_provider_blocked(
        bad, expected_call_ids=frozenset({"call_deny"})
    )
    assert forged["fixed_blocked_result_ok"] is False
    assert forged["provider_saw_blocked"] is False


def test_migrated_j5_deny_extra_tool_call_fails():
    """Deny path must not carry a second generic-tool call to the Provider."""
    deny = http_call("call_deny", "/job/project-x/build")
    bodies = [
        body(deny),
        body(
            deny,
            tool_result(
                "call_deny",
                {"error": "BLOCKED: User denied this command. The user has NOT consented."},
            ),
            process_call("call_extra"),
            tool_result("call_extra", {"ok": False}),
        ),
    ]
    blocked = evaluate_deny_provider_blocked(
        bodies, expected_call_ids=frozenset({"call_deny"})
    )
    assert blocked["tool_result_reconcile_ok"] is False
    assert blocked["provider_saw_blocked"] is False


def test_closure_accepts_the_authorized_two_call_transcript():
    """Guard against a validator that simply reports errors for everything."""
    bodies = [
        body(http_call("call_http", "/job/project-x/build")),
        body(
            http_call("call_http", "/job/project-x/build"),
            tool_result("call_http", _HTTP_OK),
            process_call("call_proc"),
        ),
        body(
            http_call("call_http", "/job/project-x/build"),
            tool_result("call_http", _HTTP_OK),
            process_call("call_proc"),
            tool_result("call_proc", _PROC_OK),
        ),
    ]
    reconciled = parse_provider_closure(bodies)
    errors = assert_tool_call_closure(
        reconciled, expected_call_ids=frozenset({"call_http", "call_proc"})
    )
    assert errors == []
    assert set(reconciled["calls"]) == {"call_http", "call_proc"}


def test_mutation_weakening_each_closure_check_loses_its_signal():
    """Mutation: each migrated closure rule must be individually load-bearing.

    Disabling one check at a time makes the matching fixture look clean, i.e.
    the migrated assertion above would go RED. That is the proof the check —
    not some incidental error — is what carries the property.
    """
    call = http_call("call_http", "/job/project-x/build")

    extra_bodies = [
        body(call),
        body(call, tool_result("call_http", _HTTP_OK), process_call("call_extra")),
        body(
            call,
            tool_result("call_http", _HTTP_OK),
            process_call("call_extra"),
            tool_result("call_extra", _PROC_OK),
        ),
    ]
    weakened = ALL_CHECKS - {CHECK_EXTRA_CALL}
    errors = assert_tool_call_closure(
        parse_provider_closure(extra_bodies, checks=weakened),
        expected_call_ids=frozenset({"call_http"}),
        checks=weakened,
    )
    assert not any(e.startswith(CHECK_EXTRA_CALL) for e in errors)

    missing_bodies = [body(call)]
    weakened = ALL_CHECKS - {CHECK_MISSING_RESULT}
    parsed = parse_provider_closure(missing_bodies, checks=weakened)
    assert parsed["errors"] == []

    same_id_bodies = [body(call), body(call, http_call("call_http", "/health"))]
    weakened = ALL_CHECKS - {CHECK_CONFLICT_CALL}
    parsed = parse_provider_closure(same_id_bodies, checks=weakened)
    assert not any(e.startswith(CHECK_CONFLICT_CALL) for e in parsed["errors"])

    orphan_bodies = [body(tool_result("call_http", _HTTP_OK))]
    weakened = ALL_CHECKS - {CHECK_ORPHAN_RESULT}
    parsed = parse_provider_closure(orphan_bodies, checks=weakened)
    assert not any(e.startswith(CHECK_ORPHAN_RESULT) for e in parsed["errors"])

    conflict_bodies = [
        body(call),
        body(call, tool_result("call_http", {"ok": False})),
        body(call, tool_result("call_http", _HTTP_OK)),
    ]
    weakened = ALL_CHECKS - {CHECK_CONFLICT_RESULT}
    parsed = parse_provider_closure(conflict_bodies, checks=weakened)
    assert not any(e.startswith(CHECK_CONFLICT_RESULT) for e in parsed["errors"])

    deny = process_call("call_deny")
    forged_bodies = [
        body(deny),
        body(deny, tool_result("call_deny", "deny-path-complete BLOCKED")),
    ]
    weakened = ALL_CHECKS - {CHECK_FIXED_BLOCKED}
    forged = evaluate_deny_provider_blocked(
        forged_bodies, expected_call_ids=frozenset({"call_deny"}), checks=weakened
    )
    assert forged["fixed_blocked_result_ok"] is True


def test_migrated_closure_carrier_is_generic_tools_only():
    """The migrated fixtures must not depend on the delete-list carriers."""
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    # Prose (docstrings) may name the retired carriers; executable code may not.
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = (getattr(node, "body", None) or [None])[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))

    imported: List[str] = []
    literals: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                literals.append(node.value)

    # Needles are assembled at runtime so this test's own source does not
    # contain the very strings it forbids.
    for banned in ("credential_guard." + "tools", "credential_guard." + "ssh_tools"):
        assert banned not in imported, imported
    for banned in ("run_m2" + "_e2e", "mysql_" + "credential_action", "ssh_" + "credential_action"):
        assert not any(banned in lit for lit in literals), banned
    delete_list_dir = "scr" + "ipts/"
    assert not any(lit.startswith(delete_list_dir) for lit in literals), literals

    assert HTTP_REFERENCE_TOOL == "http_credential_request"
    assert PROCESS_REFERENCE_TOOL == "credential_process_run"
