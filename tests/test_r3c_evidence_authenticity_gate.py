"""R3C C3: unified evidence authenticity gate — reject known false-green patterns.

Candidate evidence only — does not claim R3/R3C PASS.
Mutations must feed *mutated* text into validate_r3c_evidence_source and fail.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import pytest

REPO = Path(__file__).resolve().parents[1]

# Frozen canonical AST identity for scripts/run_r3c_wire_e2e.py (reviewed carrier).
# SHA-256 of ast.dump(..., annotate_fields=True, include_attributes=False).
# Must NOT be derived from the text under validation at check time.
_WIRE_CANONICAL_AST_SHA256 = (
    "5d97004c7a32d0cadbd44a6f163ce49d97a83f014bfccfdfd63a472290763c65"
)

_TARGETS = (
    REPO / "tests" / "test_r3c_wire_e2e.py",
    REPO / "tests" / "test_r3c_plugin_manager_graph.py",
    REPO / "scripts" / "run_r3c_wire_e2e.py",
    REPO / "scripts" / "run_r3c_e2e.py",
)

_FORBIDDEN = (
    re.compile(r"""mgr\._middleware\[\s*['"]tool_request['"]\s*\]\s*="""),
    re.compile(r"""mgr\._middleware\[\s*['"]tool_execution['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*\.clear\s*\("""),
    re.compile(r"""['"]adapter_ok['"]\s*:\s*True\b"""),
    re.compile(r"""['"]process_start_delta['"]\s*:\s*1\b"""),
    re.compile(r"""['"]http_adapter_delta['"]\s*:\s*1\b"""),
    re.compile(r"""order\s*=\s*\[\s*['"]tool_request['"].*['"]adapter['"]\s*\]"""),
    re.compile(r"""counts\[\s*['"]consume['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""counts\[\s*['"]resolve['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""counts\[\s*['"]adapter['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""wire_secret_count\s*=\s*0\b"""),
    re.compile(r"""['"]loopback_only['"]\s*:\s*True\b"""),
    re.compile(r"""['"]used_environ_copy['"]\s*:\s*False\b"""),
)

_PROBE_FORBIDDEN = (
    re.compile(r"""class\s+Ctx\s*:"""),
    re.compile(r"""registry\.deregister\s*\("""),
    re.compile(r"""register\s*\(\s*Ctx\s*\("""),
    re.compile(r"""os\.environ\.copy\s*\("""),
    re.compile(r"""dict\s*\(\s*os\.environ\s*\)"""),
    re.compile(r"""os\.environ\s*\|\s*"""),
    re.compile(r"""mgr\._middleware\[\s*['"]tool_request['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*\.clear\s*\("""),
    re.compile(r"""['"]loopback_only['"]\s*:\s*True\b"""),
    re.compile(r"""['"]used_environ_copy['"]\s*:\s*False\b"""),
)

_REQUIRED_BY_KIND = {
    "wire_script": (
        "raw_requests",
        "approval_raw",
        "wire_secret_count",
        "127.0.0.1",
        "raw_http_has_request_line",
        "raw_http_has_headers",
        "raw_http_has_body",
        "non_loopback_original_calls",
        "_bomb_connect",
        "_guard_connect",
        "_minimal_child_env",
        "sys.setprofile",
        "http_approve",
        "env_approve",
        "stdin_approve",
        "http_deny",
        "env_deny",
        "stdin_deny",
        "http_replay",
        "env_replay",
        "stdin_replay",
        "http_mutate",
        "env_mutate",
        "stdin_mutate",
        "http_timeout",
        "env_timeout",
        "stdin_timeout",
        "approval_timeout_branch",
        "approval_is_timeout",
        "host_approval_raw",
        "_await_gateway_decision",
        "tool_request_identities",
        "replay_identity_same",
        "args_digest",
        "trace_artifact_count",
        "trace_secret_count",
        "trace_inventory",
        "state.db-wal",
        "state.db-shm",
        "parent_env_secret_count",
        "cg_probe_in_parent",
        "followup_child_status",
        "manifest_bytes_identical",
        "http_target_evidence_layer",
        "production_default_transport_loopback_tls",
        "_default_transport",
        "create_default_context",
        "load_verify_locations",
        "subjectAltName=DNS:svc.example.test,IP:127.0.0.1",
        "default_transport_enter_count",
        "http_transport_override_calls",
        "execute_http",
        "execute_process",
        "AIAgent",
        "run_conversation",
        "PluginManager",
        "discover_plugins",
    ),
    "wire_tests": (
        "approval_raw",
        "wire_secret_count",
        "token_in_provider_raw",
        "token_in_approval_raw",
        "raw_http_has_request_line",
        "non_loopback_original_calls",
        "http_approve",
        "env_approve",
        "stdin_approve",
        "http_replay",
        "env_replay",
        "stdin_replay",
        "http_mutate",
        "env_mutate",
        "stdin_mutate",
        "http_timeout",
        "env_timeout",
        "stdin_timeout",
        "approval_is_timeout",
        "host_approval_raw",
        "tool_request_identities",
        "replay_identity_same",
        "trace_artifact_count",
        "trace_inventory",
        "enumerate_runtime_carriers",
        "parent_env_secret_count",
        "followup_child_status",
        "manifest_bytes_identical",
        "sys.setprofile",
        "guard_enabled",
        "validate_r3c_evidence_source",
        "production_default_transport_loopback_tls",
        "default_transport_enter_count",
        "http_transport_override_calls",
        "second_http_target_delta",
    ),
    "probe_graph": (
        "discover_plugins",
        "sys.setprofile",
        "identity_unchanged",
        "ordinary",
        "stdin",
        "before.get(k) == after.get(k)",
    ),
    "e2e_runner": (
        "test_r3c_wire_e2e",
        "test_r3c_evidence_authenticity_gate",
        "test_r3c_historical_identity_gate",
    ),
    "any": (),
}


def _scan_false_green(text: str) -> List[Tuple[str, str]]:
    hits: List[Tuple[str, str]] = []
    for cre in _FORBIDDEN:
        for m in cre.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.start())
            if line_end < 0:
                line_end = len(text)
            line = text[line_start:line_end]
            if line.lstrip().startswith("assert "):
                continue
            hits.append((cre.pattern, m.group(0)))
    return hits


def _scan_probe_forbidden(text: str) -> List[Tuple[str, str]]:
    hits: List[Tuple[str, str]] = []
    for cre in _PROBE_FORBIDDEN:
        for m in cre.finditer(text):
            hits.append((cre.pattern, m.group(0)))
    return hits


def _missing_evidence_contracts(text: str, kind: str) -> List[str]:
    required = _REQUIRED_BY_KIND.get(kind, ())
    missing: List[str] = []
    for sym in required:
        if sym not in text:
            missing.append(f"missing:{sym}")
    if kind == "wire_script":
        if re.search(r"""['"]loopback_only['"]\s*:\s*True\b""", text):
            missing.append("hardcoded:loopback_only_True")
        if re.search(r"""['"]used_environ_copy['"]\s*:\s*False\b""", text):
            missing.append("hardcoded:used_environ_copy_False")
        if "os.environ.copy" in text:
            missing.append("forbidden:os.environ.copy")
        if "raw_requests.append(body)" in text and "raw_http_has_request_line" not in text:
            missing.append("incomplete:raw_http_body_only")
        if re.search(r"""loopback_only\s*=\s*True\b""", text):
            missing.append("hardcoded:loopback_only_assign_True")
        # Must not call internal middleware as sole driver instead of public Agent.
        if "AIAgent" not in text or "run_conversation" not in text:
            missing.append("missing:public_agent_path")
        if "_run_agent_tool_execution_middleware" in text and "AIAgent" not in text:
            missing.append("forbidden:internal_middleware_only")
        if re.search(r"""['"]identity_unchanged['"]\s*:\s*True\b""", text):
            missing.append("hardcoded:identity_unchanged_True")
        if "os.environ.copy" in text:
            missing.append("forbidden:os.environ.copy")
        # Round3 authenticity: same-turn replay (one conversation), host timeout raw,
        # full carrier scan, no decoy env ferry, no temp manifest patch.
        if "result2 = agent.run_conversation" in text:
            missing.append("forbidden:two_conversation_replay")
        if re.search(
            r"""\.setdefault\s*\(\s*['"]outcome['"]\s*,\s*['"]timeout['"]\s*\)""",
            text,
        ):
            missing.append("forbidden:setdefault_timeout_outcome")
        if "timed out without user response. Silence is not consent." in text and (
            "decision[\"message\"]" in text or "decision['message']" in text
        ):
            # Appending host timeout wording into decision after host return.
            if "Force-visible timeout" in text or "timeout semantic if host" in text:
                missing.append("forbidden:append_timeout_message")
        if "CG_DECOY_HTTP" in text or "CG_DECOY_ENV" in text or "CG_DECOY_STDIN" in text:
            missing.append("forbidden:decoy_env_ferry")
        if re.search(
            r"""startswith\s*\(\s*['"]CG_DECOY_""",
            text,
        ) or "k.startswith(\"CG_DECOY_\")" in text or "k.startswith('CG_DECOY_')" in text:
            missing.append("forbidden:parent_env_decoy_skip")
        if re.search(
            r"""credential_process_run\\n["']\s*,\s*encoding""",
            text,
        ) or '+ "\\n  - credential_process_run\\n"' in text or "+ '\\n  - credential_process_run\\n'" in text:
            missing.append("forbidden:temp_manifest_patch")
        if 'if "credential_guard" in rel_parts' in text or "credential_guard\" in rel_parts" in text:
            missing.append("forbidden:broad_credential_guard_exclude")
        # R3 reclosure: production HTTPS transport on public wire — no test override.
        if "set_http_transport_override_for_tests(" in text:
            missing.append("forbidden:http_transport_override")
        if "_fake_http_target" in text:
            missing.append("forbidden:fake_http_target")
        if "R3A_signed_transport_override_in_R3C_wire" in text:
            missing.append("forbidden:signed_transport_override_layer")
        if re.search(r"""['"]http_target_hits['"]\s*:\s*1\b""", text):
            missing.append("hardcoded:http_target_hits_1")
        if re.search(r"""http_target_hits\s*=\s*1\b""", text):
            missing.append("hardcoded:http_target_hits_assign_1")
        if "verify=False" in text or "verify = False" in text:
            missing.append("forbidden:tls_verify_disabled")
        # R8: binding may select http|https. Illegal schemes stay forbidden.
        # Absolute ban on plaintext http is retired; keep TLS/proxy/redirect contracts.
        if re.search(
            r"""['"]scheme['"]\s*:\s*['"](?:ftp|file|ws|HTTP|HTTPS)['"]""",
            text,
        ):
            missing.append("forbidden:illegal_scheme")
        if (
            'replace("https://", "http://")' in text
            or "replace('https://', 'http://')" in text
        ):
            missing.append("forbidden:https_to_http_downgrade")
        if "trust_env=True" in text or "allow_redirects=True" in text:
            missing.append("forbidden:insecure_transport_flags")
        # R3C historical wire remains HTTPS-bearing; require synthetic/loopback TLS target.
        if "https://svc.example.test" not in text and "https://127.0.0.1" not in text:
            missing.append("missing:https_loopback_or_synthetic_target")
        # Production HTTPS TLS markers must remain load-bearing on the wire corpus.
        if "create_default_context" not in text:
            missing.append("missing:tls_default_context")
        if "_default_transport" not in text:
            missing.append("missing:_default_transport")
    if kind == "probe_graph":
        if re.search(r"""['"]identity_unchanged['"]\s*:\s*True\b""", text):
            missing.append("hardcoded:identity_unchanged_True")
        if "before.get(k) == after.get(k)" not in text and "before[k] == after[k]" not in text:
            if "identity_unchanged = all(" not in text:
                missing.append("missing:derived_identity_compare")
    return missing


_REPLAY_FIRST_ID = "first_tool_call_id"
_REPLAY_FIRST_ARGS = "first_serialized_args"
_HOST_TIMEOUT_FRAG_A = "timed out without user response"
_HOST_TIMEOUT_FRAG_B = "Silence is not consent"


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _name_id(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    return None


def _attr_parts(node: ast.AST) -> Tuple[str, ...]:
    parts: List[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return tuple(reversed(parts))
    return tuple()


def _dict_mapping(node: ast.Dict) -> dict:
    out = {}
    for k, v in zip(node.keys, node.values):
        ks = _const_str(k)
        if ks is not None:
            out[ks] = v
    return out


def _tool_call_id_and_args(node: ast.AST) -> Optional[Tuple[ast.AST, ast.AST]]:
    """If node is a tool_calls entry dict, return (id_expr, arguments_expr)."""
    if not isinstance(node, ast.Dict):
        return None
    keys = _dict_mapping(node)
    if "id" not in keys or "function" not in keys:
        return None
    fn = keys["function"]
    if not isinstance(fn, ast.Dict):
        return None
    fkeys = _dict_mapping(fn)
    if "arguments" not in fkeys:
        return None
    return keys["id"], fkeys["arguments"]


def _uses_replay_second_issued(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == "_replay_second_issued":
            return True
        if isinstance(child, ast.Constant) and child.value == "_replay_second_issued":
            return True
    return False


def _check_replay_second_identity_reuse(tree: ast.AST) -> List[str]:
    """Second replay function payload must reuse first_tool_call_id / first_serialized_args."""
    violations: List[str] = []
    has_first_id_bind = False
    has_first_args_bind = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == _REPLAY_FIRST_ID:
                    has_first_id_bind = True
                if isinstance(t, ast.Name) and t.id == _REPLAY_FIRST_ARGS:
                    has_first_args_bind = True
    if not has_first_id_bind or not has_first_args_bind:
        # Without explicit first-identity binds, second-payload reuse is not mechanically load-bearing.
        violations.append("mutation:second_tool_call_id_changed")
        violations.append("mutation:second_args_changed")
        return violations

    second_payloads: List[Tuple[ast.AST, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _uses_replay_second_issued(node.test):
            for stmt in node.body:
                for child in ast.walk(stmt):
                    pair = _tool_call_id_and_args(child)
                    if pair is not None:
                        second_payloads.append(pair)
    if not second_payloads:
        violations.append("mutation:second_tool_call_id_changed")
        violations.append("mutation:second_args_changed")
        return violations

    for id_expr, args_expr in second_payloads:
        if _name_id(id_expr) != _REPLAY_FIRST_ID:
            violations.append("mutation:second_tool_call_id_changed")
        if _name_id(args_expr) != _REPLAY_FIRST_ARGS:
            violations.append("mutation:second_args_changed")
    return list(dict.fromkeys(violations))


def _has_real_await_gateway_code_label(tree: ast.AST) -> bool:
    """True when approval_mod._await_gateway_decision enters code_labels mapping."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Tuple, ast.List)):
            continue
        if len(node.elts) < 2:
            continue
        parts = _attr_parts(node.elts[0])
        label = _const_str(node.elts[1])
        if parts == ("approval_mod", "_await_gateway_decision") and label == "_await_gateway_decision":
            return True
    return False


def _await_count_increment_is_label_guarded(tree: ast.AST) -> bool:
    """await_gateway_call_count += 1 must sit under label == '_await_gateway_decision'."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.AugAssign):
            continue
        if not (isinstance(node.target, ast.Name) and node.target.id == "await_gateway_call_count"):
            continue
        if not (
            isinstance(node.op, ast.Add)
            and isinstance(node.value, ast.Constant)
            and node.value.value == 1
        ):
            # Unusual increment form — treat as non-guarded forge.
            return False
        # Walk parents via containing If tests: search enclosing If in tree by lineno range.
        guarded = False
        for parent in ast.walk(tree):
            if not isinstance(parent, ast.If):
                continue
            if not (parent.lineno <= node.lineno <= (parent.end_lineno or parent.lineno)):
                continue
            # label == "_await_gateway_decision"
            test = parent.test
            if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
                left_name = _name_id(test.left)
                right = test.comparators[0] if test.comparators else None
                if left_name == "label" and _const_str(right) == "_await_gateway_decision":
                    # Confirm this If's body contains our AugAssign
                    for child in parent.body:
                        for sub in ast.walk(child):
                            if sub is node:
                                guarded = True
                                break
        if not guarded:
            return False
        return True
    return False


def _await_count_forged_constant(tree: ast.AST) -> bool:
    """Detect await_gateway_call_count = <positive int> forge (init 0 is allowed)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "await_gateway_call_count":
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                        if node.value.value != 0:
                            return True
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "await_gateway_call_count":
                # += N where N != 1, or unguarded handled elsewhere
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                    if node.value.value != 1:
                        return True
    return False


def _approval_timeout_branch_requires_await_count(tree: ast.AST) -> bool:
    """approval_timeout_branch must AND-include await_gateway_call_count > 0."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "approval_timeout_branch" for t in node.targets):
            continue
        # Peel bool(...)
        val = node.value
        if isinstance(val, ast.Call) and _name_id(val.func) == "bool" and val.args:
            val = val.args[0]
        # Collect compare nodes under AND / nested BoolOp
        compares: List[ast.Compare] = []
        if isinstance(val, ast.BoolOp) and isinstance(val.op, ast.And):
            stack = list(val.values)
            while stack:
                item = stack.pop()
                if isinstance(item, ast.BoolOp) and isinstance(item.op, ast.And):
                    stack.extend(item.values)
                elif isinstance(item, ast.Compare):
                    compares.append(item)
        elif isinstance(val, ast.Compare):
            compares.append(val)
        for cmp in compares:
            if _name_id(cmp.left) == "await_gateway_call_count":
                if cmp.ops and isinstance(cmp.ops[0], ast.Gt):
                    right = cmp.comparators[0] if cmp.comparators else None
                    if isinstance(right, ast.Constant) and right.value == 0:
                        return True
            # Also allow 0 < await_gateway_call_count
            if cmp.ops and isinstance(cmp.ops[0], ast.Lt) and isinstance(cmp.left, ast.Constant) and cmp.left.value == 0:
                if _name_id(cmp.comparators[0]) == "await_gateway_call_count":
                    return True
        return False
    return False


def _check_host_await_timeout_dataflow(text: str, tree: ast.AST) -> List[str]:
    """Host timeout branch must depend on real _await_gateway_decision profile mapping."""
    has_timeout_text = _HOST_TIMEOUT_FRAG_A in text and _HOST_TIMEOUT_FRAG_B in text
    if not has_timeout_text:
        return []
    if "approval_timeout_branch" not in text:
        return []

    bypassed = False
    if not _has_real_await_gateway_code_label(tree):
        bypassed = True
    if not _await_count_increment_is_label_guarded(tree):
        bypassed = True
    if _await_count_forged_constant(tree):
        bypassed = True
    if not _approval_timeout_branch_requires_await_count(tree):
        bypassed = True
    # host_timeout_text must be derived / referenced in the branch formula
    if "host_timeout_text" not in text:
        bypassed = True

    if bypassed:
        return ["mutation:host_await_bypassed_with_timeout_text"]
    return []


def _extract_probe_source(text: str) -> Optional[str]:
    """Extract embedded PROBE body from run_r3c_wire_e2e.py carrier (or mutated copy)."""
    try:
        outer = ast.parse(text)
    except SyntaxError:
        return None
    for node in outer.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "PROBE" for t in node.targets):
            continue
        val = node.value
        # textwrap.dedent(r"""...""") or dedent("""...""")
        if isinstance(val, ast.Call) and val.args:
            arg0 = val.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                return arg0.value
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            return val.value
    return None


_DENY_TIMEOUT_MUTATE_SCENARIOS = frozenset(
    {
        "http_deny",
        "env_deny",
        "stdin_deny",
        "http_timeout",
        "env_timeout",
        "stdin_timeout",
        "http_mutate",
        "env_mutate",
        "stdin_mutate",
    }
)


def _const_strs_in(node: ast.AST) -> set:
    found = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.add(child.value)
    return found


def _is_subscript_r_key(node: ast.AST, key: str) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    if _name_id(node.value) != "r":
        return False
    return _const_str(node.slice) == key


def _assert_compare(node: ast.Assert) -> Optional[ast.Compare]:
    test = node.test
    return test if isinstance(test, ast.Compare) else None


def _is_eq_zero(cmp: ast.Compare) -> bool:
    if len(cmp.ops) != 1 or not isinstance(cmp.ops[0], ast.Eq):
        return False
    right = cmp.comparators[0]
    return isinstance(right, ast.Constant) and right.value == 0


def _parent_map(tree: ast.AST) -> dict:
    parents: dict = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _is_under(node: ast.AST, ancestor: ast.AST, parents: dict) -> bool:
    cur: Optional[ast.AST] = node
    while cur in parents:
        cur = parents[cur]
        if cur is ancestor:
            return True
    return False


_FUNC_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _enclosing_function_scope(node: ast.AST, parents: dict) -> Optional[ast.AST]:
    """Nearest enclosing FunctionDef / AsyncFunctionDef / Lambda, else None (module)."""
    cur: Optional[ast.AST] = node
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, _FUNC_SCOPE_TYPES):
            return cur
    return None


def _is_static_false_test(test: ast.AST) -> bool:
    """Recognize statically-false predicates used as unreachable decoy wrappers."""
    if isinstance(test, ast.Constant):
        return test.value is False or test.value == 0
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        if isinstance(test.operand, ast.Constant) and test.operand.value is True:
            return True
        if isinstance(test.operand, ast.Constant) and test.operand.value == 1:
            return True
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return any(_is_static_false_test(v) for v in test.values)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return bool(test.values) and all(_is_static_false_test(v) for v in test.values)
    return False


def _is_static_true_test(test: ast.AST) -> bool:
    if isinstance(test, ast.Constant):
        return test.value is True or test.value == 1
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _is_static_false_test(test.operand)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return any(_is_static_true_test(v) for v in test.values)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return bool(test.values) and all(_is_static_true_test(v) for v in test.values)
    return False


def _is_static_empty_iterable(node: ast.AST) -> bool:
    """Recognize statically-empty iterables used as unreachable decoy wrappers."""
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return len(node.elts) == 0
    if isinstance(node, ast.Dict):
        return len(node.keys) == 0
    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, (str, bytes)) and len(v) == 0:
            return True
    if isinstance(node, ast.Call):
        fname = _name_id(node.func)
        if fname in {"set", "list", "tuple", "dict", "frozenset"} and (
            not node.args and not node.keywords
        ):
            return True
        if fname == "range":
            if len(node.args) == 1:
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and a0.value == 0:
                    return True
            if len(node.args) >= 2:
                a0, a1 = node.args[0], node.args[1]
                if (
                    isinstance(a0, ast.Constant)
                    and isinstance(a1, ast.Constant)
                    and a0.value == a1.value
                ):
                    return True
    return False


def _direct_stmt_list(
    parent: ast.AST, child: ast.AST
) -> Optional[Tuple[list, str]]:
    """If child is a direct statement in parent.body/orelse/finalbody, return (list, attr)."""
    for attr in ("body", "orelse", "finalbody"):
        lst = getattr(parent, attr, None)
        if isinstance(lst, list) and child in lst:
            return lst, attr
    if isinstance(parent, ast.ExceptHandler) and child in parent.body:
        return parent.body, "body"
    return None


def _is_unconditional_terminator(stmt: ast.AST, *, loop_body: bool) -> bool:
    """Bare Return/Raise always terminate; Break/Continue only inside a loop body list."""
    if isinstance(stmt, (ast.Return, ast.Raise)):
        return True
    if loop_body and isinstance(stmt, (ast.Break, ast.Continue)):
        return True
    return False


def _is_statically_reachable(node: ast.AST, parents: dict) -> bool:
    """False when node sits under a statically-dead branch, empty-loop body, or
    after an unconditional terminator in the same statement list.
    """
    cur: ast.AST = node
    while cur in parents:
        parent = parents[cur]
        if isinstance(parent, ast.If):
            if cur in parent.body and _is_static_false_test(parent.test):
                return False
            if cur in parent.orelse and _is_static_true_test(parent.test):
                return False
        elif isinstance(parent, ast.While):
            # while False / while 0 / while not True: body unreachable; orelse still runs.
            if cur in parent.body and _is_static_false_test(parent.test):
                return False
        elif isinstance(parent, ast.For):
            # for _ in ()/[]/set()/{}/"" /b""/range(0): body unreachable; orelse still runs.
            if cur in parent.body and _is_static_empty_iterable(parent.iter):
                return False
        # Same-list basic-block terminators: only prior siblings count (not nested).
        found = _direct_stmt_list(parent, cur)
        if found is not None:
            stmt_list, attr = found
            loop_body = isinstance(parent, (ast.For, ast.AsyncFor, ast.While)) and attr == "body"
            idx = stmt_list.index(cur)
            for prev in stmt_list[:idx]:
                if _is_unconditional_terminator(prev, loop_body=loop_body):
                    return False
        cur = parent
    return True


def _canonical_ast_digest(text: str) -> Optional[str]:
    """Stable SHA-256 of ast.dump(tree, annotate_fields=True, include_attributes=False)."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    dumped = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _check_wire_canonical_ast_identity(text: str) -> List[str]:
    """Pin full wire carrier AST identity; unknown semantic edits → drift RED."""
    digest = _canonical_ast_digest(text)
    if digest is None or digest != _WIRE_CANONICAL_AST_SHA256:
        return ["mutation:wire_canonical_ast_drift"]
    return []


def _find_module_main_fn(tree: ast.AST) -> Optional[ast.AST]:
    """Exactly one module-level main() — fail closed on ambiguity."""
    if not isinstance(tree, ast.Module):
        return None
    mains = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "main"
    ]
    if len(mains) != 1:
        return None
    return mains[0]


def _check_deny_timeout_mutate_target_hit_guard(tree: ast.AST) -> List[str]:
    """deny/timeout/mutate summary: one reachable main() loop covering all nine + == 0."""
    parents = _parent_map(tree)
    main_fn = _find_module_main_fn(tree)
    if main_fn is None:
        return ["mutation:deny_timeout_mutate_target_hit_guard_weakened"]

    qualifying: List[ast.AST] = []
    weakened_reachable = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        # Lexical scope must be exactly module-level main() — not a nested
        # FunctionDef / AsyncFunctionDef / Lambda / class method under main.
        if _enclosing_function_scope(node, parents) is not main_fn:
            continue
        if not _is_statically_reachable(node, parents):
            continue
        names = _const_strs_in(node.iter)
        # Load-bearing loop must include the full nine-scenario set — not any 3.
        if not _DENY_TIMEOUT_MUTATE_SCENARIOS.issubset(names):
            continue
        has_strict = False
        has_weak = False
        for stmt in ast.walk(node):
            if not isinstance(stmt, ast.Assert):
                continue
            if _enclosing_function_scope(stmt, parents) is not main_fn:
                continue
            if not _is_statically_reachable(stmt, parents):
                continue
            cmp = _assert_compare(stmt)
            if cmp is None or not _is_subscript_r_key(cmp.left, "http_target_hits"):
                continue
            if _is_eq_zero(cmp):
                has_strict = True
            else:
                has_weak = True
        if has_weak:
            weakened_reachable = True
        if has_strict and not has_weak:
            qualifying.append(node)

    # Exactly one authoritative reachable qualifying loop; decoys must not mask weakenings.
    if weakened_reachable or len(qualifying) != 1:
        return ["mutation:deny_timeout_mutate_target_hit_guard_weakened"]
    return []

def _is_name_eq_const(test: ast.AST, name: str, value: str) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    return _name_id(test.left) == name and _const_str(test.comparators[0]) == value


def _is_on_http_replay_summary_path(
    node: ast.AST, parents: dict, main_fn: ast.AST
) -> bool:
    """True under main()'s replay scenario loop and/or ``if name == "http_replay"``."""
    cur: Optional[ast.AST] = node
    while cur in parents:
        parent = parents[cur]
        if parent is main_fn:
            break
        if isinstance(parent, ast.If) and cur in parent.body:
            if _is_name_eq_const(parent.test, "name", "http_replay"):
                return True
        if isinstance(parent, ast.For):
            if _enclosing_function_scope(parent, parents) is main_fn:
                if "http_replay" in _const_strs_in(parent.iter):
                    return True
        cur = parent
    return False


def _check_replay_second_target_delta_guard(tree: ast.AST) -> List[str]:
    """replay summary: exactly one reachable main() http_replay-path == 0 assert."""
    parents = _parent_map(tree)
    main_fn = _find_module_main_fn(tree)
    if main_fn is None:
        return ["mutation:replay_second_target_delta_guard_weakened"]

    strict: List[ast.AST] = []
    weakened = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        cmp = _assert_compare(node)
        if cmp is None or not _is_subscript_r_key(cmp.left, "second_http_target_delta"):
            continue
        # Same binding discipline as nine-scenario loop: module-level main() only.
        if _enclosing_function_scope(node, parents) is not main_fn:
            continue
        if not _is_statically_reachable(node, parents):
            continue
        if not _is_on_http_replay_summary_path(node, parents, main_fn):
            continue
        if _is_eq_zero(cmp):
            strict.append(node)
        else:
            weakened = True

    # Uncalled fn / lambda / unreachable decoys cannot testify; multi-candidate fail closed.
    if weakened or len(strict) != 1:
        return ["mutation:replay_second_target_delta_guard_weakened"]
    return []


def _int_call_arg(node: Optional[ast.AST]) -> Optional[ast.AST]:
    if node is None:
        return None
    if isinstance(node, ast.Call) and _name_id(node.func) == "int" and len(node.args) == 1:
        return node.args[0]
    return None


def _is_token_encode_in_raw_join(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], ast.In):
        return False
    left, right = node.left, node.comparators[0]
    if _name_id(right) != "raw_join":
        return False
    if not isinstance(left, ast.Call) or not isinstance(left.func, ast.Attribute):
        return False
    return left.func.attr == "encode" and _name_id(left.func.value) == "token"


def _is_name_in_name(node: ast.AST, left_name: str, right_name: str) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], ast.In):
        return False
    return _name_id(node.left) == left_name and _name_id(node.comparators[0]) == right_name


_WIRE_EVIDENCE_KEYS = frozenset(
    {
        "token_in_provider_raw",
        "token_in_approval_raw",
        "token_in_result",
        "trace_secret_count",
        "wire_secret_count",
    }
)


def _print_json_dumps_sort_keys_dict(node: ast.AST) -> Optional[ast.Dict]:
    """Match print(json.dumps({...}, sort_keys=True)) and return the literal dict."""
    if not isinstance(node, ast.Call) or _name_id(node.func) != "print":
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    inner = node.args[0]
    if not isinstance(inner, ast.Call):
        return None
    func = inner.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "dumps"
        and _name_id(func.value) == "json"
    ):
        return None
    has_sort_keys = False
    for kw in inner.keywords:
        if kw.arg == "sort_keys" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            has_sort_keys = True
            break
    if not has_sort_keys:
        return None
    if not inner.args:
        return None
    # Reject aliases / non-literal dict args — must be the sink's literal dict.
    if not isinstance(inner.args[0], ast.Dict):
        return None
    return inner.args[0]


def _find_wire_evidence_sink(tree: ast.AST) -> Optional[Tuple[ast.Call, dict]]:
    """Bind to the unique reachable print(json.dumps({evidence}, sort_keys=True)) sink.

    PROBE authoritative sink is module-top-level: only nodes whose nearest function
    scope is None participate. Decoy sinks inside other functions are ignored.
    """
    parents = _parent_map(tree)
    sinks: List[Tuple[ast.Call, dict]] = []
    for node in ast.walk(tree):
        dict_node = _print_json_dumps_sort_keys_dict(node)
        if dict_node is None:
            continue
        # Authoritative PROBE sink lives at module scope (no enclosing function).
        if _enclosing_function_scope(node, parents) is not None:
            continue
        if not _is_statically_reachable(node, parents):
            continue
        mapping = _dict_mapping(dict_node)
        if not _WIRE_EVIDENCE_KEYS.issubset(mapping.keys()):
            continue
        sinks.append((node, mapping))
    # Unused/decoy dicts are ignored; multiple authoritative sinks → fail closed.
    if len(sinks) != 1:
        return None
    return sinks[0]


def _find_wire_evidence_dict(tree: ast.AST) -> Optional[dict]:
    sink = _find_wire_evidence_sink(tree)
    return None if sink is None else sink[1]


def _reachable_name_assigns(
    tree: ast.AST,
    name: str,
    parents: dict,
    *,
    before_lineno: Optional[int],
    scope: Optional[ast.AST],
) -> List[ast.Assign]:
    """Collect reachable Assigns of ``name`` in the same lexical function scope as sink."""
    out: List[ast.Assign] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            continue
        if _enclosing_function_scope(node, parents) is not scope:
            continue
        if not _is_statically_reachable(node, parents):
            continue
        if before_lineno is not None and (getattr(node, "lineno", 0) or 0) >= before_lineno:
            continue
        out.append(node)
    return out


def _is_bytes_newline_join_raw_requests(node: ast.AST) -> bool:
    """True for b'\\n'.join(raw_requests)."""
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "join":
        return False
    sep = node.func.value
    if not (isinstance(sep, ast.Constant) and sep.value == b"\n"):
        return False
    if len(node.args) != 1:
        return False
    return _name_id(node.args[0]) == "raw_requests"


def _is_json_dumps_of_name(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "dumps"
        and _name_id(func.value) == "json"
    ):
        return False
    if not node.args or _name_id(node.args[0]) != name:
        return False
    return True


def _raw_join_dataflow_ok(
    tree: ast.AST, parents: dict, sink_lineno: int, sink_scope: Optional[ast.AST]
) -> bool:
    """raw_join: exactly one reachable pre-sink assign from b'\\n'.join(raw_requests)."""
    assigns = _reachable_name_assigns(
        tree, "raw_join", parents, before_lineno=sink_lineno, scope=sink_scope
    )
    if len(assigns) != 1:
        return False
    node = assigns[0]
    if isinstance(node.value, ast.Constant) and node.value.value in (b"", ""):
        return False
    return _is_bytes_newline_join_raw_requests(node.value)


def _approval_blob_dataflow_ok(
    tree: ast.AST, parents: dict, sink_lineno: int, sink_scope: Optional[ast.AST]
) -> bool:
    """approval_blob: exactly one reachable pre-sink assign from json.dumps(approval_raw)."""
    assigns = _reachable_name_assigns(
        tree, "approval_blob", parents, before_lineno=sink_lineno, scope=sink_scope
    )
    if len(assigns) != 1:
        return False
    node = assigns[0]
    if isinstance(node.value, ast.Constant) and node.value.value in (b"", ""):
        return False
    return _is_json_dumps_of_name(node.value, "approval_raw")


def _blob_dataflow_ok(
    tree: ast.AST, parents: dict, sink_lineno: int, sink_scope: Optional[ast.AST]
) -> bool:
    """blob: exactly one reachable pre-sink assign assembled from result carrier."""
    assigns = _reachable_name_assigns(
        tree, "blob", parents, before_lineno=sink_lineno, scope=sink_scope
    )
    if len(assigns) != 1:
        return False
    val = assigns[0].value
    if isinstance(val, ast.Constant):
        return False
    uses_result = False
    for child in ast.walk(val):
        if isinstance(child, ast.Name) and child.id == "result":
            uses_result = True
            break
    if not uses_result:
        return False
    if isinstance(val, ast.IfExp):
        saw_dumps = False
        for child in ast.walk(val):
            if _is_json_dumps_of_name(child, "result"):
                saw_dumps = True
                break
        if not saw_dumps and _name_id(val.body) != "result" and _name_id(val.orelse) != "result":
            return False
        return True
    return _name_id(val) == "result" or _is_json_dumps_of_name(val, "result")


def _expr_is_decoy_byte_count(node: ast.AST) -> bool:
    """data.count(decoy.encode(...)) style membership count."""
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "count":
        return False
    if not node.args:
        return False
    arg0 = node.args[0]
    # decoy.encode(...) or <name>.encode(...)
    if isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute):
        if arg0.func.attr == "encode":
            return True
    return False


def _trace_secret_count_dataflow_ok(
    tree: ast.AST, parents: dict, sink_lineno: int, sink_scope: Optional[ast.AST]
) -> bool:
    """trace_secret_count: reachable init+scan accumulate before sink; no late forge."""
    init_zeros: List[ast.AST] = []
    late_forges: List[ast.AST] = []
    augments: List[ast.AST] = []
    for node in ast.walk(tree):
        if _enclosing_function_scope(node, parents) is not sink_scope:
            continue
        if not _is_statically_reachable(node, parents):
            continue
        if (getattr(node, "lineno", 0) or 0) >= sink_lineno:
            continue
        if isinstance(node, ast.Assign):
            if not any(
                isinstance(t, ast.Name) and t.id == "trace_secret_count"
                for t in node.targets
            ):
                continue
            if isinstance(node.value, ast.Constant) and node.value.value == 0:
                init_zeros.append(node)
            else:
                late_forges.append(node)
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            if isinstance(node.target, ast.Name) and node.target.id == "trace_secret_count":
                if _expr_is_decoy_byte_count(node.value):
                    augments.append(node)
                else:
                    late_forges.append(node)
    if not augments or not init_zeros or late_forges:
        return False
    # Covering re-init after first accumulate is a forge.
    if len(init_zeros) != 1:
        return False
    first_aug = min(getattr(a, "lineno", 0) or 0 for a in augments)
    if (getattr(init_zeros[0], "lineno", 0) or 0) > first_aug:
        return False
    return True


def _flatten_add_terms(node: ast.AST) -> List[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add_terms(node.left) + _flatten_add_terms(node.right)
    return [node]


def _is_name_count_call(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "count":
        return False
    return _name_id(node.func.value) == name


def _is_wire_secret_sum_expr(node: ast.AST) -> bool:
    """Sum of raw_join/approval_blob/blob counts plus trace_secret_count."""
    if isinstance(node, ast.Constant):
        return False
    terms = _flatten_add_terms(node)
    has_raw = has_approval = has_blob = has_trace = False
    for term in terms:
        if _is_name_count_call(term, "raw_join"):
            has_raw = True
        elif _is_name_count_call(term, "approval_blob"):
            has_approval = True
        elif _is_name_count_call(term, "blob"):
            has_blob = True
        elif _name_id(term) == "trace_secret_count":
            has_trace = True
        elif (
            isinstance(term, ast.Call)
            and _name_id(term.func) == "int"
            and term.args
            and _name_id(term.args[0]) == "trace_secret_count"
        ):
            has_trace = True
    return has_raw and has_approval and has_blob and has_trace


def _wire_secret_count_dataflow_ok(
    tree: ast.AST, parents: dict, sink_lineno: int, sink_scope: Optional[ast.AST]
) -> bool:
    """wire_secret_count: exactly one reachable pre-sink multi-carrier sum assign."""
    assigns = _reachable_name_assigns(
        tree, "wire_secret_count", parents, before_lineno=sink_lineno, scope=sink_scope
    )
    if len(assigns) != 1:
        return False
    return _is_wire_secret_sum_expr(assigns[0].value)


def _check_secret_counter_authenticity(tree: ast.AST) -> List[str]:
    """Zero-leak counters must derive from real carriers + membership/count exprs."""
    sink = _find_wire_evidence_sink(tree)
    if sink is None:
        return [
            "mutation:provider_secret_counter_forged",
            "mutation:approval_secret_counter_forged",
            "mutation:result_secret_counter_forged",
            "mutation:trace_or_wire_secret_counter_forged",
        ]
    sink_call, evidence = sink
    parents = _parent_map(tree)
    sink_lineno = getattr(sink_call, "lineno", 0) or 0
    sink_scope = _enclosing_function_scope(sink_call, parents)
    violations: List[str] = []
    provider_inner = _int_call_arg(evidence.get("token_in_provider_raw"))
    if (
        provider_inner is None
        or not _is_token_encode_in_raw_join(provider_inner)
        or not _raw_join_dataflow_ok(tree, parents, sink_lineno, sink_scope)
    ):
        violations.append("mutation:provider_secret_counter_forged")
    approval_inner = _int_call_arg(evidence.get("token_in_approval_raw"))
    if (
        approval_inner is None
        or not _is_name_in_name(approval_inner, "token", "approval_blob")
        or not _approval_blob_dataflow_ok(tree, parents, sink_lineno, sink_scope)
    ):
        violations.append("mutation:approval_secret_counter_forged")
    result_inner = _int_call_arg(evidence.get("token_in_result"))
    if (
        result_inner is None
        or not _is_name_in_name(result_inner, "token", "blob")
        or not _blob_dataflow_ok(tree, parents, sink_lineno, sink_scope)
    ):
        violations.append("mutation:result_secret_counter_forged")
    trace_inner = _int_call_arg(evidence.get("trace_secret_count"))
    wire_inner = _int_call_arg(evidence.get("wire_secret_count"))
    trace_ok = trace_inner is not None and _name_id(trace_inner) == "trace_secret_count"
    wire_ok = wire_inner is not None and _name_id(wire_inner) == "wire_secret_count"
    if not (
        trace_ok
        and wire_ok
        and _trace_secret_count_dataflow_ok(tree, parents, sink_lineno, sink_scope)
        and _wire_secret_count_dataflow_ok(tree, parents, sink_lineno, sink_scope)
    ):
        violations.append("mutation:trace_or_wire_secret_counter_forged")
    return violations


def _wire_script_load_bearing_mutations(text: str) -> List[str]:
    """AST/structural contracts for Round4 load-bearing mutations (wire_script only)."""
    violations: List[str] = []
    try:
        outer = ast.parse(text)
        violations.extend(_check_deny_timeout_mutate_target_hit_guard(outer))
        violations.extend(_check_replay_second_target_delta_guard(outer))
    except SyntaxError:
        pass

    probe = _extract_probe_source(text)
    if probe is None:
        # Full-file carriers without extractable PROBE: treat as missing load-bearing path.
        violations.extend(
            [
                "mutation:second_tool_call_id_changed",
                "mutation:second_args_changed",
                "mutation:host_await_bypassed_with_timeout_text",
            ]
        )
        return list(dict.fromkeys(violations))
    try:
        tree = ast.parse(probe)
    except SyntaxError:
        # Mutation tests require parseable carriers; do not fake-load-bearing on syntax break.
        return list(dict.fromkeys(violations))
    violations.extend(_check_replay_second_identity_reuse(tree))
    violations.extend(_check_host_await_timeout_dataflow(probe, tree))
    violations.extend(_check_secret_counter_authenticity(tree))
    return list(dict.fromkeys(violations))


def validate_r3c_evidence_source(text: str, kind: str) -> List[str]:
    """Unified R3C evidence completeness / authenticity predicate.

    Healthy carriers must yield []. Mutations must feed *mutated* text here
    and observe non-empty violations — never re-assert the original carrier.
    """
    violations: List[str] = []
    for pat, match in _scan_false_green(text):
        violations.append(f"false_green:{pat}:{match}")
    if kind in {"wire_script", "probe_graph", "any"} or kind.startswith("probe"):
        for pat, match in _scan_probe_forbidden(text):
            violations.append(f"probe_forbidden:{pat}:{match}")
    for miss in _missing_evidence_contracts(text, kind):
        violations.append(miss)
    if kind == "wire_script":
        # Specific load-bearing gates first; canonical AST pin is a backstop.
        for hit in _wire_script_load_bearing_mutations(text):
            violations.append(hit)
        for hit in _check_wire_canonical_ast_identity(text):
            violations.append(hit)
    return violations


def _false_green_samples() -> List[str]:
    return [
        'mgr._middleware["tool_request"] = []\n',
        'mgr._hooks["pre_tool_call"] = []\n',
        'mgr._hooks["pre_tool_call"].clear()\n',
        '{"adapter_ok": True, "x": 1}\n',
        '{"process_start_delta": 1}\n',
        '{"http_adapter_delta": 1}\n',
        'order = ["tool_request", "tool_execution", "pre_tool_call", "approval_gate", "handler", "consume", "resolve", "adapter"]\n',
        'counts["consume"] = 1\n',
        "wire_secret_count = 0\n",
        '{"loopback_only": True}\n',
        '{"used_environ_copy": False}\n',
    ]


@pytest.mark.parametrize("path", _TARGETS, ids=lambda p: p.name)
def test_r3c_gate_rejects_false_green_patterns(path: Path):
    assert path.is_file(), path
    text = path.read_text(encoding="utf-8")
    hits = _scan_false_green(text)
    assert hits == [], f"{path.name} false-green hits: {hits}"


@pytest.mark.parametrize("path", _TARGETS, ids=lambda p: p.name)
def test_r3c_gate_probe_forbids_self_register_and_environ_copy(path: Path):
    text = path.read_text(encoding="utf-8")
    hits = _scan_probe_forbidden(text)
    assert hits == [], f"{path.name} probe authenticity hits: {hits}"


def test_r3c_gate_all_carriers_pass_unified_predicate():
    carriers: Sequence[Tuple[Path, str]] = (
        (REPO / "scripts" / "run_r3c_wire_e2e.py", "wire_script"),
        (REPO / "tests" / "test_r3c_wire_e2e.py", "wire_tests"),
        (REPO / "tests" / "test_r3c_plugin_manager_graph.py", "probe_graph"),
        (REPO / "scripts" / "run_r3c_e2e.py", "e2e_runner"),
    )
    for path, kind in carriers:
        text = path.read_text(encoding="utf-8")
        violations = validate_r3c_evidence_source(text, kind)
        assert violations == [], f"{path.name}/{kind}: {violations}"


def test_r3c_gate_mutation_cover_callback_list_hits_predicate():
    sample = 'mgr._middleware["tool_request"] = []\nmgr._hooks["pre_tool_call"].clear()\n'
    assert validate_r3c_evidence_source(sample, "any")


def test_r3c_gate_mutation_self_built_ctx_hits_predicate():
    sample = "class Ctx:\n    pass\nregistry.deregister(name)\nregister(Ctx(mgr))\n"
    assert validate_r3c_evidence_source(sample, "wire_script")


def test_r3c_gate_mutation_hardcoded_order_counts_zero_hits_predicate():
    for sample in _false_green_samples():
        assert validate_r3c_evidence_source(sample, "any"), sample


def test_r3c_gate_mutation_delete_raw_provider_bytes_hits_predicate():
    wire = (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace("raw_requests", "TOKEN_ABSENT")
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("raw_requests" in x for x in v)


def test_r3c_gate_mutation_delete_approval_raw_hits_predicate():
    wire = (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")
    mutated = wire.replace("approval_raw", "TOKEN_ABSENT")
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("approval_raw" in x for x in v)


def test_r3c_gate_mutation_delete_one_adapter_hits_predicate():
    wire = (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")
    for name in ("http_approve", "env_approve", "stdin_approve"):
        mutated = wire.replace(name, "TOKEN_ABSENT")
        assert name not in mutated
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"deleting {name} must violate"
        assert any(name in x or "missing" in x for x in v)


def test_r3c_gate_mutation_environ_copy_hits_predicate():
    wire = (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")
    mutated = wire + "\nenv = os.environ.copy()\n"
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("environ" in x or "copy" in x for x in v)


def test_r3c_gate_mutation_delete_socket_bomb_spy_hits_predicate():
    wire = (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")
    mutated = (
        wire.replace("_bomb_connect", "_dropped_bomb")
        .replace("_guard_connect", "_dropped_guard")
        .replace("non_loopback_original_calls", "dropped_non_loopback")
    )
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v


def test_r3c_gate_mutation_internal_middleware_only_hits_predicate():
    # Direct internal middleware without public Agent must violate wire_script kind.
    fake = (
        "raw_requests = []\napproval_raw = []\nwire_secret_count = derived\n"
        "127.0.0.1\nraw_http_has_request_line\nraw_http_has_headers\nraw_http_has_body\n"
        "non_loopback_original_calls\n_bomb_connect\n_guard_connect\n_minimal_child_env\n"
        "sys.setprofile\nhttp_approve\nenv_approve\nstdin_approve\nexecute_http\nexecute_process\n"
        "_run_agent_tool_execution_middleware(agent, ...)\n"
    )
    v = validate_r3c_evidence_source(fake, "wire_script")
    assert v
    assert any("public_agent" in x or "middleware_only" in x or "AIAgent" in x for x in v)


def test_r3c_gate_mutation_delete_fail_close_tokens_hits_predicate():
    wire = (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")
    for name in (
        "http_replay",
        "env_replay",
        "stdin_replay",
        "http_mutate",
        "env_mutate",
        "stdin_mutate",
        "http_timeout",
        "env_timeout",
        "stdin_timeout",
        "approval_timeout_branch",
        "trace_artifact_count",
        "parent_env_secret_count",
        "followup_child_status",
        "host_approval_raw",
        "tool_request_identities",
        "replay_identity_same",
        "trace_inventory",
        "manifest_bytes_identical",
        "_await_gateway_decision",
    ):
        mutated = wire.replace(name, "TOKEN_ABSENT")
        assert name not in mutated
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"deleting {name} must violate"
        assert any(name in x or "missing" in x for x in v)


def test_r3c_gate_mutation_hardcoded_identity_unchanged_hits_predicate():
    # Split literal so this test file does not self-trip the probe_graph carrier scan.
    sample = 'print(json.dumps({"identity_unchanged"' + ": True}))\n"
    v = validate_r3c_evidence_source(sample, "probe_graph")
    assert v
    assert any("identity_unchanged" in x for x in v)


def test_r3c_gate_mutation_exit0_hardcoded_pass_hits_predicate():
    sample = 'print("PASS")\nexit(0)\nwire_secret_count = 0\n'
    assert validate_r3c_evidence_source(sample, "any")


def _wire_carrier() -> str:
    return (REPO / "scripts" / "run_r3c_wire_e2e.py").read_text(encoding="utf-8")


def _second_replay_tool_calls_needle() -> str:
    # Exact second-issuance payload fragment inside PROBE (must stay parseable).
    return (
        'elif _replay_second_issued["n"] == 0:\n'
        '                _replay_second_issued["n"] = 1\n'
        '                resp = {\n'
        '                    "id": "c1b", "object": "chat.completion", "created": 1, "model": "fake-model",\n'
        '                    "choices": [{"index": 0, "message": {"role": "assistant", "content": None,\n'
        '                        "tool_calls": [{"id": first_tool_call_id, "type": "function",\n'
        '                            "function": {"name": tool_name, "arguments": first_serialized_args}}]},'
    )


def test_r3c_gate_mutation_second_replay_tool_call_id_changed_hits_same_predicate():
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = _second_replay_tool_calls_needle()
    assert needle in wire
    # Replace only inside the second-issuance branch (c1b), not the first (c1).
    mutated = wire.replace(
        needle,
        needle.replace(
            '"id": first_tool_call_id',
            '"id": "call_mutated_second"',
            1,
        ),
        1,
    )
    assert '"id": "call_mutated_second"' in mutated
    assert mutated != wire
    ast.parse(mutated)  # mutation remains parseable
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:second_tool_call_id_changed" in v


def test_r3c_gate_mutation_second_replay_args_changed_hits_same_predicate():
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = _second_replay_tool_calls_needle()
    assert needle in wire
    mutated = wire.replace(
        needle,
        needle.replace(
            '"arguments": first_serialized_args',
            '"arguments": "{\\"mutated\\": true}"',
            1,
        ),
        1,
    )
    assert "mutated" in mutated
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:second_args_changed" in v


def test_r3c_gate_mutation_bypass_host_await_with_timeout_text_hits_same_predicate():
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    # Bypass real host function object in setprofile mapping; keep timeout wording.
    mutated = wire.replace(
        '(approval_mod._await_gateway_decision, "_await_gateway_decision"),',
        '(lambda: None, "_await_gateway_decision"),',
        1,
    )
    assert "timed out without user response" in mutated
    assert "Silence is not consent" in mutated
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:host_await_bypassed_with_timeout_text" in v

    # Forging await_gateway_call_count out of the timeout branch also RED.
    forged = wire.replace(
        "and await_gateway_call_count > 0\n",
        "and True  # forged await count\n",
        1,
    )
    assert forged != wire
    ast.parse(forged)
    v2 = validate_r3c_evidence_source(forged, "wire_script")
    assert v2
    assert "mutation:host_await_bypassed_with_timeout_text" in v2

    # Constant forge of the call counter also RED.
    forged_const = wire.replace(
        "await_gateway_call_count = 0\n",
        "await_gateway_call_count = 1\n",
        1,
    )
    assert forged_const != wire
    ast.parse(forged_const)
    v3 = validate_r3c_evidence_source(forged_const, "wire_script")
    assert v3
    assert "mutation:host_await_bypassed_with_timeout_text" in v3


def test_r3c_gate_unrelated_comment_does_not_trip_load_bearing_mutations():
    """Reverse protection: true comment/format noise must not false-positive load-bearing hits."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    # Real Python comments / trailing comments outside string constants — AST unchanged.
    noisy = wire + "\n# unrelated formatting/comment noise for reverse protection\n"
    noisy = noisy.replace(
        "if __name__ == \"__main__\":\n",
        "if __name__ == \"__main__\":  # trailing comment only\n",
        1,
    )
    assert noisy != wire
    ast.parse(noisy)
    assert _canonical_ast_digest(noisy) == _WIRE_CANONICAL_AST_SHA256
    v = validate_r3c_evidence_source(noisy, "wire_script")
    assert v == []
    assert "mutation:second_tool_call_id_changed" not in v
    assert "mutation:second_args_changed" not in v
    assert "mutation:host_await_bypassed_with_timeout_text" not in v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" not in v
    assert "mutation:replay_second_target_delta_guard_weakened" not in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v
    assert "mutation:wire_canonical_ast_drift" not in v


def test_r3c_reclosure_mutation_reinstall_transport_override_is_red():
    """Mutation 1: re-install transport override on HTTP approve path → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = (
        wire
        + "\nte_mod.set_http_transport_override_for_tests(lambda req: "
        + '{"status":201,"headers":{},"body":b"{}"})\n'
    )
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("http_transport_override" in x for x in v)


def test_r3c_reclosure_mutation_forge_target_hits_without_default_transport_is_red():
    """Mutation 2: bypass _default_transport but forge http_target_hits=1 → RED."""
    wire = _wire_carrier()
    mutated = wire.replace("_default_transport", "TOKEN_ABSENT")
    mutated = mutated + '\nprint({"http_target_hits": 1})\n'
    assert "_default_transport" not in mutated
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any(
        "_default_transport" in x or "http_target_hits" in x or "hardcoded" in x
        for x in v
    )


def test_r3c_reclosure_mutation_plaintext_or_verify_false_is_red():
    """Mutation 3 (R8): verify=False / insecure flags / illegal scheme / downgrade → RED.

    Absolute plaintext-http ban is retired; binding-selected http is covered by R8 tests.
    """
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []

    m1 = wire + "\nverify=False\n"
    v1 = validate_r3c_evidence_source(m1, "wire_script")
    assert v1
    assert any("tls_verify" in x or "verify" in x for x in v1)

    m2 = wire + "\nallow_redirects=True\n"
    v2 = validate_r3c_evidence_source(m2, "wire_script")
    assert v2
    assert any("insecure_transport" in x for x in v2)

    m3 = wire + "\ntrust_env=True\n"
    v3 = validate_r3c_evidence_source(m3, "wire_script")
    assert v3
    assert any("insecure_transport" in x for x in v3)

    m4 = wire + '\n_bad = {"scheme": "ftp"}\n'
    v4 = validate_r3c_evidence_source(m4, "wire_script")
    assert v4
    assert any("illegal_scheme" in x for x in v4)

    m5 = wire + '\nurl = url.replace("https://", "http://")\n'
    v5 = validate_r3c_evidence_source(m5, "wire_script")
    assert v5
    assert any("downgrade" in x for x in v5)

    # Production gate section ends before the first test_ function.
    gate_body = Path(REPO / "tests" / "test_r3c_evidence_authenticity_gate.py").read_text(
        encoding="utf-8"
    ).split("\ndef test_", 1)[0]
    assert "forbidden:plaintext_http_scheme" not in gate_body
    assert "forbidden:plaintext_loopback_url" not in gate_body
    assert "forbidden:illegal_scheme" in gate_body
    assert "forbidden:https_to_http_downgrade" in gate_body
    assert "forbidden:insecure_transport_flags" in gate_body


def test_r3c_reclosure_mutation_hardcoded_target_hits_is_red():
    """Mutation 4: forge approve target hits as constant 1 → RED."""
    wire = _wire_carrier()
    mutated = wire + '\nprint({"http_target_hits": 1})\n'
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any("http_target_hits" in x for x in v)


def test_r3c_reclosure_mutation_delete_socket_guard_is_red():
    """Mutation 7: delete real socket guard/loopback bomb → RED."""
    wire = _wire_carrier()
    mutated = (
        wire.replace("_bomb_connect", "TOKEN_ABSENT")
        .replace("_guard_connect", "TOKEN_ABSENT")
        .replace("non_loopback_original_calls", "TOKEN_ABSENT")
    )
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert any(
        "bomb" in x or "guard" in x or "non_loopback" in x or "missing" in x for x in v
    )


def test_r3c_reclosure_mutation_comment_only_stays_green():
    """Mutation 8: unrelated comment/format noise stays GREEN on same predicate."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    noisy = wire + "\n# reclosure comment-only mutation\n"
    assert validate_r3c_evidence_source(noisy, "wire_script") == []


def test_r3c_reclosure_mutation5_weaken_deny_timeout_mutate_target_hits_is_red():
    """Mutation 5a: deny/timeout/mutate http_target_hits == 0 → <= 1 must RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = (
        '            assert r["http_target_hits"] == 0\n'
        '            assert r["default_transport_enter_count"] == 0'
    )
    assert needle in wire
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        '            assert r["http_target_hits"] <= 1\n'
        '            assert r["default_transport_enter_count"] == 0',
        1,
    )
    assert 'assert r["http_target_hits"] <= 1' in mutated
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v
    assert "mutation:replay_second_target_delta_guard_weakened" not in v


def test_r3c_reclosure_mutation5_weaken_replay_second_delta_is_red():
    """Mutation 5b: replay second_http_target_delta == 0 → <= 1 must RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = '                assert r["second_http_target_delta"] == 0'
    assert needle in wire
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, '                assert r["second_http_target_delta"] <= 1', 1)
    assert 'assert r["second_http_target_delta"] <= 1' in mutated
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" not in v


def test_r3c_reclosure_mutation6_forge_provider_secret_counter_is_red():
    """Mutation 6a: forge token_in_provider_raw to constant False → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = '"token_in_provider_raw": int(token.encode("utf-8") in raw_join)'
    assert needle in wire
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, '"token_in_provider_raw": int(False)', 1)
    assert '"token_in_provider_raw": int(False)' in mutated
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_mutation6_forge_approval_secret_counter_is_red():
    """Mutation 6b: forge token_in_approval_raw to constant False → RED."""
    wire = _wire_carrier()
    needle = '"token_in_approval_raw": int(token in approval_blob)'
    assert needle in wire
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, '"token_in_approval_raw": int(False)', 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v


def test_r3c_reclosure_mutation6_forge_result_secret_counter_is_red():
    """Mutation 6c: forge token_in_result to constant False → RED."""
    wire = _wire_carrier()
    needle = '"token_in_result": int(token in blob)'
    assert needle in wire
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, '"token_in_result": int(False)', 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v


def test_r3c_reclosure_mutation6_forge_trace_or_wire_secret_counter_is_red():
    """Mutation 6d: forge trace_secret_count / wire_secret_count to int(0) → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle_trace = '"trace_secret_count": int(trace_secret_count)'
    assert needle_trace in wire
    assert wire.count(needle_trace) == 1
    m_trace = wire.replace(needle_trace, '"trace_secret_count": int(0)', 1)
    assert m_trace != wire
    ast.parse(m_trace)
    v_trace = validate_r3c_evidence_source(m_trace, "wire_script")
    assert v_trace
    assert "mutation:trace_or_wire_secret_counter_forged" in v_trace
    assert "mutation:provider_secret_counter_forged" not in v_trace

    needle_wire = '"wire_secret_count": int(wire_secret_count)'
    assert needle_wire in wire
    assert wire.count(needle_wire) == 1
    m_wire = wire.replace(needle_wire, '"wire_secret_count": int(0)', 1)
    assert m_wire != wire
    ast.parse(m_wire)
    v_wire = validate_r3c_evidence_source(m_wire, "wire_script")
    assert v_wire
    assert "mutation:trace_or_wire_secret_counter_forged" in v_wire


_DENY_TIMEOUT_MUTATE_LOOP = (
    "        for name in (\n"
    '            "http_deny",\n'
    '            "env_deny",\n'
    '            "stdin_deny",\n'
    '            "http_timeout",\n'
    '            "env_timeout",\n'
    '            "stdin_timeout",\n'
    '            "http_mutate",\n'
    '            "env_mutate",\n'
    '            "stdin_mutate",\n'
    "        ):"
)

_DENY_TIMEOUT_MUTATE_SCENARIO_ORDER = (
    "http_deny",
    "env_deny",
    "stdin_deny",
    "http_timeout",
    "env_timeout",
    "stdin_timeout",
    "http_mutate",
    "env_mutate",
    "stdin_mutate",
)


def test_r3c_reclosure_round2_mutation5_delete_each_scenario_from_loop_is_red():
    """Round2 Blocker A: deleting any one of the nine loop scenarios must RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    assert wire.count(_DENY_TIMEOUT_MUTATE_LOOP) == 1
    for dropped in _DENY_TIMEOUT_MUTATE_SCENARIO_ORDER:
        remaining = [s for s in _DENY_TIMEOUT_MUTATE_SCENARIO_ORDER if s != dropped]
        new_loop = (
            "        for name in (\n"
            + "".join(f'            "{s}",\n' for s in remaining)
            + "        ):"
        )
        mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, new_loop, 1)
        assert mutated != wire
        assert f'"{dropped}"' not in new_loop
        ast.parse(mutated)
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"deleting {dropped} from summary loop must violate"
        assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v, dropped
        assert "mutation:replay_second_target_delta_guard_weakened" not in v


def test_r3c_reclosure_round2_mutation5_shrink_loop_to_three_is_red():
    """Round2 Blocker A: shrinking the nine-scenario loop to any three must RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    three = (
        "        for name in (\n"
        '            "http_deny",\n'
        '            "env_deny",\n'
        '            "stdin_deny",\n'
        "        ):"
    )
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, three, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v
    assert "mutation:replay_second_target_delta_guard_weakened" not in v


def test_r3c_reclosure_round2_mutation6_forge_raw_join_upstream_is_red():
    """Round2 Blocker B: raw_join = b'' (drop join(raw_requests)) → provider forged."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = 'raw_join = b"\\n".join(raw_requests)'
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, 'raw_join = b""', 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round2_mutation6_forge_approval_blob_upstream_is_red():
    """Round2 Blocker B: approval_blob = '' (drop json.dumps(approval_raw)) → RED."""
    wire = _wire_carrier()
    needle = "approval_blob = json.dumps(approval_raw, default=str)"
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, 'approval_blob = ""', 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round2_mutation6_forge_result_blob_upstream_is_red():
    """Round2 Blocker B: blob = '' (drop result carrier assembly) → RED."""
    wire = _wire_carrier()
    needle = (
        "blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result"
    )
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, 'blob = ""', 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round2_mutation6_forge_trace_accumulate_upstream_is_red():
    """Round2 Blocker B: delete decoy accumulate / force trace_secret_count=0 → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle_acc = 'trace_secret_count += data.count(decoy.encode("utf-8"))'
    assert wire.count(needle_acc) == 1
    m_del = wire.replace(needle_acc, "pass  # deleted decoy accumulate", 1)
    assert m_del != wire
    ast.parse(m_del)
    v_del = validate_r3c_evidence_source(m_del, "wire_script")
    assert v_del
    assert "mutation:trace_or_wire_secret_counter_forged" in v_del
    assert "mutation:provider_secret_counter_forged" not in v_del

    # Force to 0 after real scan, before evidence emission.
    force_needle = "trace_artifact_count = len(trace_inventory)\n"
    assert wire.count(force_needle) == 1
    m_force = wire.replace(
        force_needle,
        "trace_artifact_count = len(trace_inventory)\ntrace_secret_count = 0\n",
        1,
    )
    assert m_force != wire
    ast.parse(m_force)
    v_force = validate_r3c_evidence_source(m_force, "wire_script")
    assert v_force
    assert "mutation:trace_or_wire_secret_counter_forged" in v_force
    assert "mutation:provider_secret_counter_forged" not in v_force


def test_r3c_reclosure_round2_mutation6_forge_wire_secret_derive_upstream_is_red():
    """Round2 Blocker B: replace real wire_secret_count sum with constant 0 → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, "wire_secret_count = 0", 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


_NINE_SCENARIO_STRICT_LOOP_BODY = (
    "    for name in (\n"
    '        "http_deny",\n'
    '        "env_deny",\n'
    '        "stdin_deny",\n'
    '        "http_timeout",\n'
    '        "env_timeout",\n'
    '        "stdin_timeout",\n'
    '        "http_mutate",\n'
    '        "env_mutate",\n'
    '        "stdin_mutate",\n'
    "    ):\n"
    "        r = results[name]\n"
    '        assert r["http_target_hits"] == 0\n'
)

_THREE_SCENARIO_LOOP = (
    "        for name in (\n"
    '            "http_deny",\n'
    '            "env_deny",\n'
    '            "stdin_deny",\n'
    "        ):"
)

_HEALTHY_EVIDENCE_DICT_LITERAL = (
    '{"token_in_provider_raw": int(token.encode("utf-8") in raw_join), '
    '"token_in_approval_raw": int(token in approval_blob), '
    '"token_in_result": int(token in blob), '
    '"trace_secret_count": int(trace_secret_count), '
    '"wire_secret_count": int(wire_secret_count)}'
)


def test_r3c_reclosure_round3_shrink_loop_module_if_false_decoy_is_red():
    """Round3: shrink real nine-loop to 3 + module-level if False: nine decoy → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    mutated = mutated + "\nif False:\n" + _NINE_SCENARIO_STRICT_LOOP_BODY
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v


def test_r3c_reclosure_round3_shrink_loop_main_if_false_decoy_is_red():
    """Round3: shrink real nine-loop to 3 + main() if False: nine decoy → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    needle = "        return 0\n    except Exception as exc:"
    assert needle in mutated
    decoy = (
        "        if False:\n"
        "            for name in (\n"
        '                "http_deny",\n'
        '                "env_deny",\n'
        '                "stdin_deny",\n'
        '                "http_timeout",\n'
        '                "env_timeout",\n'
        '                "stdin_timeout",\n'
        '                "http_mutate",\n'
        '                "env_mutate",\n'
        '                "stdin_mutate",\n'
        "            ):\n"
        "                r = results[name]\n"
        '                assert r["http_target_hits"] == 0\n'
        "        return 0\n    except Exception as exc:"
    )
    mutated = mutated.replace(needle, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v


def test_r3c_reclosure_round3_forge_provider_with_unused_decoy_dicts_is_red():
    """Round3: forge authoritative sink provider; unused healthy decoy dicts must not mask."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = '"token_in_provider_raw": int(token.encode("utf-8") in raw_join)'
    assert wire.count(needle) == 1
    # Forge the authoritative sink first so decoy literals cannot steal the replace.
    mutated = wire.replace(needle, '"token_in_provider_raw": int(False)', 1)
    decoy_assign = f"_unused_decoy_ev = {_HEALTHY_EVIDENCE_DICT_LITERAL}\n"
    sink_start = 'print(json.dumps({\n    "scenario": scenario,'
    assert mutated.count(sink_start) == 1
    mutated = mutated.replace(sink_start, decoy_assign + sink_start, 1)
    # Also place a healthy decoy after the authoritative sink.
    end = "}, sort_keys=True))"
    idx = mutated.find('"token_in_provider_raw": int(False)')
    pos = mutated.find(end, idx)
    assert pos > 0
    insert_at = pos + len(end)
    mutated = (
        mutated[:insert_at]
        + "\n_unused_decoy_ev_after = "
        + _HEALTHY_EVIDENCE_DICT_LITERAL
        + mutated[insert_at:]
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round3_raw_join_only_in_if_false_is_red():
    """Round3: delete reachable raw_join; healthy join only under if False → provider RED."""
    wire = _wire_carrier()
    needle = 'raw_join = b"\\n".join(raw_requests)'
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        'if False:\n    raw_join = b"\\n".join(raw_requests)',
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round3_approval_blob_only_in_if_false_is_red():
    """Round3: approval_blob healthy assign only under if False → approval RED."""
    wire = _wire_carrier()
    needle = "approval_blob = json.dumps(approval_raw, default=str)"
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "if False:\n    approval_blob = json.dumps(approval_raw, default=str)",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round3_blob_only_in_if_false_is_red():
    """Round3: blob healthy assign only under if False → result RED."""
    wire = _wire_carrier()
    needle = (
        "blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result"
    )
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "if False:\n    blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round3_trace_accumulate_only_in_if_false_is_red():
    """Round3: delete reachable trace accumulate; healthy += only under if False → RED."""
    wire = _wire_carrier()
    needle = '            trace_secret_count += data.count(decoy.encode("utf-8"))'
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "            if False:\n"
        '                trace_secret_count += data.count(decoy.encode("utf-8"))',
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    probe = _extract_probe_source(mutated)
    assert probe is not None
    ast.parse(probe)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_round3_wire_secret_only_in_if_false_is_red():
    """Round3: forge reachable wire_secret_count; healthy sum only under if False → RED."""
    wire = _wire_carrier()
    needle = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    assert wire.count(needle) == 1
    healthy = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    mutated = wire.replace(
        needle,
        "wire_secret_count = int(False)\nif False:\n    " + healthy.replace("\n", "\n    "),
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_round3_comment_and_reachable_format_stay_green():
    """Round3 GREEN: healthy carrier, comment-only, reachable no-op format stay GREEN."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    comment = wire + "\n# round3 reachable-path comment-only noise\n"
    assert validate_r3c_evidence_source(comment, "wire_script") == []
    # Reachable no-semantic whitespace inside main summary loop header.
    spaced = wire.replace(
        _DENY_TIMEOUT_MUTATE_LOOP,
        _DENY_TIMEOUT_MUTATE_LOOP.replace("for name in (", "for name in  (", 1),
        1,
    )
    assert spaced != wire
    ast.parse(spaced)
    assert validate_r3c_evidence_source(spaced, "wire_script") == []


_HEALTHY_NINE_LOOP_IN_NESTED = (
    "            for name in (\n"
    '                "http_deny",\n'
    '                "env_deny",\n'
    '                "stdin_deny",\n'
    '                "http_timeout",\n'
    '                "env_timeout",\n'
    '                "stdin_timeout",\n'
    '                "http_mutate",\n'
    '                "env_mutate",\n'
    '                "stdin_mutate",\n'
    "            ):\n"
    "                r = results[name]\n"
    '                assert r["http_target_hits"] == 0\n'
)

_HEALTHY_SINK_PRINT = (
    "print(json.dumps({\n"
    '    "token_in_provider_raw": int(token.encode("utf-8") in raw_join),\n'
    '    "token_in_approval_raw": int(token in approval_blob),\n'
    '    "token_in_result": int(token in blob),\n'
    '    "trace_secret_count": int(trace_secret_count),\n'
    '    "wire_secret_count": int(wire_secret_count),\n'
    "}, sort_keys=True))"
)


def test_r3c_reclosure_round4_shrink_loop_nested_never_called_def_is_red():
    """Round4: shrink real nine-loop; healthy nine only in never-called nested def → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    needle = "        return 0\n    except Exception as exc:"
    assert needle in mutated
    decoy = (
        "        def never_called_decoy():\n"
        + _HEALTHY_NINE_LOOP_IN_NESTED
        + "        return 0\n    except Exception as exc:"
    )
    mutated = mutated.replace(needle, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v


def test_r3c_reclosure_round4_shrink_loop_nested_never_called_async_def_is_red():
    """Round4: same as nested def but async def never_called_decoy → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    needle = "        return 0\n    except Exception as exc:"
    decoy = (
        "        async def never_called_decoy():\n"
        + _HEALTHY_NINE_LOOP_IN_NESTED
        + "        return 0\n    except Exception as exc:"
    )
    mutated = mutated.replace(needle, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v


def test_r3c_reclosure_round4_raw_join_only_in_never_called_fn_is_red():
    """Round4: delete reachable raw_join; healthy join only in never-called fn → provider RED."""
    wire = _wire_carrier()
    needle = 'raw_join = b"\\n".join(raw_requests)'
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        'def never_called_raw_join():\n    raw_join = b"\\n".join(raw_requests)\n',
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    probe = _extract_probe_source(mutated)
    assert probe is not None
    ast.parse(probe)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round4_approval_blob_only_in_never_called_fn_is_red():
    """Round4: approval_blob healthy assign only in never-called fn → approval RED."""
    wire = _wire_carrier()
    needle = "approval_blob = json.dumps(approval_raw, default=str)"
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "def never_called_approval_blob():\n"
        "    approval_blob = json.dumps(approval_raw, default=str)\n",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round4_blob_only_in_never_called_fn_is_red():
    """Round4: blob healthy assign only in never-called fn → result RED."""
    wire = _wire_carrier()
    needle = (
        "blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result"
    )
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "def never_called_blob():\n"
        "    blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result\n",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round4_trace_accumulate_only_in_never_called_fn_is_red():
    """Round4: delete reachable trace accumulate; healthy += only in never-called fn → RED."""
    wire = _wire_carrier()
    needle = '            trace_secret_count += data.count(decoy.encode("utf-8"))'
    assert wire.count(needle) == 1
    # Replace reachable accumulate with pass; append never-called healthy accumulate.
    mutated = wire.replace(needle, "            pass  # deleted reachable accumulate", 1)
    insert_at = 'print(json.dumps({\n    "scenario": scenario,'
    assert mutated.count(insert_at) == 1
    decoy_fn = (
        "def never_called_trace_acc():\n"
        '    trace_secret_count += data.count(decoy.encode("utf-8"))\n'
    )
    mutated = mutated.replace(insert_at, decoy_fn + insert_at, 1)
    assert mutated != wire
    ast.parse(mutated)
    probe = _extract_probe_source(mutated)
    assert probe is not None
    ast.parse(probe)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_round4_wire_secret_only_in_never_called_fn_is_red():
    """Round4: forge reachable wire_secret_count; healthy sum only in never-called fn → RED."""
    wire = _wire_carrier()
    needle = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    assert wire.count(needle) == 1
    healthy = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    mutated = wire.replace(
        needle,
        "wire_secret_count = int(False)\n"
        "def never_called_wire_secret():\n"
        "    " + healthy.replace("\n", "\n    ") + "\n",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_round4_decoy_sink_in_other_fn_does_not_mask_forge():
    """Round4: forge authoritative sink; healthy sink in other fn must not mask or ambiguate."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    needle = '"token_in_provider_raw": int(token.encode("utf-8") in raw_join)'
    assert wire.count(needle) == 1
    mutated = wire.replace(needle, '"token_in_provider_raw": int(False)', 1)
    # Place a healthy evidence sink inside a never-called function (must not count).
    insert_at = 'print(json.dumps({\n    "scenario": scenario,'
    assert mutated.count(insert_at) == 1
    decoy = (
        "def never_called_decoy_sink():\n"
        "    " + _HEALTHY_SINK_PRINT.replace("\n", "\n    ") + "\n"
    )
    mutated = mutated.replace(insert_at, decoy + insert_at, 1)
    assert mutated != wire
    ast.parse(mutated)
    probe = _extract_probe_source(mutated)
    assert probe is not None
    ast.parse(probe)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v

    # Unused decoy sink fn is an AST semantic change: must RED via canonical drift backstop
    # (load-bearing gates alone may stay quiet when the authoritative sink is intact).
    healthy_plus = wire.replace(
        insert_at,
        "def never_called_decoy_sink():\n"
        "    " + _HEALTHY_SINK_PRINT.replace("\n", "\n    ") + "\n"
        + insert_at,
        1,
    )
    assert healthy_plus != wire
    ast.parse(healthy_plus)
    v_plus = validate_r3c_evidence_source(healthy_plus, "wire_script")
    assert v_plus
    assert "mutation:wire_canonical_ast_drift" in v_plus
    assert "mutation:provider_secret_counter_forged" not in v_plus


def test_r3c_reclosure_round4_comment_only_stays_green():
    """Round4 GREEN: healthy carrier and comment-only stay GREEN."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    comment = wire + "\n# round4 lexical-scope comment-only noise\n"
    assert validate_r3c_evidence_source(comment, "wire_script") == []


_MAIN_RETURN_NEEDLE = "        return 0\n    except Exception as exc:"

_REPLAY_STRICT_ASSERT = '                assert r["second_http_target_delta"] == 0'

_HEALTHY_NINE_LOOP_UNDER_MAIN = (
    "            for name in (\n"
    '                "http_deny",\n'
    '                "env_deny",\n'
    '                "stdin_deny",\n'
    '                "http_timeout",\n'
    '                "env_timeout",\n'
    '                "stdin_timeout",\n'
    '                "http_mutate",\n'
    '                "env_mutate",\n'
    '                "stdin_mutate",\n'
    "            ):\n"
    "                r = results[name]\n"
    '                assert r["http_target_hits"] == 0\n'
)


def test_r3c_reclosure_round5_shrink_loop_main_while_false_decoy_is_red():
    """Round5: shrink real nine-loop to 3 + main() while False: nine decoy → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    assert _MAIN_RETURN_NEEDLE in mutated
    decoy = (
        "        while False:\n"
        + _HEALTHY_NINE_LOOP_UNDER_MAIN
        + _MAIN_RETURN_NEEDLE
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v


def test_r3c_reclosure_round5_shrink_loop_empty_for_decoy_is_red():
    """Round5: shrink real nine-loop; healthy nine under for _ in () / [] → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    for empty_iter in ("()", "[]"):
        mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
        decoy = (
            f"        for _ in {empty_iter}:\n"
            + _HEALTHY_NINE_LOOP_UNDER_MAIN
            + _MAIN_RETURN_NEEDLE
        )
        mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
        assert mutated != wire
        ast.parse(mutated)
        v = validate_r3c_evidence_source(mutated, "wire_script")
        assert v, f"empty for {empty_iter} decoy must violate"
        assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v, empty_iter


def test_r3c_reclosure_round5_authoritative_sink_in_while_false_is_red():
    """Round5: wrap authoritative evidence sink in while False → four counters fail closed."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    sink_start = 'print(json.dumps({\n    "scenario": scenario,'
    assert wire.count(sink_start) == 1
    idx = wire.find(sink_start)
    end = "}, sort_keys=True))"
    end_idx = wire.find(end, idx)
    assert end_idx > 0
    full_sink = wire[idx : end_idx + len(end)]
    wrapped = "while False:\n    " + full_sink.replace("\n", "\n    ")
    mutated = wire[:idx] + wrapped + wire[end_idx + len(end) :]
    assert mutated != wire
    ast.parse(mutated)
    probe = _extract_probe_source(mutated)
    assert probe is not None
    ast.parse(probe)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:trace_or_wire_secret_counter_forged" in v


def test_r3c_reclosure_round5_authoritative_sink_in_empty_for_is_red():
    """Round5: wrap authoritative sink in for _ in () → four counters fail closed."""
    wire = _wire_carrier()
    sink_start = 'print(json.dumps({\n    "scenario": scenario,'
    idx = wire.find(sink_start)
    end = "}, sort_keys=True))"
    end_idx = wire.find(end, idx)
    full_sink = wire[idx : end_idx + len(end)]
    wrapped = "for _ in ():\n    " + full_sink.replace("\n", "\n    ")
    mutated = wire[:idx] + wrapped + wire[end_idx + len(end) :]
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:trace_or_wire_secret_counter_forged" in v


def test_r3c_reclosure_round5_replay_assert_only_in_never_called_def_is_red():
    """Round5: delete real replay ==0; healthy assert only in never-called def → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    assert wire.count(_REPLAY_STRICT_ASSERT) == 1
    mutated = wire.replace(_REPLAY_STRICT_ASSERT, "                pass  # deleted replay strict", 1)
    decoy = (
        "        def never_called_replay():\n"
        '            assert r["second_http_target_delta"] == 0\n'
        + _MAIN_RETURN_NEEDLE
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" not in v


def test_r3c_reclosure_round5_replay_assert_only_in_never_called_async_def_is_red():
    """Round5: delete real replay ==0; healthy assert only in never-called async def → RED."""
    wire = _wire_carrier()
    mutated = wire.replace(_REPLAY_STRICT_ASSERT, "                pass  # deleted replay strict", 1)
    decoy = (
        "        async def never_called_replay():\n"
        '            assert r["second_http_target_delta"] == 0\n'
        + _MAIN_RETURN_NEEDLE
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v


def test_r3c_reclosure_round5_replay_assert_only_in_lambda_is_red():
    """Round5: delete real replay ==0; healthy ==0 only inside never-used lambda → RED."""
    wire = _wire_carrier()
    mutated = wire.replace(_REPLAY_STRICT_ASSERT, "                pass  # deleted replay strict", 1)
    # Lambda cannot host Assert statements; a Compare inside lambda must not testify.
    decoy = (
        '        _ = (lambda: r["second_http_target_delta"] == 0)\n'
        + _MAIN_RETURN_NEEDLE
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v


def test_r3c_reclosure_round5_replay_assert_only_in_if_false_is_red():
    """Round5: delete real replay ==0; healthy assert only under if False → RED."""
    wire = _wire_carrier()
    mutated = wire.replace(_REPLAY_STRICT_ASSERT, "                pass  # deleted replay strict", 1)
    decoy = (
        "        if False:\n"
        '            assert r["second_http_target_delta"] == 0\n'
        + _MAIN_RETURN_NEEDLE
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v


def test_r3c_reclosure_round5_replay_assert_only_in_while_false_is_red():
    """Round5: delete real replay ==0; healthy assert only under while False → RED."""
    wire = _wire_carrier()
    mutated = wire.replace(_REPLAY_STRICT_ASSERT, "                pass  # deleted replay strict", 1)
    decoy = (
        "        while False:\n"
        '            assert r["second_http_target_delta"] == 0\n'
        + _MAIN_RETURN_NEEDLE
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v


def test_r3c_reclosure_round5_comment_only_stays_green():
    """Round5 GREEN: healthy carrier and comment-only stay GREEN."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    comment = wire + "\n# round5 static-reachability / replay-scope comment-only noise\n"
    assert validate_r3c_evidence_source(comment, "wire_script") == []


_HEALTHY_NINE_LOOP_AFTER_RETURN = (
    "        for name in (\n"
    '            "http_deny",\n'
    '            "env_deny",\n'
    '            "stdin_deny",\n'
    '            "http_timeout",\n'
    '            "env_timeout",\n'
    '            "stdin_timeout",\n'
    '            "http_mutate",\n'
    '            "env_mutate",\n'
    '            "stdin_mutate",\n'
    "        ):\n"
    "            r = results[name]\n"
    '            assert r["http_target_hits"] == 0\n'
)


def test_r3c_reclosure_round6_shrink_loop_healthy_after_return_is_red():
    """Round6: shrink real nine-loop; healthy nine only after return 0 → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    mutated = mutated.replace(
        _MAIN_RETURN_NEEDLE,
        "        return 0\n" + _HEALTHY_NINE_LOOP_AFTER_RETURN + "    except Exception as exc:",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v


def test_r3c_reclosure_round6_replay_assert_after_return_is_red():
    """Round6: delete real replay ==0; healthy assert on path only after return → RED."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire.replace(_REPLAY_STRICT_ASSERT, "                pass  # deleted replay strict", 1)
    decoy = (
        "        return 0\n"
        '        for name in ("http_replay",):\n'
        "            r = results[name]\n"
        '            assert r["second_http_target_delta"] == 0\n'
        "    except Exception as exc:"
    )
    mutated = mutated.replace(_MAIN_RETURN_NEEDLE, decoy, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:replay_second_target_delta_guard_weakened" in v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" not in v


def test_r3c_reclosure_round6_raw_join_after_raise_is_red():
    """Round6: healthy raw_join only after unconditional raise in same list → provider RED."""
    wire = _wire_carrier()
    needle = 'raw_join = b"\\n".join(raw_requests)'
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "if True:\n"
        "    raise RuntimeError('round6_decoy')\n"
        '    raw_join = b"\\n".join(raw_requests)',
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:provider_secret_counter_forged" in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round6_approval_blob_after_raise_is_red():
    """Round6: healthy approval_blob only after unconditional raise → approval RED."""
    wire = _wire_carrier()
    needle = "approval_blob = json.dumps(approval_raw, default=str)"
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "if True:\n"
        "    raise RuntimeError('round6_decoy')\n"
        "    approval_blob = json.dumps(approval_raw, default=str)",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:approval_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round6_blob_after_raise_is_red():
    """Round6: healthy blob only after unconditional raise → result RED."""
    wire = _wire_carrier()
    needle = (
        "blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result"
    )
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "if True:\n"
        "    raise RuntimeError('round6_decoy')\n"
        "    blob = json.dumps(result, default=str) "
        "if not isinstance(result, str) else result",
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:result_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:trace_or_wire_secret_counter_forged" not in v


def test_r3c_reclosure_round6_trace_accumulate_after_raise_is_red():
    """Round6: healthy trace += only after unconditional raise in same loop body → RED."""
    wire = _wire_carrier()
    needle = '            trace_secret_count += data.count(decoy.encode("utf-8"))'
    assert wire.count(needle) == 1
    mutated = wire.replace(
        needle,
        "            raise RuntimeError('round6_decoy')\n"
        '            trace_secret_count += data.count(decoy.encode("utf-8"))',
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    probe = _extract_probe_source(mutated)
    assert probe is not None
    ast.parse(probe)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_round6_wire_secret_after_raise_is_red():
    """Round6: healthy wire_secret_count sum only after unconditional raise → RED."""
    wire = _wire_carrier()
    needle = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    assert wire.count(needle) == 1
    healthy = (
        "wire_secret_count = (\n"
        '    raw_join.count(token.encode("utf-8"))\n'
        "    + approval_blob.count(token)\n"
        "    + blob.count(token)\n"
        "    + int(trace_secret_count)\n"
        ")"
    )
    mutated = wire.replace(
        needle,
        "if True:\n"
        "    raise RuntimeError('round6_decoy')\n"
        "    " + healthy.replace("\n", "\n    "),
        1,
    )
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:trace_or_wire_secret_counter_forged" in v
    assert "mutation:provider_secret_counter_forged" not in v
    assert "mutation:approval_secret_counter_forged" not in v
    assert "mutation:result_secret_counter_forged" not in v


def test_r3c_reclosure_round6_unenumerated_ast_semantic_change_is_red():
    """Round6: unused assign / decoy expr (unenumerated) must hit canonical AST drift."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    mutated = wire + "\n_decoy_unused_ast_pin = 1\n"
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:wire_canonical_ast_drift" in v


def test_r3c_reclosure_round6_known_mutation_keeps_specific_violation():
    """Round6: known mutation must keep dedicated violation (may also include drift)."""
    wire = _wire_carrier()
    mutated = wire.replace(_DENY_TIMEOUT_MUTATE_LOOP, _THREE_SCENARIO_LOOP, 1)
    assert mutated != wire
    ast.parse(mutated)
    v = validate_r3c_evidence_source(mutated, "wire_script")
    assert v
    assert "mutation:deny_timeout_mutate_target_hit_guard_weakened" in v
    # Drift is allowed as extra; must not be the sole red signal for known mutations.
    assert any(x != "mutation:wire_canonical_ast_drift" for x in v)


def test_r3c_reclosure_round6_canonical_ast_digest_matches_pin():
    """Round6: healthy carrier digest independently recomputed must equal frozen pin."""
    wire = _wire_carrier()
    digest = _canonical_ast_digest(wire)
    assert digest is not None
    assert digest == _WIRE_CANONICAL_AST_SHA256
    assert validate_r3c_evidence_source(wire, "wire_script") == []


def test_r3c_reclosure_round6_comment_and_format_stay_green():
    """Round6 GREEN: comment-only / whitespace format leave AST digest unchanged → GREEN."""
    wire = _wire_carrier()
    assert validate_r3c_evidence_source(wire, "wire_script") == []
    healthy_digest = _canonical_ast_digest(wire)
    assert healthy_digest == _WIRE_CANONICAL_AST_SHA256

    comment = wire + "\n# round6 terminator-reachability / canonical-ast comment-only noise\n"
    assert _canonical_ast_digest(comment) == healthy_digest
    assert validate_r3c_evidence_source(comment, "wire_script") == []

    spaced = wire.replace(
        _DENY_TIMEOUT_MUTATE_LOOP,
        _DENY_TIMEOUT_MUTATE_LOOP.replace("for name in (", "for name in  (", 1),
        1,
    )
    assert spaced != wire
    ast.parse(spaced)
    assert _canonical_ast_digest(spaced) == healthy_digest
    assert validate_r3c_evidence_source(spaced, "wire_script") == []
