#!/usr/bin/env python3
"""R6 installed-ZIP approval-chain + wire-matrix E2E harness (opt-in).

Installs the pinned CURRENT-RELEASE plugin ZIP into an isolated HOME/HERMES_HOME, proves
the loaded modules come from that install (not the source tree), then reuses
the frozen R3C wire probe (read-only) — with ``_install_plugin`` replaced by
the shared ZIP installer so the wire path exercises the packaged bytes.

Owns:
- 4a approval-chain scenarios (``SCENARIOS``)
- 4b full 3×5 wire matrix (``MATRIX_SCENARIOS``) + manifest↔registry parity

Never touches ``~/.hermes/profiles/worker/``, ``~/.ssh``, real credentials, or
non-loopback peers. Never calls ``build_all``. Never edits the R3 carrier file.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

REPO = Path(__file__).resolve().parents[1]

#: C9 (0.4.5) unified egress redaction marker: ``<SECRET:cg_[0-9a-f]{16}>``.
_REDACTION_MARKER_RE = re.compile(r"<SECRET:cg_[0-9a-f]{16}>")

#: Pinned plugin ZIP identity — E2E fails closed if dist bytes drift.
#:
#: Was pinned to 0.4.0, which has NEVER existed in dist/ on any commit
#: (``git ls-tree HEAD dist/`` starts at 0.4.2). Every run therefore died with
#: FileNotFoundError before installing anything, so all 15 matrix cells errored
#: — while three RETIRED tests in tests/test_r3c_wire_e2e.py still cited this
#: matrix as their "live equivalent coverage". Repointed at the current release
#: so that claim is backed by a run that can actually happen.
EXPECTED_PLUGIN_ZIP = "credential-guard-0.4.5-hermes-plugin.zip"
EXPECTED_PLUGIN_ZIP_SHA256 = (
    "125af9a681f65900a04edb51099ec52a1ebb01001f4396ab85770875a5951611"
)

#: 4a scenarios (subset).
SCENARIOS: Tuple[str, ...] = (
    "http_approve",
    "env_approve",
    "stdin_approve",
    "http_deny",
    "http_mutate",
)

#: 4b full wire matrix: 3 adapters × 5 outcomes = 15 cells.
MATRIX_ADAPTERS: Tuple[str, ...] = ("http", "env", "stdin")
MATRIX_OUTCOMES: Tuple[str, ...] = (
    "approve",
    "deny",
    "timeout",
    "mutate",
    "replay",
)
MATRIX_SCENARIOS: Tuple[str, ...] = tuple(
    f"{adapter}_{outcome}"
    for adapter in MATRIX_ADAPTERS
    for outcome in MATRIX_OUTCOMES
)

#: Sanity-only expected tool set (primary check is set equality).
EXPECTED_TOOL_SET: frozenset = frozenset(
    {"credential_process_run", "http_credential_request"}
)

KEY_MODULE_REL = "credential_guard/__init__.py"


def _load_zip_helpers():
    path = REPO / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("installed_zip_plugin_r6", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_r3c():
    """Load the frozen R3C carrier read-only (AST pin must stay untouched)."""
    path = REPO / "scripts" / "run_r3c_wire_e2e.py"
    spec = importlib.util.spec_from_file_location("run_r3c_wire_e2e_r6wrap", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def resolve_plugin_zip(
    *,
    repo: Path = REPO,
    expected_name: str = EXPECTED_PLUGIN_ZIP,
    expected_sha256: str = EXPECTED_PLUGIN_ZIP_SHA256,
) -> Path:
    """Return the pinned ZIP path or raise with a clear identity mismatch."""
    helpers = _load_zip_helpers()
    path = repo / "dist" / expected_name
    if not path.is_file():
        raise FileNotFoundError(f"missing pinned plugin ZIP: {path}")
    digest = helpers.sha256_file(path)
    if digest != expected_sha256:
        raise AssertionError(
            f"plugin ZIP identity mismatch: got {digest}, "
            f"expected {expected_sha256} ({expected_name})"
        )
    return path


def install_pinned_zip(
    hermes_home: Path,
    *,
    extract_root: Path,
    plugin_zip: Optional[Path] = None,
) -> Path:
    helpers = _load_zip_helpers()
    zip_path = plugin_zip if plugin_zip is not None else resolve_plugin_zip()
    return helpers.install_zip_over_plugin(hermes_home, zip_path, extract_root)


def prove_zip_install(
    plugin_dest: Path,
    plugin_zip: Path,
    *,
    source_root: Path = REPO,
) -> Dict[str, Any]:
    """Path proof + key-module digest vs ZIP member."""
    helpers = _load_zip_helpers()
    sp, mw, hooks = helpers.load_credential_guard_from_plugin(plugin_dest)
    path_proof = helpers.prove_installed_module_path(
        plugin_dest, source_root, Path(sp.__file__)
    )
    module_match = helpers.assert_key_module_matches_zip(
        plugin_dest, plugin_zip, relative=KEY_MODULE_REL
    )
    return {
        **path_proof,
        "loaded_module_file": str(Path(sp.__file__).resolve()),
        "key_module_match": module_match,
        "sensitive_paths": sp,
        "middleware": mw,
        "hooks": hooks,
    }


def _load_runtime_from_plugin(plugin_dest: Path, *, home: Path, hermes: Path):
    """Publish runtime from the *installed* plugin under the isolated homes.

    Returns ``(middleware, hooks)`` module objects loaded from ``plugin_dest``.
    Caller must treat them as one-shot handles for the subsequent probes.
    """
    import importlib

    os.environ["HOME"] = str(home.resolve())
    os.environ["HERMES_HOME"] = str(hermes.resolve())
    plugin_str = str(plugin_dest.resolve())
    for k in list(sys.modules):
        if k == "credential_guard" or k.startswith("credential_guard."):
            sys.modules.pop(k, None)
    if plugin_str in sys.path:
        sys.path.remove(plugin_str)
    sys.path.insert(0, plugin_str)
    try:
        rc = importlib.import_module("credential_guard.runtime_config")
        if hasattr(rc, "reset_runtime_for_tests"):
            rc.reset_runtime_for_tests()
        rc.load_and_publish_runtime()
        mw = importlib.import_module("credential_guard.middleware")
        hooks = importlib.import_module("credential_guard.hooks")
        mw = importlib.reload(mw)
        hooks = importlib.reload(hooks)
        return mw, hooks
    finally:
        # Keep plugin_str at front only for the duration of import; probes hold
        # direct module references so sys.path can be restored.
        if plugin_str in sys.path:
            sys.path.remove(plugin_str)


def encoding_probe_via_installed_middleware(mw, secret: str) -> Dict[str, Any]:
    """Outbound middleware must strip plain + encoding forms of ``secret``."""
    helpers = _load_zip_helpers()
    import base64
    from urllib.parse import quote, quote_plus

    raw = secret.encode("utf-8")
    payload = (
        f"plain={secret};"
        f"pct={quote(secret, safe='')};"
        f"qp={quote_plus(secret)};"
        f"b64={base64.b64encode(raw).decode('ascii')};"
        f"url={base64.urlsafe_b64encode(raw).decode('ascii')}"
    )
    captured: List[Any] = []

    def _next(req):
        captured.append(req)
        return {"ok": True}

    mw.on_llm_execution(
        request={"messages": [{"role": "user", "content": payload}]},
        next_call=_next,
    )
    assert len(captured) == 1, "middleware next_call must fire once"
    outbound = json.dumps(captured[0], ensure_ascii=False).encode("utf-8")
    counts = helpers.assert_secret_absent_in_blob(outbound, secret)
    return {
        "encoding_forms": counts,
        "outbound_bytes": len(outbound),
        "secret_prefix": secret[:32],
    }


def result_echo_redaction_via_installed_hooks(hooks, secret: str) -> Dict[str, Any]:
    """Target-echo shaped tool result must not return the raw secret to the model."""
    echoed = json.dumps(
        {"ok": True, "echo_authorization": f"Bearer {secret}", "token": secret},
        ensure_ascii=False,
    )
    out = hooks.on_transform_tool_result(
        result=echoed, tool_name="http_credential_request", arguments={}
    )
    present = out.count(secret)
    # C9 (0.4.5) UNIFIED THE REDACTION PLACEHOLDER.
    #
    # The plaintext-absence check (``present == 0``) is the security assertion
    # and is unchanged. This second clause only confirms the model actually sees
    # a redaction marker rather than a silently emptied field. Pre-0.4.5 the
    # marker was ``<CREDENTIAL:...>``; C9 unified every egress marker to
    # ``<SECRET:cg_[0-9a-f]{16}>``, so the old spelling no longer appears and the
    # historical check reported ``redacted_ok=False`` on a correctly redacted
    # result. Both spellings are accepted here: the old one keeps historical
    # artifacts (0.4.2/0.4.3/0.4.4 ZIPs) evaluable by this same harness.
    marker_present = bool(_REDACTION_MARKER_RE.search(out)) or (
        "<CREDENTIAL:" in out or "REDACTED" in out
    )
    redacted_ok = present == 0 and marker_present
    return {
        "echo_secret_count_in_model_view": present,
        "redacted_ok": bool(redacted_ok),
        "result_preview": out[:160],
    }


def run_approval_chain(
    work: Path,
    *,
    plugin_zip: Optional[Path] = None,
    scenarios: Sequence[str] = SCENARIOS,
) -> Dict[str, Any]:
    """Install pinned ZIP, prove path, run wire scenarios, encoding + echo probes."""
    helpers = _load_zip_helpers()
    r3c = _load_r3c()
    zip_path = plugin_zip if plugin_zip is not None else resolve_plugin_zip()

    home = work / "home"
    hermes = work / "hermes"
    helper_dir = work / "helper"
    home.mkdir(parents=True)
    hermes.mkdir(parents=True)
    helper_dir.mkdir(mode=0o700)
    (home / "tmp").mkdir()

    # Isolation hard-check: paths must be under a temp tree, never the worker profile.
    home_r = home.resolve()
    hermes_r = hermes.resolve()
    _tmp_prefixes = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    assert str(home_r).startswith(_tmp_prefixes), home_r
    assert str(hermes_r).startswith(_tmp_prefixes), hermes_r
    worker = (Path.home() / ".hermes" / "profiles" / "worker").resolve()
    assert hermes_r != worker
    assert worker not in hermes_r.parents
    assert hermes_r not in worker.parents if worker.exists() else True

    plugin_dest = install_pinned_zip(
        hermes, extract_root=work / "zip-extract", plugin_zip=zip_path
    )
    install_proof = prove_zip_install(plugin_dest, zip_path)
    if install_proof.get("installed_from_zip") is not True:
        raise AssertionError(f"installed_from_zip proof failed: {install_proof}")
    if install_proof.get("plugin_path_is_source_tree") is True:
        raise AssertionError("plugin_path_is_source_tree must be False")

    env_h, stdin_h = r3c._write_helpers(helper_dir)
    env_marker = helper_dir / "mark.env"
    stdin_marker = helper_dir / "mark.stdin"

    results: Dict[str, Any] = {}
    for scenario in scenarios:
        r3c._write_helpers(helper_dir)
        r3c._write_config(
            hermes,
            env_program=env_h,
            env_marker=env_marker,
            stdin_program=stdin_h,
            stdin_marker=stdin_marker,
            decoy_http=r3c.DECOY_HTTP,
            decoy_env=r3c.DECOY_ENV,
            decoy_stdin=r3c.DECOY_STDIN,
        )
        for m in (env_marker, stdin_marker):
            if m.exists():
                m.unlink()
        results[scenario] = r3c._run_scenario(
            scenario,
            home=home,
            hermes=hermes,
            env_marker=env_marker,
            stdin_marker=stdin_marker,
            env_program=env_h,
            stdin_program=stdin_h,
        )

    # Reload installed middleware/hooks with runtime published from the iso config.
    re_proof = prove_zip_install(plugin_dest, zip_path)
    mw, hooks = _load_runtime_from_plugin(plugin_dest, home=home, hermes=hermes)
    # Wire decoys are synthetic CG_R3C_WIRE_* values written into the iso store.
    encoding = encoding_probe_via_installed_middleware(mw, r3c.DECOY_HTTP)
    echo = result_echo_redaction_via_installed_hooks(hooks, r3c.DECOY_HTTP)

    loopback_ok = all(bool(results[s].get("loopback_only")) for s in scenarios)
    non_loopback = sum(
        int(results[s].get("non_loopback_original_calls") or 0) for s in scenarios
    )
    net_violations = sum(int(results[s].get("net_violations") or 0) for s in scenarios)

    summary = {
        "ok": True,
        "plugin_zip": zip_path.name,
        "plugin_zip_sha256": helpers.sha256_file(zip_path),
        "home": str(home_r),
        "hermes_home": str(hermes_r),
        "plugin_dest": str(plugin_dest),
        "loaded_module_file": re_proof["loaded_module_file"],
        "installed_from_zip": re_proof["installed_from_zip"],
        "plugin_path_is_source_tree": re_proof["plugin_path_is_source_tree"],
        "key_module_match": re_proof["key_module_match"],
        "scenarios": {
            name: {
                "approval_raw_count": r.get("approval_raw_count"),
                "approval_outcome": r.get("approval_outcome"),
                "injection_resolve_delta": r.get("injection_resolve_delta"),
                "http_target_hits": r.get("http_target_hits"),
                "http_target_auth_applied": r.get("http_target_auth_applied"),
                "process_start_delta": r.get("process_start_delta"),
                "marker_ok": r.get("marker_ok"),
                "wire_secret_count": r.get("wire_secret_count"),
                "token_in_provider_raw": r.get("token_in_provider_raw"),
                "token_in_result": r.get("token_in_result"),
                "plan_state": r.get("plan_state"),
                "loopback_only": r.get("loopback_only"),
                "non_loopback_original_calls": r.get("non_loopback_original_calls"),
                "net_violations": r.get("net_violations"),
                "counts": r.get("counts"),
            }
            for name, r in results.items()
        },
        "encoding_probe": encoding,
        "result_echo_redaction": echo,
        "loopback_ok": bool(loopback_ok and non_loopback == 0 and net_violations == 0),
        "non_loopback_original_calls_total": int(non_loopback),
        "net_violations_total": int(net_violations),
    }
    # Drop live module objects before returning (not JSON-safe).
    return summary


def evaluate_approval_chain(summary: Dict[str, Any]) -> None:
    """Raise AssertionError unless the 4a contract holds."""
    assert summary.get("plugin_zip_sha256") == EXPECTED_PLUGIN_ZIP_SHA256
    assert summary.get("installed_from_zip") is True
    assert summary.get("plugin_path_is_source_tree") is False
    assert summary.get("loopback_ok") is True
    assert summary["result_echo_redaction"]["echo_secret_count_in_model_view"] == 0
    assert summary["result_echo_redaction"]["redacted_ok"] is True
    enc = summary["encoding_probe"]["encoding_forms"]
    assert all(v == 0 for v in enc.values()), enc

    for name in ("http_approve", "env_approve", "stdin_approve"):
        r = summary["scenarios"][name]
        assert int(r["approval_raw_count"] or 0) >= 1, name
        assert int(r["injection_resolve_delta"] or 0) == 1, name
        assert int(r["wire_secret_count"] or 0) == 0, name
        assert int(r["token_in_provider_raw"] or 0) == 0, name
        assert int(r["token_in_result"] or 0) == 0, name
        if name == "http_approve":
            assert int(r["http_target_hits"] or 0) == 1, name
            assert int(r["http_target_auth_applied"] or 0) == 1, name
        else:
            assert r.get("marker_ok") is True, name
            assert int(r["process_start_delta"] or 0) == 1, name

    deny = summary["scenarios"]["http_deny"]
    assert int(deny["injection_resolve_delta"] or 0) == 0
    assert int(deny["http_target_hits"] or 0) == 0
    assert deny.get("approval_outcome") == "denied"

    mut = summary["scenarios"]["http_mutate"]
    assert int(mut["injection_resolve_delta"] or 0) == 0
    assert int(mut["http_target_hits"] or 0) == 0
    assert mut.get("plan_state") == "invalidated"


# ---------------------------------------------------------------------------
# 4b — manifest ↔ registry parity on the installed release ZIP
# ---------------------------------------------------------------------------


def parse_provides_tools(plugin_yaml_text: str) -> List[str]:
    """Parse ``provides_tools`` from a plugin.yaml body (no PyYAML dependency)."""
    tools: List[str] = []
    in_section = False
    for raw in plugin_yaml_text.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("provides_tools:"):
            in_section = True
            rest = line.split(":", 1)[1].strip()
            if rest.startswith("[") and rest.endswith("]"):
                inner = rest[1:-1].strip()
                if inner:
                    for part in inner.split(","):
                        name = part.strip().strip("'\"")
                        if name:
                            tools.append(name)
                in_section = False
            continue
        if not in_section:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if not (line.startswith(" ") or line.startswith("\t")):
            break
        if stripped.startswith("- "):
            tools.append(stripped[2:].strip().strip("'\""))
    return tools


class _ToolCtx:
    def __init__(self) -> None:
        self.tools: List[Dict[str, Any]] = []
        self.middlewares: List[Any] = []
        self.hooks: List[Any] = []
        self.cli: List[Any] = []

    def register_tool(self, **kwargs: Any) -> None:
        self.tools.append(kwargs)

    def register_middleware(self, *a: Any, **k: Any) -> None:
        self.middlewares.append((a, k))

    def register_hook(self, *a: Any, **k: Any) -> None:
        self.hooks.append((a, k))

    def register_cli_command(self, **kwargs: Any) -> None:
        self.cli.append(kwargs)


def load_register_from_plugin(plugin_dest: Path):
    """Import ``credential_guard.register`` from an installed plugin dir."""
    plugin_str = str(plugin_dest.resolve())
    purged = {
        k: sys.modules.pop(k)
        for k in list(sys.modules)
        if k == "credential_guard" or k.startswith("credential_guard.")
    }
    removed_path = False
    if plugin_str in sys.path:
        sys.path.remove(plugin_str)
        removed_path = True
    sys.path.insert(0, plugin_str)
    try:
        pkg = importlib.import_module("credential_guard")
        pkg = importlib.reload(pkg)
        register = getattr(pkg, "register")
        return register, Path(pkg.__file__).resolve()
    finally:
        if plugin_str in sys.path:
            sys.path.remove(plugin_str)
        if removed_path:
            sys.path.insert(0, plugin_str)
        for name in list(sys.modules):
            if name == "credential_guard" or name.startswith("credential_guard."):
                sys.modules.pop(name, None)
        sys.modules.update(purged)


def check_manifest_registry_consistency(
    plugin_dest: Path,
    *,
    register_fn=None,
) -> Dict[str, Any]:
    """Assert installed plugin.yaml tools == register() tools (set equality).

    Primary predicate: the two sets are equal. ``EXPECTED_TOOL_SET`` is only a
    sanity check so both sides cannot drift to the same wrong set unnoticed.
    """
    yaml_path = plugin_dest / "plugin.yaml"
    if not yaml_path.is_file():
        raise AssertionError(f"missing installed plugin.yaml: {yaml_path}")
    manifest_tools = parse_provides_tools(yaml_path.read_text(encoding="utf-8"))
    manifest_set: Set[str] = set(manifest_tools)

    if register_fn is None:
        register_fn, loaded_file = load_register_from_plugin(plugin_dest)
    else:
        loaded_file = plugin_dest / KEY_MODULE_REL

    ctx = _ToolCtx()
    register_fn(ctx)
    registry_tools = [t["name"] for t in ctx.tools]
    registry_set: Set[str] = set(registry_tools)

    equal = manifest_set == registry_set
    result = {
        "manifest_tools": sorted(manifest_set),
        "registry_tools": sorted(registry_set),
        "sets_equal": equal,
        "sanity_expected": sorted(EXPECTED_TOOL_SET),
        "sanity_match": equal and manifest_set == set(EXPECTED_TOOL_SET),
        "loaded_register_file": str(loaded_file),
        "plugin_dest": str(plugin_dest.resolve()),
    }
    if not equal:
        raise AssertionError(
            "manifest↔registry tool-set mismatch: "
            f"manifest={sorted(manifest_set)} registry={sorted(registry_set)} "
            f"only_manifest={sorted(manifest_set - registry_set)} "
            f"only_registry={sorted(registry_set - manifest_set)}"
        )
    if manifest_set != set(EXPECTED_TOOL_SET):
        raise AssertionError(
            f"tool-set sanity failed: got {sorted(manifest_set)}, "
            f"expected {sorted(EXPECTED_TOOL_SET)}"
        )
    return result


# ---------------------------------------------------------------------------
# 4b — full 3×5 wire matrix on the installed release ZIP
# ---------------------------------------------------------------------------


def _patch_probe_provider_encoding_forms(r3c) -> None:
    """In-memory only: enrich the frozen PROBE JSON with encoding-form counts.

    Does not write ``scripts/run_r3c_wire_e2e.py``; file sha256 stays pinned.
    """
    if getattr(r3c, "_cg_r6_encoding_patched", False):
        return
    inject_compute = """
import base64 as _cg_b64
from urllib.parse import quote as _cg_quote, quote_plus as _cg_quote_plus
_cg_tok = token.encode("utf-8")
_cg_plain = token
_cg_pct = _cg_quote(token, safe="")
_cg_qp = _cg_quote_plus(token)
_cg_b64s = _cg_b64.b64encode(_cg_tok).decode("ascii")
_cg_url = _cg_b64.urlsafe_b64encode(_cg_tok).decode("ascii")
provider_encoding_forms = {
    "plain": int(raw_join.count(_cg_tok)),
    "percent": int(raw_join.count(_cg_pct.encode("utf-8"))) if _cg_pct != _cg_plain else 0,
    "quote_plus": int(raw_join.count(_cg_qp.encode("utf-8"))) if _cg_qp not in {_cg_plain, _cg_pct} else 0,
    "base64": int(raw_join.count(_cg_b64s.encode("utf-8"))),
    "urlsafe_base64": (
        int(raw_join.count(_cg_url.encode("utf-8")))
        if _cg_url != _cg_b64s
        else int(raw_join.count(_cg_b64s.encode("utf-8")))
    ),
}
"""
    anchor_compute = "plan_state = None\n\nprint(json.dumps({"
    if anchor_compute not in r3c.PROBE:
        raise AssertionError("PROBE compute anchor missing; carrier shape changed")
    r3c.PROBE = r3c.PROBE.replace(
        anchor_compute,
        "plan_state = None\n" + inject_compute + "\nprint(json.dumps({",
        1,
    )
    anchor_final = (
        '"final_preview": (final if isinstance(final, str) else str(final))[:200],\n'
        "}, sort_keys=True))"
    )
    if anchor_final not in r3c.PROBE:
        raise AssertionError("PROBE final_preview anchor missing; carrier shape changed")
    r3c.PROBE = r3c.PROBE.replace(
        anchor_final,
        '"final_preview": (final if isinstance(final, str) else str(final))[:200],\n'
        '    "provider_encoding_forms": provider_encoding_forms,\n'
        "}, sort_keys=True))",
        1,
    )
    r3c._cg_r6_encoding_patched = True


def _adapter_of(scenario: str) -> str:
    return scenario.split("_", 1)[0]


def _outcome_of(scenario: str) -> str:
    return scenario.split("_", 1)[1]


def target_hit_count(r: Dict[str, Any], *, adapter: str) -> int:
    """Per-adapter 'target was hit' counter used by the matrix assertions."""
    if adapter == "http":
        return int(r.get("http_target_hits") or 0)
    # env / stdin: marker file proves the helper ran once under injection.
    return 1 if r.get("marker_ok") is True else 0


def _assert_zero_secrets_cell(r: Dict[str, Any], *, cell: str) -> Dict[str, int]:
    assert int(r.get("wire_secret_count") or 0) == 0, cell
    assert int(r.get("token_in_provider_raw") or 0) == 0, cell
    assert int(r.get("token_in_approval_raw") or 0) == 0, cell
    assert int(r.get("token_in_result") or 0) == 0, cell
    assert int(r.get("trace_secret_count") or 0) == 0, cell
    forms = r.get("provider_encoding_forms")
    if not isinstance(forms, dict):
        raise AssertionError(f"{cell}: missing provider_encoding_forms")
    for key in ("plain", "percent", "quote_plus", "base64", "urlsafe_base64"):
        assert key in forms, (cell, key)
        assert int(forms[key]) == 0, (cell, key, forms)
    return {k: int(forms[k]) for k in (
        "plain", "percent", "quote_plus", "base64", "urlsafe_base64"
    )}


def _cell_reading(r: Dict[str, Any], *, adapter: str) -> Dict[str, Any]:
    forms = _assert_zero_secrets_cell(r, cell=f"{adapter}_reading")
    identities = r.get("tool_request_identities") or []
    return {
        "injection_resolve_delta": int(r.get("injection_resolve_delta") or 0),
        "http_adapter_delta": int(r.get("http_adapter_delta") or 0),
        "process_start_delta": int(r.get("process_start_delta") or 0),
        "target_hits": target_hit_count(r, adapter=adapter),
        "http_target_hits": int(r.get("http_target_hits") or 0),
        "approval_outcome": r.get("approval_outcome"),
        "approval_is_timeout": bool(r.get("approval_is_timeout")),
        "approval_timeout_branch": bool(r.get("approval_timeout_branch")),
        "approval_message": (r.get("approval_message") or "")[:200],
        "plan_state": r.get("plan_state"),
        "replay_closed": bool(r.get("replay_closed")),
        "replay_identity_same": bool(r.get("replay_identity_same")),
        "second_resolve_delta": r.get("second_resolve_delta"),
        "second_adapter_delta": r.get("second_adapter_delta"),
        "second_start_delta": r.get("second_start_delta"),
        "second_http_target_delta": r.get("second_http_target_delta"),
        "run_conversation_calls": r.get("run_conversation_calls"),
        "tool_request_identities": identities,
        "provider_encoding_forms": forms,
        "wire_secret_count": int(r.get("wire_secret_count") or 0),
        "loopback_only": bool(r.get("loopback_only")),
        "non_loopback_original_calls": int(r.get("non_loopback_original_calls") or 0),
        "net_violations": int(r.get("net_violations") or 0),
        "counts": r.get("counts"),
        "result2_preview": (r.get("result2_preview") or "")[:120],
        # Observer-independent approval evidence. The ``approval_*`` fields
        # above are profiler-derived and blind to the worker thread; this one is
        # written by the approval chain itself, so it stays truthful under the
        # current thread model. Load-bearing for timeout-vs-deny.
        #
        # NOT truncated: the distinguishing phrases live at the END of the
        # timeout notice ("... Silence is not consent."), so a [:200] slice
        # would cut them off and make a correct timeout look like a failure.
        # The message is a fixed host-authored string, never a credential value
        # (zero-secret assertions above already cover the whole result).
        "host_approval_message": str(
            (r.get("host_approval_raw") or {}).get("message") or ""
        ),
    }


def evaluate_matrix_cell(
    r: Dict[str, Any],
    *,
    adapter: str,
    outcome: str,
    deny_r: Optional[Dict[str, Any]] = None,
    target_hits_key: str = "target_hits",
) -> Dict[str, Any]:
    """Evaluate one matrix cell. ``target_hits_key`` is for M-B1 mutation only."""
    reading = _cell_reading(r, adapter=adapter)
    hits = int(reading.get(target_hits_key, reading["target_hits"]))

    if outcome == "approve":
        assert int(reading["injection_resolve_delta"]) == 1, (adapter, outcome)
        assert hits == 1, (adapter, outcome, hits)
        if adapter == "http":
            assert int(reading["http_adapter_delta"]) == 1
            assert int(reading["process_start_delta"]) == 0
        else:
            assert int(reading["process_start_delta"]) == 1
            assert int(reading["http_adapter_delta"]) == 0
    elif outcome == "deny":
        assert int(reading["injection_resolve_delta"]) == 0
        assert hits == 0
        assert reading["approval_outcome"] == "denied"
    elif outcome == "timeout":
        assert int(reading["injection_resolve_delta"]) == 0
        assert hits == 0
        # R5 THREAD-MODEL ADAPTATION (observation only, not a relaxation).
        #
        # ``approval_is_timeout`` / ``approval_timeout_branch`` /
        # ``approval_outcome`` are all derived from the carrier's
        # ``await_gateway_call_count``, which comes from ``sys.setprofile`` and
        # therefore only sees the CALLING thread. Hermes now dispatches tools on
        # a worker thread, so that counter reads 0 and all three collapse to
        # "non_timeout" even though the timeout branch really executed.
        # Identical treatment to tests/test_r3c_wire_e2e.py::_assert_timeout_distinct.
        #
        # Load-bearing replacement: the HOST's own raw approval record, which is
        # produced by the approval chain itself and is not observer-derived.
        host = r.get("host_approval_raw") or {}
        assert isinstance(host, dict) and host, (adapter, outcome)
        host_msg = str(host.get("message") or "")
        assert "timed out without user response" in host_msg, host_msg[:200]
        assert "Silence is not consent" in host_msg, host_msg[:200]
        if deny_r is not None:
            deny_host = deny_r.get("host_approval_raw") or {}
            deny_msg = str(deny_host.get("message") or "")
            assert host_msg != deny_msg, "timeout must not read like deny"
    elif outcome == "mutate":
        # Fail-closed after post-approval tamper: no resolve, no target hit.
        # HTTP flips plan_state to invalidated (config identity recheck).
        # Process adapters tamper the helper program; R3C live tests likewise
        # require resolve/start/hits == 0 and do not require plan_state.
        assert int(reading["injection_resolve_delta"]) == 0
        assert hits == 0
        assert int(reading["http_adapter_delta"]) == 0
        assert int(reading["process_start_delta"]) == 0
        if adapter == "http":
            assert reading["plan_state"] == "invalidated"
    elif outcome == "replay":
        assert int(reading["injection_resolve_delta"]) == 1
        assert hits == 1  # first execution hits once; second is closed
        # R5 THREAD-MODEL ADAPTATION — ``replay_identity_same``,
        # ``replay_closed``, ``tool_request_identities`` and the four
        # ``second_*`` deltas are all profiler-derived and blind to the worker
        # thread; the deltas are unconditionally ``None`` (the carrier only
        # assigns them when ``tool_request_identities`` has >= 2 entries, and it
        # has 0). Asserting them as-is is either false or vacuous.
        #
        # Load-bearing replacement: whole-run production totals. The scenario
        # issues TWO calls on the same reference, so an OPEN replay would show
        # resolve==2 / adapter==2 / hits==2. Same contract as
        # tests/test_r3c_wire_e2e.py::_assert_replay_second_call_did_not_execute.
        if adapter == "http":
            assert int(reading["http_adapter_delta"]) == 1
            assert int(reading["process_start_delta"]) == 0
        else:
            assert int(reading["process_start_delta"]) == 1
            assert int(reading["http_adapter_delta"]) == 0
        # C8 (0.4.5) split the collapsed RUNTIME_ADAPTER_NOT_READY exit into
        # stage-specific codes; a replayed reference is refused at the
        # reference-path guard, strictly earlier than the plan-state gate.
        preview = reading.get("result2_preview") or ""
        assert "REFERENCE_PATH_BLOCKED" in preview, preview[:200]
    else:
        raise AssertionError(f"unknown outcome: {outcome}")

    assert reading["loopback_only"] is True
    assert reading["non_loopback_original_calls"] == 0
    assert reading["net_violations"] == 0
    reading["evaluated_target_hits"] = hits
    reading["cell_ok"] = True
    return reading


def run_wire_matrix(
    work: Path,
    *,
    plugin_zip: Optional[Path] = None,
    scenarios: Sequence[str] = MATRIX_SCENARIOS,
) -> Dict[str, Any]:
    """Install pinned ZIP, check manifest↔registry, run the 15-cell matrix."""
    helpers = _load_zip_helpers()
    r3c = _load_r3c()
    _patch_probe_provider_encoding_forms(r3c)
    zip_path = plugin_zip if plugin_zip is not None else resolve_plugin_zip()

    home = work / "home"
    hermes = work / "hermes"
    helper_dir = work / "helper"
    home.mkdir(parents=True)
    hermes.mkdir(parents=True)
    helper_dir.mkdir(mode=0o700)
    (home / "tmp").mkdir()

    home_r = home.resolve()
    hermes_r = hermes.resolve()
    _tmp_prefixes = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    assert str(home_r).startswith(_tmp_prefixes), home_r
    assert str(hermes_r).startswith(_tmp_prefixes), hermes_r
    worker = (Path.home() / ".hermes" / "profiles" / "worker").resolve()
    assert hermes_r != worker
    assert worker not in hermes_r.parents

    plugin_dest = install_pinned_zip(
        hermes, extract_root=work / "zip-extract", plugin_zip=zip_path
    )
    install_proof = prove_zip_install(plugin_dest, zip_path)
    if install_proof.get("installed_from_zip") is not True:
        raise AssertionError(f"installed_from_zip proof failed: {install_proof}")

    manifest_registry = check_manifest_registry_consistency(plugin_dest)

    env_h, stdin_h = r3c._write_helpers(helper_dir)
    env_marker = helper_dir / "mark.env"
    stdin_marker = helper_dir / "mark.stdin"

    results: Dict[str, Any] = {}
    for scenario in scenarios:
        r3c._write_helpers(helper_dir)
        r3c._write_config(
            hermes,
            env_program=env_h,
            env_marker=env_marker,
            stdin_program=stdin_h,
            stdin_marker=stdin_marker,
            decoy_http=r3c.DECOY_HTTP,
            decoy_env=r3c.DECOY_ENV,
            decoy_stdin=r3c.DECOY_STDIN,
        )
        for m in (env_marker, stdin_marker):
            if m.exists():
                m.unlink()
        results[scenario] = r3c._run_scenario(
            scenario,
            home=home,
            hermes=hermes,
            env_marker=env_marker,
            stdin_marker=stdin_marker,
            env_program=env_h,
            stdin_program=stdin_h,
        )

    cells: Dict[str, Any] = {}
    for scenario in scenarios:
        adapter = _adapter_of(scenario)
        outcome = _outcome_of(scenario)
        deny_r = results.get(f"{adapter}_deny")
        cells[scenario] = evaluate_matrix_cell(
            results[scenario],
            adapter=adapter,
            outcome=outcome,
            deny_r=deny_r,
        )

    non_loopback = sum(
        int(results[s].get("non_loopback_original_calls") or 0) for s in scenarios
    )
    net_violations = sum(int(results[s].get("net_violations") or 0) for s in scenarios)

    return {
        "ok": True,
        "plugin_zip": zip_path.name,
        "plugin_zip_sha256": helpers.sha256_file(zip_path),
        "home": str(home_r),
        "hermes_home": str(hermes_r),
        "plugin_dest": str(plugin_dest),
        "installed_from_zip": install_proof["installed_from_zip"],
        "plugin_path_is_source_tree": install_proof["plugin_path_is_source_tree"],
        "manifest_registry": manifest_registry,
        "matrix_scenarios": list(scenarios),
        "cells": cells,
        "raw": {
            name: {
                "injection_resolve_delta": r.get("injection_resolve_delta"),
                "http_target_hits": r.get("http_target_hits"),
                "process_start_delta": r.get("process_start_delta"),
                "marker_ok": r.get("marker_ok"),
                "approval_outcome": r.get("approval_outcome"),
                "approval_is_timeout": r.get("approval_is_timeout"),
                "plan_state": r.get("plan_state"),
                "replay_closed": r.get("replay_closed"),
                "replay_identity_same": r.get("replay_identity_same"),
                "second_resolve_delta": r.get("second_resolve_delta"),
                "second_adapter_delta": r.get("second_adapter_delta"),
                "second_start_delta": r.get("second_start_delta"),
                "provider_encoding_forms": r.get("provider_encoding_forms"),
                "tool_request_identities": r.get("tool_request_identities"),
                "wire_secret_count": r.get("wire_secret_count"),
                "loopback_only": r.get("loopback_only"),
                "non_loopback_original_calls": r.get("non_loopback_original_calls"),
                "net_violations": r.get("net_violations"),
            }
            for name, r in results.items()
        },
        "cells_ok_count": sum(1 for c in cells.values() if c.get("cell_ok")),
        "cells_expected": len(scenarios),
        "loopback_ok": bool(non_loopback == 0 and net_violations == 0),
        "non_loopback_original_calls_total": int(non_loopback),
        "net_violations_total": int(net_violations),
    }


def evaluate_wire_matrix(summary: Dict[str, Any]) -> None:
    """Raise unless the full matrix + manifest↔registry contract holds."""
    assert summary.get("plugin_zip_sha256") == EXPECTED_PLUGIN_ZIP_SHA256
    assert summary.get("installed_from_zip") is True
    assert summary.get("plugin_path_is_source_tree") is False
    assert summary.get("loopback_ok") is True
    assert summary.get("non_loopback_original_calls_total") == 0
    assert summary.get("net_violations_total") == 0
    mr = summary["manifest_registry"]
    assert mr["sets_equal"] is True
    assert mr["sanity_match"] is True
    assert set(mr["manifest_tools"]) == set(mr["registry_tools"]) == set(
        EXPECTED_TOOL_SET
    )
    assert list(summary["matrix_scenarios"]) == list(MATRIX_SCENARIOS)
    assert int(summary["cells_ok_count"]) == len(MATRIX_SCENARIOS)
    for name in MATRIX_SCENARIOS:
        cell = summary["cells"][name]
        assert cell.get("cell_ok") is True, name
        forms = cell["provider_encoding_forms"]
        assert all(int(forms[k]) == 0 for k in forms), (name, forms)


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = "matrix" if "--matrix" in argv else "approval_chain"
    prefix = (
        "r6-installed-zip-matrix-"
        if mode == "matrix"
        else "r6-installed-zip-e2e-"
    )
    work = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        if mode == "matrix":
            summary = run_wire_matrix(work)
            evaluate_wire_matrix(summary)
            safe = {
                k: v
                for k, v in summary.items()
                if k != "raw"
            }
        else:
            summary = run_approval_chain(work)
            evaluate_approval_chain(summary)
            safe = dict(summary)
            if "result_echo_redaction" in safe:
                safe["result_echo_redaction"] = {
                    k: v
                    for k, v in safe["result_echo_redaction"].items()
                    if k != "result_preview"
                }
        print(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"R6_INSTALLED_ZIP_E2E_FAIL {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
