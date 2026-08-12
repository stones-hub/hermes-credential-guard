"""R5 approval host posture — Hermes provides standard approval; no second ticket.

Also hosts the approval.py ↔ tools.py deletion-blocker isolation tests, plus two
generic-tool properties migrated off ``tests/test_m2_release_blockers.py``:
the short-lived argv probe (H9) and the host session/always non-carryover
property on a reused Provider tool_call_id (H2). Both originals used carriers on
the R5 delete list; the versions here use ``/bin/sleep`` and
``http_credential_request`` so they survive the atomic delete slice.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import FrozenSet

import pytest

REPO = Path(__file__).resolve().parents[1]

HERMES_ROOT = Path("/Users/yelei/.hermes/hermes-agent")
HERMES_PY = HERMES_ROOT / "venv" / "bin" / "python"

# ---------------------------------------------------------------------------
# Host posture (green now)
# ---------------------------------------------------------------------------


def test_no_second_approval_ticket_module():
    """Plugin must not ship a second approval-ticket system."""
    assert not (REPO / "credential_guard" / "approval_ticket.py").exists()
    assert importlib.util.find_spec("credential_guard.approval_ticket") is None


def test_reference_rule_key_exists_and_binds_tool_call_id():
    """R2 reference approval key helper binds tool_call_id (active implementation).

    Replaces test_approval_rule_key_shape_preserved after R5 dead-code cleanup.
    The old _approval_rule_key explicitly discarded tool_call_id; the active
    implementation _reference_rule_key binds it along with other digest components.
    """
    from credential_guard.approval import _reference_rule_key

    a = _reference_rule_key(
        nonce="n1",
        tool_call_id="id_a",
        tool_name="http_credential_request",
        args_digest="ad1",
        config_digest="cd1",
        binding_digest="bd1",
    )
    b = _reference_rule_key(
        nonce="n1",
        tool_call_id="id_b",  # Different tool_call_id
        tool_name="http_credential_request",
        args_digest="ad1",
        config_digest="cd1",
        binding_digest="bd1",
    )
    # Different tool_call_id must produce different keys (binding property)
    assert a != b
    assert a.startswith("cg-ref:http_credential_request:")
    assert b.startswith("cg-ref:http_credential_request:")


def test_legacy_tools_no_longer_return_dedicated_approve():
    """No unregistered tool name may earn a dedicated approve directive.

    Rewritten by the R5 atomic-delete slice. This used to name the two deleted
    fixed-action tools as string literals, which after deletion asserted
    nothing about the product — they became arbitrary strings. The property
    that actually matters is general: ``on_pre_tool_call`` must return None
    (no plugin-side approve/deny directive) for any tool this plugin does not
    register. The two historical names are kept in the sample only as
    regression anchors, alongside names that were never ours.
    """
    from credential_guard.approval import on_pre_tool_call

    unregistered = (
        # Historical anchors: the deleted 0.3.1 fixed-action tools.
        "mysql_credential_action",
        "ssh_credential_action",
        # Never ours — the property must not be specific to deleted names.
        "read_file_like_tool",
        "some_other_plugin_tool",
        "credential_process_run_not_really",
    )
    for name in unregistered:
        out = on_pre_tool_call(
            tool_name=name,
            args={"target": "t1", "action": "check_connection"},
            tool_call_id="call_x",
        )
        assert out is None, name


def test_sensitive_path_block_still_works(tmp_path, monkeypatch):
    from credential_guard.approval import on_pre_tool_call
    from credential_guard.config import CONFIG_FILENAME

    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir(mode=0o700)
    cfg = store / CONFIG_FILENAME
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    blocked = on_pre_tool_call(
        tool_name="read_file",
        args={"path": str(cfg)},
    )
    assert blocked is not None
    assert blocked["action"] == "block"


def test_exception_path_fail_closed_never_raises(monkeypatch):
    from credential_guard import approval as ap

    def boom(*_a, **_k):
        raise RuntimeError("forced")

    monkeypatch.setattr(ap, "_block_sensitive_path", boom)
    out = ap.on_pre_tool_call(tool_name="terminal", args={"command": "true"})
    assert isinstance(out, dict)
    assert out["action"] == "block"


# ---------------------------------------------------------------------------
# Migrated property: short-lived argv probe is really observable (was H9).
#
# Carrier is ``/bin/sleep`` plus the retained ``tests/support/approval_pty.py``
# harness — no legacy tool involved.
# ---------------------------------------------------------------------------


def test_short_lived_argv_probe_is_actually_captured():
    """The argv sampler must really see a sub-second child's command line.

    ``argv_sample_ok`` is only meaningful if a process that lives ~0.3s is
    caught; asserting "did not raise" would let a silently non-sampling harness
    report clean argv for every future decoy scan.
    """
    from tests.support.approval_pty import run_with_approval_pty

    token = "CG_R5_ARGV_PROBE_" + "K7QW3Z"
    result = run_with_approval_pty(
        ["/bin/sleep", "0.8"],
        cwd="/",
        env=dict(os.environ),
        approval_replies=[],
        decoy="",
        timeout=20.0,
        argv_sample_interval=0.02,
        write_pty_choices=False,
        short_lived_argv_probe=token,
    )
    assert result.argv_sample_ok is True
    assert result.argv_samples, "sampler collected no argv lines at all"
    assert any(token in line for line in result.argv_samples), (
        "short-lived probe token never appeared in sampled argv"
    )


# ---------------------------------------------------------------------------
# Migrated property: host session/always must not cover the next call (was H2).
#
# Runs the REAL Hermes approval chain under the Hermes venv with a synthetic
# callback. Carrier is the generic ``http_credential_request`` tool and the live
# reference rule-key minter; the retired MySQL tool is not involved.
# ---------------------------------------------------------------------------


_HOST_SESSION_PROBE = r"""
import json
import sys
from pathlib import Path

plugin_root = Path(sys.argv[1])
sys.path.insert(0, str(plugin_root))
sys.path.insert(0, sys.argv[2])

from credential_guard.approval import _reference_rule_key
from credential_guard.injection_plan import InjectionPlanStore
from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
from tools.approval import request_tool_approval
from tools.terminal_tool import set_approval_callback

REUSED = "reused_provider_id"
MSG = "Credential Guard requests one-shot use of a local credential"

state = {"n": 0, "choices": []}


def _cb(command, description, **kwargs):
    state["n"] += 1
    # First answer session, then always — neither may cover a later call.
    choice = "session" if state["n"] == 1 else "always"
    state["choices"].append(choice)
    return choice


set_approval_callback(_cb)
store = InjectionPlanStore()


def key_for(nonce):
    return _reference_rule_key(
        nonce=nonce,
        tool_call_id=REUSED,
        tool_name=HTTP_REFERENCE_TOOL,
        args_digest="a" * 16,
        config_digest="c" * 16,
        binding_digest="b" * 16,
    )


n1 = store._new_nonce()
n2 = store._new_nonce()
k1, k2 = key_for(n1), key_for(n2)
r1 = request_tool_approval(HTTP_REFERENCE_TOOL, MSG, rule_key=k1, approval_callback=_cb)
r2 = request_tool_approval(HTTP_REFERENCE_TOOL, MSG, rule_key=k2, approval_callback=_cb)
prompts = state["n"]
choices = list(state["choices"])

# Mutation baked in: if the plugin reused the nonce for the same provider id,
# both calls would carry one rule_key and the host session grant would swallow
# the second prompt. Proves the fresh nonce is what carries the property.
state["n"] = 0
state["choices"] = []
k_same = key_for(store._new_nonce())
request_tool_approval(HTTP_REFERENCE_TOOL, MSG, rule_key=k_same, approval_callback=_cb)
request_tool_approval(HTTP_REFERENCE_TOOL, MSG, rule_key=k_same, approval_callback=_cb)

print(json.dumps({
    "prompts": prompts,
    "choices": choices,
    "keys_differ": k1 != k2,
    "nonces_differ": n1 != n2,
    "raw_id_absent": REUSED not in k1 and REUSED not in k2,
    "nonce_absent": n1 not in k1 and n2 not in k2,
    "r1_approved": bool(r1.get("approved")),
    "r2_approved": bool(r2.get("approved")),
    "reused_key_prompts": state["n"],
}))
"""


def test_host_session_always_still_prompts_on_reused_provider_id():
    """Real Hermes gate: session/always on call 1 cannot cover call 2.

    The Provider reuses one ``tool_call_id``; the plugin mints a fresh nonce per
    call, so the host's ``request_tool_approval`` must prompt both times. Only
    skip condition is a missing Hermes venv (other machines / CI).
    """
    if not HERMES_PY.is_file():
        pytest.skip("Hermes Python missing")

    with tempfile.TemporaryDirectory(prefix="cg-r5-host-") as tmp:
        hermes_home = Path(tmp) / "hermes"
        hermes_home.mkdir(parents=True, exist_ok=True)
        env = {
            "HOME": tmp,
            "HERMES_HOME": str(hermes_home),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": tmp,
            "HERMES_INTERACTIVE": "1",
            "PYTHONPATH": str(HERMES_ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
        proc = subprocess.run(
            [str(HERMES_PY), "-c", _HOST_SESSION_PROBE, str(REPO), str(HERMES_ROOT)],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    assert proc.returncode == 0, proc.stderr[-800:]
    payload = json.loads(proc.stdout.strip().splitlines()[-1])

    assert payload["nonces_differ"] is True
    assert payload["keys_differ"] is True
    assert payload["raw_id_absent"] is True
    assert payload["nonce_absent"] is True
    assert payload["prompts"] == 2
    assert payload["choices"] == ["session", "always"]
    assert payload["r1_approved"] is True
    assert payload["r2_approved"] is True
    # Nonce reuse would let one host grant cover the next call — the mutation.
    assert payload["reused_key_prompts"] == 1


# ---------------------------------------------------------------------------
# Blocker 2: approval must import without tools.py
# ---------------------------------------------------------------------------


class _BlockModuleFinder:
    def __init__(self, blocked: FrozenSet[str]) -> None:
        self._blocked = blocked

    def find_spec(self, fullname, path, target=None):  # noqa: ANN001
        if fullname in self._blocked:
            raise ImportError(f"{fullname} is blocked for isolation test")
        return None


def _reimport_approval_with_tools_blocked():
    saved_ap = sys.modules.pop("credential_guard.approval", None)
    saved_tools = sys.modules.pop("credential_guard.tools", None)
    finder = _BlockModuleFinder(frozenset({"credential_guard.tools"}))
    sys.meta_path.insert(0, finder)
    try:
        import credential_guard.approval as ap

        return ap
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        if saved_tools is None:
            sys.modules.pop("credential_guard.tools", None)
        else:
            sys.modules["credential_guard.tools"] = saved_tools
        if saved_ap is None:
            sys.modules.pop("credential_guard.approval", None)
        else:
            sys.modules["credential_guard.approval"] = saved_ap
        import credential_guard as pkg

        if saved_ap is not None:
            setattr(pkg, "approval", saved_ap)


def test_r5_prep_approval_imports_without_tools_module():
    """approval.py must import and work with the deleted modules unavailable.

    Rewritten by the R5 atomic-delete slice. The probe call used to pass the
    literal ``mysql_credential_action``; after deletion that name proves
    nothing on its own, so the call now uses a name that was never registered
    and the assertion is stated generally. The load-bearing property is
    unchanged: with ``credential_guard.tools`` unimportable, approval must
    still import, must return no directive for unregistered tools, and must
    keep the R2 rule-key grain.
    """
    src = (REPO / "credential_guard" / "approval.py").read_text(encoding="utf-8")
    assert "from .tools import" not in src
    assert "from .file_backend import" not in src

    ap = _reimport_approval_with_tools_blocked()
    out = ap.on_pre_tool_call(
        tool_name="an_unregistered_tool_name",
        args={"target": "t1", "action": "check_connection"},
    )
    assert out is None
    # Active reference approval key helper must be available (R5 dead-code cleanup).
    key = ap._reference_rule_key(
        nonce="n",
        tool_call_id="id",
        tool_name="http_credential_request",
        args_digest="ad",
        config_digest="cd",
        binding_digest="bd",
    )
    assert key.startswith("cg-ref:http_credential_request:")


def test_r5_approval_host_exactly_two_tools_posture():
    """register() must expose exactly the two surviving R3 reference tools."""
    from credential_guard import register

    class Ctx:
        def __init__(self) -> None:
            self.tools = []

        def register_tool(self, **kwargs):
            self.tools.append(kwargs)

        def register_middleware(self, *a, **k):
            pass

        def register_hook(self, *a, **k):
            pass

        def register_cli_command(self, **kwargs):
            pass

    ctx = Ctx()
    register(ctx)
    assert sorted(t["name"] for t in ctx.tools) == [
        "credential_process_run",
        "http_credential_request",
    ]
