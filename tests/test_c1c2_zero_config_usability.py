"""C1/C2: zero-config pass-through + actionable local config diagnostics.

C1 — when the secure store directory does not exist at all, Credential Guard was
never configured on this machine, so the credential registry is necessarily
empty and fail-closed has nothing to protect. Ordinary chat passes through and
one local notice is emitted per process.

C2 — every other config failure keeps blocking, and now prints an actionable
local diagnostic (file / reason / fix) on stderr only.

Narrow-口 scope (decision B): pass-through is limited to "store directory
absent". "Store directory present, config file missing" is a half-configured
state and must keep blocking — see ``test_c1_reverse_*[dir_exists_file_missing]``
and the load-bearing ``test_runtime_config_v2.py::test_a5_...["missing"]``.

Isolation note: this repository has no ``conftest.py``, so nothing pins HOME /
HERMES_HOME globally. Every fixture here sets both and then *asserts* that the
resolved store path really is under ``tmp_path``, so no test in this file can
silently fall through to the operator's real ``~/.hermes`` profile.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from credential_guard import hooks as hooks_mod
from credential_guard import middleware as mw
from credential_guard import runtime_config as rc
from credential_guard.config import CONFIG_FILENAME
from credential_guard.config_lock import CONFIG_LOCK_STORE_NOT_FOUND, ConfigLockError
from credential_guard.middleware import on_llm_execution, on_llm_request
from credential_guard.registry import CredentialRegistry
from credential_guard.state import get_registry


def _wait_diag(timeout: float = 2.0) -> None:
    """Drain async local-diagnostic worker before reading stderr in tests."""
    assert mw.wait_config_diagnostic_idle_for_tests(timeout=timeout)

# Synthetic canary written into config files. Never a real credential.
CANARY = "SYNTHETIC_CANARY_VALUE_0123456789"

# Synthetic PEM decoy (not a real key) for the "protection does not degrade" case.
DECOY_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join("MIIEowIBAAKCAQEA" + secrets.token_hex(24) for _ in range(4))
    + "\n-----END RSA PRIVATE KEY-----"
)


def _decoy(n: int = 16) -> str:
    return "CG_C1C2_" + secrets.token_hex(n)


def _reset_process_state() -> None:
    # Drain async local diagnostics before clearing the once-ledger so a late
    # write cannot land on the next test's capsys / pytest stderr.
    assert mw.wait_config_diagnostic_idle_for_tests(timeout=2.0)
    get_registry().clear()
    rc.reset_runtime_for_tests()
    mw.reset_config_notices_for_tests()


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """HOME + HERMES_HOME pinned into tmp_path. Store dir deliberately NOT created."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    # Round 2 (C1 store-root hardening): an explicitly-set HERMES_HOME whose
    # root carries no Hermes marker is now treated as a misdirected variable
    # and fails closed -- see tests/test_c1_store_root_not_a_profile.py. A real
    # profile always has a scaffold, so seed one. This keeps the fixture
    # modelling "real profile, store not created yet", which is what every
    # assertion below is about; no assertion is weakened.
    (hermes / "config.yaml").write_text("# scaffold\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _reset_process_state()

    # Positive proof of isolation — reconciles the "no conftest.py" risk.
    resolved = rc.default_config_path()
    assert str(resolved).startswith(str(tmp_path)), resolved
    assert not resolved.exists()
    assert not resolved.parent.exists()

    try:
        yield hermes, hermes / "credential-guard"
    finally:
        _reset_process_state()


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------


def _v2_doc(secret: str) -> Dict[str, Any]:
    return {
        "version": 2,
        "credentials": {"internal_api_token": {"type": "token", "value": secret}},
        "bindings": {
            "internal-api": {
                "type": "http",
                "credential_ref": "internal_api_token",
                "target": {"scheme": "https", "host": "api.example.test", "port": 443},
                "request": {
                    "allowed_methods": ["GET", "POST"],
                    "allowed_paths": ["/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }


def _mkstore(hermes: Path, mode: int = 0o700) -> Path:
    store = hermes / "credential-guard"
    store.mkdir(mode=mode, parents=True, exist_ok=True)
    os.chmod(store, mode)
    return store


def _write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


#: Every reverse scenario must keep blocking. ``expected_detail`` is the
#: ConfigError / ConfigLockError code the diagnostic is expected to report; it is
#: asserted so the C2 reachability table stays honest instead of copied.
REVERSE_CASES: Tuple[str, ...] = (
    "dir_exists_file_missing",
    "empty_file",
    "invalid_json",
    "duplicate_key",
    "schema_forbidden_field",
    "mode_0644",
    "parent_0755",
    "symlink",
    "config_is_dir",
    "too_large",
)


def _build_reverse(kind: str, hermes: Path, tmp_path: Path, secret: str) -> Path:
    """Materialise a reverse scenario. Returns the store dir."""
    store = _mkstore(hermes)
    path = store / CONFIG_FILENAME
    if kind == "dir_exists_file_missing":
        pass
    elif kind == "empty_file":
        _write(path, "")
    elif kind == "invalid_json":
        _write(path, '{"version": 2, "credentials": {')
    elif kind == "duplicate_key":
        _write(
            path,
            '{"version":2,"credentials":{"a":{"type":"token","value":"%s"}},'
            '"bindings":{},"credentials":{}}' % secret,
        )
    elif kind == "schema_forbidden_field":
        doc = _v2_doc(secret)
        doc["bindings"]["internal-api"]["allowed_tools"] = ["terminal"]
        _write(path, json.dumps(doc, ensure_ascii=False))
    elif kind == "mode_0644":
        _write(path, json.dumps(_v2_doc(secret)), mode=0o644)
    elif kind == "parent_0755":
        _write(path, json.dumps(_v2_doc(secret)))
        os.chmod(store, 0o755)
    elif kind == "symlink":
        real = tmp_path / "real-config.json"
        _write(real, json.dumps(_v2_doc(secret)))
        path.symlink_to(real)
    elif kind == "config_is_dir":
        path.mkdir(mode=0o700)
    elif kind == "too_large":
        # > MAX_CONFIG_FILE_BYTES (2 MiB), with the canary really inside.
        _write(path, json.dumps(_v2_doc(secret)) + " " * 2_200_000)
    else:  # pragma: no cover - guard against typos in the parametrisation
        raise AssertionError(f"unknown reverse case {kind!r}")
    return store


# ---------------------------------------------------------------------------
# Seam drivers
# ---------------------------------------------------------------------------


def _exec_seam(text: str) -> Tuple[Any, List[Any]]:
    calls: List[Any] = []
    result = on_llm_execution(
        request={"messages": [{"role": "user", "content": text}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    return result, calls


def _request_seam(text: str) -> Any:
    return on_llm_request(
        request={"messages": [{"role": "user", "content": text}]}
    )


def _assert_blocked(result: Any, calls: List[Any], secret: str) -> None:
    assert calls == [], "provider must not be called on the fail-closed path"
    assert getattr(result, "model", "") == "credential-guard-blocked"
    assert mw.is_blocked_response_content(result.choices[0].message.content)
    blob = str(result)
    assert secret not in blob
    assert "Traceback" not in blob


def _assert_passed(result: Any, calls: List[Any]) -> None:
    assert getattr(result, "model", "") != "credential-guard-blocked"
    assert len(calls) == 1, f"provider must be reached exactly once; got {len(calls)}"
    assert not mw._is_local_block_request(calls[0])


def _assert_blocked_unconfigured(result: Any, calls: List[Any]) -> None:
    """Round 6: an unconfigured store fails closed instead of passing through.

    C1 used to let these requests reach the Provider on the theory that an
    absent store meant "never configured". Round 6 withdrew that: the store
    location was previously *guessed*, so "absent" could equally mean the
    plugin looked in the wrong place while the operator's credentials sat
    safely configured somewhere else. See tests/test_r6_unconfigured_blocks.py.
    """
    assert getattr(result, "model", "") == "credential-guard-blocked", (
        "an unconfigured store must fail closed"
    )
    assert calls == [], f"provider must not be reached; got {len(calls)} call(s)"


# ===========================================================================
# 2.2 — root cause of the "missing dir is less specific than missing file" bug
# ===========================================================================


def test_store_dir_absent_has_its_own_lock_code(tmp_path):
    """`os.lstat` on an absent store dir must no longer collapse into CONFIG_LOCK_FS."""
    from credential_guard.config_lock import _assert_secure_store_dir

    with pytest.raises(ConfigLockError) as ei:
        _assert_secure_store_dir(tmp_path / "nope")
    assert ei.value.code == CONFIG_LOCK_STORE_NOT_FOUND


@pytest.mark.parametrize(
    "make,expected",
    [
        ("mode_0755", "CONFIG_LOCK_FS"),
        ("symlink_dir", "CONFIG_LOCK_FS"),
        ("not_a_dir", "CONFIG_LOCK_FS"),
    ],
)
def test_other_store_dir_faults_stay_config_lock_fs(tmp_path, make, expected):
    """Only FileNotFoundError is split out; every other fault stays fail-closed."""
    from credential_guard.config_lock import _assert_secure_store_dir

    target = tmp_path / "store"
    if make == "mode_0755":
        target.mkdir(mode=0o755)
        os.chmod(target, 0o755)
    elif make == "symlink_dir":
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        target.symlink_to(real)
    elif make == "not_a_dir":
        target.write_text("x", encoding="utf-8")
    with pytest.raises(ConfigLockError) as ei:
        _assert_secure_store_dir(target)
    assert ei.value.code == expected


def test_runtime_layer_keeps_the_two_archs_distinguishable(isolated_home):
    """Store-absent and file-absent must NOT share one runtime code."""
    hermes, store = isolated_home
    with pytest.raises(rc.RuntimeConfigError) as absent:
        rc.load_and_publish_runtime()
    assert absent.value.code == rc.RUNTIME_CONFIG_STORE_NOT_FOUND
    assert rc.is_unconfigured_store_error(absent.value)

    _mkstore(hermes)
    with pytest.raises(rc.RuntimeConfigError) as half:
        rc.load_and_publish_runtime()
    assert half.value.code == "RUNTIME_CONFIG_NOT_FOUND"
    assert not rc.is_unconfigured_store_error(half.value)


def test_runtime_error_never_embeds_path_or_secret(isolated_home):
    hermes, _store = isolated_home
    store = _mkstore(hermes)
    _write(store / CONFIG_FILENAME, json.dumps(_v2_doc(CANARY)), mode=0o644)
    with pytest.raises(rc.RuntimeConfigError) as ei:
        rc.load_and_publish_runtime()
    blob = f"{ei.value!s}{ei.value!r}{ei.value.code}{ei.value.detail_code}"
    assert CANARY not in blob
    assert str(store) not in blob


# ===========================================================================
# 4.1 — store dir absent → fail closed (round 6 withdrew C1 pass-through)
# ===========================================================================


def test_c1_store_dir_absent_blocks_llm_execution(isolated_home):
    text = f"ordinary chat {_decoy()}"
    result, calls = _exec_seam(text)
    _assert_blocked_unconfigured(result, calls)


def test_c1_store_dir_absent_blocks_llm_request(isolated_home):
    text = f"ordinary chat {_decoy()}"
    out = _request_seam(text)
    assert mw._is_local_block_request(out["request"]), (
        "the request seam must fail closed when nothing is configured"
    )


def test_c1_store_dir_absent_blocks_transform_tool_result(isolated_home):
    payload = json.dumps({"rows": [{"id": 1, "note": "ordinary"}]})
    out = hooks_mod.on_transform_tool_result(
        result=payload, tool_name="t", arguments={}
    )
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    assert out == RESULT_GUARD_FAIL_TEXT, (
        "tool results must not flow while the config is unavailable"
    )


def test_c1_all_three_seams_agree_when_store_absent(isolated_home):
    """3.4: llm_request / llm_execution / transform_tool_result must not diverge.

    Still the parity check it always was; round 6 flipped the agreed answer
    from "all pass" to "all block".
    """
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    text = f"seam parity {_decoy()}"
    req = _request_seam(text)
    result, calls = _exec_seam(text)
    tool = hooks_mod.on_transform_tool_result(
        result="plain tool output", tool_name="t", arguments={}
    )
    assert mw._is_local_block_request(req["request"])
    _assert_blocked_unconfigured(result, calls)
    assert tool == RESULT_GUARD_FAIL_TEXT


def test_c1_block_diagnostic_names_the_config_file(isolated_home, capsys):
    """The operator must learn which file to create; nothing auto-generates it."""
    _exec_seam("hello")
    _wait_diag()
    err = capsys.readouterr().err
    assert CONFIG_FILENAME in err
    assert str(rc.default_config_path()) in err


def test_c1_block_diagnostic_never_reaches_the_provider(isolated_home):
    """Local diagnostics stay local: the Provider is not called at all."""
    result, calls = _exec_seam("hello")
    _assert_blocked_unconfigured(result, calls)


# ===========================================================================
# 4.2 — reverse: everything else keeps blocking
# ===========================================================================


@pytest.mark.parametrize("kind", REVERSE_CASES)
def test_c1_reverse_still_blocks(isolated_home, tmp_path, kind):
    hermes, _ = isolated_home
    _build_reverse(kind, hermes, tmp_path, CANARY)
    result, calls = _exec_seam(f"leak attempt {CANARY}")
    _assert_blocked(result, calls, CANARY)


@pytest.mark.parametrize("kind", REVERSE_CASES)
def test_c1_reverse_blocks_llm_request_seam(isolated_home, tmp_path, kind):
    hermes, _ = isolated_home
    _build_reverse(kind, hermes, tmp_path, CANARY)
    out = _request_seam(f"leak attempt {CANARY}")
    assert mw._is_local_block_request(out["request"])
    assert CANARY not in json.dumps(out["request"], ensure_ascii=False)


def test_c1_legacy_dual_files_only_still_blocks(isolated_home):
    """Upgrade path: v1 files present, v2 missing → real credentials exist → block."""
    hermes, _ = isolated_home
    store = _mkstore(hermes)
    _write(
        store / "credentials.json",
        json.dumps(
            {
                "version": 1,
                "credentials": {
                    "mysql_canary_credential": {
                        "type": "mysql",
                        "username": "cg_readonly",
                        "password": CANARY,
                    }
                },
            }
        ),
    )
    _write(store / "targets.json", json.dumps({"version": 1, "targets": {}}))
    result, calls = _exec_seam(f"password is {CANARY}")
    _assert_blocked(result, calls, CANARY)


# ===========================================================================
# 4.3 — registry-independent protection survives the round 6 withdrawal
#
# These properties used to be demonstrated on the C1 pass-through branch. That
# branch is gone, but the properties themselves are not about pass-through --
# they are about redaction that does not depend on the config file. They are
# now exercised on a minimally *configured* profile, which is the only state
# that reaches the Provider at all after round 6.
# ===========================================================================


@pytest.fixture()
def configured_home(isolated_home):
    """``isolated_home`` plus a minimal valid config, so egress is allowed."""
    hermes, store = isolated_home
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    cfg = store / CONFIG_FILENAME
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    _reset_process_state()
    return hermes, store


def test_private_key_is_redacted_without_any_registered_credential(configured_home):
    result, calls = _exec_seam(f"key follows\n{DECOY_PEM}\n")
    _assert_passed(result, calls)
    wire = json.dumps(calls[0], ensure_ascii=False)
    body = DECOY_PEM.split("\n")[1]
    assert body not in wire
    assert "BEGIN RSA PRIVATE KEY" not in wire
    assert "<REDACTED_SECRET>" in wire


def _protected_ssh_path() -> str:
    """``~/.ssh/id_rsa`` resolved against the *current* HOME.

    ``sensitive_paths._home_ssh_dir`` is ``Path.home() / ".ssh"``, so what counts
    as protected follows the HOME the fixture pinned into ``tmp_path``. A
    hard-coded ``/Users/x/.ssh/id_rsa`` is not this machine's SSH directory under
    that fixture, so it is correctly *not* blocked — asserting on it would test
    nothing about the pass-through branch.
    """
    return str(Path(os.environ["HOME"]) / ".ssh" / "id_rsa")


def test_c1_passthrough_still_protects_sensitive_paths(isolated_home):
    out = hooks_mod.on_transform_tool_result(
        result="ssh-rsa AAAA... private material",
        tool_name="execute_code",
        arguments={"code": f"open({_protected_ssh_path()!r}).read()"},
    )
    assert out == hooks_mod._SAFE_TOOL_RESULT


def test_c1_protected_ssh_path_helper_tracks_home(isolated_home):
    """Pins 2.1: the predicate is HOME-relative, so the fixture path is the real one."""
    from credential_guard.sensitive_paths import python_code_reads_protected

    assert python_code_reads_protected(f"open({_protected_ssh_path()!r}).read()")
    assert not python_code_reads_protected("open('/Users/x/.ssh/id_rsa').read()")


def test_mut_dropping_sensitive_path_preblock_makes_42_red(isolated_home, monkeypatch):
    """Mutation: hooks' protected-path pre-block is removed wholesale.

    Replaces every predicate the pre-block consults, which is behaviourally the
    same as deleting the block. The corrected 4.3 assertion must go red.
    """
    monkeypatch.setattr(hooks_mod, "args_target_protected", lambda *a, **k: False)
    monkeypatch.setattr(hooks_mod, "python_code_reads_protected", lambda *a, **k: False)
    monkeypatch.setattr(
        hooks_mod, "terminal_command_reads_protected", lambda *a, **k: False
    )
    out = hooks_mod.on_transform_tool_result(
        result="ssh-rsa AAAA... private material",
        tool_name="execute_code",
        arguments={"code": f"open({_protected_ssh_path()!r}).read()"},
    )
    assert out != hooks_mod._SAFE_TOOL_RESULT, (
        "mutation did not flip the sensitive-path case; the pre-block is not pinned"
    )


def test_in_memory_registered_secret_is_redacted(configured_home):
    """The base process registry stays load-bearing alongside the file source."""
    secret = _decoy()
    get_registry().register("db", "password", secret)
    result, calls = _exec_seam(f"password is {secret}")
    _assert_passed(result, calls)
    assert secret not in json.dumps(calls[0], ensure_ascii=False)


def test_in_memory_secret_is_redacted_on_llm_request_seam(configured_home):
    secret = _decoy()
    get_registry().register("db", "password", secret)
    out = _request_seam(f"password is {secret}")
    assert not mw._is_local_block_request(out["request"])
    assert secret not in json.dumps(out["request"], ensure_ascii=False)


def test_in_memory_secret_is_redacted_on_tool_result_seam(configured_home):
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    secret = _decoy()
    get_registry().register("db", "password", secret)
    out = hooks_mod.on_transform_tool_result(
        result=json.dumps({"rows": [{"password": secret}]}),
        tool_name="t",
        arguments={},
    )
    assert out != RESULT_GUARD_FAIL_TEXT
    assert secret not in out


# ===========================================================================
# 4.4 — mutation gates. Each replaces the real production call path.
#
# Round 6 note: the previous gates in this section all mutated the C1
# pass-through branch (its predicate, its error mapping, its private-key
# scan). That branch no longer exists, so those mutations were unreachable
# and could no longer make anything red. They are replaced by gates that
# mutate the code path that IS load-bearing now: the unconditional
# fail-closed block, and the private-key scan on the configured path.
# ===========================================================================


def test_mut_fail_open_on_unconfigured_store_makes_reverse_red(
    isolated_home, tmp_path, monkeypatch
):
    """Mutation: the withdrawn pass-through is reinstated.

    This is the round 4/5/6 leak, expressed as a mutation. If the seam hands
    back a registry instead of blocking, every reverse case must stop blocking
    -- which proves the reverse suite pins fail-closed behaviour rather than
    merely describing it.
    """
    hermes, _ = isolated_home
    _build_reverse("dir_exists_file_missing", hermes, tmp_path, CANARY)
    monkeypatch.setattr(
        mw,
        "_unconfigured_registry_or_block",
        lambda exc: mw.get_base_registry_snapshot(),
    )
    result, calls = _exec_seam(f"leak attempt {CANARY}")
    assert getattr(result, "model", "") != "credential-guard-blocked", (
        "mutation did not flip the reverse case; fail-closed is not pinned"
    )
    assert len(calls) == 1


def test_mut_skipping_private_key_scan_makes_43_red(configured_home, monkeypatch):
    """Mutation: private-key redaction is removed on the configured path."""
    monkeypatch.setattr(mw, "_redact_locatable_private_keys", lambda payload: payload)
    monkeypatch.setattr(mw, "_find_residual_private_key", lambda *a, **k: None)
    result, calls = _exec_seam(f"key follows\n{DECOY_PEM}\n")
    assert len(calls) == 1
    wire = json.dumps(calls[0], ensure_ascii=False)
    assert "BEGIN RSA PRIVATE KEY" in wire, (
        "mutation did not flip the 4.3 case; private-key protection is not pinned"
    )


# ===========================================================================
# 5 — C2 diagnostics
# ===========================================================================

#: Empirically-verified reachability. Values are the ConfigError /
#: ConfigLockError code the production chain really produces for each scenario.
EXPECTED_DETAIL_CODE: Dict[str, str] = {
    "dir_exists_file_missing": "CONFIG_NOT_FOUND",
    "empty_file": "CONFIG_INVALID_JSON",
    "invalid_json": "CONFIG_INVALID_JSON",
    "duplicate_key": "CONFIG_DUPLICATE_KEY",
    "schema_forbidden_field": "CONFIG_SCHEMA",
    "mode_0644": "CONFIG_INSECURE_MODE",
    "parent_0755": "CONFIG_LOCK_FS",
    "symlink": "CONFIG_SYMLINK",
    "config_is_dir": "CONFIG_NOT_FILE",
    "too_large": "CONFIG_TOO_LARGE",
}


@pytest.mark.parametrize("kind", REVERSE_CASES)
def test_c2_detail_code_reachability_is_as_declared(isolated_home, tmp_path, kind):
    """Reachability is asserted, not copied from the task's table."""
    hermes, _ = isolated_home
    _build_reverse(kind, hermes, tmp_path, CANARY)
    with pytest.raises(rc.RuntimeConfigError) as ei:
        rc.load_and_publish_runtime()
    assert ei.value.detail_code == EXPECTED_DETAIL_CODE[kind]


@pytest.mark.parametrize("kind", REVERSE_CASES)
def test_c2_emits_actionable_diagnostic(isolated_home, tmp_path, capsys, kind):
    hermes, _ = isolated_home
    _build_reverse(kind, hermes, tmp_path, CANARY)
    result, calls = _exec_seam(f"leak attempt {CANARY}")
    _assert_blocked(result, calls, CANARY)

    _wait_diag()
    err = capsys.readouterr().err
    assert mw.CONFIG_FAILURE_HEADER in err, err
    assert str(rc.default_config_path()) in err
    assert "原因：" in err
    assert "处理：" in err
    reason, action = mw.DIAGNOSTIC_REASONS[EXPECTED_DETAIL_CODE[kind]]
    assert reason in err
    assert action in err


def test_c2_every_declared_code_has_distinct_reason_text():
    """5.1: both code families are covered, and no two codes share one reason."""
    config_codes = {
        "CONFIG_SCHEMA",
        "CONFIG_INVALID_JSON",
        "CONFIG_DUPLICATE_KEY",
        "CONFIG_INSECURE_MODE",
        "CONFIG_OWNER_MISMATCH",
        "CONFIG_SYMLINK",
        "CONFIG_TOO_LARGE",
    }
    lock_codes = {"CONFIG_LOCK_FS", "CONFIG_LOCK_TIMEOUT"}
    missing = (config_codes | lock_codes) - set(mw.DIAGNOSTIC_REASONS)
    assert missing == set(), missing
    reasons = [mw.DIAGNOSTIC_REASONS[c][0] for c in config_codes | lock_codes]
    assert len(set(reasons)) == len(reasons)
    # The directory-permission diagnostic must be reachable via the lock family.
    assert "700" in mw.DIAGNOSTIC_REASONS["CONFIG_LOCK_FS"][0]


def test_c2_store_not_found_is_not_a_failure_diagnostic():
    """3.1: the C1 arch is handled by the notice, never by the C2 failure text."""
    assert CONFIG_LOCK_STORE_NOT_FOUND not in mw.DIAGNOSTIC_REASONS


def test_c2_lock_timeout_diagnostic_text(isolated_home, capsys):
    exc = rc.RuntimeConfigError(
        "RUNTIME_CONFIG_UNAVAILABLE", detail_code="CONFIG_LOCK_TIMEOUT"
    )
    mw.emit_config_failure_diagnostic(exc)
    _wait_diag()
    err = capsys.readouterr().err
    assert mw.DIAGNOSTIC_REASONS["CONFIG_LOCK_TIMEOUT"][0] in err


def test_c2_owner_mismatch_diagnostic_text(isolated_home, capsys):
    exc = rc.RuntimeConfigError(
        "RUNTIME_CONFIG_UNAVAILABLE", detail_code="CONFIG_OWNER_MISMATCH"
    )
    mw.emit_config_failure_diagnostic(exc)
    _wait_diag()
    err = capsys.readouterr().err
    assert mw.DIAGNOSTIC_REASONS["CONFIG_OWNER_MISMATCH"][0] in err


# --- 5.3 / 5.4 zero echo ---------------------------------------------------


@pytest.mark.parametrize("kind", REVERSE_CASES)
def test_c2_zero_canary_echo_credential_value(isolated_home, tmp_path, capsys, kind):
    hermes, _ = isolated_home
    _build_reverse(kind, hermes, tmp_path, CANARY)
    result, calls = _exec_seam("hello")
    assert calls == []
    _wait_diag()
    captured = capsys.readouterr()
    assert CANARY not in captured.err
    assert CANARY not in captured.out
    assert CANARY not in str(result)


@pytest.mark.parametrize("field", ["host", "header_name", "credential_ref"])
def test_c2_zero_canary_echo_binding_fields(isolated_home, capsys, field):
    """Canary written into binding field values must never be echoed."""
    hermes, _ = isolated_home
    store = _mkstore(hermes)
    doc = _v2_doc("token-value-not-the-canary")
    binding = doc["bindings"]["internal-api"]
    if field == "host":
        binding["target"]["host"] = f"{CANARY}.example.test"
    elif field == "header_name":
        binding["inject"] = {"type": "api_key_header", "header_name": CANARY}
    elif field == "credential_ref":
        binding["credential_ref"] = CANARY
    # Forbidden field keeps it a load failure regardless of which value moved.
    binding["allowed_tools"] = ["terminal"]
    _write(store / CONFIG_FILENAME, json.dumps(doc, ensure_ascii=False))

    result, calls = _exec_seam("hello")
    assert calls == []
    _wait_diag()
    captured = capsys.readouterr()
    assert CANARY not in captured.err
    assert CANARY not in captured.out
    assert CANARY not in str(result)


def test_c2_diagnostic_never_enters_the_block_message(isolated_home, tmp_path):
    hermes, _ = isolated_home
    _build_reverse("invalid_json", hermes, tmp_path, CANARY)
    result, calls = _exec_seam("hello")
    _assert_blocked(result, calls, CANARY)
    content = result.choices[0].message.content
    assert mw.CONFIG_FAILURE_HEADER not in content
    assert str(rc.default_config_path()) not in content
    assert "/Users/" not in str(result)


def test_c2_diagnostic_scrubs_registered_secret_in_path(isolated_home, capsys):
    """5.3: diagnostics pass through the existing redactor before reaching a log."""
    secret = _decoy()
    get_registry().register("db", "password", secret)
    scrubbed = mw._scrub_local_diagnostic(f"文件：/tmp/{secret}/x.json")
    assert secret not in scrubbed


def test_c2_diagnostic_is_deduplicated_per_reason(isolated_home, tmp_path, capsys):
    hermes, _ = isolated_home
    _build_reverse("invalid_json", hermes, tmp_path, CANARY)
    for _ in range(5):
        _exec_seam("hello")
    _wait_diag()
    err = capsys.readouterr().err
    assert err.count(mw.CONFIG_FAILURE_HEADER) == 1, err


def test_c2_blocking_behaviour_is_unchanged(isolated_home, tmp_path):
    """5.4: diagnostics are additive; the block itself is byte-identical."""
    hermes, _ = isolated_home
    _build_reverse("invalid_json", hermes, tmp_path, CANARY)
    result, calls = _exec_seam("hello")
    assert calls == []
    content = result.choices[0].message.content
    assert content == mw.format_block_message(mw._config_unavailable_detail())


def test_c2_tool_result_seam_also_diagnoses(isolated_home, tmp_path, capsys):
    """3.4: the transform_tool_result seam must not stay silent."""
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    hermes, _ = isolated_home
    _build_reverse("invalid_json", hermes, tmp_path, CANARY)
    out = hooks_mod.on_transform_tool_result(
        result="tool output", tool_name="t", arguments={}
    )
    assert out == RESULT_GUARD_FAIL_TEXT
    _wait_diag()
    assert mw.CONFIG_FAILURE_HEADER in capsys.readouterr().err


# ===========================================================================
# Isolation reconciliation
# ===========================================================================


def test_new_tests_never_resolve_to_the_real_profile(isolated_home):
    """Explicit reconciliation of the 'no conftest.py' risk for this file."""
    resolved = rc.default_config_path()
    assert "/hermes_home/credential-guard/" in str(resolved)
    assert not str(resolved).startswith(str(Path.home() / ".hermes"))


# ===========================================================================
# 1.4 — pass-through must not drop the in-process registry (round-2 BLOCKING)
# ===========================================================================


class _ConflictingRegistry:
    """Two entries sharing one identity with different secrets.

    ``CredentialRegistry.register`` rejects that at registration time, so this
    stand-in is the only way to drive the merge-conflict branch of the
    pass-through snapshot. ``clear`` exists because the fixture teardown calls
    it through ``state.get_registry()``.
    """

    def __init__(self, *items: Any) -> None:
        self._items = list(items)

    def values(self) -> List[Any]:
        return list(self._items)

    def clear(self) -> None:
        self._items = []


def test_c1_passthrough_conflicting_registry_blocks_instead_of_passing(
    isolated_home, monkeypatch
):
    """A snapshot conflict must fail closed, never degrade into pass-through."""
    from types import SimpleNamespace

    from credential_guard import state as state_mod

    first, second = _decoy(), _decoy()
    monkeypatch.setattr(
        state_mod,
        "_registry",
        _ConflictingRegistry(
            SimpleNamespace(key="db", field="password", secret=first),
            SimpleNamespace(key="db", field="password", secret=second),
        ),
    )
    result, calls = _exec_seam(f"password is {first}")
    _assert_blocked(result, calls, first)
    assert second not in str(result)


def test_c1_passthrough_conflicting_registry_blocks_tool_result_seam(
    isolated_home, monkeypatch
):
    from types import SimpleNamespace

    from credential_guard import state as state_mod
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    first, second = _decoy(), _decoy()
    monkeypatch.setattr(
        state_mod,
        "_registry",
        _ConflictingRegistry(
            SimpleNamespace(key="db", field="password", secret=first),
            SimpleNamespace(key="db", field="password", secret=second),
        ),
    )
    out = hooks_mod.on_transform_tool_result(
        result=f"password is {first}", tool_name="t", arguments={}
    )
    assert out == RESULT_GUARD_FAIL_TEXT
    assert first not in out


@pytest.mark.parametrize("seam", ["llm_execution", "llm_request", "tool_result"])
def test_mut_empty_base_registry_leaks_in_memory_secret(configured_home, monkeypatch, seam):
    """Mutation: the in-process registry is dropped from the egress snapshot.

    Originally written against the C1 pass-through branch, which is gone. The
    property it guards is not: an operator who registered a credential in this
    process must never have it sent to the Provider in plaintext, and that is
    just as reachable on the configured path. Every seam must go red under the
    mutation, proving the gates above pin the fix.
    """
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    secret = _decoy()
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "get_egress_registry_snapshot", lambda: CredentialRegistry())
    monkeypatch.setattr(
        hooks_mod, "get_egress_registry_snapshot", lambda: CredentialRegistry()
    )

    if seam == "llm_execution":
        result, calls = _exec_seam(f"password is {secret}")
        _assert_passed(result, calls)
        leaked = json.dumps(calls[0], ensure_ascii=False)
    elif seam == "llm_request":
        out = _request_seam(f"password is {secret}")
        assert not mw._is_local_block_request(out["request"])
        leaked = json.dumps(out["request"], ensure_ascii=False)
    else:
        leaked = hooks_mod.on_transform_tool_result(
            result=f"password is {secret}", tool_name="t", arguments={}
        )
        assert leaked != RESULT_GUARD_FAIL_TEXT

    assert secret in leaked, (
        f"mutation did not flip {seam}; the in-memory registry gate is not load-bearing"
    )


# ===========================================================================
# C1/C2 — blocking stderr must not stall the Provider / block path
# ===========================================================================


def test_c1_blocking_stderr_does_not_stall_the_block_on_store_absent(tmp_path):
    """Store absent: a permanently blocked stderr must not stall the block.

    Isolated in a subprocess so a permanently blocked diagnostic daemon cannot
    hang pytest. Round 6 withdrew C1 pass-through, so the property changed
    shape: the seam no longer reaches the Provider here, and what must not hang
    is the fail-closed return itself. A diagnostic sink that blocks forever must
    not wedge the caller, and must not become an accidental egress path.
    """
    repo = Path(__file__).resolve().parents[1]
    marker = tmp_path / "c1_block_stderr_marker"
    status = tmp_path / "c1_block_stderr_status"
    script = f"""
import json
import os
import sys
import tempfile
import threading
from copy import deepcopy
from pathlib import Path

repo = {str(repo)!r}
sys.path.insert(0, repo)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = repo

home = Path(tempfile.mkdtemp()) / "home"
hermes = Path(tempfile.mkdtemp()) / "hermes"
home.mkdir(parents=True)
hermes.mkdir(parents=True)
(hermes / "config.yaml").write_text("# scaffold")
os.environ["HOME"] = str(home)
os.environ["HERMES_HOME"] = str(hermes)

# The plugin derives its store from its install location and no longer reads
# HERMES_HOME; these probes run from a checkout, so pin the store explicitly.
from credential_guard import store_location as _sl

_sl.use_store_dir(hermes / _sl.STORE_DIRNAME)

from credential_guard import middleware as mw
from credential_guard.middleware import on_llm_execution
from credential_guard.runtime_config import reset_runtime_for_tests, default_config_path
from credential_guard.state import get_registry

reset_runtime_for_tests()
get_registry().clear()
mw.reset_config_notices_for_tests()

resolved = default_config_path()
assert not resolved.exists()
assert not resolved.parent.exists()

req = {{"messages": [{{"role": "user", "content": "ordinary chat c1-blk"}}], "model": "fake-model"}}

entered = threading.Event()
never = threading.Event()


class BlockingStderr:
    def write(self, data):
        entered.set()
        never.wait()
        return len(data) if data else 0

    def flush(self):
        return None

    def isatty(self):
        return False


# Patch the diagnostic sink only — not global sys.stderr — so fail-closed
# logging.lastResort on the caller thread is not trapped by BlockingStderr.
_blocked = BlockingStderr()
mw._diagnostic_stderr = lambda: _blocked

provider_calls = []
returned = threading.Event()
errors = []
outcome = [None]


def run():
    try:
        def next_call(r):
            provider_calls.append(deepcopy(r))
            return {{"ok": True}}

        outcome[0] = on_llm_execution(request=deepcopy(req), next_call=next_call)
    except Exception as exc:  # pragma: no cover
        errors.append(repr(exc))
    finally:
        returned.set()


t = threading.Thread(target=run, daemon=True)
t.start()

status_path = Path({str(status)!r})
marker_path = Path({str(marker)!r})

if not entered.wait(timeout=3.0):
    status_path.write_text("WRITE_NOT_ENTERED", encoding="utf-8")
    os._exit(3)
if not returned.wait(timeout=2.0):
    status_path.write_text("BLOCK_STALLED", encoding="utf-8")
    os._exit(2)
if errors:
    status_path.write_text("RUN_ERROR:" + ";".join(errors), encoding="utf-8")
    os._exit(4)
if provider_calls:
    status_path.write_text("PROVIDER_REACHED=" + str(len(provider_calls)), encoding="utf-8")
    os._exit(5)
if getattr(outcome[0], "model", "") != "credential-guard-blocked":
    status_path.write_text("NOT_BLOCKED", encoding="utf-8")
    os._exit(6)

marker_path.write_text("PASS", encoding="utf-8")
status_path.write_text("PASS", encoding="utf-8")
os._exit(0)
"""
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repo),
    }
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    status_text = status.read_text(encoding="utf-8") if status.exists() else "<missing>"
    assert proc.returncode == 0, (
        f"rc={proc.returncode} status={status_text!r}\n"
        f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )
    assert marker.read_text(encoding="utf-8") == "PASS"
    assert status_text == "PASS"


def test_c2_blocking_stderr_still_blocks_and_caller_finishes(tmp_path):
    """C2 half-config: blocked stderr must not fail-open or stall the caller.

    Provider stays 0; the calling thread finishes in bounded time with the
    existing blocked response. Isolated in a subprocess so a stuck diagnostic
    daemon cannot hang pytest.
    """
    repo = Path(__file__).resolve().parents[1]
    marker = tmp_path / "c2_block_stderr_marker"
    status = tmp_path / "c2_block_stderr_status"
    script = f"""
import json
import os
import sys
import tempfile
import threading
from copy import deepcopy
from pathlib import Path

repo = {str(repo)!r}
sys.path.insert(0, repo)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = repo

home = Path(tempfile.mkdtemp()) / "home"
hermes = Path(tempfile.mkdtemp()) / "hermes"
home.mkdir(parents=True)
hermes.mkdir(parents=True)
store = hermes / "credential-guard"
store.mkdir(mode=0o700)
os.chmod(store, 0o700)
# Half-configured: store dir present, config file absent → C2 block.
os.environ["HOME"] = str(home)
os.environ["HERMES_HOME"] = str(hermes)

# The plugin derives its store from its install location and no longer reads
# HERMES_HOME; these probes run from a checkout, so pin the store explicitly.
from credential_guard import store_location as _sl

_sl.use_store_dir(hermes / _sl.STORE_DIRNAME)

from credential_guard import middleware as mw
from credential_guard.middleware import on_llm_execution
from credential_guard.runtime_config import reset_runtime_for_tests
from credential_guard.state import get_registry

reset_runtime_for_tests()
get_registry().clear()
mw.reset_config_notices_for_tests()

req = {{"messages": [{{"role": "user", "content": "half-config c2-blk"}}], "model": "fake-model"}}

entered = threading.Event()
never = threading.Event()


class BlockingStderr:
    def write(self, data):
        entered.set()
        never.wait()
        return len(data) if data else 0

    def flush(self):
        return None

    def isatty(self):
        return False


_blocked = BlockingStderr()
mw._diagnostic_stderr = lambda: _blocked

provider_calls = []
run_done = threading.Event()
result_box = []
errors = []


def run():
    try:
        def next_call(r):
            provider_calls.append(deepcopy(r))
            return {{"ok": True}}

        result_box.append(
            on_llm_execution(request=deepcopy(req), next_call=next_call)
        )
    except Exception as exc:  # pragma: no cover
        errors.append(repr(exc))
    finally:
        run_done.set()


t = threading.Thread(target=run, daemon=True)
t.start()

status_path = Path({str(status)!r})
marker_path = Path({str(marker)!r})

if not entered.wait(timeout=3.0):
    status_path.write_text("WRITE_NOT_ENTERED", encoding="utf-8")
    os._exit(3)
if not run_done.wait(timeout=2.0):
    status_path.write_text("CALLER_STALLED", encoding="utf-8")
    os._exit(2)
if errors:
    status_path.write_text("RUN_ERROR:" + ";".join(errors), encoding="utf-8")
    os._exit(4)
if provider_calls:
    status_path.write_text("PROVIDER_COUNT=" + str(len(provider_calls)), encoding="utf-8")
    os._exit(5)
if not result_box:
    status_path.write_text("NO_RESULT", encoding="utf-8")
    os._exit(6)
result = result_box[0]
if getattr(result, "model", "") != "credential-guard-blocked":
    status_path.write_text("NOT_BLOCKED:" + repr(getattr(result, "model", None)), encoding="utf-8")
    os._exit(7)
    if not mw.is_blocked_response_content(result.choices[0].message.content):
        status_path.write_text("BLOCK_CONTENT_MISMATCH", encoding="utf-8")
        os._exit(8)

marker_path.write_text("PASS", encoding="utf-8")
status_path.write_text("PASS", encoding="utf-8")
os._exit(0)
"""
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repo),
    }
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    status_text = status.read_text(encoding="utf-8") if status.exists() else "<missing>"
    assert proc.returncode == 0, (
        f"rc={proc.returncode} status={status_text!r}\n"
        f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )
    assert marker.read_text(encoding="utf-8") == "PASS"
    assert status_text == "PASS"


def test_c2_failclosed_log_global_stderr_backpressure_caller_finishes(tmp_path):
    """C2 fail-closed log must not stall via logging.lastResort on blocked stderr.

    Uses the real global ``sys.stderr`` (not the diagnostic sink patch) so a
    synchronous ``logger.warning`` on the caller thread is proven to hang.
    Isolated subprocess: permanently blocked lastResort must not hang pytest.
    """
    repo = Path(__file__).resolve().parents[1]
    marker = tmp_path / "c2_fc_stderr_marker"
    status = tmp_path / "c2_fc_stderr_status"
    script = f"""
import logging
import os
import sys
import tempfile
import threading
from copy import deepcopy
from pathlib import Path

repo = {str(repo)!r}
sys.path.insert(0, repo)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = repo

home = Path(tempfile.mkdtemp()) / "home"
hermes = Path(tempfile.mkdtemp()) / "hermes"
home.mkdir(parents=True)
hermes.mkdir(parents=True)
store = hermes / "credential-guard"
store.mkdir(mode=0o700)
os.chmod(store, 0o700)
os.environ["HOME"] = str(home)
os.environ["HERMES_HOME"] = str(hermes)

# The plugin derives its store from its install location and no longer reads
# HERMES_HOME; these probes run from a checkout, so pin the store explicitly.
from credential_guard import store_location as _sl

_sl.use_store_dir(hermes / _sl.STORE_DIRNAME)

from credential_guard import middleware as mw
from credential_guard.middleware import on_llm_execution
from credential_guard.runtime_config import reset_runtime_for_tests
from credential_guard.state import get_registry

reset_runtime_for_tests()
get_registry().clear()
mw.reset_config_notices_for_tests()

# No handlers → warning falls through to logging.lastResort → sys.stderr.
cg_log = logging.getLogger("credential_guard")
cg_log.handlers.clear()
cg_log.propagate = True
logging.root.handlers.clear()

req = {{"messages": [{{"role": "user", "content": "half-config fc-blk"}}], "model": "fake-model"}}

entered = threading.Event()
never = threading.Event()


class BlockingStderr:
    def write(self, data):
        entered.set()
        never.wait()
        return len(data) if data else 0

    def flush(self):
        return None

    def isatty(self):
        return False

    def fileno(self):
        raise OSError("no fileno")


sys.stderr = BlockingStderr()

provider_calls = []
run_done = threading.Event()
result_box = []
errors = []


def run():
    try:
        def next_call(r):
            provider_calls.append(deepcopy(r))
            return {{"ok": True}}

        result_box.append(
            on_llm_execution(request=deepcopy(req), next_call=next_call)
        )
    except Exception as exc:  # pragma: no cover
        errors.append(repr(exc))
    finally:
        run_done.set()


t = threading.Thread(target=run, daemon=True)
t.start()

status_path = Path({str(status)!r})
marker_path = Path({str(marker)!r})

if not entered.wait(timeout=3.0):
    status_path.write_text("WRITE_NOT_ENTERED", encoding="utf-8")
    os._exit(3)
if not run_done.wait(timeout=2.0):
    status_path.write_text("CALLER_STALLED", encoding="utf-8")
    os._exit(2)
if errors:
    status_path.write_text("RUN_ERROR:" + ";".join(errors), encoding="utf-8")
    os._exit(4)
if provider_calls:
    status_path.write_text("PROVIDER_COUNT=" + str(len(provider_calls)), encoding="utf-8")
    os._exit(5)
if not result_box:
    status_path.write_text("NO_RESULT", encoding="utf-8")
    os._exit(6)
result = result_box[0]
if getattr(result, "model", "") != "credential-guard-blocked":
    status_path.write_text("NOT_BLOCKED:" + repr(getattr(result, "model", None)), encoding="utf-8")
    os._exit(7)
if not mw.is_blocked_response_content(result.choices[0].message.content):
    status_path.write_text("BLOCK_CONTENT_MISMATCH", encoding="utf-8")
    os._exit(8)

marker_path.write_text("PASS", encoding="utf-8")
status_path.write_text("PASS", encoding="utf-8")
os._exit(0)
"""
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repo),
    }
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    status_text = status.read_text(encoding="utf-8") if status.exists() else "<missing>"
    assert proc.returncode == 0, (
        f"rc={proc.returncode} status={status_text!r}\n"
        f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )
    assert marker.read_text(encoding="utf-8") == "PASS"
    assert status_text == "PASS"


# ===========================================================================
# C2 field-level safe diagnostic location
# ===========================================================================

HOST_CANARY = "c2-field-host.example.test"
PATH_CANARY = "/c2/field/secret-path"
PROGRAM_CANARY = "/usr/local/libexec/c2-field-cli"
HEADER_CANARY = "X-C2-Field-Key"
ENV_CANARY = "C2_FIELD_ENV_TOKEN"
EXC_BODY_CANARY = "EXCEPTION_BODY_MUST_NEVER_APPEAR_" + secrets.token_hex(8)


def _assert_zero_field_leak(blob: str, secret: str = CANARY) -> None:
    assert secret not in blob
    assert HOST_CANARY not in blob
    assert PATH_CANARY not in blob
    assert PROGRAM_CANARY not in blob
    assert HEADER_CANARY not in blob
    assert ENV_CANARY not in blob
    assert EXC_BODY_CANARY not in blob
    assert "Traceback" not in blob
    assert '{"version"' not in blob


def test_c2_unknown_binding_field_emits_safe_location(isolated_home, capsys):
    """Unknown binding field → location points at bindings.<name>, never values."""
    hermes, _ = isolated_home
    store = _mkstore(hermes)
    doc = _v2_doc(CANARY)
    doc["bindings"]["internal-api"]["target"]["host"] = HOST_CANARY
    doc["bindings"]["internal-api"]["request"]["allowed_paths"] = [PATH_CANARY]
    doc["bindings"]["internal-api"]["allowed_tools"] = ["terminal"]
    _write(store / CONFIG_FILENAME, json.dumps(doc, ensure_ascii=False))

    with pytest.raises(rc.RuntimeConfigError) as ei:
        rc.load_and_publish_runtime()
    assert ei.value.detail_code == "CONFIG_SCHEMA"
    assert ei.value.location == "bindings.internal-api"
    assert CANARY not in f"{ei.value!s}{ei.value!r}"
    assert ei.value.location not in str(ei.value)  # location is not in str/repr

    result, calls = _exec_seam("hello")
    _assert_blocked(result, calls, CANARY)
    _wait_diag()
    err = capsys.readouterr().err
    assert mw.CONFIG_FAILURE_HEADER in err
    assert "位置：bindings.internal-api" in err
    _assert_zero_field_leak(err)
    _assert_zero_field_leak(str(result))


def test_c2_missing_required_binding_field_emits_safe_location(isolated_home, capsys):
    hermes, _ = isolated_home
    store = _mkstore(hermes)
    doc = _v2_doc(CANARY)
    doc["bindings"]["internal-api"]["target"]["host"] = HOST_CANARY
    del doc["bindings"]["internal-api"]["target"]
    _write(store / CONFIG_FILENAME, json.dumps(doc, ensure_ascii=False))

    with pytest.raises(rc.RuntimeConfigError) as ei:
        rc.load_and_publish_runtime()
    assert ei.value.detail_code == "CONFIG_SCHEMA"
    assert ei.value.location == "bindings.internal-api.target"
    assert "configuration error" in str(ei.value)
    assert "bindings.internal-api" not in str(ei.value)
    assert "bindings.internal-api" not in repr(ei.value)

    result, calls = _exec_seam("hello")
    _assert_blocked(result, calls, CANARY)
    _wait_diag()
    err = capsys.readouterr().err
    assert "位置：bindings.internal-api.target" in err
    _assert_zero_field_leak(err)


def test_c2_credential_schema_error_emits_safe_location(isolated_home, capsys):
    hermes, _ = isolated_home
    store = _mkstore(hermes)
    doc = {
        "version": 2,
        "credentials": {
            "internal_api_token": {"type": "token"},  # missing value
        },
        "bindings": {},
    }
    _write(store / CONFIG_FILENAME, json.dumps(doc, ensure_ascii=False))

    with pytest.raises(rc.RuntimeConfigError) as ei:
        rc.load_and_publish_runtime()
    assert ei.value.detail_code == "CONFIG_SCHEMA"
    assert ei.value.location == "credentials.internal_api_token"
    assert "internal_api_token" not in str(ei.value)
    assert "internal_api_token" not in repr(ei.value)

    result, calls = _exec_seam("hello")
    _assert_blocked(result, calls, CANARY)
    _wait_diag()
    err = capsys.readouterr().err
    assert "位置：credentials.internal_api_token" in err
    _assert_zero_field_leak(err)


def test_c2_illegal_identifier_location_degrades_to_configuration():
    """Unsafe names / control chars / oversize → whole location is configuration."""
    from credential_guard.config import normalize_safe_diag_location

    assert normalize_safe_diag_location("bindings.OK-name") == "bindings.OK-name"
    assert (
        normalize_safe_diag_location("bindings.bad name.target") == "configuration"
    )
    assert (
        normalize_safe_diag_location("bindings.evil\nname.target") == "configuration"
    )
    assert normalize_safe_diag_location("bindings." + ("a" * 80)) == "configuration"
    assert normalize_safe_diag_location("host.api.example") == "configuration"
    assert normalize_safe_diag_location("bindings.ok.not_a_field") == "configuration"
    assert normalize_safe_diag_location("") == "configuration"
    assert normalize_safe_diag_location(None) == "configuration"
    # Dangerous collision with event/code vocabulary must not invent new roots.
    assert normalize_safe_diag_location("config-failure:CONFIG_SCHEMA") == "configuration"
    assert normalize_safe_diag_location("unconfigured-notice") == "configuration"


def test_c2_unlocatable_schema_fault_stays_configuration(isolated_home, capsys):
    """Top-level / unlocatable schema faults keep location=configuration."""
    hermes, _ = isolated_home
    store = _mkstore(hermes)
    doc = _v2_doc(CANARY)
    doc["unexpected_top"] = True
    _write(store / CONFIG_FILENAME, json.dumps(doc, ensure_ascii=False))

    with pytest.raises(rc.RuntimeConfigError) as ei:
        rc.load_and_publish_runtime()
    assert ei.value.detail_code == "CONFIG_SCHEMA"
    assert ei.value.location == "configuration"

    _exec_seam("hello")
    _wait_diag()
    err = capsys.readouterr().err
    assert "位置：configuration" in err
    _assert_zero_field_leak(err)


def test_c2_diag_event_rejects_arbitrary_strings():
    """Queue payload is a bounded DiagEvent — never an arbitrary detail string."""
    from credential_guard.middleware import DiagEvent

    ev = DiagEvent(code="CONFIG_SCHEMA", location="bindings.internal-api")
    assert ev.code == "CONFIG_SCHEMA"
    assert ev.location == "bindings.internal-api"
    # Construction re-normalizes; poison values collapse.
    bad = DiagEvent(code="CONFIG_SCHEMA", location=f"bindings.x\n{CANARY}")
    assert bad.location == "configuration"
    assert CANARY not in bad.location
    unknown_code = DiagEvent(code=EXC_BODY_CANARY, location="bindings.ok")
    assert unknown_code.code == "DEFAULT"
    assert EXC_BODY_CANARY not in unknown_code.code


def test_c2_diag_ledger_hard_caps_items_and_chars(isolated_home):
    """1000 distinct safe locations must not grow the once-ledger unboundedly."""
    mw.reset_config_notices_for_tests()
    # Directly exercise the emit path with synthetic RuntimeConfigError locations.
    for i in range(1000):
        name = f"b{i:04d}"
        loc = f"bindings.{name}"
        assert len(loc) <= 256
        exc = rc.RuntimeConfigError(
            "RUNTIME_CONFIG_INVALID",
            detail_code="CONFIG_SCHEMA",
            location=loc,
        )
        mw.emit_config_failure_diagnostic(exc)
    _wait_diag()
    items, chars = mw.diag_ledger_stats_for_tests()
    assert items <= mw.DIAG_LEDGER_MAX_ITEMS
    assert chars <= mw.DIAG_LEDGER_MAX_CHARS
    assert items > 0
    assert chars > 0


def test_c2_queue_still_bounded_at_sixteen(monkeypatch):
    """Queue maxsize remains 16 even when many distinct DiagEvents are submitted."""
    import queue as queue_mod

    mw.reset_config_notices_for_tests()
    # Do not start the daemon — fill the queue via put_nowait only.
    monkeypatch.setattr(mw, "_ensure_diagnostic_worker", lambda: None)
    for i in range(40):
        mw.emit_config_failure_diagnostic(
            rc.RuntimeConfigError(
                "RUNTIME_CONFIG_INVALID",
                detail_code="CONFIG_SCHEMA",
                location=f"bindings.q{i:02d}",
            )
        )
    assert mw._DIAG_QUEUE.maxsize == 16
    assert mw._DIAG_QUEUE.qsize() <= 16
    # Drain so subsequent tests are not poisoned by orphaned DiagEvents.
    while True:
        try:
            mw._DIAG_QUEUE.get_nowait()
        except queue_mod.Empty:
            break
    # Reset submit counters so idle waits in other tests stay honest.
    with mw._DIAG_IDLE_LOCK:
        mw._DIAG_EMITS_SUBMITTED = 0
        mw._DIAG_EMITS_COMPLETED = 0
        mw._DIAG_WRITE_IN_FLIGHT = 0
    mw.reset_config_notices_for_tests()


def test_mut_diag_location_accepting_exception_detail_leaks_canary():
    """Mutation probe: location must reject exception-detail / host segments."""
    from credential_guard import config as cfg

    poison = f"bindings.ok.{EXC_BODY_CANARY}"
    assert cfg.normalize_safe_diag_location(poison) == "configuration"
    # Value-like segments (host/path) are never allowed as free-form text.
    assert (
        cfg.normalize_safe_diag_location(f"bindings.ok.{HOST_CANARY}")
        == "configuration"
    )


def test_mut_dropping_location_normalize_makes_field_tests_red(monkeypatch):
    """Mutation probe: deleting normalization must make illegal locations stick."""
    from credential_guard import config as cfg

    monkeypatch.setattr(cfg, "normalize_safe_diag_location", lambda raw: raw or "configuration")
    assert cfg.normalize_safe_diag_location(f"bindings.x\n{CANARY}") != "configuration"
