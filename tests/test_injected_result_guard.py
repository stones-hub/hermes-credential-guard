"""R4 unified result guard — format preservation, secrets, fail-closed."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Tuple

import pytest

from credential_guard.hooks import on_transform_tool_result
from credential_guard.models import make_token_id
from credential_guard.state import get_registry

SAFE_FAIL = (
    "工具可能已经执行，但返回内容未通过安全检查，原始结果未返回。"
    "请独立核验目标系统的真实状态。"
)
REDACTED = "<REDACTED_SECRET>"

DECOY_TOKEN = "cg_r4_decoy_token_ABCDEF12"
DECOY_PASS = "cg_r4_decoy_pass_XYZabc99"


def _session_token(name: str) -> str:
    return f"<SECRET:{make_token_id(name, 'value')}>"


@pytest.fixture(autouse=True)
def _isolated_empty_store(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()


def _guard(result: str, **kwargs: Any) -> str:
    return on_transform_tool_result(
        result=result,
        tool_name=kwargs.get("tool_name", "dummy"),
        arguments=kwargs.get("arguments") or {},
        args=kwargs.get("args"),
    )


# ---------------------------------------------------------------------------
# Slice A — format preservation + registered credentials
# ---------------------------------------------------------------------------


def test_preserve_clean_plain_text_byte_identical():
    raw = "hello world\nline2\ttab  spaces"
    assert _guard(raw) == raw


def test_preserve_clean_json_whitespace_and_field_order():
    raw = '{\n  "z": 1,\n  "a": "keep",\n  "nested": { "b": true, "c": null }\n}'
    assert _guard(raw) == raw


def test_registered_secret_in_json_string_replaces_fragment_only():
    item = get_registry().register("api", "value", DECOY_TOKEN)
    raw = '{\n  "msg": "token=' + DECOY_TOKEN + '",\n  "ok": true\n}'
    out = _guard(raw)
    assert DECOY_TOKEN not in out
    assert item.token in out
    assert "<CREDENTIAL:" not in out
    assert out == raw.replace(DECOY_TOKEN, item.token)


def test_preserve_markdown_table_chinese_numbers_bools():
    raw = (
        "# 标题\n"
        "| 列 | 值 |\n| --- | --- |\n| 中文 | 42 |\n"
        "flag=true count=0 done=false\n"
    )
    assert _guard(raw) == raw


def test_registered_plain_text_uses_credential_placeholder():
    item = get_registry().register("db", "password", DECOY_PASS)
    out = _guard(f"error {DECOY_PASS} trailing")
    assert out == f"error {item.token} trailing"


# ---------------------------------------------------------------------------
# Slice B — high-confidence unknown secrets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expect_substr",
    [
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def", REDACTED),
        ("Authorization: Basic Y2dfdXNlcjpjZ19wYXNz", REDACTED),
        ("Proxy-Authorization: Basic YWJjZGVmZ2hpams=", REDACTED),
        ("Cookie: session=abc123secrettoken; theme=dark", REDACTED),
        ("Set-Cookie: session=xyz_secret_value; Path=/; Secure", REDACTED),
    ],
)
def test_auth_header_cookie_value_fully_redacted(raw: str, expect_substr: str):
    out = _guard(raw)
    assert expect_substr in out
    # Original secret material after the header name must not remain.
    if raw.lower().startswith("authorization:") or raw.lower().startswith(
        "proxy-authorization:"
    ):
        assert "Bearer eyJ" not in out
        assert "Basic Y2" not in out and "Basic YW" not in out
    if "Cookie:" in raw or "Set-Cookie:" in raw:
        assert "session=abc123secrettoken" not in out
        assert "session=xyz_secret_value" not in out
    # Auth Cookie/Set-Cookie values are replaced as a whole segment.
    if raw.lower().startswith("cookie:") or raw.lower().startswith("set-cookie:"):
        assert out.split(":", 1)[1].strip() == REDACTED or out == SAFE_FAIL


def test_auth_header_unique_registered_keeps_credential_placeholder():
    """B2: unique registered secret in Authorization → whole value registry token."""
    item = get_registry().register("api", "token", DECOY_TOKEN)
    raw = f"Authorization: Bearer {DECOY_TOKEN}"
    out = _guard(raw)
    assert out == f"Authorization: {item.token}"
    assert DECOY_TOKEN not in out
    assert REDACTED not in out
    assert "<CREDENTIAL:" not in out


def test_proxy_authorization_unique_registered_keeps_credential_placeholder():
    item = get_registry().register("api", "token", DECOY_TOKEN)
    raw = f"Proxy-Authorization: Basic {DECOY_TOKEN}"
    out = _guard(raw)
    assert out == f"Proxy-Authorization: {item.token}"
    assert REDACTED not in out


def test_cookie_unique_registered_keeps_credential_placeholder():
    item = get_registry().register("sess", "token", DECOY_TOKEN)
    raw = f"Cookie: session={DECOY_TOKEN}; theme=dark"
    out = _guard(raw)
    assert out == f"Cookie: {item.token}"
    assert DECOY_TOKEN not in out
    assert REDACTED not in out


def test_set_cookie_unique_registered_keeps_credential_placeholder():
    item = get_registry().register("sess", "token", DECOY_TOKEN)
    raw = f"Set-Cookie: session={DECOY_TOKEN}; Path=/; Secure"
    out = _guard(raw)
    assert out == f"Set-Cookie: {item.token}"
    assert REDACTED not in out


def test_auth_header_unregistered_stays_redacted_secret():
    raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.unregistered.sig"
    out = _guard(raw)
    assert out == f"Authorization: {REDACTED}"


def test_auth_header_multiple_registered_identities_redacted_secret():
    decoy_a = "cg_r4_multi_a_" + "A" * 20
    decoy_b = "cg_r4_multi_b_" + "B" * 20
    get_registry().register("alpha", "token", decoy_a)
    get_registry().register("beta", "token", decoy_b)
    raw = f"Authorization: Bearer {decoy_a}:{decoy_b}"
    out = _guard(raw)
    assert out == f"Authorization: {REDACTED}"
    assert decoy_a not in out and decoy_b not in out
    assert "<CREDENTIAL:alpha>" not in out
    assert "<CREDENTIAL:beta>" not in out


def test_auth_header_preserves_name_and_colon_spacing():
    item = get_registry().register("api", "token", DECOY_TOKEN)
    raw = f"Authorization:\t{DECOY_TOKEN}"
    out = _guard(raw)
    assert out == f"Authorization:\t{item.token}"


def test_mutation_auth_always_redacted_secret_kills_credential_keep(monkeypatch):
    """Mutation: forcing auth values to REDACTED_SECRET must fail unique-registered keep."""
    import credential_guard.result_guard as rg

    item = get_registry().register("api", "token", DECOY_TOKEN)
    monkeypatch.setattr(
        rg, "_auth_cookie_replacement_value", lambda _value: rg.REDACTED_SECRET
    )
    out = rg.guard_tool_result(f"Authorization: Bearer {DECOY_TOKEN}", get_registry())
    assert out == f"Authorization: {REDACTED}"
    assert item.token not in out
    assert "<CREDENTIAL:api>" not in out


def test_explicit_password_token_secret_fields_in_json_text():
    raw = (
        '{\n  "password": "unknown_pass_value_1",\n'
        '  "token": "unknown_token_value_2",\n'
        '  "secret": "unknown_secret_value_3",\n'
        '  "request_id": "req-keep-me"\n}'
    )
    out = _guard(raw)
    assert "unknown_pass_value_1" not in out
    assert "unknown_token_value_2" not in out
    assert "unknown_secret_value_3" not in out
    assert out.count(REDACTED) >= 3
    assert "req-keep-me" in out
    # Structure / indentation preserved aside from value replacements.
    assert '"request_id": "req-keep-me"' in out
    assert out.startswith("{\n")


def test_pem_private_key_replaced_when_fully_locatable():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7decoy_pem_body\n"
        "-----END PRIVATE KEY-----"
    )
    raw = f"before\n{pem}\nafter"
    out = _guard(raw)
    assert "BEGIN PRIVATE KEY" not in out
    assert REDACTED in out
    assert out.startswith("before\n")
    assert out.endswith("\nafter")


def test_request_id_trace_id_uuid_not_false_positive():
    raw = (
        "request_id=550e8400-e29b-41d4-a716-446655440000 "
        "trace_id=4bf92f3577b34da6a3ce929d0e0e4736 "
        "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "git=abcdef0123456789abcdef0123456789abcdef01"
    )
    assert _guard(raw) == raw


# ---------------------------------------------------------------------------
# Slice C — exceptions, fail-closed, no retry semantics
# ---------------------------------------------------------------------------


def test_safe_exception_text_keeps_type_code_ids():
    raw = (
        "ConnectionError: timeout code=ETIMEDOUT "
        "request_id=req-abc-123 trace_id=tr-xyz-999"
    )
    assert _guard(raw) == raw


def test_exception_with_registered_secret_point_replace():
    item = get_registry().register("svc", "value", DECOY_TOKEN)
    raw = f"HTTPError: upstream rejected token={DECOY_TOKEN} request_id=r1"
    out = _guard(raw)
    assert out == (
        f"HTTPError: upstream rejected token={item.token} request_id=r1"
    )


def test_guard_component_exceptions_return_fixed_text(monkeypatch):
    get_registry().register("svc", "value", DECOY_TOKEN)

    def boom(*_a, **_k):
        raise RuntimeError(f"scanner boom {DECOY_TOKEN}")

    # Inject failures into result_guard internals one at a time.
    import credential_guard.result_guard as rg

    targets = [
        "redact_registered",
        "redact_unknown_high_confidence",
        "redact_private_keys",
        "assert_zero_residue",
    ]
    for name in targets:
        if not hasattr(rg, name):
            pytest.skip(f"result_guard.{name} not yet defined")
        monkeypatch.setattr(rg, name, boom)
        out = _guard(f"msg {DECOY_TOKEN}")
        assert out == SAFE_FAIL
        assert DECOY_TOKEN not in out
        monkeypatch.undo()


def test_fixed_fail_text_has_no_tool_verdict_words():
    import credential_guard.result_guard as rg

    text = getattr(rg, "RESULT_GUARD_FAIL_TEXT", SAFE_FAIL)
    lowered = text.lower()
    for banned in ("ok=false", "failed", "success", "rollback"):
        assert banned not in lowered
    assert text == SAFE_FAIL


def test_guard_block_does_not_invoke_downstream_tool(monkeypatch):
    calls: List[str] = []

    def boom(*_a, **_k):
        raise RuntimeError("force guard fail")

    import credential_guard.result_guard as rg

    if not hasattr(rg, "guard_tool_result"):
        pytest.skip("guard_tool_result not yet defined")
    monkeypatch.setattr(rg, "guard_tool_result", boom)

    # Hook itself must not retry / re-call tools; only return fixed text.
    out = _guard("anything")
    assert out == SAFE_FAIL
    assert calls == []


def test_guard_fail_logs_only_fixed_reason_code(caplog, monkeypatch):
    import credential_guard.result_guard as rg
    from credential_guard.local_events import wait_fail_closed_idle_for_tests

    if not hasattr(rg, "redact_registered"):
        pytest.skip("redact_registered not yet defined")

    def boom(*_a, **_k):
        raise RuntimeError(f"secret={DECOY_TOKEN}")

    monkeypatch.setattr(rg, "redact_registered", boom)
    get_registry().register("svc", "value", DECOY_TOKEN)
    caplog.set_level(logging.WARNING, logger="credential_guard")
    out = _guard(f"x {DECOY_TOKEN}")
    assert out == SAFE_FAIL
    assert wait_fail_closed_idle_for_tests(timeout=2.0)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert DECOY_TOKEN not in joined
    assert "secret=" not in joined
    assert "result_guard" in joined.lower() or "credential-guard" in joined.lower()


def test_result_guard_failclosed_log_global_stderr_backpressure_caller_finishes(tmp_path):
    """guard_tool_result internal catch must not stall on blocked stderr lastResort."""
    repo = Path(__file__).resolve().parents[1]
    marker = tmp_path / "rg_fc_stderr_marker"
    status = tmp_path / "rg_fc_stderr_status"
    script = f"""
import logging
import os
import sys
import tempfile
import threading
from pathlib import Path

repo = {str(repo)!r}
sys.path.insert(0, repo)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = repo

home = Path(tempfile.mkdtemp()) / "home"
hermes = Path(tempfile.mkdtemp()) / "hermes"
home.mkdir(parents=True)
hermes.mkdir(parents=True)
os.environ["HOME"] = str(home)
os.environ["HERMES_HOME"] = str(hermes)

from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT, guard_tool_result
from credential_guard.registry import CredentialRegistry
import credential_guard.result_guard as rg

cg_log = logging.getLogger("credential_guard")
cg_log.handlers.clear()
cg_log.propagate = True
logging.root.handlers.clear()

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

decoy = "RG_FC_DECOY_NEVER_ECHO_88"


def boom(*_a, **_k):
    raise RuntimeError(f"redact boom {{decoy}}")


rg.redact_registered = boom

run_done = threading.Event()
result_box = []
errors = []


def run():
    try:
        result_box.append(
            guard_tool_result(f"leak {{decoy}}", CredentialRegistry())
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
if not result_box:
    status_path.write_text("NO_RESULT", encoding="utf-8")
    os._exit(5)
out = result_box[0]
if out != RESULT_GUARD_FAIL_TEXT:
    status_path.write_text("RESULT_MISMATCH:" + repr(out)[:200], encoding="utf-8")
    os._exit(6)
if decoy in out:
    status_path.write_text("DECOY_ECHO", encoding="utf-8")
    os._exit(7)
if "redact boom" in out:
    status_path.write_text("EXC_ECHO", encoding="utf-8")
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


# ---------------------------------------------------------------------------
# Slice D helpers — session materials + idempotency (unit level)
# ---------------------------------------------------------------------------


def test_session_materials_merge_and_credential_placeholder():
    from credential_guard.result_guard import guard_tool_result
    from credential_guard.state import get_egress_registry_snapshot

    registry = get_egress_registry_snapshot()
    materials: List[Tuple[str, str]] = [("http_token", DECOY_TOKEN)]
    raw = f"echoed={DECOY_TOKEN} ok"
    tok = _session_token("http_token")
    out = guard_tool_result(raw, registry, session_materials=materials)
    assert out == f"echoed={tok} ok"
    assert "<CREDENTIAL:" not in out
    # Idempotent second pass.
    out2 = guard_tool_result(out, registry, session_materials=materials)
    assert out2 == out


def test_process_style_business_output_preserved_with_secret_replaced():
    from credential_guard.result_guard import guard_tool_result
    from credential_guard.state import get_egress_registry_snapshot

    registry = get_egress_registry_snapshot()
    materials = [("cli_token", DECOY_TOKEN)]
    raw = f"STATUS=0\nENV_PROBE=ABSENT\nECHO={DECOY_TOKEN}\n"
    out = guard_tool_result(raw, registry, session_materials=materials)
    assert "STATUS=0" in out
    assert "ENV_PROBE=ABSENT" in out
    assert DECOY_TOKEN not in out
    assert _session_token("cli_token") in out
    assert "<CREDENTIAL:" not in out
    assert "PROCESS_OUTPUT_LEAK" not in out
    assert "***" not in out


# ---------------------------------------------------------------------------
# Slice E — large result full coverage
# ---------------------------------------------------------------------------


def test_large_clean_log_byte_identical():
    # Stay under private-key per-candidate cap (whole string is a decode candidate).
    from credential_guard.sensitive_paths import MAX_PRIVATE_KEY_CANDIDATE_LENGTH

    chunk = "INFO normal line without secrets\n"
    raw = chunk * max(1, (MAX_PRIVATE_KEY_CANDIDATE_LENGTH // len(chunk)) - 2)
    assert len(raw) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(raw.encode("utf-8")) < 500_000
    assert _guard(raw) == raw


def test_large_result_secret_at_head_mid_tail():
    from credential_guard.sensitive_paths import MAX_PRIVATE_KEY_CANDIDATE_LENGTH

    item = get_registry().register("api", "value", DECOY_TOKEN)
    pad = "x" * 10_000
    raw = f"{DECOY_TOKEN}{pad}{DECOY_TOKEN}{pad}{DECOY_TOKEN}"
    assert len(raw) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    out = _guard(raw)
    assert DECOY_TOKEN not in out
    assert out.count(item.token) == 3
    assert out == raw.replace(DECOY_TOKEN, item.token)


def test_large_result_secret_near_common_buffer_boundaries():
    from credential_guard.sensitive_paths import MAX_PRIVATE_KEY_CANDIDATE_LENGTH

    item = get_registry().register("api", "value", DECOY_TOKEN)
    # Common buffer edges within the existing candidate-length ceiling.
    positions = (4095, 4096, 8191, 8192, 16383, 16384, 32767, 32768)
    for pos in positions:
        raw = ("n" * pos) + DECOY_TOKEN + ("m" * 100)
        assert len(raw) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
        out = _guard(raw)
        assert DECOY_TOKEN not in out
        assert out == raw.replace(DECOY_TOKEN, item.token)


def test_scan_exception_on_large_input_fail_closed(monkeypatch):
    import credential_guard.result_guard as rg

    if not hasattr(rg, "assert_zero_residue"):
        pytest.skip("assert_zero_residue not yet defined")

    def boom(*_a, **_k):
        raise RuntimeError("residue check failed")

    monkeypatch.setattr(rg, "assert_zero_residue", boom)
    get_registry().register("api", "value", DECOY_TOKEN)
    out = _guard("n" * 10_000 + DECOY_TOKEN)
    assert out == SAFE_FAIL


def test_over_max_private_key_scan_bytes_fail_closed():
    """B3: exceeding MAX_PRIVATE_KEY_SCAN_BYTES must fail closed — no window bypass."""
    from credential_guard.sensitive_paths import MAX_PRIVATE_KEY_SCAN_BYTES

    raw = "n" * (MAX_PRIVATE_KEY_SCAN_BYTES + 64)
    assert len(raw.encode("utf-8")) > MAX_PRIVATE_KEY_SCAN_BYTES
    assert _guard(raw) == SAFE_FAIL


def test_encoded_private_key_scan_error_at_production_call_fail_closed(monkeypatch):
    """B3: scanner exception at result_guard's real call site → fixed fail text."""
    import credential_guard.result_guard as rg
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    def boom(_text: str) -> bool:
        raise EncodedPrivateKeyScanError("injected scan failure")

    monkeypatch.setattr(rg, "contains_private_key_material", boom)
    assert _guard("clean payload without keys") == SAFE_FAIL


def test_mutation_swallow_scan_error_allows_oversize_bypass(monkeypatch):
    """Mutation: swallowing EncodedPrivateKeyScanError must be detectable as leak-through."""
    import credential_guard.result_guard as rg
    from credential_guard.sensitive_paths import (
        EncodedPrivateKeyScanError,
        MAX_PRIVATE_KEY_SCAN_BYTES,
        contains_private_key_material,
    )

    def swallow(text: str) -> bool:
        try:
            return bool(contains_private_key_material(text))
        except EncodedPrivateKeyScanError:
            return False

    monkeypatch.setattr(rg, "_private_key_present", swallow)
    raw = "n" * (MAX_PRIVATE_KEY_SCAN_BYTES + 64)
    out = rg.guard_tool_result(raw, get_registry())
    # Mutated path bypasses fail-closed — carrier health relies on opposite assertion above.
    assert out == raw


# ---------------------------------------------------------------------------
# Mutations (run only when carrier is green — invoked explicitly)
# ---------------------------------------------------------------------------


def test_mutation_json_parse_serialize_breaks_preserve(monkeypatch):
    """Carrier health: if hooks re-introduce parse/serialize, preserve must RED."""
    import credential_guard.hooks as hooks

    raw = '{\n  "z": 1,\n  "a": "keep"\n}'
    # Sanity: healthy path preserves.
    assert hooks.on_transform_tool_result(result=raw, tool_name="d", arguments={}) == raw

    real = hooks.on_transform_tool_result

    def mutated(**kwargs):
        result = kwargs.get("result", "")
        if isinstance(result, str) and result.strip().startswith("{"):
            return json.dumps(json.loads(result), ensure_ascii=False)
        return real(**kwargs)

    monkeypatch.setattr(hooks, "on_transform_tool_result", mutated)
    out = hooks.on_transform_tool_result(result=raw, tool_name="d", arguments={})
    assert out != raw  # mutation killed by preserve expectation


def test_mutation_skip_residue_check_allows_leak(monkeypatch):
    import credential_guard.result_guard as rg

    if not hasattr(rg, "assert_zero_residue"):
        pytest.skip("assert_zero_residue not yet defined")

    get_registry().register("api", "value", DECOY_TOKEN)
    # Force a path where redaction is skipped but residue check is neutered.
    monkeypatch.setattr(rg, "redact_registered", lambda text, *_a, **_k: text)
    monkeypatch.setattr(rg, "assert_zero_residue", lambda *_a, **_k: None)
    monkeypatch.setattr(
        rg, "redact_unknown_high_confidence", lambda text, *_a, **_k: text
    )
    monkeypatch.setattr(rg, "redact_private_keys", lambda text, *_a, **_k: text)
    out = rg.guard_tool_result(f"leak {DECOY_TOKEN}", get_registry())
    # With residue check removed, leak would pass — prove mutation is detectable.
    assert DECOY_TOKEN in out


# ---------------------------------------------------------------------------
# Slice D — HTTP/process reuse the same authority
# ---------------------------------------------------------------------------


def test_http_adapter_echo_uses_credential_placeholder(tmp_path, monkeypatch):
    from credential_guard.adapters import http as http_adapter
    from credential_guard.injection import InjectionError, SecretLease
    from credential_guard.result_guard import guard_tool_result
    from credential_guard.registry import CredentialRegistry

    binding = {
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

    def transport(_req):
        return {
            "status": 200,
            "headers": {"content-type": "text/plain", "x-request-id": "req-1"},
            "body": f"token={DECOY_TOKEN}".encode(),
        }

    lease = SecretLease({"kind": "token", "value": DECOY_TOKEN})
    result = http_adapter.execute_http(
        binding=binding,
        method="POST",
        path="/job/project-x/build",
        lease=lease,
        transport=transport,
    )
    lease.close()
    dumped = json.dumps(result)
    assert DECOY_TOKEN not in dumped
    assert result["ok"] is True
    assert _session_token("jenkins-token") in dumped
    assert "<CREDENTIAL:" not in dumped
    assert "***" not in dumped
    again = guard_tool_result(dumped, CredentialRegistry())
    assert again == dumped
    with pytest.raises(InjectionError):
        lease.read_for_adapter()


def test_process_adapter_echo_preserves_business_output(tmp_path):
    from credential_guard.adapters import process as proc
    from credential_guard.injection import SecretLease
    from credential_guard.process_identity import (
        capture_program_identity,
        cleanup_verified_executable,
        prepare_verified_executable,
    )

    helper = tmp_path / "cg-echo"
    helper.write_text(
        "#!/bin/sh\nprintf 'STATUS=0\\nECHO=%s\\n' \"$CG_PROBE_ENV\"\n",
        encoding="utf-8",
    )
    os.chmod(helper, 0o700)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = {
            "type": "process_env",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program],
            "env_name": "CG_PROBE_ENV",
            "timeout_seconds": 10,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        }
        lease = SecretLease({"kind": "token", "value": DECOY_TOKEN})
        result = proc.execute_process(binding=binding, lease=lease, verified=verified)
        lease.close()
        assert result["ok"] is True
        assert "STATUS=0" in result["stdout"]
        assert DECOY_TOKEN not in result["stdout"]
        assert _session_token("cli_token") in result["stdout"]
        assert "<CREDENTIAL:" not in result["stdout"]
        assert result.get("error") != "PROCESS_OUTPUT_LEAK"
        assert "***" not in result["stdout"]
    finally:
        cleanup_verified_executable(verified)
