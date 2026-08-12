"""R7 Round 2: long-text JSON-escape PEM + non-forgeable local block state."""

from __future__ import annotations

import base64
import json
import os
import textwrap
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

import pytest

from credential_guard.middleware import (
    SAFE_BLOCK_MESSAGE,
    on_llm_execution,
    on_llm_request,
)
from credential_guard.sensitive_paths import (
    MAX_PRIVATE_KEY_CANDIDATE_LENGTH,
    MAX_PRIVATE_KEY_DECODE_CANDIDATES,
    MAX_PRIVATE_KEY_SCAN_BYTES,
    EncodedPrivateKeyScanError,
    contains_private_key_material,
)
from credential_guard.state import get_registry


OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----
"""

# Historical Round-1 public sentinel strings (must NOT be the live block signal).
_LEGACY_LOCAL_BLOCK_MODEL = "credential-guard-local-block"
_LEGACY_LOCAL_BLOCK_MARKER = "_credential_guard_local_block"
_LEGACY_LOCAL_BLOCK_VALUE = "terminate-v1"

HERMES_AGENT_ROOT = Path("/Users/yelei/.hermes/hermes-agent")
HERMES_PYTHON = Path("/Users/yelei/.hermes/hermes-agent/venv/bin/python")


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


def _ordinary_long_text() -> str:
    # Spaces/punctuation break continuous Base64 alphabet runs; not a PEM / encoded key.
    text = (
        "Ordinary Hermes system prompt line with spaces, punctuation, and words. "
        * 2000
    )
    assert len(text) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(text.encode("utf-8")) < MAX_PRIVATE_KEY_SCAN_BYTES
    assert "PRIVATE KEY" not in text
    assert "-----BEGIN" not in text
    return text


def _fully_unicode_escape(text: str) -> str:
    """Encode every character as \\uXXXX so plaintext BEGIN/END markers are absent."""
    return "".join(f"\\u{ord(ch):04x}" for ch in text)


def _long_text_with_fully_unicode_escaped_pem() -> str:
    escaped = _fully_unicode_escape(OPENSSH_KEY)
    assert "BEGIN" not in escaped
    assert "PRIVATE KEY" not in escaped
    assert "END" not in escaped
    assert "\\u" in escaped
    pad = (
        "Ordinary Hermes system prompt line with spaces, punctuation, and words. "
        * 2000
    )
    # Embed the escape run inside long ordinary prose.
    mid = max(0, (MAX_PRIVATE_KEY_CANDIDATE_LENGTH // 2) - (len(escaped) // 2))
    text = pad[:mid] + escaped + pad
    while len(text) <= MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
        text += " more ordinary words for length."
    assert "-----BEGIN" not in text
    assert "PRIVATE KEY" not in text
    assert "\\u" in text
    assert len(text) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(text.encode("utf-8")) < MAX_PRIVATE_KEY_SCAN_BYTES
    return text


# ---------------------------------------------------------------------------
# Round 1 regressions (still required)
# ---------------------------------------------------------------------------


def test_r7_t1_long_ordinary_text_does_not_false_block():
    """T1: long ordinary string must pass request + execution."""
    long_text = _ordinary_long_text()
    assert contains_private_key_material(long_text) is False

    model = "fake-model"
    original = {
        "model": model,
        "messages": [
            {"role": "system", "content": long_text},
            {"role": "user", "content": "你好"},
        ],
    }
    out = on_llm_request(request=original)
    assert out["request"]["model"] == model
    assert out["request"]["messages"][0]["content"] == long_text
    assert out["request"]["messages"][1]["content"] == "你好"
    assert SAFE_BLOCK_MESSAGE not in json.dumps(out, ensure_ascii=False)
    assert original["messages"][0]["content"] == long_text

    calls = []

    def next_call(request):
        calls.append(request)
        return {"ok": True}

    result = on_llm_execution(request=out["request"], next_call=next_call)
    assert result == {"ok": True}
    assert len(calls) == 1
    assert calls[0]["model"] == model


def test_r7_t2_raw_pem_still_detected():
    assert contains_private_key_material(OPENSSH_KEY) is True


def test_r7_t2_short_encoded_pem_variants_still_detected():
    pem = OPENSSH_KEY
    std = base64.b64encode(pem.encode("utf-8")).decode("ascii")
    url = base64.urlsafe_b64encode(pem.encode("utf-8")).decode("ascii")
    pct = quote(pem, safe="")
    esc = json.dumps(pem, ensure_ascii=True)[1:-1]
    assert len(std) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(url) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(pct) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(esc) < MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    for label, encoded in (("std", std), ("url", url), ("pct", pct), ("esc", esc)):
        assert contains_private_key_material(encoded) is True, label


def test_r7_t2_scan_byte_budget_still_fail_closed():
    huge = "A" * (MAX_PRIVATE_KEY_SCAN_BYTES + 10)
    with pytest.raises(EncodedPrivateKeyScanError, match="payload exceeds scan byte limit"):
        contains_private_key_material(huge)


def test_r7_t2_candidate_count_budget_still_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "credential_guard.sensitive_paths.MAX_PRIVATE_KEY_DECODE_CANDIDATES", 2
    )
    chunks = [base64.b64encode(f"cg_cand_{i}_".encode() + b"x" * 40).decode() for i in range(8)]
    text = " ".join(chunks)
    with pytest.raises(EncodedPrivateKeyScanError, match="too many decode candidates"):
        contains_private_key_material(text)


def test_r7_t2_overlong_encoding_like_candidate_still_fail_closed():
    """A continuous Base64-alphabet blob over the candidate limit must fail closed."""
    overlong = "A" * (MAX_PRIVATE_KEY_CANDIDATE_LENGTH + 64)
    assert len(overlong) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH
    assert len(overlong.encode("utf-8")) < MAX_PRIVATE_KEY_SCAN_BYTES
    with pytest.raises(EncodedPrivateKeyScanError, match="candidate exceeds max length"):
        contains_private_key_material(overlong)

    calls = []
    blocked = on_llm_execution(
        request={"messages": [{"role": "user", "content": overlong}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert blocked.choices[0].message.content == SAFE_BLOCK_MESSAGE


# ---------------------------------------------------------------------------
# Slice A — fully Unicode-escaped PEM inside overlong ordinary text
# ---------------------------------------------------------------------------


def test_r7_a1_fully_unicode_escaped_pem_in_long_text_is_detected():
    """A1: synthetic PEM as per-char \\uXXXX inside long prose must be detected."""
    text = _long_text_with_fully_unicode_escaped_pem()
    assert contains_private_key_material(text) is True

    calls = []
    blocked = on_llm_execution(
        request={"model": "fake-model", "messages": [{"role": "user", "content": text}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == [], "encoded PEM in long text must not reach downstream"
    assert blocked.choices[0].message.content == SAFE_BLOCK_MESSAGE


def test_r7_a3_mutation_whole_text_decode_skip_is_load_bearing(monkeypatch):
    """A3: if overlong prose is again treated as one decode candidate, T1 must RED."""
    import credential_guard.sensitive_paths as sp

    long_text = _ordinary_long_text()
    assert contains_private_key_material(long_text) is False

    def always_add_stripped(text: str):
        candidates = []
        seen = set()

        def add(item: str) -> None:
            if not item or item in seen:
                return
            if len(item) > sp.MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
                raise sp.EncodedPrivateKeyScanError("candidate exceeds max length")
            seen.add(item)
            candidates.append(item)
            if len(candidates) > sp.MAX_PRIVATE_KEY_DECODE_CANDIDATES:
                raise sp.EncodedPrivateKeyScanError("too many decode candidates")

        add(text.strip())
        return candidates

    monkeypatch.setattr(sp, "_iter_decode_candidates", always_add_stripped)
    with pytest.raises(EncodedPrivateKeyScanError, match="candidate exceeds max length"):
        sp.contains_private_key_material(long_text)


def test_r7_a3_mutation_drop_json_escape_subcandidates_is_red(monkeypatch):
    """A3: removing JSON-escape run extraction must miss fully \\uXXXX PEM in long text."""
    import credential_guard.sensitive_paths as sp

    text = _long_text_with_fully_unicode_escaped_pem()
    assert sp.contains_private_key_material(text) is True

    def no_json_escape_subcandidates(blob: str):
        """Mutated extractor: keep short whole-field JSON path; drop overlong run scan."""
        candidates = []
        seen = set()

        def add(item: str) -> None:
            if not item or item in seen:
                return
            if len(item) > sp.MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
                raise sp.EncodedPrivateKeyScanError("candidate exceeds max length")
            seen.add(item)
            candidates.append(item)
            if len(candidates) > sp.MAX_PRIVATE_KEY_DECODE_CANDIDATES:
                raise sp.EncodedPrivateKeyScanError("too many decode candidates")

        stripped = blob.strip()
        if len(stripped) <= sp.MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
            add(stripped)
        for match in sp._B64_ALPHABET_RE.finditer(blob):
            token = match.group(0)
            if len(token) >= sp.MIN_PRIVATE_KEY_B64_CANDIDATE:
                add(token)
        for match in sp._PERCENT_RUN_RE.finditer(blob):
            add(match.group(0))
        # Intentionally omit overlong JSON-escape run extraction (load-bearing).
        if "\\u" in blob or '\\"' in blob or "\\\\" in blob:
            if len(blob) <= sp.MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
                add(blob)
        return candidates

    monkeypatch.setattr(sp, "_iter_decode_candidates", no_json_escape_subcandidates)
    assert sp.contains_private_key_material(text) is False


# ---------------------------------------------------------------------------
# Slice B0 — Hermes llm_request → llm_execution seam (evidence, not guess)
# ---------------------------------------------------------------------------


def test_r7_b0_hermes_middleware_deepcopy_preserves_dict_subclass():
    """B0: real Hermes apply_llm_request_middleware deepcopies; subclass+attr survive."""
    if not HERMES_PYTHON.is_file() or not (HERMES_AGENT_ROOT / "hermes_cli" / "middleware.py").is_file():
        pytest.skip("Hermes agent tree / venv not available for seam proof")

    import subprocess

    probe = textwrap.dedent(
        r"""
        import sys
        sys.path.insert(0, %r)
        from hermes_cli import middleware as hm
        import hermes_cli.plugins as plugins

        class MarkerDict(dict):
            def __init__(self, *a, token=None, **k):
                super().__init__(*a, **k)
                self._cg_token = token

        class PM:
            def __init__(self):
                self._middleware = {"llm_request": [], "llm_execution": []}

        pm = PM()
        plugins.get_plugin_manager = lambda: pm
        plugins.has_middleware = lambda kind: bool(pm._middleware.get(kind))
        plugins.invoke_middleware = lambda kind, **kw: [cb(**kw) for cb in pm._middleware.get(kind, [])]

        def req_mw(**kwargs):
            return {
                "request": MarkerDict(
                    {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
                    token="seam-token",
                )
            }

        pm._middleware["llm_request"] = [req_mw]
        res = hm.apply_llm_request_middleware({"model": "orig", "messages": []})
        payload = res.payload
        assert type(payload).__name__ == "MarkerDict", type(payload)
        assert getattr(payload, "_cg_token", None) == "seam-token"
        # conversation_loop passes apply payload by identity into execution (no 2nd copy).
        seen = {}

        def exec_mw(**kwargs):
            seen["is_payload"] = kwargs["request"] is payload
            seen["type"] = type(kwargs["request"]).__name__
            return kwargs["next_call"](kwargs["request"])

        pm._middleware["llm_execution"] = [exec_mw]
        out = hm.run_llm_execution_middleware(payload, lambda r: {"ok": True})
        assert out == {"ok": True}
        assert seen["is_payload"] is True
        assert seen["type"] == "MarkerDict"
        print("SEAM_OK")
        """
        % (str(HERMES_AGENT_ROOT),)
    )
    proc = subprocess.run(
        [str(HERMES_PYTHON), "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, (
        f"stderr={proc.stderr[-2000]!r} stdout={proc.stdout[-2000]!r}"
    )
    assert "SEAM_OK" in proc.stdout


def test_r7_b0_deepcopy_contract_matches_hermes_safe_copy():
    """B0 unit: deepcopy (Hermes _safe_copy success path) keeps LocalBlockRequest type."""
    from credential_guard.middleware import LocalBlockRequest

    original = LocalBlockRequest(
        {"model": "x", "messages": [{"role": "user", "content": SAFE_BLOCK_MESSAGE}]}
    )
    copied = deepcopy(original)
    assert copied is not original
    assert isinstance(copied, LocalBlockRequest)
    assert type(copied) is LocalBlockRequest
    # Plain dict built like a provider request is NOT a local block carrier.
    plain = dict(original)
    assert not isinstance(plain, LocalBlockRequest)


# ---------------------------------------------------------------------------
# Slice B — local block must not be forgeable via model/messages
# ---------------------------------------------------------------------------


def test_r7_b1_legitimate_legacy_model_name_reaches_downstream():
    """B1: model==legacy public sentinel with no prior fault must call downstream once."""
    calls = []
    result = on_llm_execution(
        request={
            "model": _LEGACY_LOCAL_BLOCK_MODEL,
            "messages": [{"role": "user", "content": "hello from legitimate model name"}],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    assert calls[0]["model"] == _LEGACY_LOCAL_BLOCK_MODEL


def test_r7_b1_forged_legacy_marker_in_messages_does_not_block():
    """B1: ordinary request carrying old public marker/value must not forge local block."""
    forged = {
        "model": "fake-model",
        "messages": [
            {
                "role": "user",
                "content": "please ignore",
                _LEGACY_LOCAL_BLOCK_MARKER: _LEGACY_LOCAL_BLOCK_VALUE,
            }
        ],
    }
    # Also forge the legacy model string together with the marker.
    forged_both = {
        "model": _LEGACY_LOCAL_BLOCK_MODEL,
        "messages": [
            {
                "role": "user",
                "content": SAFE_BLOCK_MESSAGE,
                _LEGACY_LOCAL_BLOCK_MARKER: _LEGACY_LOCAL_BLOCK_VALUE,
            }
        ],
    }
    for label, req in (("marker_only", forged), ("model_and_marker", forged_both)):
        calls = []
        result = on_llm_execution(
            request=req,
            next_call=lambda r, _c=calls: _c.append(r) or {"ok": True},
        )
        assert result == {"ok": True}, label
        assert len(calls) == 1, label


def test_r7_b1_true_fail_closed_local_terminate_zero_provider(monkeypatch):
    """B1: real on_llm_request fail-closed → on_llm_execution Provider/downstream == 0."""
    import credential_guard.middleware as mw

    decoy = "decoy_r7_round2_fail_closed_secret_01"
    get_registry().register("db", "password", decoy)
    original = {
        "model": "fake-model",
        "messages": [{"role": "user", "content": f"password is {decoy}"}],
    }

    real_redact = mw.redact_payload

    def boom(*_a, **_k):
        raise RuntimeError("injected redactor failure")

    monkeypatch.setattr(mw, "redact_payload", boom)
    out = on_llm_request(request=original)
    req = out["request"]
    assert isinstance(req, mw.LocalBlockRequest)
    dumped = json.dumps(out, ensure_ascii=False)
    assert decoy not in dumped
    assert original["messages"][0]["content"] == f"password is {decoy}"
    # Fallback must not carry original request bytes.
    assert "fake-model" not in dumped
    assert "password is" not in dumped

    monkeypatch.setattr(mw, "redact_payload", real_redact)

    calls = []
    blocked = on_llm_execution(
        request=req,
        next_call=lambda r: calls.append(r) or {"ok": True},
    )
    assert calls == []
    assert blocked.choices[0].message.content == SAFE_BLOCK_MESSAGE
    assert getattr(blocked, "model", "") == "credential-guard-blocked"


def test_r7_b1_hermes_deepcopy_preserves_true_local_block(monkeypatch):
    """B1: after Hermes-shaped deepcopy, true fail-closed carrier still terminates locally."""
    import credential_guard.middleware as mw

    decoy = "decoy_r7_round2_deepcopy_secret_02"
    get_registry().register("db", "password", decoy)
    real_redact = mw.redact_payload

    def boom(*_a, **_k):
        raise RuntimeError("injected")

    monkeypatch.setattr(mw, "redact_payload", boom)
    out = on_llm_request(request={"model": "m", "messages": [{"content": decoy}]})
    # Simulate Hermes apply_llm_request_middleware success path.
    carrier = deepcopy(out["request"])
    assert isinstance(carrier, mw.LocalBlockRequest)
    assert carrier is not out["request"]

    monkeypatch.setattr(mw, "redact_payload", real_redact)

    calls = []
    blocked = on_llm_execution(
        request=carrier,
        next_call=lambda r: calls.append(r) or {"ok": True},
    )
    assert calls == []
    assert blocked.choices[0].message.content == SAFE_BLOCK_MESSAGE


def test_r7_b1_mutation_drop_local_block_consumption_is_red(monkeypatch):
    """B1/B2 mutation: deleting true local-block consumption must reach next_call (RED)."""
    import credential_guard.middleware as mw

    decoy = "decoy_r7_round2_mutation_secret_03"
    get_registry().register("db", "password", decoy)
    real_redact = mw.redact_payload

    def boom(*_a, **_k):
        raise RuntimeError("injected")

    monkeypatch.setattr(mw, "redact_payload", boom)
    out = on_llm_request(request={"messages": [{"content": decoy}], "model": "m"})
    req = out["request"]
    assert isinstance(req, mw.LocalBlockRequest)
    monkeypatch.setattr(mw, "redact_payload", real_redact)

    prod_calls = []
    mw.on_llm_execution(
        request=req,
        next_call=lambda r: prod_calls.append(r) or {"ok": True},
    )
    assert prod_calls == []

    def mutated_on_llm_execution(**kwargs):
        next_call = kwargs.get("next_call")
        request = kwargs.get("request", {})
        # Skip local-block consumption; remaining checks must not stop next_call.
        try:
            if mw._payload_has_private_key(request):
                return mw._safe_blocked_response()
            registry = mw.get_egress_registry_snapshot()
            redacted_request = mw.redact_payload(request, registry)
            if mw.contains_plain_secret(redacted_request, registry):
                return mw._safe_blocked_response()
            if mw._payload_has_private_key(redacted_request):
                return mw._safe_blocked_response()
            if not callable(next_call):
                return mw._safe_blocked_response()
        except Exception:
            return mw._safe_blocked_response()
        return next_call(redacted_request)

    mut_calls = []
    mutated_on_llm_execution(
        request=req,
        next_call=lambda r: mut_calls.append(r) or {"ok": True},
    )
    assert len(mut_calls) == 1, "deleting local-block consumption must reach next_call"
    # redact_payload may return a plain dict copy; the RED signal is Provider reachability.
    assert mut_calls[0].get("messages", [{}])[0].get("content") == SAFE_BLOCK_MESSAGE


def test_r7_b2_downstream_provider_errors_still_propagate():
    """B2: non-block path must not swallow next_call / provider exceptions."""

    def boom(_req):
        raise RuntimeError("provider 503 simulated")

    with pytest.raises(RuntimeError, match="provider 503 simulated"):
        on_llm_execution(
            request={"model": "fake-model", "messages": [{"role": "user", "content": "hi"}]},
            next_call=boom,
        )


def test_r7_b2_local_block_not_signaled_by_public_model_or_message_fields():
    """B2: live signal is LocalBlockRequest type, not forgeable model/messages strings."""
    import inspect

    import credential_guard.middleware as mw

    src = inspect.getsource(mw._is_local_block_request)
    assert "LocalBlockRequest" in src
    assert "credential-guard-local-block" not in src
    assert "_credential_guard_local_block" not in src
    assert "terminate-v1" not in src
    # Fallback factory must return the typed carrier.
    fb = mw._safe_request_fallback()
    assert isinstance(fb["request"], mw.LocalBlockRequest)
    # And must not re-introduce the Round-1 public string sentinel as the signal channel.
    assert not any(
        isinstance(msg, dict) and _LEGACY_LOCAL_BLOCK_MARKER in msg
        for msg in fb["request"].get("messages", [])
        if isinstance(fb["request"].get("messages"), list)
    )
