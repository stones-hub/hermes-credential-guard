"""Round 6: an unconfigured install blocks. C1 pass-through is withdrawn.

C1 originally traded safety for onboarding: if the store directory was absent
the plugin assumed "this operator has never configured anything", let the
request reach the Provider, and printed a one-line notice on stderr.

Three rounds of leaks showed the premise cannot be trusted. "No config here"
never actually meant "no config anywhere" -- it also meant the plugin had
looked in the wrong place, which is exactly what happened when ``$HERMES_HOME``
was wrong (round 4), stale (round 5), or simply absent (round 6). A configured
operator silently lost redaction, and a one-line stderr notice scrolls past.

Round 6 removes the guess (see ``store_location``) and, with it, the reason to
keep the pass-through. A missing configuration is now a hard block: the plugin
tells the operator to create the file per the README. The trade is deliberate
and was made by the product owner -- install-and-chat no longer works, and that
is the point.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from credential_guard import middleware as mw
from credential_guard import runtime_config, store_location
from credential_guard.middleware import RequestBlock


DECOY = "sk-round6-block-decoy-0f1e2d3c"


@pytest.fixture()
def profile(tmp_path, monkeypatch):
    """A profile whose store directory does not exist at all."""
    root = tmp_path / "profiles" / "worker"
    root.mkdir(parents=True)
    store = root / store_location.STORE_DIRNAME
    monkeypatch.setattr(
        store_location, "_OVERRIDE_STORE_DIR", store, raising=False
    )
    runtime_config.reset_runtime_for_tests()
    mw.reset_config_notices_for_tests()
    return store


def _egress(store_absent_ok=False):
    seen = []

    def next_call(request):
        seen.append(json.dumps(request))
        return {"ok": True}

    request = {
        "messages": [{"role": "user", "content": f"use {DECOY}"}],
        "model": "m",
    }
    out = mw.on_llm_execution(
        request=request, next_call=next_call, session_id="r6-block"
    )
    # The seam converts the internal RequestBlock into a synthetic completion
    # rather than propagating an exception to the caller; a block is therefore
    # identified by that fixed marker, not by a raise.
    blocked = getattr(out, "id", None) == "credential_guard_blocked"
    return blocked, len(seen), any(DECOY in s for s in seen)


def test_absent_store_blocks_instead_of_passing_through(profile):
    """The headline change: no configuration means no Provider call."""
    assert not profile.exists()

    blocked, calls, leaked = _egress()

    assert blocked, "an unconfigured install must fail closed, not pass through"
    assert calls == 0, "the Provider must not be reached without a config"
    assert not leaked


def test_half_configured_store_still_blocks(profile):
    """Directory present, config file absent -- unchanged, still blocks."""
    profile.mkdir(mode=0o700, parents=True)

    blocked, calls, leaked = _egress()

    assert blocked
    assert calls == 0
    assert not leaked


def test_configured_store_still_chats(profile):
    """The block is specific to missing configuration, not a blanket denial."""
    profile.mkdir(mode=0o700, parents=True)
    cfg = profile / store_location.CONFIG_FILENAME
    cfg.write_text(
        json.dumps(
            {
                "version": 2,
                "credentials": {"tok": {"type": "token", "value": DECOY}},
                "bindings": {},
            }
        ),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    runtime_config.reset_runtime_for_tests()

    blocked, calls, leaked = _egress()

    assert not blocked, "a configured profile must remain usable"
    assert calls == 1
    assert not leaked, "the registered credential must still be redacted"


def test_block_message_points_at_the_readme(profile):
    """The operator needs to know what to do, since nothing auto-generates."""
    out = mw.on_llm_execution(
        request={"messages": [{"role": "user", "content": "hi"}], "model": "m"},
        next_call=lambda r: {"ok": True},
        session_id="r6-msg",
    )
    assert getattr(out, "id", None) == "credential_guard_blocked"
    text = out.choices[0].message.content

    assert DECOY not in text
    # The operator must learn that a config is required and nothing will
    # generate it for them; the concrete path is carried by the local
    # diagnostic, which never crosses the Provider boundary.
    assert "Credential Guard" in text
    assert "CG-CONFIG-UNAVAILABLE" in text


def test_unconfigured_predicate_no_longer_grants_pass_through():
    """The helper that drove C1 pass-through must not survive as a bypass.

    Either it is gone, or nothing consults it to decide whether to reach the
    Provider. A leftover 'unconfigured means allow' branch is precisely the
    shape of the bug this round removes.
    """
    src = Path(mw.__file__).read_text(encoding="utf-8")

    for idx, line in enumerate(src.splitlines()):
        if "is_unconfigured_store_error" not in line:
            continue
        window = "\n".join(src.splitlines()[idx : idx + 12])
        assert "return snapshot" not in window, (
            "middleware still passes through on an unconfigured store; C1 "
            f"pass-through was withdrawn in round 6. Offending block:\n{window}"
        )
