#!/usr/bin/env python3
"""R12 host-contract verification against the REAL Hermes interpreter.

Why this exists as a separate script instead of a pytest case:

  The repo venv is Python 3.9. ``AnthropicTransport.normalize_response``
  lazily imports ``agent.anthropic_adapter``, which uses PEP 604 unions
  (``str | object``) and needs >= 3.10. So the in-suite test skips that one
  round-trip on 3.9. A skip proves nothing, so the same contract is asserted
  here against the Hermes 3.11 interpreter and this script is what the
  release checklist runs.

Run with the Hermes venv, NOT the repo venv:

    /Users/yelei/.hermes/hermes-agent/venv/bin/python \
        scripts/run_r12_host_contract.py

Exit code 0 = every host-contract assertion held. Non-zero = contract broken.
Read-only: touches no config, no credentials, no network, no provider.
"""

from __future__ import annotations

import os
import sys
import tempfile

HERMES_ROOT = "/Users/yelei/.hermes/hermes-agent"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    if sys.version_info < (3, 10):
        print(
            f"FAIL: needs Python >= 3.10 to exercise the host adapter, got "
            f"{sys.version_info.major}.{sys.version_info.minor}. "
            f"Use {HERMES_ROOT}/venv/bin/python"
        )
        return 2

    sys.path.insert(0, HERMES_ROOT)
    sys.path.insert(0, REPO_ROOT)

    # Keep the host away from the operator's real profile.
    with tempfile.TemporaryDirectory(prefix="cg-r12-contract-") as tmp:
        os.environ["HERMES_HOME"] = tmp

        from agent.transports.anthropic import AnthropicTransport
        from agent.transports.chat_completions import ChatCompletionsTransport
        from credential_guard import middleware as mw

        failures: list[str] = []

        def check(name: str, cond: bool, extra: str = "") -> None:
            status = "ok  " if cond else "FAIL"
            print(f"  [{status}] {name}{(' — ' + extra) if extra and not cond else ''}")
            if not cond:
                failures.append(name)

        detail = mw._config_unavailable_detail()
        expected_text = mw.format_block_message(detail)
        anth = AnthropicTransport()
        cc = ChatCompletionsTransport()

        print("A. anthropic_messages — the branch this release adds")
        blocked = mw._safe_blocked_response(detail, api_mode="anthropic_messages")
        check("validate_response accepts it", anth.validate_response(blocked) is True)

        norm = anth.normalize_response(blocked)
        check(
            "normalize_response round-trips the message verbatim",
            (norm.content or "") == expected_text,
            repr((norm.content or "")[:80]),
        )
        check("the CG-… reason code survives", detail.code in (norm.content or ""))
        check("no tool calls smuggled in", norm.tool_calls is None)
        check("finish_reason is 'stop'", norm.finish_reason == "stop")

        print()
        print("B. zero regression — every other api_mode keeps the legacy shape")
        for mode in (
            None,
            "chat_completions",
            "bedrock_converse",
            "codex_responses",
            "unknown_future_mode",
        ):
            obj = mw._safe_blocked_response(detail, api_mode=mode)
            label = repr(mode)
            check(
                f"{label}: still the OpenAI chat.completion shape",
                hasattr(obj, "choices") and not hasattr(obj, "content"),
            )
            check(
                f"{label}: chat_completions transport still accepts it",
                cc.validate_response(obj) is True,
            )
            check(
                f"{label}: block text unchanged",
                obj.choices[0].message.content == expected_text,
            )

        print()
        print("C. the seam actually forwards api_mode (else the fix is inert)")
        calls: list[object] = []
        req = mw._safe_request_fallback(detail)["request"]
        resp = mw.on_llm_execution(
            request=req,
            next_call=lambda r: calls.append(r),
            session_id="s",
            api_mode="anthropic_messages",
        )
        check("on_llm_execution honours api_mode", anth.validate_response(resp) is True)
        check("provider was never called", calls == [])

        resp_default = mw.on_llm_execution(
            request=mw._safe_request_fallback(detail)["request"],
            next_call=lambda r: calls.append(r),
            session_id="s",
        )
        check(
            "omitting api_mode keeps the legacy shape",
            hasattr(resp_default, "choices") and not hasattr(resp_default, "content"),
        )
        check("provider still never called", calls == [])

        print()
        if failures:
            print(f"RESULT: BROKEN — {len(failures)} failed: {failures}")
            return 1
        print("RESULT: all host-contract assertions held")
        return 0


if __name__ == "__main__":
    sys.exit(main())
