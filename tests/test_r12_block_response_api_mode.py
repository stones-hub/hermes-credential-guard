"""R12 / 0.4.6: the local-block response must match the host's api_mode.

Root cause this pins (see docs/R12-0.4.6-阻断响应形状适配-方案.md):

``_safe_blocked_response()`` only ever built an OpenAI ``chat.completion``
shape (``.choices``).  ``AnthropicTransport.validate_response()`` requires
``.content`` to be a list, so on ``api_mode="anthropic_messages"`` the host
judged our local block to be a malformed provider reply, retried it three
times, and finally surfaced ``Invalid API response after 3 retries`` — a
local fail-closed block disguised as an upstream API fault, with the real
Chinese diagnostic (including the ``代码：CG-…`` line) swallowed entirely.

Two halves are pinned here:

1. anthropic_messages gets a shape the host accepts, and the diagnostic
   survives ``normalize_response`` intact.
2. **Zero regression** for every other api_mode.  This fix adds a branch;
   it does not narrow support.  bedrock_converse validates the OpenAI shape
   today and must keep doing so, and codex_responses — which we cannot load
   locally to verify — must come out byte-identical to before, so this
   change can neither improve nor worsen it.

The host transports are imported from the installed Hermes tree.  When that
tree is unavailable the host-contract tests skip; the shape-level assertions
below never skip, so the plugin-side contract stays pinned in any checkout.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from credential_guard import middleware as mw


HERMES_ROOT = "/Users/yelei/.hermes/hermes-agent"


def _anthropic_transport():
    """Load the real host transport, or skip if this checkout has no Hermes."""
    if HERMES_ROOT not in sys.path:
        sys.path.insert(0, HERMES_ROOT)
    try:
        from agent.transports.anthropic import AnthropicTransport
    except Exception as exc:  # pragma: no cover - depends on host install
        pytest.skip(f"host Hermes tree unavailable: {type(exc).__name__}: {exc}")
    return AnthropicTransport()


def _detail():
    return mw._config_unavailable_detail()


# ---------------------------------------------------------------------------
# 1. anthropic_messages: the host must accept our block instead of retrying it
# ---------------------------------------------------------------------------


def test_blocked_response_passes_anthropic_validate():
    """RED before the fix: the OpenAI shape has no ``.content`` list."""
    transport = _anthropic_transport()
    blocked = mw._safe_blocked_response(_detail(), api_mode="anthropic_messages")

    assert transport.validate_response(blocked) is True, (
        "AnthropicTransport.validate_response rejected the local block, so the "
        "host will retry it as an invalid provider response and report "
        "'Invalid API response after N retries' instead of showing the block."
    )


def test_blocked_message_survives_anthropic_normalize():
    """The operator must actually see the diagnostic, not just pass validation."""
    transport = _anthropic_transport()
    detail = _detail()
    blocked = mw._safe_blocked_response(detail, api_mode="anthropic_messages")

    try:
        normalized = transport.normalize_response(blocked)
    except TypeError as exc:  # pragma: no cover - interpreter-version dependent
        # normalize_response lazily imports agent.anthropic_adapter, which uses
        # PEP 604 (``str | object``) and therefore needs Python >= 3.10. This
        # repo's venv is 3.9, so the round-trip is proven out-of-band against
        # the Hermes 3.11 interpreter instead (scripts/run_r12_host_contract.py).
        if "unsupported operand type" in str(exc):
            pytest.skip(f"host adapter needs a newer interpreter: {exc}")
        raise

    text = normalized.content or ""

    assert text == mw.format_block_message(detail), (
        "normalize_response did not round-trip the block message verbatim"
    )
    assert detail.code in text, "the CG-… reason code was lost in normalization"
    assert normalized.tool_calls is None, "a block must not smuggle tool calls"
    assert normalized.finish_reason == "stop"


def test_anthropic_block_is_a_terminal_text_turn():
    """Shape-level pin that does not need the host tree installed."""
    detail = _detail()
    blocked = mw._safe_blocked_response(detail, api_mode="anthropic_messages")

    assert isinstance(blocked.content, list) and blocked.content, (
        "anthropic_messages requires a non-empty content block list"
    )
    assert [b.type for b in blocked.content] == ["text"]
    assert blocked.content[0].text == mw.format_block_message(detail)
    # end_turn is what makes an empty-content reply legitimate upstream; we are
    # non-empty, but the stop reason still has to read as a completed turn so
    # the agent loop does not treat it as truncation and retry.
    assert blocked.stop_reason == "end_turn"
    assert blocked.role == "assistant"
    assert not hasattr(blocked, "choices"), (
        "the anthropic branch must not also carry an OpenAI 'choices' field; "
        "that would be shape-spoofing rather than honouring the contract"
    )


# ---------------------------------------------------------------------------
# 2. Zero regression for everything else (plan §7.3)
# ---------------------------------------------------------------------------

#: Every api_mode that is NOT anthropic_messages must keep the pre-fix object.
#: bedrock_converse validates the OpenAI shape today (measured), and
#: codex_responses cannot be loaded locally — so "unchanged" is the only
#: claim we are entitled to make about them.
_NON_ANTHROPIC_MODES = [
    None,
    "",
    "chat_completions",
    "bedrock_converse",
    "codex_responses",
    "some_future_mode_we_have_never_heard_of",
]


def _openai_shape_fields(obj):
    """Flatten the legacy shape so a mismatch names the exact field."""
    choice = obj.choices[0]
    message = choice.message
    return {
        "id": obj.id,
        "object": obj.object,
        "created": obj.created,
        "model": obj.model,
        "n_choices": len(obj.choices),
        "choice.index": choice.index,
        "choice.finish_reason": choice.finish_reason,
        "choice.logprobs": choice.logprobs,
        "message.role": message.role,
        "message.content": message.content,
        "message.tool_calls": message.tool_calls,
        "message.refusal": message.refusal,
        "message.function_call": message.function_call,
        "usage.prompt_tokens": obj.usage.prompt_tokens,
        "usage.completion_tokens": obj.usage.completion_tokens,
        "usage.total_tokens": obj.usage.total_tokens,
    }


#: The pre-fix object, transcribed from middleware.py@0.4.5 rather than
#: computed, so this stays a real oracle even if the production code drifts.
def _expected_legacy_fields(detail):
    return {
        "id": "credential_guard_blocked",
        "object": "chat.completion",
        "created": 0,
        "model": "credential-guard-blocked",
        "n_choices": 1,
        "choice.index": 0,
        "choice.finish_reason": "stop",
        "choice.logprobs": None,
        "message.role": "assistant",
        "message.content": mw.format_block_message(detail),
        "message.tool_calls": None,
        "message.refusal": None,
        "message.function_call": None,
        "usage.prompt_tokens": 0,
        "usage.completion_tokens": 0,
        "usage.total_tokens": 0,
    }


@pytest.mark.parametrize("api_mode", _NON_ANTHROPIC_MODES)
def test_non_anthropic_shape_is_field_identical(api_mode):
    """GREEN before AND after: this fix must not touch working transports."""
    detail = _detail()
    blocked = mw._safe_blocked_response(detail, api_mode=api_mode)

    assert _openai_shape_fields(blocked) == _expected_legacy_fields(detail), (
        f"api_mode={api_mode!r} no longer produces the pre-fix OpenAI shape; "
        "fixing anthropic_messages must not regress any other transport"
    )
    assert not hasattr(blocked, "content"), (
        f"api_mode={api_mode!r} grew an Anthropic-style .content field"
    )


def test_default_call_still_works_without_api_mode():
    """Callers that never pass api_mode keep the legacy behaviour."""
    detail = _detail()
    assert _openai_shape_fields(
        mw._safe_blocked_response(detail)
    ) == _expected_legacy_fields(detail)


def test_no_argument_call_still_works():
    """``_safe_blocked_response()`` with no detail must not raise."""
    blocked = mw._safe_blocked_response()
    assert blocked.choices[0].message.content


@pytest.mark.parametrize("api_mode", _NON_ANTHROPIC_MODES)
def test_non_anthropic_still_validates_on_hosts_that_accept_it(api_mode):
    """bedrock/chat_completions accept the legacy shape — keep it that way."""
    if HERMES_ROOT not in sys.path:
        sys.path.insert(0, HERMES_ROOT)
    try:
        from agent.transports.chat_completions import ChatCompletionsTransport
    except Exception as exc:  # pragma: no cover - depends on host install
        pytest.skip(f"host Hermes tree unavailable: {type(exc).__name__}: {exc}")

    blocked = mw._safe_blocked_response(_detail(), api_mode=api_mode)
    assert ChatCompletionsTransport().validate_response(blocked) is True


# ---------------------------------------------------------------------------
# 3. The seam actually carries api_mode through to the constructor
# ---------------------------------------------------------------------------


def test_on_llm_execution_forwards_api_mode_on_prior_block():
    """A block decided in llm_request must still honour the caller's api_mode.

    The host passes ``api_mode=agent.api_mode`` into the llm_execution
    middleware (conversation_loop.py). If we ignore it here, the fix is
    inert in production no matter how correct the constructor is.
    """
    transport = _anthropic_transport()

    blocked_request = mw._safe_request_fallback(_detail())["request"]
    response = mw.on_llm_execution(
        request=blocked_request,
        next_call=lambda req: pytest.fail("provider must not be called"),
        session_id="s",
        api_mode="anthropic_messages",
    )

    assert transport.validate_response(response) is True, (
        "on_llm_execution ignored api_mode, so the anthropic branch never runs "
        "in the real call path"
    )


def test_on_llm_execution_blocks_without_calling_provider_regardless_of_mode():
    """Safety is unchanged by this work: still fail-closed, still Provider=0."""
    calls = []

    for api_mode in ("anthropic_messages", "chat_completions", None):
        blocked_request = mw._safe_request_fallback(_detail())["request"]
        mw.on_llm_execution(
            request=blocked_request,
            next_call=lambda req: calls.append(req),
            session_id="s",
            api_mode=api_mode,
        )

    assert calls == [], "a local block must never reach the provider"
