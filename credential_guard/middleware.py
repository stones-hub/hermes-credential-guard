from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any

from .redactor import contains_plain_secret, redact_payload
from .sensitive_paths import contains_private_key_material
from .state import get_egress_registry_snapshot

logger = logging.getLogger("credential_guard")

SAFE_BLOCK_MESSAGE = "request blocked by credential-guard"


class LocalBlockRequest(dict):
    """Provider-bound fail-closed carrier between llm_request and llm_execution.

    Hermes ``apply_llm_request_middleware`` deepcopies the middleware return
    value on the success path; dict subclasses (and their type identity) survive
    that copy. The conversation loop then passes the resulting payload object by
    identity into ``run_llm_execution_middleware`` (no second copy).

    Ordinary provider kwargs are plain ``dict`` instances built from JSON-shaped
    conversation state. Model/messages string fields therefore cannot forge this
    carrier. Detection MUST use ``isinstance(..., LocalBlockRequest)`` — never a
    public fixed model name or message marker.
    """


def _safe_blocked_response() -> SimpleNamespace:
    """OpenAI-compatible chat.completion shape Hermes conversation loop can consume."""
    return SimpleNamespace(
        id="credential_guard_blocked",
        object="chat.completion",
        created=0,
        model="credential-guard-blocked",
        choices=[
            SimpleNamespace(
                index=0,
                message=SimpleNamespace(
                    role="assistant",
                    content=SAFE_BLOCK_MESSAGE,
                    tool_calls=None,
                    refusal=None,
                    function_call=None,
                ),
                finish_reason="stop",
                logprobs=None,
            )
        ],
        usage=SimpleNamespace(prompt_tokens=0, completion_tokens=0, total_tokens=0),
    )


def _safe_request_fallback() -> dict[str, Any]:
    """Provider-bound fail-closed copy: typed local carrier, no original bytes."""
    return {
        "request": LocalBlockRequest(
            {
                # Placeholder only — NOT the block signal (see LocalBlockRequest).
                "model": "credential-guard-blocked",
                "messages": [
                    {
                        "role": "user",
                        "content": SAFE_BLOCK_MESSAGE,
                    }
                ],
            }
        ),
        "source": "credential-guard",
        "reason": "redaction failed closed",
    }


def _is_local_block_request(request: Any) -> bool:
    return isinstance(request, LocalBlockRequest)


def _log_fail_closed(stage: str) -> None:
    # Never log exception objects — they may embed decoy/secret text.
    logger.warning("credential-guard failed closed at %s", stage)


def _payload_has_private_key(payload: Any) -> bool:
    """Scan structured payload strings + flattened form for private-key material."""

    def walk(node: Any) -> bool:
        if isinstance(node, str):
            return contains_private_key_material(node)
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and contains_private_key_material(key):
                    return True
                if walk(value):
                    return True
            return False
        if isinstance(node, (list, tuple)):
            return any(walk(item) for item in node)
        return False

    if walk(payload):
        return True
    try:
        flattened = json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        flattened = str(payload)
    return contains_private_key_material(flattened)


def on_llm_request(**kwargs: Any) -> dict[str, Any]:
    try:
        request = kwargs.get("request", {})
        if _payload_has_private_key(request):
            _log_fail_closed("llm_request_private_key")
            return _safe_request_fallback()
        registry = get_egress_registry_snapshot()
        redacted = redact_payload(request, registry)
        if _payload_has_private_key(redacted):
            _log_fail_closed("llm_request_private_key_post")
            return _safe_request_fallback()
        return {
            "request": redacted,
            "source": "credential-guard",
            "reason": "redacted known credential canaries",
        }
    except Exception:
        _log_fail_closed("llm_request")
        return _safe_request_fallback()


def on_llm_execution(**kwargs: Any) -> Any:
    next_call = kwargs.get("next_call")
    try:
        request = kwargs.get("request", {})
        # Prior llm_request middleware decided to block — terminate locally.
        if _is_local_block_request(request):
            _log_fail_closed("llm_execution_prior_block")
            return _safe_blocked_response()
        if _payload_has_private_key(request):
            _log_fail_closed("llm_execution_private_key")
            return _safe_blocked_response()
        registry = get_egress_registry_snapshot()
        redacted_request = redact_payload(request, registry)
        if contains_plain_secret(redacted_request, registry):
            _log_fail_closed("llm_execution_plain_secret")
            return _safe_blocked_response()
        if _payload_has_private_key(redacted_request):
            _log_fail_closed("llm_execution_private_key_post")
            return _safe_blocked_response()
        if not callable(next_call):
            _log_fail_closed("llm_execution_missing_next")
            return _safe_blocked_response()
    except Exception:
        _log_fail_closed("llm_execution")
        return _safe_blocked_response()
    # Downstream/provider errors must propagate — do not swallow next_call failures.
    return next_call(redacted_request)
