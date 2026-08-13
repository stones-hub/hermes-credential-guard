from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Optional

from .redactor import (
    RedactionCollisionError,
    collect_protected_replacements,
    contains_plain_secret,
    redact_payload,
)
from .result_guard import redact_private_keys
from .runtime_config import RuntimeConfigError
from .sensitive_paths import EncodedPrivateKeyScanError, contains_private_key_material
from .state import get_egress_registry_snapshot

logger = logging.getLogger("credential_guard")

SAFE_BLOCK_MESSAGE = "request blocked by credential-guard"
BLOCK_RESPONSE_TITLE = "Credential Guard 已阻止本次请求"
# Fixed whole-field placeholder for boundary-unknown material in ordinary strings.
# Must never embed original text, digests, lengths, tool names, hosts, or exc bodies.
REDACTED_UNRESOLVED_SENSITIVE_FIELD = "<REDACTED_UNRESOLVED_SENSITIVE_FIELD>"
# Provider-bound history quarantine markers (fixed; never derived from secret meta).
QUARANTINED_HISTORY_FIELD = "<CREDENTIAL_GUARD_QUARANTINED_HISTORY_FIELD>"
QUARANTINED_HISTORY_MESSAGE = (
    "（Credential Guard：某段历史因本地安全检查被隔离，原文未发送给外部模型。）"
)
# Scanner-boundary quarantine markers (distinct reason path; never derived).
QUARANTINED_SCANNER_HISTORY_FIELD = (
    "<CREDENTIAL_GUARD_SCANNER_QUARANTINED_HISTORY_FIELD>"
)
QUARANTINED_SCANNER_HISTORY_MESSAGE = (
    "（Credential Guard：某段历史因安全扫描器边界被隔离，原文未发送给外部模型。）"
)
QUARANTINED_TOOL_ARGUMENTS = "{}"
# Bounded residual / scanner-field recovery iterations per Provider-bound prepare.
MAX_RESIDUAL_RECOVERY_ITERATIONS = 32

# Production-reachable block codes only. Unknown CG-* must not false-green helpers.
KNOWN_BLOCK_CODES = frozenset(
    {
        "CG-CONFIG-UNAVAILABLE",
        "CG-REDACTION-COLLISION",
        "CG-RESIDUAL-SECRET",
        "CG-SCANNER-ERROR",
    }
)


def is_blocked_response_content(text: Any) -> bool:
    """True only for the exact six-line actionable local-block prompt.

    Requires fixed line order, non-empty reason/location/action, and a known
    production code. Any CG- prefix alone is not enough.
    """
    if not isinstance(text, str):
        return False
    lines = text.split("\n")
    if len(lines) != 6:
        return False
    if lines[0] != BLOCK_RESPONSE_TITLE:
        return False
    if not lines[1].startswith("原因：") or len(lines[1]) <= len("原因："):
        return False
    if not lines[2].startswith("位置：") or len(lines[2]) <= len("位置："):
        return False
    if not lines[3].startswith("代码："):
        return False
    code = lines[3][len("代码："):]
    if code not in KNOWN_BLOCK_CODES:
        return False
    if not lines[4].startswith("处理：") or len(lines[4]) <= len("处理："):
        return False
    if lines[5] != "发送状态：未发送给外部模型。":
        return False
    return True

_SAFE_PATH_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


@dataclass(frozen=True)
class BlockDetail:
    """Out-of-band block reason carried on LocalBlockRequest → llm_execution."""

    code: str
    location: str
    summary: str
    action: str


@dataclass(frozen=True, order=True)
class DictEntryOrd:
    """Unforgeable dict entry ordinal (insertion order) for provider-bound navigation.

    Never embeds the dynamic key string, hash, or length. Public/safe paths map
    this to ``<key>`` via ``_format_struct_path`` / ``humanize_location``.
    """

    ordinal: int


@dataclass(frozen=True)
class ResidualFinding:
    """Internal path-aware residual hit (never echoed as raw field values)."""

    kind: str  # registered-secret | private-key | aggregate-only | scanner-error
    path: tuple
    detail: BlockDetail
    # True when the residual is the dict KEY itself (not its value).
    targets_key: bool = False


class RequestBlock(Exception):
    """Internal control-flow: fail closed with a concrete BlockDetail."""

    def __init__(self, detail: BlockDetail):
        self.detail = detail
        super().__init__(detail.code)


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

    ``block_detail`` (instance attribute) carries the actionable BlockDetail; it
    is not part of the JSON-shaped dict body and cannot be forged via messages.
    """

    block_detail: Optional[BlockDetail] = None


def format_block_message(detail: BlockDetail) -> str:
    return (
        f"{BLOCK_RESPONSE_TITLE}\n"
        f"原因：{detail.summary}\n"
        f"位置：{detail.location}\n"
        f"代码：{detail.code}\n"
        f"处理：{detail.action}\n"
        "发送状态：未发送给外部模型。"
    )


def _config_unavailable_detail() -> BlockDetail:
    return BlockDetail(
        code="CG-CONFIG-UNAVAILABLE",
        location="Credential Guard 本地配置",
        summary="Credential Guard 配置暂时不可用，无法完成本次外发检查。",
        action=(
            "检查 credential-guard.json 的 JSON 格式、文件权限以及 "
            "hermes credential-guard check 结果，修复后直接重试。"
        ),
    )


def _format_struct_path(path: tuple) -> str:
    out = "request"
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        elif isinstance(part, DictEntryOrd) or part == "<key>":
            out += ".<key>"
        elif isinstance(part, str) and _SAFE_PATH_KEY_RE.fullmatch(part):
            out += f".{part}"
        else:
            out += ".<field>"
    return out


def _machine_path_segment(key: Any, ordinal: int) -> Any:
    """Machine path segment: safe fixed keys stay literal; dynamic → entry ordinal."""
    seg = _path_segment(key)
    if seg == "<key>":
        return DictEntryOrd(ordinal)
    return seg


def _path_sort_key(path: tuple) -> tuple:
    """Total order for ResidualFinding.path (int / DictEntryOrd / str mixed)."""
    parts: list[tuple] = []
    for p in path:
        if isinstance(p, int):
            parts.append((0, p, ""))
        elif isinstance(p, DictEntryOrd):
            parts.append((1, p.ordinal, ""))
        else:
            parts.append((2, 0, str(p)))
    return tuple(parts)


def humanize_location(payload: Any, path: tuple) -> str:
    """Map a structural path to a user-facing location (never field values)."""
    if not path:
        return "request"

    if path[0] == "messages" and len(path) >= 2 and isinstance(path[1], int):
        idx = path[1]
        n = idx + 1
        msg: Any = None
        if isinstance(payload, dict):
            messages = payload.get("messages")
            if isinstance(messages, (list, tuple)) and 0 <= idx < len(messages):
                msg = messages[idx]
        rest = path[2:]
        role = msg.get("role") if isinstance(msg, dict) else None

        if not rest or rest == ("content",) or (
            rest and rest[0] == "content"
        ):
            if role == "tool":
                # Never echo untrusted message.name (may carry secrets/hostnames).
                return f"第 {n} 条消息（工具结果）"
            if role in ("user", "assistant", "system"):
                return f"第 {n} 条消息（{role}）"
            return f"第 {n} 条消息"

        if (
            len(rest) >= 4
            and rest[0] == "tool_calls"
            and isinstance(rest[1], int)
            and rest[2] == "function"
            and rest[3] == "arguments"
        ):
            return f"第 {n} 条消息的第 {rest[1] + 1} 个工具调用参数"

        return f"第 {n} 条消息（{_format_struct_path(('messages', idx) + rest)}）"

    return _format_struct_path(path)


def _detail_scanner_error(
    location: str, *, action_kind: str = "unrecoverable"
) -> BlockDetail:
    if action_kind == "current_input":
        action = (
            "编辑或分段当前输入后直接重试；无需新建 Session，历史任务仍保留。"
        )
    else:
        action = (
            f"保留原因码和位置（{location}）并报告 Credential Guard Bug；"
            "修复后在同一 Session 发送「继续」，无需重做长任务。"
        )
    return BlockDetail(
        code="CG-SCANNER-ERROR",
        location=location,
        summary=f"扫描{location}时安全扫描器异常，无法证明请求已安全。",
        action=action,
    )


def _detail_residual(
    location: str, *, action_kind: str = "unrecoverable"
) -> BlockDetail:
    if action_kind == "current_input":
        action = (
            "编辑当前输入后直接重试；无需新建 Session，历史任务仍保留。"
        )
    else:
        # unrecoverable / core / budget / aggregate-unknown
        action = (
            "保留原因码并报告 Credential Guard Bug；"
            "修复后在同一 Session 发送「继续」，无需重做长任务。"
        )
    return BlockDetail(
        code="CG-RESIDUAL-SECRET",
        location=location,
        summary=f"{location}完成脱敏后仍检测到敏感内容残留。",
        action=action,
    )


def _detail_collision(location: str) -> BlockDetail:
    return BlockDetail(
        code="CG-REDACTION-COLLISION",
        location=location,
        summary=(
            f"{location}在脱敏后会与另一个字段重名，继续发送可能覆盖原内容。"
        ),
        action=(
            "不要直接重试；保留原因码并报告 Credential Guard Bug。"
        ),
    )


def _safe_blocked_response(detail: Optional[BlockDetail] = None) -> SimpleNamespace:
    """OpenAI-compatible chat.completion shape Hermes conversation loop can consume."""
    if detail is None:
        detail = _detail_scanner_error("request")
    content = format_block_message(detail)
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
                    content=content,
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


def _safe_request_fallback(detail: Optional[BlockDetail] = None) -> dict[str, Any]:
    """Provider-bound fail-closed copy: typed local carrier, no original bytes."""
    if detail is None:
        detail = _detail_scanner_error("request")
    carrier = LocalBlockRequest(
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
    )
    carrier.block_detail = detail
    return {
        "request": carrier,
        "source": "credential-guard",
        "reason": "redaction failed closed",
    }


def _is_local_block_request(request: Any) -> bool:
    return isinstance(request, LocalBlockRequest)


def _log_fail_closed(stage: str, code: str = "") -> None:
    # Never log exception objects — they may embed decoy/secret text.
    if code:
        logger.warning("credential-guard failed closed at %s code=%s", stage, code)
    else:
        logger.warning("credential-guard failed closed at %s", stage)


def _payload_has_private_key(payload: Any) -> bool:
    """Scan structured payload strings/keys only — never re-flatten the whole request.

    Per-string ``MAX_PRIVATE_KEY_SCAN_BYTES`` still applies. Cumulative safe fields
    across a long session must not trip a second whole-payload scan budget.
    """

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

    return walk(payload)


def _path_segment(key: Any) -> Any:
    if isinstance(key, int):
        return key
    if isinstance(key, str) and _SAFE_PATH_KEY_RE.fullmatch(key) and key in {
        "model",
        "messages",
        "role",
        "content",
        "name",
        "tool_calls",
        "function",
        "arguments",
        "tools",
        "tool_call_id",
        "metadata",
        "extension",
    }:
        return key
    return "<key>"


def _redact_locatable_private_keys(payload: Any) -> Any:
    """Build a fresh provider-bound copy with fully locatable raw PEM replaced.

    Does not mutate ``payload``. Ordinary string values whose private-key
    material cannot be fully localized are replaced wholesale with
    ``REDACTED_UNRESOLVED_SENSITIVE_FIELD``. Dict keys with the same failure
    fail closed (structure cannot be safely whole-key replaced). Scanner
    errors still raise ``RequestBlock``.
    """

    root = payload

    def walk(node: Any, path: tuple) -> Any:
        def _redact_string(text: str, str_path: tuple, *, is_dict_key: bool) -> str:
            try:
                return redact_private_keys(text)
            except EncodedPrivateKeyScanError:
                if is_dict_key:
                    loc = humanize_location(root, str_path)
                    raise RequestBlock(_detail_scanner_error(loc)) from None
                # Field-level scanner failure on ordinary values: leave intact so
                # the path-aware residual/scanner recovery chain can quarantine
                # recoverable historical leaves (or fail closed with machine path).
                return text
            except RequestBlock:
                raise
            except RuntimeError as exc:
                loc = humanize_location(root, str_path)
                # Narrow match on the known localizable-boundary failure only.
                if str(exc) == "private key material not fully localizable":
                    if is_dict_key:
                        # Whole-key replace risks silent overwrite / collision.
                        raise RequestBlock(_detail_collision(loc)) from None
                    return REDACTED_UNRESOLVED_SENSITIVE_FIELD
                raise RequestBlock(_detail_scanner_error(loc)) from None
            except Exception:
                loc = humanize_location(root, str_path)
                raise RequestBlock(_detail_scanner_error(loc)) from None

        if isinstance(node, str):
            return _redact_string(node, path, is_dict_key=False)
        if isinstance(node, dict):
            out: dict[Any, Any] = {}
            for ordinal, (key, value) in enumerate(node.items()):
                key_path = path + (_machine_path_segment(key, ordinal),)
                if isinstance(key, str):
                    new_key = _redact_string(key, key_path, is_dict_key=True)
                else:
                    new_key = key
                if new_key in out:
                    loc = humanize_location(root, path + ("<key>",))
                    raise RequestBlock(_detail_collision(loc))
                out[new_key] = walk(value, key_path)
            return out
        if isinstance(node, list):
            return [walk(item, path + (idx,)) for idx, item in enumerate(node)]
        if isinstance(node, tuple):
            return tuple(walk(item, path + (idx,)) for idx, item in enumerate(node))
        return node

    return walk(payload, ())


def _as_residual_finding(
    result: Any, *, default_kind: str, default_path: tuple = ()
) -> Optional[ResidualFinding]:
    """Normalize finder results; tolerate older BlockDetail monkeypatches."""
    if result is None:
        return None
    if isinstance(result, ResidualFinding):
        return result
    if isinstance(result, BlockDetail):
        kind = (
            "scanner-error"
            if result.code == "CG-SCANNER-ERROR"
            else default_kind
        )
        return ResidualFinding(kind=kind, path=tuple(default_path), detail=result)
    return None


def _find_residual_private_key(
    payload: Any, root: Any, path: tuple = ()
) -> Optional[ResidualFinding]:
    if isinstance(payload, str):
        try:
            if contains_private_key_material(payload):
                loc = humanize_location(root, path)
                return ResidualFinding(
                    kind="private-key",
                    path=tuple(path),
                    detail=_detail_residual(loc),
                )
        except EncodedPrivateKeyScanError:
            loc = humanize_location(root, path)
            return ResidualFinding(
                kind="scanner-error",
                path=tuple(path),
                detail=_detail_scanner_error(loc),
            )
        return None
    if isinstance(payload, dict):
        for ordinal, (key, value) in enumerate(payload.items()):
            key_path = path + (_machine_path_segment(key, ordinal),)
            if isinstance(key, str):
                try:
                    if contains_private_key_material(key):
                        loc = humanize_location(root, key_path)
                        return ResidualFinding(
                            kind="private-key",
                            path=tuple(key_path),
                            detail=_detail_residual(loc),
                            targets_key=True,
                        )
                except EncodedPrivateKeyScanError:
                    loc = humanize_location(root, key_path)
                    return ResidualFinding(
                        kind="scanner-error",
                        path=tuple(key_path),
                        detail=_detail_scanner_error(loc),
                        targets_key=True,
                    )
            found = _find_residual_private_key(value, root, key_path)
            if found is not None:
                return found
        return None
    if isinstance(payload, (list, tuple)):
        for idx, item in enumerate(payload):
            found = _find_residual_private_key(item, root, path + (idx,))
            if found is not None:
                return found
        return None
    return None


def _find_residual_plain_secret(
    payload: Any, registry: Any, root: Any, path: tuple = ()
) -> Optional[ResidualFinding]:
    try:
        pairs = collect_protected_replacements(registry)
    except Exception:
        loc = humanize_location(root, path)
        return ResidualFinding(
            kind="scanner-error",
            path=tuple(path),
            detail=_detail_scanner_error(loc),
        )
    if not pairs:
        return None

    def text_has(text: str) -> bool:
        return any(variant and variant in text for variant, _token in pairs)

    if isinstance(payload, str):
        if text_has(payload):
            loc = humanize_location(root, path)
            return ResidualFinding(
                kind="registered-secret",
                path=tuple(path),
                detail=_detail_residual(loc),
            )
        return None
    if isinstance(payload, dict):
        for ordinal, (key, value) in enumerate(payload.items()):
            key_path = path + (_machine_path_segment(key, ordinal),)
            if isinstance(key, str) and text_has(key):
                loc = humanize_location(root, key_path)
                return ResidualFinding(
                    kind="registered-secret",
                    path=tuple(key_path),
                    detail=_detail_residual(loc),
                    targets_key=True,
                )
            found = _find_residual_plain_secret(value, registry, root, key_path)
            if found is not None:
                return found
        return None
    if isinstance(payload, (list, tuple)):
        for idx, item in enumerate(payload):
            found = _find_residual_plain_secret(item, registry, root, path + (idx,))
            if found is not None:
                return found
        return None
    return None


def _current_user_input_index(root: Any) -> Optional[int]:
    """Index of the last role=user message (may be followed by assistant/tool)."""
    if not isinstance(root, dict):
        return None
    messages = root.get("messages")
    if not isinstance(messages, (list, tuple)) or not messages:
        return None
    for idx in range(len(messages) - 1, -1, -1):
        msg = messages[idx]
        if isinstance(msg, dict) and msg.get("role") == "user":
            return idx
    return None


def _is_current_user_input_path(root: Any, path: tuple) -> bool:
    """True for any field under the current last user message (not only content)."""
    cur = _current_user_input_index(root)
    if cur is None:
        return False
    return (
        len(path) >= 2
        and path[0] == "messages"
        and path[1] == cur
    )


def _message_role_at(root: Any, idx: int) -> Optional[str]:
    if not isinstance(root, dict):
        return None
    messages = root.get("messages")
    if not isinstance(messages, (list, tuple)) or not (0 <= idx < len(messages)):
        return None
    msg = messages[idx]
    if isinstance(msg, dict):
        role = msg.get("role")
        return role if isinstance(role, str) else None
    return None


def _resolve_path_key(payload: Any, path_prefix: tuple, segment: Any) -> Optional[str]:
    """Resolve a path segment to its string key on ``payload`` (DictEntryOrd-aware)."""
    if isinstance(segment, str):
        return segment
    if not isinstance(segment, DictEntryOrd):
        return None
    try:
        cur: Any = payload
        for part in path_prefix:
            cur = _step_path(cur, part)
        if not isinstance(cur, dict):
            return None
        items = list(cur.items())
        if not (0 <= segment.ordinal < len(items)):
            return None
        key = items[segment.ordinal][0]
        return key if isinstance(key, str) else None
    except (KeyError, IndexError, TypeError):
        return None


def _is_approved_scanner_recovery_path(payload: Any, path: tuple) -> bool:
    """Closed allowlist: whether a scanner-error path may be field-quarantined.

    Only historical user/assistant/tool content, metadata/extension dynamic
    values, and assistant tool_calls[*].function.arguments are approved.
    Everything else (current last role=user, system, name/role/ids, top-level
    metadata/tools/unknown, dynamic keys themselves, unlocated) fails closed.
    """
    if (
        not path
        or path[0] != "messages"
        or len(path) < 3
        or not isinstance(path[1], int)
    ):
        return False
    msg_idx = path[1]
    role = _message_role_at(payload, msg_idx)
    if role not in {"user", "assistant", "tool"}:
        return False
    # Current last role=user message (trail assistant/tool allowed): no recovery.
    if _is_current_user_input_path(payload, path):
        return False

    field = _resolve_path_key(payload, path[:2], path[2])
    if field == "content" and len(path) == 3:
        return True

    if field in {"metadata", "extension"} and len(path) >= 4:
        # Ordinary dynamic-key VALUE under metadata/extension subtree only.
        # First child under the subtree must be a dynamic entry (DictEntryOrd).
        if not isinstance(path[3], DictEntryOrd):
            return False
        return True

    if (
        role == "assistant"
        and field == "tool_calls"
        and len(path) == 6
        and isinstance(path[3], int)
        and path[4] == "function"
        and path[5] == "arguments"
    ):
        return True

    return False


def _is_system_or_core_path(root: Any, path: tuple) -> bool:
    """Residual (non-scanner) core/system blacklist — do not invert for scanner."""
    if not path:
        return True
    if path[0] == "model":
        return True
    if path[0] != "messages" or len(path) < 2 or not isinstance(path[1], int):
        # Unknown top-level / non-message branch: treat as core if not metadata-like.
        if path[0] in {"messages", "metadata", "tools"}:
            return path[0] != "metadata"
        return True
    role = _message_role_at(root, path[1])
    if role == "system":
        return True
    if len(path) >= 3 and path[2] in {"role", "name", "tool_call_id"}:
        return True
    if len(path) >= 3 and path[2] == "tool_calls":
        # arguments string is quarantinable; other tool-call skeleton is core.
        return "arguments" not in path
    return False


def _step_path(cur: Any, part: Any) -> Any:
    """Resolve one machine-path segment (supports DictEntryOrd)."""
    if isinstance(part, DictEntryOrd):
        if not isinstance(cur, dict):
            raise KeyError("dict entry on non-dict")
        items = list(cur.items())
        if not (0 <= part.ordinal < len(items)):
            raise KeyError("dict entry ordinal out of range")
        return items[part.ordinal][1]
    if part == "<key>":
        raise KeyError("unresolved dynamic key")
    return cur[part]


def _navigate_parent(payload: Any, path: tuple) -> tuple[Any, Any]:
    """Return (parent, last_segment) for a structural path on a mutable copy.

    For ``DictEntryOrd`` last segments, ``last_segment`` is the real dict key
    resolved by insertion ordinal (never stored on the finding).
    """
    if not path:
        raise KeyError("empty path")
    cur: Any = payload
    for part in path[:-1]:
        cur = _step_path(cur, part)
    last = path[-1]
    if isinstance(last, DictEntryOrd):
        if not isinstance(cur, dict):
            raise KeyError("dict entry on non-dict")
        items = list(cur.items())
        if not (0 <= last.ordinal < len(items)):
            raise KeyError("dict entry ordinal out of range")
        return cur, items[last.ordinal][0]
    if last == "<key>":
        raise KeyError("unresolved dynamic key")
    return cur, last


def _block_for_quarantine_failure(
    payload: Any, path: tuple, finding: ResidualFinding
) -> BlockDetail:
    loc = humanize_location(payload, path)
    if finding.kind == "scanner-error":
        return _detail_scanner_error(loc)
    return _detail_residual(loc, action_kind="unrecoverable")


def _quarantine_markers(finding: ResidualFinding) -> tuple[str, str]:
    """Return (content_marker, field_marker) for the finding kind."""
    if finding.kind == "scanner-error":
        return (
            QUARANTINED_SCANNER_HISTORY_MESSAGE,
            QUARANTINED_SCANNER_HISTORY_FIELD,
        )
    return QUARANTINED_HISTORY_MESSAGE, QUARANTINED_HISTORY_FIELD


def _quarantine_residual_path(
    payload: Any, path: tuple, finding: ResidualFinding
) -> Any:
    """Deterministic quarantine on a deep copy. Never derives markers from secrets."""
    out = deepcopy(payload)
    if not path:
        raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))

    # Dynamic KEY residual cannot be silently rewritten here (use redactor anonymity
    # or fail closed). Unresolved legacy ``<key>`` paths also fail closed.
    if getattr(finding, "targets_key", False) or "<key>" in path:
        raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))

    try:
        parent, last = _navigate_parent(out, path)
    except (KeyError, IndexError, TypeError):
        raise RequestBlock(
            _block_for_quarantine_failure(payload, path, finding)
        ) from None

    content_mark, field_mark = _quarantine_markers(finding)

    if (
        len(path) >= 4
        and path[0] == "messages"
        and isinstance(path[1], int)
        and path[2] == "tool_calls"
        and "arguments" in path
        and last == "arguments"
    ):
        if not isinstance(parent, dict) or last not in parent:
            raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))
        parent[last] = QUARANTINED_TOOL_ARGUMENTS
        return out

    if not isinstance(parent, (dict, list)):
        raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))

    if isinstance(parent, dict):
        if last not in parent or not isinstance(parent[last], str):
            raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))
        if last == "content":
            parent[last] = content_mark
        else:
            parent[last] = field_mark
        return out

    if isinstance(parent, list) and isinstance(last, int) and 0 <= last < len(parent):
        if not isinstance(parent[last], str):
            raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))
        parent[last] = field_mark
        return out

    raise RequestBlock(_block_for_quarantine_failure(payload, path, finding))


def _scan_residuals(
    payload: Any, registry: Any, root: Any
) -> list[ResidualFinding]:
    """Deterministic structured residual scan (at most one actionable hit)."""
    pk = _as_residual_finding(
        _find_residual_private_key(payload, root),
        default_kind="private-key",
    )
    ps = _as_residual_finding(
        _find_residual_plain_secret(payload, registry, root),
        default_kind="registered-secret",
    )
    ordered = [f for f in (pk, ps) if f is not None]
    if not ordered:
        return []
    for finding in ordered:
        if finding.kind == "scanner-error":
            return [finding]
    ordered.sort(key=lambda f: _path_sort_key(f.path))
    return [ordered[0]]


def _aggregate_variant_hit_count(payload: Any, registry: Any) -> int:
    """Count distinct registered variants present in flattened serialization."""
    try:
        flattened = json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        flattened = str(payload)
    try:
        pairs = collect_protected_replacements(registry)
    except Exception:
        return 0
    hits = 0
    for variant, _token in pairs:
        if variant and variant in flattened:
            hits += 1
    return hits


def _try_aggregate_recovery(
    payload: Any, registry: Any, root: Any
) -> Optional[Any]:
    """Isolate one historical branch that strictly reduces aggregate-only hits.

    Does not require the whole request to become clean in a single step; the
    outer recovery loop repeats until final gate is clean or budget/no-progress.
    """
    if not contains_plain_secret(payload, registry):
        return payload
    if not isinstance(payload, dict):
        return None
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return None
    current_idx = _current_user_input_index(payload)
    base_hits = _aggregate_variant_hit_count(payload, registry)
    if base_hits <= 0:
        return None

    def _trial_progress(trial: Any) -> bool:
        # Must not introduce structured leaf residuals while breaking aggregate glue.
        if _find_residual_plain_secret(trial, registry, root) is not None:
            return False
        if _find_residual_private_key(trial, root) is not None:
            return False
        trial_hits = _aggregate_variant_hit_count(trial, registry)
        return trial_hits < base_hits

    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "system":
            continue
        if current_idx is not None and i == current_idx:
            continue
        if not isinstance(msg.get("content"), str):
            continue
        # Already quarantined — skipping prevents no-progress loops.
        if msg.get("content") in {
            QUARANTINED_HISTORY_MESSAGE,
            QUARANTINED_HISTORY_FIELD,
            QUARANTINED_SCANNER_HISTORY_MESSAGE,
            QUARANTINED_SCANNER_HISTORY_FIELD,
        }:
            continue
        trial = deepcopy(payload)
        trial_messages = trial.get("messages")
        if not isinstance(trial_messages, list):
            continue
        trial_messages[i] = dict(msg)
        trial_messages[i]["content"] = QUARANTINED_HISTORY_MESSAGE
        if _trial_progress(trial):
            return trial

    # Assistant tool-call arguments branches (historical).
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict) or msg.get("role") != "assistant":
            continue
        tool_calls = msg.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue
        for j, tc in enumerate(tool_calls):
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function")
            if not isinstance(fn, dict) or not isinstance(fn.get("arguments"), str):
                continue
            if fn.get("arguments") == QUARANTINED_TOOL_ARGUMENTS:
                continue
            trial = deepcopy(payload)
            t_msg = trial["messages"][i]
            t_fn = t_msg["tool_calls"][j]["function"]
            t_fn["arguments"] = QUARANTINED_TOOL_ARGUMENTS
            if _trial_progress(trial):
                return trial
    return None


def _block_for_finding(root: Any, finding: ResidualFinding) -> BlockDetail:
    loc = finding.detail.location or humanize_location(root, finding.path)
    if finding.kind == "scanner-error":
        if _is_current_user_input_path(root, finding.path):
            return _detail_scanner_error(loc, action_kind="current_input")
        return _detail_scanner_error(loc, action_kind="unrecoverable")
    if _is_current_user_input_path(root, finding.path):
        return _detail_residual(loc, action_kind="current_input")
    return _detail_residual(loc, action_kind="unrecoverable")


def _leaf_already_quarantined(payload: Any, path: tuple) -> bool:
    """True when the navigated leaf is already a fixed quarantine marker."""
    if not path:
        return False
    try:
        parent, last = _navigate_parent(payload, path)
    except (KeyError, IndexError, TypeError):
        return False
    markers = {
        QUARANTINED_HISTORY_MESSAGE,
        QUARANTINED_HISTORY_FIELD,
        QUARANTINED_SCANNER_HISTORY_MESSAGE,
        QUARANTINED_SCANNER_HISTORY_FIELD,
        QUARANTINED_TOOL_ARGUMENTS,
    }
    if isinstance(parent, dict) and last in parent:
        return parent[last] in markers
    if isinstance(parent, list) and isinstance(last, int) and 0 <= last < len(parent):
        return parent[last] in markers
    return False


def _recover_residuals(payload: Any, registry: Any, root: Any) -> Any:
    """Bounded deterministic quarantine of recoverable historical residuals."""
    current = payload
    prev_aggregate_hits: Optional[int] = None

    def _is_fully_clean(candidate: Any) -> bool:
        if _scan_residuals(candidate, registry, root):
            return False
        return not contains_plain_secret(candidate, registry)

    if _is_fully_clean(current):
        return current

    for _ in range(MAX_RESIDUAL_RECOVERY_ITERATIONS):
        findings = _scan_residuals(current, registry, root)
        if findings:
            finding = findings[0]
            if finding.kind == "scanner-error":
                # Explicit closed allowlist — never invert residual core blacklist.
                if not _is_approved_scanner_recovery_path(current, finding.path):
                    raise RequestBlock(_block_for_finding(root, finding))
                if getattr(finding, "targets_key", False):
                    raise RequestBlock(_block_for_finding(root, finding))
                # Scanner failure on an already-quarantined safe marker ⇒ systemic.
                if _leaf_already_quarantined(current, finding.path):
                    raise RequestBlock(_block_for_finding(root, finding))
            else:
                if _is_current_user_input_path(root, finding.path):
                    raise RequestBlock(_block_for_finding(root, finding))
                if _is_system_or_core_path(root, finding.path):
                    raise RequestBlock(_block_for_finding(root, finding))
                if getattr(finding, "targets_key", False):
                    raise RequestBlock(_block_for_finding(root, finding))
            quarantined = _quarantine_residual_path(current, finding.path, finding)
            if quarantined == current:
                raise RequestBlock(_block_for_finding(root, finding))
            current = quarantined
            # Re-scan from root after isolation; never reuse the prior failure.
            # A successful isolation may finish recovery without consuming another
            # budget iteration solely to observe cleanliness.
            if _is_fully_clean(current):
                return current
            continue

        # Structured clean — check aggregate-only defense-in-depth.
        if contains_plain_secret(current, registry):
            before_hits = _aggregate_variant_hit_count(current, registry)
            recovered = _try_aggregate_recovery(current, registry, root)
            if recovered is None or recovered == current:
                raise RequestBlock(
                    _detail_residual("request", action_kind="unrecoverable")
                )
            after_hits = _aggregate_variant_hit_count(recovered, registry)
            # No-progress / oscillation guard: hits must strictly decrease.
            if after_hits >= before_hits:
                raise RequestBlock(
                    _detail_residual("request", action_kind="unrecoverable")
                )
            if prev_aggregate_hits is not None and after_hits >= prev_aggregate_hits:
                raise RequestBlock(
                    _detail_residual("request", action_kind="unrecoverable")
                )
            prev_aggregate_hits = after_hits
            current = recovered
            if _is_fully_clean(current):
                return current
            continue
        return current

    # Budget exhausted: classify by last known scan shape when possible.
    final_findings = _scan_residuals(current, registry, root)
    if final_findings and final_findings[0].kind == "scanner-error":
        raise RequestBlock(_block_for_finding(root, final_findings[0]))
    raise RequestBlock(_detail_residual("request", action_kind="unrecoverable"))


def _final_residual_gate(
    payload: Any, registry: Any, root: Any
) -> Optional[BlockDetail]:
    """Full final residual recheck. None means Provider may proceed."""
    pk = _as_residual_finding(
        _find_residual_private_key(payload, root),
        default_kind="private-key",
    )
    if pk is not None:
        if pk.kind == "scanner-error":
            return pk.detail
        return _block_for_finding(root, pk)
    ps = _as_residual_finding(
        _find_residual_plain_secret(payload, registry, root),
        default_kind="registered-secret",
    )
    if ps is not None:
        if ps.kind == "scanner-error":
            return ps.detail
        return _block_for_finding(root, ps)
    if contains_plain_secret(payload, registry):
        return _detail_residual("request", action_kind="unrecoverable")
    return None


def _prepare_provider_bound(request: Any) -> Any:
    """Redact, recover recoverable history residuals, then final residual gate."""
    prepared = _redact_locatable_private_keys(request)
    try:
        registry = get_egress_registry_snapshot()
    except RuntimeConfigError:
        raise RequestBlock(_config_unavailable_detail()) from None
    except Exception:
        raise RequestBlock(_config_unavailable_detail()) from None
    try:
        redacted = redact_payload(prepared, registry)
    except RedactionCollisionError as exc:
        loc = humanize_location(request, getattr(exc, "path", ()))
        raise RequestBlock(_detail_collision(loc)) from None
    except RuntimeConfigError:
        raise RequestBlock(_config_unavailable_detail()) from None
    except Exception:
        raise RequestBlock(_detail_scanner_error("request")) from None

    recovered = _recover_residuals(redacted, registry, request)
    blocked = _final_residual_gate(recovered, registry, request)
    if blocked is not None:
        raise RequestBlock(blocked)
    return recovered


def on_llm_request(**kwargs: Any) -> dict[str, Any]:
    try:
        request = kwargs.get("request", {})
        redacted = _prepare_provider_bound(request)
        return {
            "request": redacted,
            "source": "credential-guard",
            "reason": "redacted known credential canaries",
        }
    except RequestBlock as rb:
        _log_fail_closed("llm_request", rb.detail.code)
        return _safe_request_fallback(rb.detail)
    except Exception:
        _log_fail_closed("llm_request")
        return _safe_request_fallback(_detail_scanner_error("request"))


def on_llm_execution(**kwargs: Any) -> Any:
    next_call = kwargs.get("next_call")
    try:
        request = kwargs.get("request", {})
        # Prior llm_request middleware decided to block — terminate locally.
        if _is_local_block_request(request):
            detail = getattr(request, "block_detail", None)
            if not isinstance(detail, BlockDetail):
                detail = _detail_scanner_error("request")
            _log_fail_closed("llm_execution_prior_block", detail.code)
            return _safe_blocked_response(detail)
        redacted_request = _prepare_provider_bound(request)
        if not callable(next_call):
            detail = _detail_scanner_error("request")
            _log_fail_closed("llm_execution_missing_next", detail.code)
            return _safe_blocked_response(detail)
    except RequestBlock as rb:
        _log_fail_closed("llm_execution", rb.detail.code)
        return _safe_blocked_response(rb.detail)
    except Exception:
        _log_fail_closed("llm_execution")
        return _safe_blocked_response(_detail_scanner_error("request"))
    # Downstream/provider errors must propagate — do not swallow next_call failures.
    return next_call(redacted_request)
