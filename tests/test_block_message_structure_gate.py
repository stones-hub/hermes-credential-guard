"""Block-message structure gate — reject malformed actionable prompts (narrow TDD)."""

from __future__ import annotations

import pytest

from credential_guard.middleware import (
    BlockDetail,
    format_block_message,
    is_blocked_response_content,
    _config_unavailable_detail,
    _detail_collision,
    _detail_residual,
    _detail_scanner_error,
)


def _healthy_six_line(
    *,
    summary: str = "示例原因",
    location: str = "第 1 条消息（user）",
    code: str = "CG-SCANNER-ERROR",
    action: str = "保留原因码并报告 Bug",
) -> str:
    return (
        "Credential Guard 已阻止本次请求\n"
        f"原因：{summary}\n"
        f"位置：{location}\n"
        f"代码：{code}\n"
        f"处理：{action}\n"
        "发送状态：未发送给外部模型。"
    )


@pytest.mark.parametrize(
    "label,text",
    [
        (
            "missing_reason",
            (
                "Credential Guard 已阻止本次请求\n"
                "位置：第 1 条消息\n"
                "代码：CG-SCANNER-ERROR\n"
                "处理：报告 Bug\n"
                "发送状态：未发送给外部模型。"
            ),
        ),
        (
            "missing_location",
            (
                "Credential Guard 已阻止本次请求\n"
                "原因：扫描异常\n"
                "代码：CG-SCANNER-ERROR\n"
                "处理：报告 Bug\n"
                "发送状态：未发送给外部模型。"
            ),
        ),
        (
            "missing_action",
            (
                "Credential Guard 已阻止本次请求\n"
                "原因：扫描异常\n"
                "位置：第 1 条消息\n"
                "代码：CG-SCANNER-ERROR\n"
                "发送状态：未发送给外部模型。"
            ),
        ),
        (
            "empty_reason",
            _healthy_six_line(summary=""),
        ),
        (
            "empty_location",
            _healthy_six_line(location=""),
        ),
        (
            "empty_action",
            _healthy_six_line(action=""),
        ),
        (
            "code_cg_fake",
            _healthy_six_line(code="CG-FAKE"),
        ),
        (
            "code_request_size_bug",
            _healthy_six_line(code="CG-REQUEST-SIZE-BUG"),
        ),
        (
            "wrong_line_order",
            (
                "Credential Guard 已阻止本次请求\n"
                "位置：第 1 条消息\n"
                "原因：扫描异常\n"
                "代码：CG-SCANNER-ERROR\n"
                "处理：报告 Bug\n"
                "发送状态：未发送给外部模型。"
            ),
        ),
        (
            "extra_prefix",
            "前缀\n" + _healthy_six_line(),
        ),
        (
            "extra_suffix",
            _healthy_six_line() + "\n额外一行",
        ),
    ],
)
def test_malformed_block_message_rejected(label, text):
    """Structure helper must not false-green on incomplete / unknown-code prompts."""
    assert is_blocked_response_content(text) is False, label


@pytest.mark.parametrize(
    "detail_factory",
    [
        _config_unavailable_detail,
        lambda: _detail_collision("request.messages[0].<key>"),
        lambda: _detail_residual("第 1 条消息（user）"),
        lambda: _detail_scanner_error("第 3 条消息（user）"),
    ],
    ids=[
        "CG-CONFIG-UNAVAILABLE",
        "CG-REDACTION-COLLISION",
        "CG-RESIDUAL-SECRET",
        "CG-SCANNER-ERROR",
    ],
)
def test_healthy_production_block_details_accepted(detail_factory):
    detail = detail_factory()
    assert isinstance(detail, BlockDetail)
    text = format_block_message(detail)
    assert is_blocked_response_content(text) is True
    assert detail.code in text
    assert detail.location in text
    assert detail.summary in text
    assert detail.action in text


def test_retired_boundary_unknown_code_rejected_by_structure_helper():
    """CG-PRIVATE-KEY-BOUNDARY-UNKNOWN is no longer a user-visible block code."""
    text = _healthy_six_line(code="CG-PRIVATE-KEY-BOUNDARY-UNKNOWN")
    assert is_blocked_response_content(text) is False


def test_mutation_dropping_action_line_must_reject():
    """Load-bearing: strip 处理： from a real formatted prompt → helper False."""
    text = format_block_message(_detail_scanner_error("第 1 条消息（user）"))
    assert is_blocked_response_content(text) is True
    lines = text.split("\n")
    mutated = "\n".join(line for line in lines if not line.startswith("处理："))
    assert "处理：" not in mutated
    assert is_blocked_response_content(mutated) is False


def test_mutation_swapping_code_to_cg_fake_must_reject():
    """Load-bearing: replace a known code with CG-FAKE → helper False."""
    text = format_block_message(_config_unavailable_detail())
    assert is_blocked_response_content(text) is True
    mutated = text.replace("代码：CG-CONFIG-UNAVAILABLE", "代码：CG-FAKE", 1)
    assert "CG-FAKE" in mutated
    assert "CG-CONFIG-UNAVAILABLE" not in mutated
    assert is_blocked_response_content(mutated) is False
