# R0 Hermes 工具参数审批后注入 — 实测报告

> 日期：2026-07-31  
> 范围：仅 spike + 专项测试；本轮脚本使用临时 HOME/HERMES_HOME，不修改 Credential Guard 生产代码、Hermes 源码或 0.3.1 制品。真实 worker 配置的历史修改与恢复事件见第 10 节。  
> 判定：**PASS（复验）** — 首轮独立复核发现阻塞，修复后复验通过

## 0. 首轮假绿与独立复核阻塞

首轮自报 6 passed / Verdict PASS，但独立读码发现证据不足，**不得签 PASS**：

| 阻塞 | 问题 | 假绿表现 |
|---|---|---|
| B1 | 假工具把 `token[:32]`（诱饵连续前缀）写入 `received_values` | `_count_plain` 只找完整诱饵 → `shared_state_plain_count=0` |
| B2 | 并发两次共用同一 decoy；顺序 A/B 只查 `plain_count` | 即使串 plan 也会通过，未证明 A 收 A、B 收 B |
| B3 | `TIP_FAULT` 预设分支直接返回阻断 | 未让 analyze/build_approval/resolve/inject 真实 raise |
| B4 | 未扫描 stderr / 完整 state 的 ≥8 连续片段 | 前缀残留与子进程杂讯未被 gate |

本轮按严格 TDD：先增失败测试（RED：`5 failed, 4 passed`），再最小修复 spike，复验 GREEN。

## 1. 目标与方法

验证现有 Hermes 插件接口在不改核心的前提下能否实现：

```text
模型工具参数带逻辑引用
→ tool_request 只识别，不注入
→ pre_tool_call 触发标准人工审批（resolve_pre_tool_block → request_tool_approval）
→ 只有批准后才进入 tool_execution 并解析诱饵真值
→ 假工具收到真值（仅以不可逆摘要/布尔证明）
```

环境：临时 `HOME` / `HERMES_HOME`；运行时合成诱饵（报告只记 `decoy_len`，不打印正文）；真实 `PluginManager`、middleware、`resolve_pre_tool_block`；假工具 `tip_probe_tool` 只回计数；空 Provider Key。

Hermes 源码只读路径：`/Users/yelei/.hermes/hermes-agent`（`git status --porcelain` 行数 = 0）。

## 2. TDD RED（阻塞修复轮）

在已有首轮 spike 上新增 B1–B4 断言后执行：

```bash
.venv/bin/python -m pytest tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# 5 failed, 4 passed
```

准确失败断言（摘录）：

1. B3：`fault=tool_request did not raise a real internal exception`（无 `real_exception_count`）
2. B3：`used preset branch, not real raise`（无 `fault_via_real_raise`）
3. B2：`concurrent plans did not prove distinct secret binding`
4. B1/B4：`partial_secret_residue_count` / `residue_gate_passed` / `resolver_store_empty` 缺失

## 3. GREEN 修复（仅 spike + 测试 + 本报告）

| 文件 | 作用 |
|---|---|
| `spikes/tool-injection-proof/__init__.py` | 提取 `_analyze_request` / `_build_approval` / `_resolve_ref` / `_inject_args`；fault 真实 raise；下游只记 digest；多 ref resolver_store |
| `spikes/tool-injection-proof/run_proof.py` | 并发双诱饵双引用；子进程内 residue gate；只输出安全 JSON |
| `tests/test_tool_injection_foundation.py` | B1–B4 完成判据断言 |
| `docs/R0-Hermes工具参数审批后注入-实测报告.md` | 本文件（首轮假绿不隐瞒） |

生产 `credential_guard/`、`plugin.yaml`、`pyproject.toml`、`release-metadata.json` 和 `dist/` 本轮未改。worker Profile 不能仅凭本轮 spike 断言“从未改动”；真实 `config.yaml` 此前曾被助手修改，用户已于 15:52:29 手工恢复。

## 4. 实际调用顺序（批准路径）

```text
tool_request → pre_tool_call → approval_gate → tool_execution → downstream_tool
```

```json
{
  "before_execution_plain_count": 0,
  "tool_received_plain_count": 1,
  "downstream_call_count": 1,
  "approval_payload_plain_count": 0,
  "middleware_trace_plain_count": 0,
  "secret_resolve_count": 1,
  "next_call_count": 1,
  "partial_secret_residue_count": 0,
  "residue_gate_passed": true,
  "resolver_store_empty": true
}
```

## 5. 拒绝路径

```text
secret_resolve_count=0
downstream_call_count=0
tool_received_plain_count=0
approval_denied=true
residue_gate_passed=true
resolver_store_empty=true
```

## 6. 异常路径与 fail-closed（真实 raise）

宿主默认行为（实测记录，**不能**把裸异常旁路当成插件 fail-closed）：

- `invoke_middleware` / `invoke_hook`：裸 callback raise 被吞，流程继续；
- `run_tool_execution_middleware`：裸 raise 在 `next_call` 前会旁路调用下游。

spike 在内部函数真实 raise 后由生产式 `except` 捕获，返回安全标记/block/固定错误且不调下游：

| 故障点 | 真实 raise 点 | real_exception_count | downstream |
|---|---|---|---|
| tool_request | `_analyze_request` | ≥1 | 0 |
| pre_tool_call | `_build_approval` | ≥1 | 0 |
| tool_execution_resolver | `_resolve_ref` | ≥1 | 0 |
| tool_execution_inject | `_inject_args` | ≥1 | 0 |

聚合：`real_exception_count>=4`，`all_fault_downstream_call_count=0`，`fault_via_real_raise=true`。

## 7. 单次执行、并发绑定与残留门控（T5 / B1 / B2 / B4）

- 单次批准：`next_call_count=1`；`original_args` 仍含引用；
- 顺序 A/B：不同运行时诱饵 + 不同引用；摘要 A=秘密 A≠B，B 相反；
- 并发 `conc-1`/`conc-2`：`concurrent_distinct_secret_binding=true`，`concurrent_each_next_call_once=true`；
- 下游 / shared state / evidence **不**保存完整诱饵或 ≥8 连续前缀/后缀；仅不可逆摘要（扫描前擦除）与布尔；
- 子进程内扫描 stdout 杂讯、stderr、approval、trace、共享 state → `residue_gate_passed=true`；
- 执行后清空 resolver store → `resolver_store_empty=true`。

## 8. 是否需要修改 Hermes 核心

**不需要。** 现有顺序已满足「审批前不注入、审批后才注入」。

注意：宿主对裸插件异常默认旁路；生产实现必须在插件内捕获并返回固定阻断（本 spike 已用真实内部 raise + except 证明），不能把「Hermes 吞异常继续跑」当成 fail-closed。

## 9. 命令与结果

```bash
# RED（阻塞修复轮，修复前）
.venv/bin/python -m pytest tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# 5 failed, 4 passed

# GREEN（修复后）
.venv/bin/python -m pytest tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# .........  9 passed

python3 -m compileall -q spikes/tool-injection-proof tests/test_tool_injection_foundation.py
# COMPILE_OK
```

## 10. 边界证据与配置恢复事件

| 对象 | 证据 |
|---|---|
| Hermes 源码 | `git -C ~/.hermes/hermes-agent status --porcelain` → **0 行** |
| 生产 `plugin.yaml` | 仍为 `version: 0.3.1`；无 `tool_request`/`tool_execution`；sha256=`96d90f84d3c828b7bc010ce8e20429d7c7bc82a9239cd176a017e308945d9e94` |
| `pyproject.toml` | `version = "0.3.1"` |
| `release-metadata.json` | sha256=`5fea9bda39ac0270bd1245dca1ddfdcd2e5c3b175cea8d0f6e35e23630a9c3bc` |
| `dist/credential-guard-0.3.1-hermes-plugin.zip` | sha256=`7ebc8652d6a763a8ff9fa1d7596919e811bcff92b8eee572af30b61b54651ac6` |
| worker `config.yaml` | 助手此前曾修改真实配置；用户于 **2026-07-31 15:52:29** 手工恢复。恢复后基线：sha256=`2bad7d2dd9746d5d6283fc0e99b010212261dae713624089bf8754cd59337977`，size=`19011`，mode=`0600`。R0 复验后实测仍为该基线 |
| R0 配置写入位置 | `run_proof.py` 只向临时 `HERMES_HOME/config.yaml` 写入，不以真实 worker 配置作为测试目标 |
| `credential_guard/` 生产代码 | 本轮未编辑 |

## 11. 修改文件清单

- `spikes/tool-injection-proof/__init__.py`
- `spikes/tool-injection-proof/run_proof.py`
- `tests/test_tool_injection_foundation.py`
- `docs/R0-Hermes工具参数审批后注入-实测报告.md`（本文件）

## 12. 完成判据（复验）

| 判据 | 结果 |
|---|---|
| `partial_secret_residue_count=0` | PASS |
| `residue_gate_passed=true` | PASS |
| `resolver_store_empty=true` | PASS |
| `concurrent_distinct_secret_binding=true` | PASS |
| `concurrent_each_next_call_once=true` | PASS |
| `real_exception_count>=4` | PASS |
| `all_fault_downstream_call_count=0` | PASS |

| # | 原条件 | 结果 |
|---|---|---|
| 1 | 审批前无真值 | PASS |
| 2 | 拒绝时不解析、不执行 | PASS |
| 3 | 批准后才解析并只执行一次 | PASS |
| 4 | 审批/trace/原参数无真值 | PASS |
| 5 | 插件异常 fail-closed（真实内部 raise + except） | PASS |
| 6 | 不修改 Hermes 核心 | PASS |
| 7 | 不修改生产代码 / 0.3.1；R0 复验后 worker 恢复基线不变 | PASS |

**Verdict: PASS（首轮独立复核发现阻塞，修复后复验）**

R0 结束，不开始 R1。
