# R7 · Hermes 当前版本真实外发兼容性修复方案

状态：**R7 两个插件兼容性 Bug 已行政签收 PASS（2026-08-11）**。未改 Hermes 核心、未安装/启用正式 worker、未读真实凭证。

产品口径（最终拍板）：Credential Guard 只是独立插件；Hermes `auxiliary_client.call_llm` 绕过 plugin middleware 是**当前 Hermes 插件接口不覆盖的宿主能力边界**，不是本插件待修 Bug。不修改 Hermes 源码、不 monkey patch、不声称覆盖全部模型外发。

## 1. 根因

### 缺陷 A（Round 1）：长普通文本误判 fail-closed

`sensitive_paths._iter_decode_candidates()` 曾无条件 `add(text.strip())`。当单个普通系统提示词 / 消息字符串长度超过 `MAX_PRIVATE_KEY_CANDIDATE_LENGTH`（65,536）且仍小于 `MAX_PRIVATE_KEY_SCAN_BYTES`（512,000）时，抛出 `EncodedPrivateKeyScanError: candidate exceeds max length`，`on_llm_request` fail-closed。

### 缺陷 A′（Round 2 复审阻断）：超长文本内嵌完全 Unicode-escape PEM 绕过

Round 1 修复跳过超长整段候选后，仅当整段 ≤ 候选长度时才把含 `\\u` 的字段加入候选。合成 PEM 逐字符编码为 `\\uXXXX` 并嵌入超长普通文本时，原始文本无明文 BEGIN/END marker，扫描返回 False，`on_llm_execution` 会调用 downstream。

### 缺陷 B（Round 1）：fail-closed 伪请求仍外发 Provider

`_safe_request_fallback()` 曾返回 `model=credential-guard-blocked` 的“安全请求”。Hermes 主链顺序为 `llm_request → llm_execution → provider`；`on_llm_execution` 对这份干净 fallback 重新扫描后继续 `next_call()`，于是真实 Provider 收到伪模型并返回 503。

### 缺陷 B′（Round 2 复审阻断）：公开固定 model/messages 哨兵可伪造

Round 1 用 `model=credential-guard-local-block` 与 messages 内 `_credential_guard_local_block=terminate-v1` 作为本地阻断信号。合法模型名可碰撞；普通请求亦可在 messages 中伪造旧公开 marker。

## 2. 修复（已签收）

| 文件 | 变更 |
| --- | --- |
| `credential_guard/sensitive_paths.py` | 整段文本仅在 ≤ 候选长度时作为 decode candidate；超长普通整段跳过整段候选；**有界 JSON-escape run**（`\\uXXXX` / 标准 JSON string escape）仍被提取；形似编码且超长的候选继续 fail-closed；三层预算不变 |
| `credential_guard/middleware.py` | fail-closed 返回 `LocalBlockRequest`（dict 子类）作为带外 Python 状态；`on_llm_execution` 仅以 `isinstance(..., LocalBlockRequest)` 判定并本地终止；**不再**用公开 model/messages 字符串作信号 |
| `tests/test_r7_long_text_and_local_block.py` | Round 2 A/B RED→GREEN、B0 宿主 seam 证明、load-bearing mutation |
| `tests/test_hermes_cli_e2e.py` + helpers | 主链隔离（正式配置关闭 `auxiliary.title_generation`）、长文本、fail-closed=0、插件关闭非干扰 |
| `scripts/run_canary_e2e.py` / `tests/test_canary_gates.py` | 同步 fail-closed 契约为 Provider=0 |
| `credential_guard/cli.py` | check/help 明确主链覆盖与 auxiliary 宿主边界（不宣称已覆盖） |

### B0 宿主 seam（只读实测，非猜测）

证据来源：`/Users/yelei/.hermes/hermes-agent/hermes_cli/middleware.py` + `agent/conversation_loop.py`，项目内测试 `test_r7_b0_*`。

| 事实 | 结论 |
| --- | --- |
| `apply_llm_request_middleware` 对 middleware 返回的 `request` 执行 `_safe_copy`（成功路径 = `deepcopy`） | **不保留**返回对象身份 |
| `deepcopy` 保留 dict **子类类型**与实例属性 | `LocalBlockRequest` 可作为带外信号穿过 seam |
| `conversation_loop` 将 `apply` 的 `payload` **按同一对象**传入 `run_llm_execution_middleware`（无二次拷贝） | execution 所见即 deepcopy 后的 carrier |
| middleware 只接受 `isinstance(next_request, dict)` | 不能返回非 dict 自定义对象代替 request |
| 普通 Provider kwargs 为 JSON 形 plain `dict` | model/messages 字段无法表达 `LocalBlockRequest` 类型 |

设计约束遵守：

- 不靠抬高 65,536 掩盖；
- 不依赖把伪模型名发给 Provider 作为阻断信号；
- 阻断状态不可由普通 provider request 的 model/messages 伪造；
- 不修改 canonical conversation history；
- 不为某个 auxiliary task 名写硬编码补丁；
- 下游 Provider 异常仍传播，不吞掉。

## 3. 产品覆盖边界（宿主接口能力，非插件待修 Bug）

证据来源：当前本机 Hermes 树 `/Users/yelei/.hermes/hermes-agent`（只读）。

| 调用类型 | 是否经过 plugin llm_request | 是否经过 llm_execution | 当前是否受保护 | 证据 |
| --- | --- | --- | --- | --- |
| 主 conversation loop（`agent/conversation_loop.py`） | 是 | 是 | 是（插件注册后） | `apply_llm_request_middleware` → `run_llm_execution_middleware` 包裹 `_perform_api_call` |
| `auxiliary_client.call_llm` / `async_call_llm`（title_generation、compression、vision、session_search 等 task） | 否 | 否 | **不保证** | `auxiliary_client.py` 无 middleware import；经 `_relay_sync_completion` → `client.chat.completions.create` |
| `agent.oneshot.run_oneshot` | 否 | 否 | **不保证** | `oneshot.py` 直接 `call_llm(...)` |
| `agent/title_generator.py` 自动标题 | 否 | 否 | **不保证** | `generate_title` → `call_llm(task="title_generation")` |
| context compression | 否 | 否 | **不保证** | `context_compressor.py` → `call_llm` |
| vision / 其他 auxiliary task | 否 | 否 | **不保证** | `tools/vision_tools.py` 等经 `async_call_llm` |
| relay / fallback（主链内） | 是（先经 middleware） | 是 | 是（主链） | middleware 在 `relay_llm.execute` 之前应用 |
| 委托 / subagent 主循环 | 是（若走同一 conversation_loop） | 是 | 是（同主链） | 同 `conversation_loop` seam |

### 判定（产品口径）

这是 **Hermes 当前插件接口不覆盖的宿主能力边界**：

- 主聊天 `conversation loop` 的模型请求与主链工具结果受 Credential Guard 保护；
- 自动标题、上下文压缩、vision、oneshot、session_search 及其他 auxiliary / relay-fallback 辅助调用**不保证**受保护；
- 插件不修改 Hermes、不 monkey patch 内部函数、不声称覆盖全部模型外发或全部 auxiliary 路径；
- 关闭 `auxiliary.title_generation` **只能减少一条暴露路径**，不能等同于全覆盖。

曾评估的 Hermes 统一外发拦截接口见 `docs/R8-Hermes统一模型外发拦截接口-落地方案.md`——**已否决、禁止执行**，仅作调查记录。

临时兼容（仅主链 E2E / 运维缓解，不改变上述边界）：

```yaml
auxiliary:
  title_generation:
    enabled: false
```

`credential-guard check` 在通过时打印主链覆盖与 auxiliary 不覆盖边界。

## 4. Mutation 证据纪律

Round 1 文档曾写「mutation 已验证」，但当时 **缺少**「长普通文本不整段解码」的 load-bearing mutation 门禁，属过报。Round 2 起仅以下可复现项可写「已验证」：

| Mutation | 门禁测试 | 失效后可见 RED |
| --- | --- | --- |
| 恢复「整段超长文本一律 `add(strip)`」 | `test_r7_a3_mutation_whole_text_decode_skip_is_load_bearing` | `EncodedPrivateKeyScanError: candidate exceeds max length` |
| 删除 JSON-escape 子候选提取 | `test_r7_a3_mutation_drop_json_escape_subcandidates_is_red` | 完全 `\\uXXXX` PEM 长文本检测变为 False |
| 删除 `LocalBlockRequest` 消费分支 | `test_r7_b1_mutation_drop_local_block_consumption_is_red` | `next_call` 被调用（Provider 可达） |

## 5. 验证读数与签收（2026-08-11）

两路独立只读复审对两个插件缺陷局部 **PASS**（长文本 + LocalBlockRequest）。主代理独立全量：

```text
Round 2 专项：tests/test_r7_long_text_and_local_block.py → 18 passed
相关回归：r7 + sensitive_paths + variant_limits + fail_closed + request_guard
         + hermes_cli_e2e + canary_gates → 77 passed
全量非构建：scripts/run_r5_nobuild_pytest.py -q → 1616 passed, 3 xfailed, 0 failed
compileall credential_guard tests → exit 0
mutation（临时改生产再复原，实测 RED）：
  mut1 恢复整段 add(strip) → T1 RED (candidate exceeds max length)
  mut2 删除 JSON-escape 子候选 → A1 RED (contains_private_key_material is False)
  mut3 删除 LocalBlockRequest 消费 → B1 RED (next_call 非空 / Provider 可达)
```

**行政签收范围**：上述两个插件兼容性 Bug + 产品覆盖边界口径纠正。  
**不在签收范围**：宣称 auxiliary 已受保护；修改 Hermes；升级真实 default/worker。

0.4.1 发布物与隔离安装 E2E 见 `docs/R7-0.4.1-验收报告.md`（技术候选；待主代理独立复跑与两路只读终审）。
