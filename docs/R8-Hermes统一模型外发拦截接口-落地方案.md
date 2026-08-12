# R8 · Hermes 统一模型外发拦截接口评估（已否决）

> **已否决，禁止执行。** 2026-08-11 用户重新明确产品边界：Credential Guard 只是独立插件，不能修改 Hermes 源码。
>
> 本文以下内容仅保留为“为什么插件无法覆盖 auxiliary 调用”的技术调查记录，不是实施方案，不得据此委派编码、修改 Hermes、打补丁或提交上游。
>
> 正确产品处理：只修复并发布插件能够控制的主聊天链路；对 `agent.auxiliary_client` 绕过明确披露为 Hermes 当前插件接口不覆盖的宿主能力边界，不在 Credential Guard 内 monkey patch，也不声称全局保护。

## 1. 大白话目标

当前主聊天出门前会过 Credential Guard，但自动标题、上下文压缩、视觉、oneshot、MoA、插件 LLM 等辅助调用走了另一扇门。

本轮不是逐个给标题/压缩/视觉打补丁，而是在辅助模型的统一出口安装同一套门禁。以后新增辅助任务只要使用 `call_llm()` / `async_call_llm()`，就天然经过 Credential Guard。

## 2. 现状证据

- 主聊天：`agent/conversation_loop.py` 已调用：
  - `hermes_cli.middleware.apply_llm_request_middleware()`
  - `hermes_cli.middleware.run_llm_execution_middleware()`
- 辅助调用：`agent/auxiliary_client.py` 的：
  - `call_llm()` / `async_call_llm()`
  - `_relay_sync_completion()` / `_relay_async_completion()`
  - `_relay_sync_stream()`
  当前直接进入 SDK/Relay，没有调用上述 LLM middleware。
- `title_generator`、`context_compressor`、`oneshot`、vision、MoA、plugin LLM 等均汇入 `auxiliary_client`，因此中央修复可覆盖现有辅助业务，不需要逐业务硬编码。

## 3. 实现边界

### 3.1 必须实现

1. 在 Hermes middleware 层增加可复用的同步与异步 Provider-attempt 执行入口。
2. 每次真实 Provider 尝试都按顺序执行：
   - `llm_request`：检查/改写 Provider-bound copy；
   - `llm_execution`：允许本地终止，或单次调用下游；
   - Provider / Relay。
3. auxiliary 同步、异步、stream、retry、fallback、credential-pool rotation、Relay 全部进入这套边界。
4. 传递统一的非敏感元数据：
   - `call_role=auxiliary:<task>`
   - `auxiliary_task`
   - `api_request_id`
   - `retry_count`
   - `provider` / `model` / `api_mode`
   - 可取得时传 `session_id`
5. 普通 Provider 请求无法伪造本地阻断状态；`LocalBlockRequest` 在 auxiliary 同步和异步链均可被执行 middleware 消费。
6. 中间件关闭或未注册时，Hermes 行为与现状等价。

### 3.2 明确不做

- 不把 Credential Guard 的凭证识别逻辑写进 Hermes 核心。
- 不新增 title/compression/vision 专用 guard。
- 不修改真实 default/worker Profile，不安装或启用插件。
- 不读取真实凭证、`.env`、`~/.ssh`。
- 不改 Credential Guard R0–R6 冻结侧车或历史 `dist/`。
- 不 commit、push、pull、rebase；当前 Hermes 本地 `main` 与 `origin/main` 各有一条独立 tip，本轮只在当前本机源码快照形成未提交候选。
- 不把图像生成、视频生成、TTS、转写、Web Search 等非 LLM Provider 接口混入本轮。

## 4. 严格 TDD 任务清单

### T1：同步 Provider-attempt middleware seam

文件：

- 修改 `hermes_cli/middleware.py`
- 新增/修改 `tests/hermes_cli/` 下 middleware 测试

RED：

- 同步 Provider 请求未经过 request/execution 两层；
- request 改写未到下游；
- execution 本地阻断仍调用 Provider；
- `next_call` 多次调用会重复 Provider。

GREEN：

- 新增一个同步组合入口，复用现有 contract；
- 保证 Provider 单次执行；
- 保留原请求、改写请求和 middleware trace；
- 下游 Provider 异常原样传播。

### T2：异步 Provider-attempt middleware seam

文件：

- 修改 `hermes_cli/middleware.py`
- 新增异步 contract 测试

RED：

- async Provider 直接外发；
- 同步 middleware 返回 awaitable 时未正确等待；
- async middleware 或 async downstream 的异常/本地终止语义错误。

GREEN：

- 支持同步 callback、异步 callback、返回 awaitable 的 callback；
- `next_call` 单次使用；
- 本地阻断可直接返回响应，Provider 计数为 0；
- Provider 异常不被 middleware 吞掉。

### T3：接入 auxiliary 中央出口

文件：

- 修改 `agent/auxiliary_client.py`
- 新增 `tests/agent/test_auxiliary_llm_middleware.py`（名称可按项目惯例调整）

接入点：

- `_relay_sync_completion()`
- `_relay_async_completion()`
- `_relay_sync_stream()`
- `stream=True` 下绕过 Relay 的特殊直接 Provider 分支
- fallback/retry/recovery 复用的所有 physical attempt

RED：

- title、compression、vision、oneshot 的捕获请求含合成 canary；
- request middleware 改写未到 Provider；
- execution middleware 阻断后 Provider 仍收到请求；
- fallback/retry 的第二次请求绕过 middleware。

GREEN：

- 每次 physical attempt 均过 middleware；
- 所有任务使用中央路由，无 task-name 特判；
- stream 在创建 Provider iterator 前完成检查；
- Relay 和直连行为一致。

### T4：真实调用类别矩阵

至少验证：

| 类别 | 路径 | 正常改写 | 本地阻断 Provider=0 | retry/fallback 不绕过 |
|---|---|---:|---:|---:|
| main | conversation loop | 是 | 是 | 是 |
| title | `title_generator → call_llm` | 是 | 是 | 是 |
| compression | `context_compressor → call_llm` | 是 | 是 | 是 |
| vision | `async_call_llm(task=vision)` | 是 | 是 | 是 |
| oneshot | `oneshot → call_llm` | 是 | 是 | 是 |
| MoA/plugin LLM | `call_llm` | 是 | 是 | 是 |

要求：

- 临时 HOME/HERMES_HOME；
- 真实 PluginManager 注册 middleware；
- loopback 假 Provider 捕获实际请求 body；
- 只用合成诱饵；
- 验证请求体中诱饵为 0；
- 验证禁用 middleware 后普通调用不受影响；
- 退出码承载所有断言，不只打印统计。

### T5：mutation 门禁

至少三类 mutation 必须 RED：

1. 删除 auxiliary 的 request middleware；
2. 删除 auxiliary 的 execution middleware；
3. 让 retry/fallback 直接调用 Provider 绕过统一 seam。

### T6：回归、文档与边界核验

- Hermes 定向测试；
- Hermes 全量相关测试；
- Credential Guard R7 专项与全量非构建测试；
- compileall；
- 更新 Hermes plugin/middleware 文档，明确主链与 auxiliary 均覆盖；
- 更新 Credential Guard R7 文档，把宿主 BLOCKING 只在真实 E2E 全绿后改为关闭；
- 核对 Hermes 源码以外、default/worker Profile、Credential Guard `dist/` 与 R0–R6 侧车零漂移。

## 5. 签收标准

全部满足才关闭宿主 BLOCKING：

1. 同步、异步、stream、Relay、retry、fallback 的真实 Provider 尝试均进入相同 middleware contract；
2. main/title/compression/vision/oneshot 实链 loopback E2E 全绿；
3. 故障或 Credential Guard 阻断时 Provider body 增量为 0；
4. middleware 禁用时行为不变；
5. mutation 门禁真实转 RED；
6. Hermes 与 Credential Guard 回归均为 0 failed；
7. 两路独立只读复审均 PASS；
8. 之后才升 Credential Guard 至 0.4.1、重建 ZIP/wheel/sdist/manifest，并做安装制品验收；
9. default 升级仍需用户单独确认。

## 6. 风险控制

- `agent/auxiliary_client.py` 有大量 retry/fallback 分支，禁止逐分支复制 middleware；应把统一门禁放在所有 physical attempt 必经的中央 helper。
- async contract 不能简单照搬 sync runner；必须实测同步 callback、async callback、awaitable 返回值和异常传播。
- stream 只保护“创建外发请求”这一步，不把流式 chunk 错当第二次请求。
- 不能只证明 `call_llm()` 顶层检查一次；fallback/retry 的每次真实出网都必须重新经过 final seam。
