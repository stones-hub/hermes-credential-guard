# SECURITY

## 威胁模型（M0/M1/M2）

```text
可信：本机Hermes、Hermes标准审批机制、Credential Guard、本地凭证文件、本地执行器
不可信：外部模型、模型供应商、模型生成的参数、Provider返回内容
```

- 目标：防止已登记凭证出现在模型外发请求与工具结果回流中；M2 在本机审批后执行只读 MySQL 动作。
- 非目标：不防御 Hermes 宿主审批调度自身的 bug；不实现插件侧第二套审批票据；不提供凭证导出/打印；**不治理** Hermes 本机 session/log 落盘（无覆盖全部入口的统一 fail-closed pre-persist seam）。

## 安全控制

- `llm_request`：对请求执行深层复制后脱敏，避免原地修改；任意内部异常返回不含原现场数据的安全请求副本（E2E：恰好 1 个含固定安全提示的 fallback 请求）。
- `llm_execution`：调用下游前再次脱敏并校验；插件内部异常不调用 `next_call`，返回 OpenAI 兼容安全阻断响应；**不吞** `next_call` 下游异常。
- `transform_tool_result`：工具结果二次脱敏；失败时返回固定安全 JSON，不含原工具内容。
- 凭证最短长度限制（8）：拒绝过短值。
- 重叠秘密按长度降序替换（redaction view）；元数据保持插入序。
- credential key/field 仅允许安全标识 `^[A-Za-z][A-Za-z0-9_-]{0,63}$`。
- 稳定引用为 opaque id：`<SECRET:cg_<hash>>`，与秘密解耦；注册时强制 token/token_id 与所有秘密互不包含。
- 注册表不变量：`(key,field)` 唯一；同身份同秘密幂等；同身份异秘密拒绝；跨身份同秘密拒绝；token_id 唯一；失败不部分提交。
- 递归处理 dict 字符串键；键脱敏碰撞时 fail-closed。
- 生产包不含 test fixture / 环境变量故障注入开关。
- 真实 Hermes CLI E2E 使用临时 HOME/HERMES_HOME、环境白名单、**Python socket 常规入口** loopback 审计与空 toolset。
- `credential-guard check` 只接受 PluginManager 中直接注册的 production callback identity；不按函数名/substring 泛匹配，也不信任任意 `__wrapped__` 伪造。

## 已知限制 / 架构边界

- 仅替换“注册表中已登记值”，未知敏感内容不在本轮覆盖。
- Hermes v0.19.0 **没有**覆盖 CLI、Gateway、ACP、TUI、cron、subagent 等所有 agent 入口、受支持且 fail-closed 的统一 pre-log/pre-persist seam。
  - 例外：Gateway 普通外部消息已有 `pre_gateway_dispatch` rewrite，可在 gateway 子集早期改写；但不覆盖 CLI/ACP/TUI/cron/subagent/internal event，异常仍 fail-open，不能作为全局安全边界。
- 宿主 PluginManager / `invoke_middleware` / execution chain 对回调异常默认 fail-open——独立插件无法兜住调度器自身故障。
- Loopback guard 仅约束 Python `socket` 常规入口；ctypes/原始 syscall、subprocess 外带工具等不在范围内。更强保证需容器/OS 网络隔离。
- 插件未加载/被禁用时，无防护。
- AC9 口径：本机可信区日志/WAL 残余明文已接受为非阻塞 strict-xfail；更强保证需 Hermes 核心补丁或 OS/容器隔离，不在本插件目标内。

## 事件响应建议

- 如发现历史真实凭证外泄，需要独立轮换，插件只能降低未来外发风险。
- 生产启用前，请在隔离 profile 先跑本仓库测试与 `scripts/run_canary_e2e.py`。
- AC8/AC9：在用户拍板“接受本机可信边界”或“Hermes 核心补丁”前，不建议进入文件后端（M2）。
