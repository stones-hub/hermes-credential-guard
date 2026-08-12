# Credential Guard 总控计划

> ⚠️ **历史总控计划，当前产品路线已更新。** 本文保留 M0–M3.1 的历史决策与验收记录；2026-07-31 起的通用凭证边界重构，以 `docs/Credential-Guard-通用凭证边界重构方案.md` 和 `docs/Credential-Guard-通用凭证边界实施计划.md` 为唯一现行路线。当前状态（2026-08-03）：R0、R1A、R1B、R2 已签收关闭；停在 R3 方案共创门前；正式 worker 未由 Agent 升级。

## 目标

构建一个独立、可复用、仅在本机运行的 Hermes 插件。插件从本地文件或外部 MySQL 读取已登记凭证，在发往模型前执行精确值脱敏，并为后续本地安全执行提供统一凭证解析接口。

## 架构

```text
本地 JSON 文件 / 外部 MySQL
        ↓
CredentialBackend（单一激活后端）
        ↓
Credential Registry（仅本机内存）
        ├─→ llm_request：生成脱敏后的 provider-bound 副本
        ├─→ llm_execution：实际调用前二次校验
        └─→ transform_tool_result：工具结果提前脱敏

后续：AI 提交 target + action
        ↓
Hermes pre_tool_call → 人工审批（fail-closed）
        ↓
本地执行适配器读取真实凭证 / 本机 OpenSSH 读 SSH Config
        ↓
执行结果脱敏后返回模型
```

## 开源复用与自研边界

| 组件 | 方案 |
|---|---|
| 插件发现、启停、CLI 注册 | 复用 Hermes Plugin API |
| 模型请求与工具结果接入点 | 复用 Hermes middleware/hooks |
| 人工审批 | 复用 Hermes `approvals.mode: manual` + `pre_tool_call` approve |
| 常见格式识别 | 兼容复用 Hermes `agent.redact`，不可用时走插件最小规则 |
| 已登记凭证精确替换 | 插件自研 |
| 文件后端（JSON） | 插件自研 |
| MySQL 凭证后端 | 插件自研（后续里程碑） |
| 本地执行适配器 | 按场景逐项自研，不做万能 Shell 注入 |
| SSH Config 公钥执行 | 插件自研（系统 OpenSSH argv 数组） |

## 里程碑

### M0：插件骨架

- 建立独立插件目录和 manifest。
- 注册 `llm_request`、`llm_execution`、`transform_tool_result`。
- 注册 `hermes credential-guard` 运维 CLI。
- 建立隔离测试环境，不安装到当前 worker Profile。

状态：**完成**。

### M1：诱饵凭证外发命门验证

- 诱饵注册表、递归脱敏、opaque token、工具结果脱敏与 fail-closed。
- 真实 `hermes chat` → `127.0.0.1` 假 provider E2E。
- AC8/AC9：本机可信区残余风险，保留 strict-xfail，**不阻塞后续里程碑**。

状态：**完成并关闭**。

### M2：本地文件凭证与 MySQL 只读执行闭环

合并原「文件后端」与原「最小本地执行」：

- `credentials.json` / `targets.json`（目录 `0700`，文件 `0600`）。
- 工具 `mysql_credential_action(target, action)`：仅 `check_connection`、`show_effective_grants`。
- 每次动作经 `pre_tool_call` → Hermes 标准人工审批；拒绝时 DB 连接数 / credentials 读取 = 0。
- 真实 Docker MySQL 8.0（仅绑定 `127.0.0.1`）；权限由 MySQL GRANT 决定。
- 假 Provider 两轮 tool-call E2E；插件自带 PyMySQL 依赖（`deps/`）。
- 威胁边界：本机 Hermes 及其标准审批可信；不防御宿主审批调度缺陷，不实现第二套审批票据（H6 经用户确认取消，非阻塞）。

状态：**完成**（见 `docs/M2-验收报告.md`）。

### M3：SSH Config 公钥认证与敏感路径保护

- `ssh_config` 目标：仅 `type` + `ssh_alias`；不要求 `credentials.json` 条目。
- 工具 `ssh_credential_action(target, action)`：仅 `check_connection`（`true`）、`show_remote_identity`（`id -un`）。
- 系统 OpenSSH argv 数组调用；强制 BatchMode/公钥/禁转发等选项；错误归类为固定错误码。
- `pre_tool_call` 阻断标准 `read_file` / `search_files` 对 `~/.ssh` 与 `credentials.json` 的读取；terminal 仅拦明确直接读取。
- `transform_tool_result` / `llm_request` / `llm_execution` 二次保护私钥 PEM 与已登记秘密。
- 隔离真实 E2E：临时 HOME + loopback sshd + 假 Provider；不读真实 `~/.ssh`，不连真实服务器。

状态：**完成（0.3.1）**。见 `docs/M3-验收报告.md`；M3.1 方案执行记录见 `docs/M3.1-双文件边界与外发守卫收口方案.md`。worker 升级需用户另行确认。

### M3.1：双文件边界与外发守卫收口

- 保留双文件职责：`credentials.json` = 本地秘密库；`targets.json` = 本地目标目录。
- 外部模型只接触业务 `target` 名称；普通文件/搜索/终端工具不能整份读取本地目标目录。
- 可信本地外发守卫用秘密库建立新鲜内存脱敏快照；执行器仍只在标准人工审批通过后解析本次目标凭据、连接目标系统。
- 收口编码变体、E2E gate mutation、版本化发布报告与最终 ZIP 编码 canary。

状态：**完成（随 0.3.1 发布）**。

### M4：外部 MySQL 凭证后端

- 使用 `credential_secret`、`credential_target` 两张表。
- 日常 Hermes 账号只读。
- MySQL 启动凭证从本地 `0600` 配置文件读取。
- 连接或刷新失败时进入不可用状态，不回退文件后端或环境变量。

完成标准：在真实 MySQL 8.0 测试库完成读取、刷新、故障阻断及诱饵外发验证；不使用 SQLite 替代。

### M5：安装、升级与运维交付

- 提供本地目录安装/链接方式。
- 提供 `check`、`list`、`targets`、`test-redaction` 命令。
- 提供 macOS/Linux 配置指南和回滚步骤。
- 安装到用户指定 Hermes Profile 前单独确认。

### M6：扩展本地执行适配器（后续）

- 按需增加 HTTP/Jenkins 等适配器。
- 不将真实值拼接进任意自由 Shell 命令。
- 继续复用 Hermes 人工审批与结果脱敏。

## 总体验收红线

1. 真实 provider 请求体中的诱饵秘密出现次数必须为 0。
2. 不能用 UI 掩码或单元测试代替实际 HTTP 请求捕获。
3. 插件未加载、后端不可读、脱敏异常时不得宣称处于受保护状态。
4. 已确认历史外泄的真实凭证需要单独轮换；插件只能阻止未来泄漏。
5. 本机可信区日志/WAL 残余明文不阻塞功能交付，但须在验收报告中诚实记录。
6. SSH Config / 私钥正文不得出现在 Provider 捕获、审批文案或工具返回中。
