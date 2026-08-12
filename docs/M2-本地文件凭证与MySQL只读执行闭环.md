# M2 本地文件凭证与 MySQL 只读执行闭环

## 1. 目标

在不修改 Hermes 源码、不安装到当前 worker、不接触真实凭证或生产系统的前提下，实现并验证：

```text
真实 Hermes CLI
→ 127.0.0.1 假 OpenAI Provider 发起 mysql_credential_action 工具调用
→ Hermes pre_tool_call 人工审批门禁
→ Credential Guard 本地执行器
→ 本机 Docker MySQL 8.0（仅 127.0.0.1）
→ 结果脱敏
→ Hermes 再次调用假 Provider
```

模型只能看到目标名称、动作和脱敏结果，不能看到真实用户名、密码、凭证路径或连接串。

## 2. 已拍板边界

- 本机 Hermes 运行环境为可信区；主要防外部模型和模型供应商看到凭证。
- 本轮本机后端采用 JSON 文件：目录 `0700`，`credentials.json` 和 `targets.json` 均为普通文件、权限 `0600`。
- 一个实例只启用一个后端；本轮只有文件后端，不做 MySQL 凭证后端。
- 测试数据库为本机独立 Docker MySQL 8.0，宿主端口只绑定 `127.0.0.1`。
- 模型工具固定为 `mysql_credential_action(target, action)`。
- 只支持 `check_connection`、`show_effective_grants`。
- 两个动作每次都必须走 Hermes `pre_tool_call` 人工审批；拒绝/超时/异常时数据库连接数必须为 0。
- 不维护权限字段；有效权限由 MySQL `GRANT` 唯一决定。
- 不允许任意 SQL、Shell 拼接或命令行密码。

## 3. 文件结构

`credentials.json`：

```json
{
  "version": 1,
  "credentials": {
    "mysql_canary_credential": {
      "type": "mysql",
      "username": "cg_readonly",
      "password": "<TEST_ONLY_DECOY>"
    }
  }
}
```

`targets.json`：

```json
{
  "version": 1,
  "targets": {
    "mysql-local-canary": {
      "type": "mysql",
      "host": "127.0.0.1",
      "port": 3309,
      "database": "credential_guard_test",
      "credential_ref": "mysql_canary_credential"
    }
  }
}
```

生产代码和文档不得包含具体诱饵值；具体值只能由测试 harness 在临时目录运行时生成。

## 4. 模块职责

- `file_backend.py`：安全打开、权限与结构校验、元数据读取、按引用短时解析真实值；不得提供打印/枚举 secret 的接口。
- `targets.py` 或等价模块：校验目标与凭证类型绑定；不含权限字段。
- `mysql_executor.py`：使用 Python MySQL SDK 内存连接；只允许固定动作；无自由 SQL；异常映射成固定错误码。
- `tools.py`：工具 schema、handler、可用性检查。
- `approval.py` 或 hook 模块：只对 `mysql_credential_action` 返回 `{"action":"approve"}`；审批文案只包含 target/action/credential identity/database，不含密码、路径和 DSN。
- 注册入口：注册工具和 `pre_tool_call` hook，并保持 M1 三个拦截点不变。

## 5. 动作定义

### check_connection

固定查询：

```sql
SELECT 1 AS ok, CURRENT_USER() AS account, DATABASE() AS database_name, VERSION() AS server_version
```

只返回认证状态、目标、动作、账号、数据库和版本。返回进入现有 `transform_tool_result` 再次脱敏。

### show_effective_grants

固定查询：

```sql
SHOW GRANTS FOR CURRENT_USER()
```

返回前必须清除认证插件、认证字符串、已登记秘密和高风险未知字符串；残余秘密检测失败时阻断。

## 6. 安全要求

1. 凭证目录必须是普通目录且 `0700`，不得是符号链接。
2. 文件必须是普通文件、不得是符号链接、权限必须恰好 `0600`。
3. 打开时防 TOCTOU：优先 `os.open(..., O_NOFOLLOW)`，打开后 `fstat` 再检查类型/owner/mode；平台缺少 `O_NOFOLLOW` 时必须有明确安全替代和测试。
4. 文件 owner 必须为当前有效用户。
5. JSON 版本、字段、类型和引用严格校验；未知字段按 fail-closed 策略处理。
6. 仅在审批通过后读取真实密码并建立连接；拒绝路径不得加载 secret 或连接数据库。
7. 密码不进入命令行、进程环境、审批展示、模型工具参数、stdout/stderr、异常、工具结果和 Provider 请求。
8. MySQL SDK 通过插件自己的依赖声明安装；不能假设 Hermes 核心环境已有 PyMySQL，也不能修改 Hermes `pyproject.toml`。
9. 后端失败不得回退环境变量、其他文件或其他后端。
10. handler、审批 hook、结果脱敏边界均完整捕获异常并返回固定安全响应，禁止原始异常外泄。
11. 生产代码不得包含测试后门、诱饵值、环境变量故障注入开关。

## 7. TDD 与测试矩阵

严格逐条 RED → GREEN → REFACTOR，保留能证明 RED 的测试执行记录到 `docs/M2-验收报告.md`。

至少覆盖：

- 文件后端 happy path；目录/文件权限错误；symlink；wrong owner（能安全模拟则测）；格式/版本/类型/引用错误；解析失败无部分状态。
- 工具 schema 只允许两个 action；未知 target/action 阻断；类型不匹配阻断。
- 审批 hook 只命中本工具；审批文案无秘密；拒绝/超时/异常均阻断且 DB connect spy=0；批准后才加载 secret/connect。
- `check_connection` 与 `show_effective_grants` 在真实 Docker MySQL 8.0 上通过。
- 测试账号只有 `USAGE` + 测试库必要只读权限；写入尝试由 MySQL GRANT 真实拒绝。
- 密码错误、数据库不可达、SDK 异常返回固定错误码，原始异常不回模型。
- 工具结果、审批展示、进程参数、Provider 原始 HTTP 请求中的诱饵计数均为 0。
- 插件从中立 cwd 经真实 PluginManager 加载，工具和审批 hook identity 正确。
- 保留 M1 全套回归测试。

## 8. 真实 E2E 硬验收

新增独立脚本，以临时 HOME/HERMES_HOME/TMPDIR 和白名单环境启动；不得 `os.environ.copy()`。测试 fixture 只能在 `tests/`。

假 Provider 必须驱动真实两轮 tool-call 对话，而不是测试代码直接调用 handler：

1. 第一轮返回 `mysql_credential_action` tool call；
2. Hermes 宿主真实走审批与工具执行；
3. 第二轮收到脱敏 tool result 并返回最终文本。

正常链路要求：

```text
provider_request_count >= 2
plain_password_count = 0
credential_path_count = 0
approval_plain_password_count = 0
process_argv_plain_password_count = 0
tool_result_plain_password_count = 0
check_connection_success = true
show_effective_grants_success = true
write_denied_by_mysql = true
isolation.all_temp = true
```

审批拒绝链路要求：

```text
mysql_connect_count = 0
credential_secret_load_count = 0
provider 后续只看到固定 BLOCKED 结果
CLI 退出行为与 Hermes 宿主契约一致
```

测试进程只允许：

- loopback 假 Provider；
- loopback Docker MySQL；
- AF_UNIX；

继续沿用并扩展 Python socket 守卫及 spy，禁止任何非 loopback 网络连接。Docker 端口必须验证只绑定 `127.0.0.1`。

## 9. 文档与里程碑调整

- 更新 `CLAUDE.md`：本地 JSON（不是旧 YAML）以及本机可信边界。
- 更新 `HANDOVER.md`：M1 已关闭，AC8/AC9 为已接受残余风险、不阻塞 M2。
- 更新 `docs/plan.md`：将原 M2 文件后端和原 M5 最小执行闭环合并为本 M2；M3 保留外部 MySQL 凭证后端；后续里程碑顺延或重写，禁止留下互相冲突状态。
- 新建 `docs/M2-本地文件凭证与MySQL只读执行闭环.md` 和 `docs/M2-验收报告.md`。

## 10. 禁止事项

- 禁止修改 `/Users/yelei/.hermes/hermes-agent` 任何文件。
- 禁止安装到 `/Users/yelei/.hermes/profiles/worker`。
- 禁止读取真实 `.env`、SSH、AWS、Kubernetes、Provider 或数据库凭证。
- 禁止连接现有 `aiwb-mysql-local`、`material-mysql`、`ai-news-mysql-local` 或任何远程/生产数据库。
- 禁止把真实密码拼进 shell 命令、Docker 命令或测试日志。
- 禁止初始化 Git、提交或推送。
- 禁止进入外部 MySQL 凭证后端、SSH、HTTP、Jenkins、任意 SQL、表数据预览。

## 11. 完成标准

- 独立 Docker MySQL 8.0 已由测试 harness 创建、验证并清理；无遗留容器/卷。
- 全套 pytest、compileall、独立 M2 E2E 均 exit 0。
- M1 回归保持通过，AC8/AC9 仍作为非阻塞 strict-xfail 保留。
- Hermes 源码 git clean；worker 未变化只能按证据诚实分类。
- 编码 Agent 明确列出每个 RED 测试、修改文件、真实命令和输出，不得只报“全绿”。
