# M3 SSH Config 公钥认证与敏感路径保护

## 1. 目标

在保持 M1 外发保护和 M2 MySQL 闭环兼容的前提下，新增 SSH Config 公钥认证闭环：

```text
外部模型只提交业务目标代号 + 固定动作
→ Credential Guard 本机解析业务目标到 SSH Config 别名
→ Hermes 标准人工审批
→ 系统 OpenSSH 在本机自行读取 ~/.ssh/config、known_hosts 和私钥
→ 执行固定无副作用动作
→ 结果归一化、脱敏后返回模型
```

同时阻断标准文件工具直接读取受保护 SSH 文件，避免完整 SSH Config 或私钥进入模型上下文。

## 2. 已确认边界

- 本机 Hermes、Hermes 标准审批机制、OpenSSH 和本地 SSH 文件为可信区。
- 外部模型、模型供应商、模型生成的参数和 Provider 返回内容不可信。
- 不修改 Hermes 核心。
- 不把 SSH Config、known_hosts 或私钥正文复制到 Credential Guard。
- 不在凭证库重复保存 HostName、User、Port、IdentityFile。
- 第一版仅支持 SSH Config 别名 + 公钥认证。
- 第一版不支持 SSH 用户名密码登录、私钥口令交互、任意 Shell 命令、端口转发、Agent 转发和文件传输。
- 开发与验收不得读取用户真实 `~/.ssh`，不得连接真实服务器。
- worker 中当前 0.2.0 插件在开发和隔离验收阶段不得改动；0.3.0 发布通过后另行确认升级。
- 普通插件无法将任意 terminal/execute_code 变成操作系统级沙箱。本里程碑保护标准文件/搜索工具、明显直接读取，以及 Provider 外发前可识别的私钥/已登记秘密；不宣称对任意自定义程序绕过实现绝对隔离。

## 3. 用户可见效果

用户说：

```text
检查生产运维机能否登录
```

模型只提交：

```json
{
  "target": "production-ops-server",
  "action": "check_connection"
}
```

本地 `targets.json`：

```json
{
  "version": 1,
  "targets": {
    "production-ops-server": {
      "type": "ssh_config",
      "ssh_alias": "ai-114"
    }
  }
}
```

审批通过后，插件调用系统 OpenSSH。模型只收到成功/失败与业务目标代号，不收到 SSH 别名、真实 IP、端口、用户名、私钥路径、私钥正文或完整命令。

## 4. 工具与固定动作

新增工具：

```text
ssh_credential_action(target, action)
```

只允许：

- `check_connection`：固定远端命令 `true`，返回认证是否成功。
- `show_remote_identity`：固定远端命令 `id -un`，只返回经过严格校验的远端用户名。

工具 schema 不提供 `command`、`host`、`port`、`username`、`password`、`private_key`、`private_key_path` 或 `ssh_options`。

## 5. OpenSSH 执行约束

使用 `subprocess.run` 参数数组，禁止 `shell=True`。调用时强制：

```text
BatchMode=yes
PreferredAuthentications=publickey
PasswordAuthentication=no
KbdInteractiveAuthentication=no
StrictHostKeyChecking=yes
ClearAllForwardings=yes
ForwardAgent=no
PermitLocalCommand=no
RequestTTY=no
ConnectTimeout=<固定短超时>
LogLevel=ERROR
```

- 目标参数只使用经严格字符校验并存在于 `targets.json` 的 `ssh_alias`。
- 不接受模型提供的额外 SSH 参数。
- stdout/stderr 不原样返回；stderr 只用于本机错误分类，随后丢弃。
- 未知主机、指纹变化、认证失败、不可达、超时统一映射为固定错误码。

## 6. 敏感路径保护

### 6.1 读取前门禁

`pre_tool_call` 对标准文件/搜索工具检查：

- `read_file`
- `search_files`

保护范围至少包括：

```text
~/.ssh/config
~/.ssh/known_hosts*
~/.ssh/id_*
~/.ssh/ssh_key/**
$HERMES_HOME/credential-guard/credentials.json
```

处理 `~`、绝对/相对路径、`..`、已存在路径的 `realpath`、受保护目录的父目录搜索和符号链接指向。命中后返回 `block`，工具不执行。

对 `terminal` / `execute_code` 仅拦截可明确识别的直接读取受保护路径，不宣称覆盖任意编码、动态拼接、ctypes 或子进程绕过；这些属于操作系统隔离/Broker 的后续范围。

### 6.2 工具结果保护

`transform_tool_result` 根据 `tool_name + args + result`：

- 受保护路径的结果一律替换为固定阻断 JSON；
- 检测 OpenSSH/RSA/EC/PKCS8 私钥 PEM 标记；
- 延续已登记秘密精确替换；
- 内部异常返回固定阻断结果，不记录原始异常。

### 6.3 Provider 外发前保护

`llm_request` 和 `llm_execution` 在原有已登记秘密保护之外，检测私钥 PEM 标记及其可合理处理的常见文本变体。残留高风险私钥时阻断 Provider 执行，不把原文发送出去。

不把完整 SSH Config 内容加载为常驻指纹；插件不应为了“防外发”主动读取用户真实 SSH Config。

## 7. 后端结构

MySQL 目标保持原样：

```json
{
  "type": "mysql",
  "host": "127.0.0.1",
  "port": 3309,
  "database": "credential_guard_test",
  "credential_ref": "mysql_canary_credential"
}
```

SSH Config 目标：

```json
{
  "type": "ssh_config",
  "ssh_alias": "test-ssh-alias"
}
```

两种类型分别使用严格字段集合，不允许把所有字段变成可选字段。SSH Config 目标不需要 `credentials.json` 中的凭证条目，因为真实认证材料由 OpenSSH 本机管理。

## 8. 审批

`pre_tool_call` 同时支持 MySQL 与 SSH 工具。SSH 审批文案只显示：

```text
业务目标代号
动作
目标类型=SSH
认证来源=本机 SSH Config
```

不显示 SSH 别名、真实主机、端口、用户、私钥路径或完整命令。每次调用铸造新的高熵 `rule_key`，继续复用 Hermes 标准人工审批。拒绝/超时/无人工通道时 handler 不执行，SSH 子进程启动次数为 0。

## 9. 实现模块

新增：

- `credential_guard/sensitive_paths.py`
- `credential_guard/ssh_executor.py`
- `credential_guard/ssh_tools.py`

修改：

- `credential_guard/file_backend.py`
- `credential_guard/approval.py`
- `credential_guard/hooks.py`
- `credential_guard/middleware.py`
- `credential_guard/__init__.py`
- `credential_guard/cli.py`
- `plugin.yaml`
- `pyproject.toml`
- 发布构建、测试、README、CLAUDE、HANDOVER、plan 与验收报告

发布版本：`0.3.0`。

## 10. 严格 TDD 顺序

1. SSH 目标 schema RED→GREEN：类型字段集、别名校验、MySQL 兼容。
2. 敏感路径 RED→GREEN：绝对/相对/`~`/父目录搜索/symlink，普通非敏感文件不误阻断。
3. 私钥内容保护 RED→GREEN：tool result 与 Provider 请求；安全普通文本不误阻断。
4. SSH 工具 schema RED→GREEN：只允许两个固定动作，无自由命令字段。
5. OpenSSH argv RED→GREEN：参数数组、强制选项、无 `shell=True`、无秘密参数。
6. 错误归类 RED→GREEN：固定错误码、原始 stderr/路径不外泄。
7. 审批 RED→GREEN：批准前不启动 SSH；拒绝/超时启动数为 0；文案无敏感元数据。
8. 真实隔离 SSH E2E RED→GREEN。
9. M1/M2 全量回归。
10. 可复现发布物与真实 PluginManager 加载门禁。

每个行为必须先运行失败测试，确认因功能缺失而 RED，再写最小实现转 GREEN。

## 11. 隔离真实 E2E

使用临时 `HOME`、`HERMES_HOME` 和白名单环境；不得继承真实 SSH 配置或 Provider Key。

优先使用本机 `/usr/sbin/sshd` 在 `127.0.0.1` 随机端口启动一次性 SSH 服务，运行时生成：

```text
一次性用户/或安全受限测试身份
一次性客户端密钥
一次性服务端 host key
诱饵 ~/.ssh/config
诱饵 known_hosts
假 OpenAI-compatible Provider
```

若 macOS 本机 sshd 无法在不改变系统配置的情况下安全启动，则使用已审计、固定版本、只绑定 `127.0.0.1` 的临时容器方案；不得连接现有容器或真实服务器。

E2E 必须由真实 Hermes CLI 的两轮 tool-call 驱动，不得由测试代码直接调用 handler 冒充完整链路。

## 12. 验收门禁

### 正例

- `check_connection` 经真实审批后完成真实公钥认证。
- `show_remote_identity` 经真实审批后返回预期测试身份。
- MySQL M2 正例不回归。

### 反例

- `read_file` 读取诱饵 SSH Config：执行前阻断，Provider 中配置内容计数 0。
- `read_file` 读取诱饵私钥：执行前阻断，Provider 中私钥内容计数 0。
- `search_files` 搜索受保护目录：阻断。
- 路径遍历和 symlink 指向受保护文件：阻断。
- 审批拒绝/超时：SSH 子进程启动数 0。
- 未知主机或指纹变化：固定 `host_identity_untrusted`。
- 错误私钥：固定 `ssh_authentication_failed`，原始 stderr、别名、路径计数 0。
- 额外 `command` 或 SSH 参数：schema/handler 阻断。
- 私钥内容混入普通工具结果或 Provider 请求：Provider HTTP 调用数 0 或只发送固定安全 fallback（以现有 M1 宿主契约为准），原值计数 0。
- 普通非敏感文件仍能读取，避免门禁扩大为所有文件禁用。

### 发布物

- 全套 pytest、compileall、M1 canary、M2 E2E、M3 E2E 均 exit 0。
- 最终插件 ZIP 经真实 PluginManager 加载，两个工具和全部拦截点身份正确。
- 生产发布物不含测试私钥、诱饵、sshd 配置、fixture、故障注入或 E2E helper。
- 两个独立干净目录构建出的 wheel、sdist、plugin ZIP 字节一致。
- worker 的 config/plugins/state/凭证目录在开发和隔离验收前后无非预期变化。

## 13. 禁止事项

- 禁止读取 `/Users/yelei/.ssh` 中任何真实文件。
- 禁止连接 `ai-113`、`ai-114`、`ai-115` 或其他真实 SSH 目标。
- 禁止修改 `/Users/yelei/.hermes/hermes-agent`。
- 禁止修改或升级 worker 插件。
- 禁止 SSH 密码认证、`sshpass`、任意 Shell、SCP/SFTP、端口转发、Agent 转发。
- 禁止在命令行、环境变量、审批、stdout/stderr、日志或 Provider 请求中放置私钥正文或秘密。
- 禁止初始化 Git、commit、push 或部署。
- 禁止为了测试下载未审计远程脚本或连接非 loopback 网络。

## 14. 完成定义

M3 只有在以下条件全部成立时才完成：

1. SSH Config 别名目标、固定动作和敏感路径保护均已实现；
2. 所有新增行为都有真实 RED→GREEN 记录；
3. 真实 Hermes + 假 Provider + loopback SSH E2E 正反例通过；
4. Provider、审批、工具结果、进程参数和发布物中的诱饵私钥/Config 内容计数为 0；
5. M1/M2 全量回归通过；
6. 可复现 0.3.0 发布物生成并通过真实加载；
7. worker 未被改动；
8. 独立安全复审判定 PASS。
