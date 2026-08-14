# Hermes Credential Guard

Credential Guard 是一个独立的 Hermes 插件，用于保护本机凭证，并在用户人工批准后让 Hermes 使用凭证执行受限操作，而不把真实凭证交给模型。

当前版本：`0.4.4`（制品候选已落地；可核验安装正式插件 ZIP。尚未 GitHub Release / 未由 Agent 安装正式 worker。）

```text
credentials = 要保护的秘密
bindings    = 允许申请执行的固定能力
```

只配置 `credentials`、不配置 `bindings` 时，插件仍会保护已登记凭证，但 Hermes 不能使用这些凭证调用接口或运行程序。

## 主要能力

- 在 Hermes 主聊天模型请求发出前，替换已登记的 Token、密码和受支持的可逆编码形式；
- 在主链工具结果返回模型前再次检查和脱敏；
- 在本地阻断 PEM 私钥及其受支持的常见编码形式；
- 保护当前 Profile 的 Credential Guard Store 和内置 SSH 敏感路径；
- 经人工审批后，向固定 HTTP 或 HTTPS 目标注入：
  - Bearer Token；
  - Basic Auth；
  - API Key Header；
- 经人工审批后，向固定本地程序注入：
  - 单个环境变量（`process_env`）；
  - 标准输入（`stdin`）；
- 将 binding、credential、目标、方法、路径、配置和程序身份绑定到本次批准，防止参数偷换和批准重放；
- 请求、响应和程序输出受 timeout、deadline、大小上限及 fail-closed 保护。

插件提供两个 Hermes 工具：

| 工具 | 用途 |
|---|---|
| `http_credential_request` | 调用配置允许的固定 HTTP/HTTPS API |
| `credential_process_run` | 运行配置允许的固定本地程序 |

## 安全模型

```text
用户在本机登记真实凭证
        │
        ├─ 主聊天外发前：匹配并替换已登记秘密
        │
        └─ Hermes 申请使用某条 binding
                  │
                  ▼
              人工审批
                  │
                  ▼
        本机执行阶段临时注入真实凭证
                  │
                  ▼
        结果再次脱敏后返回主聊天模型
```

- 模型只使用逻辑引用，例如 `<CREDENTIAL:service-token>`；
- 真实凭证只在本机执行阶段短暂使用；
- 每条 binding 都是固定目标、固定方法和路径，或固定程序和参数的受控能力；
- 每次执行都必须人工批准，一次批准只能消费一次；
- 拒绝审批、配置异常、参数不匹配或脱敏失败时 fail-closed。

## 适用环境

- 已安装支持原生插件的 Hermes Agent；
- macOS 或 Linux；
- Python 3.9 及以上；
- 当前 `0.4.4` 无第三方 Python 运行依赖。

> Credential Guard 是纯 Python 目录插件。正式插件 ZIP 解压后即可加载，用户不需要运行 `pip install`、`npm build`、`make` 或其他构建命令。

# 安装

下面所有命令都以 `default` Profile 为例。安装到其他 Profile 时，只需修改 `PROFILE`。

## 方式一：在线安装

在线安装会通过 Git 克隆 GitHub 默认分支。它不会自动下载 GitHub Release 中的 ZIP，也不会自动选择最新 Tag。

```bash
set -euo pipefail

PROFILE="default"
hermes -p "$PROFILE" plugins install stones-hub/hermes-credential-guard --enable
hermes -p "$PROFILE" tools enable credential_guard --platform cli
hermes -p "$PROFILE" config set approvals.mode manual
hermes -p "$PROFILE" config set security.redact_secrets true
printf '%s\n' "ONLINE_INSTALL_OK"
```

如果只想安装、暂不启用：

```bash
hermes -p "$PROFILE" plugins install stones-hub/hermes-credential-guard --no-enable
```

从 Git 安装后，后续更新使用：

```bash
hermes -p "$PROFILE" plugins update credential-guard
```

> `plugins update` 拉取已安装 Git 分支的最新提交。为避免用户安装到开发中间态，本仓库的 `main` 分支应始终保持可安装、可运行。

## 方式二：本地 ZIP 安装

本地安装必须使用正式制品。当前可核验 ZIP：

```text
credential-guard-0.4.4-hermes-plugin.zip
```

正式下载（GitHub Release 发布后；当前制品亦可从本仓库 `dist/` 取得）：

```text
https://github.com/stones-hub/hermes-credential-guard/releases/download/v0.4.4/credential-guard-0.4.4-hermes-plugin.zip
```

不要把 GitHub 自动生成的 `Source code.zip` 当作正式插件 ZIP。

### 1. 设置路径并核对 SHA-256

```bash
set -euo pipefail

PROFILE="default"
PLUGIN_ZIP="/path/to/credential-guard-0.4.4-hermes-plugin.zip"
EXPECTED_SHA256="d6ee2bf6a92a4ca55ee37f24802cf26316ab38adcbe27b9d59a4ee9e944ae265"
CONFIG_PATH="$(hermes -p "$PROFILE" config path)"
PROFILE_ROOT="$(dirname "$CONFIG_PATH")"
PLUGIN_DIR="$PROFILE_ROOT/plugins/credential-guard"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/credential-guard-0.4.4.XXXXXX")"
ACTUAL_SHA256="$(shasum -a 256 "$PLUGIN_ZIP" | cut -d ' ' -f 1)"

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  printf '%s\n' "错误：插件 ZIP 的 SHA-256 不匹配。"
  printf '%s\n' "期望：$EXPECTED_SHA256"
  printf '%s\n' "实际：$ACTUAL_SHA256"
  exit 1
fi

printf '%s\n' "ZIP_SHA256_OK"
```

上述代码块会自动比较摘要。摘要不一致时返回非零状态并立即停止，不得继续解压或安装。

### 2. 解压并检查结构

```bash
set -euo pipefail

unzip -q "$PLUGIN_ZIP" -d "$STAGE_DIR"
test -f "$STAGE_DIR/credential-guard/plugin.yaml"
test -f "$STAGE_DIR/credential-guard/__init__.py"
grep -qx 'version: 0.4.4' "$STAGE_DIR/credential-guard/plugin.yaml"
test ! -e "$STAGE_DIR/credential-guard/credential-guard"
printf '%s\n' "ZIP_STRUCTURE_OK"
```

预期版本：

```text
version: 0.4.4
```

ZIP 应只有一层插件根目录：

```text
credential-guard/
├── plugin.yaml
├── __init__.py
├── requirements.txt
└── credential_guard/
```

### 3. 安装或升级

全新安装：

```bash
set -euo pipefail

mkdir -p "$PROFILE_ROOT/plugins"
test ! -e "$PLUGIN_DIR"
cp -R "$STAGE_DIR/credential-guard" "$PLUGIN_DIR"
test -f "$PLUGIN_DIR/plugin.yaml"
grep -qx 'version: 0.4.4' "$PLUGIN_DIR/plugin.yaml"
test ! -e "$PLUGIN_DIR/credential-guard"
printf '%s\n' "PLUGIN_INSTALL_OK"
```

如果已经安装旧版本，不要把新文件覆盖到旧目录中。先停止 Gateway，并把旧插件目录整体备份移走：

```bash
set -euo pipefail

hermes -p "$PROFILE" gateway stop
BACKUP_DIR="$PROFILE_ROOT/plugins/credential-guard.backup-$(date +%Y%m%d-%H%M%S)"
test -d "$PLUGIN_DIR"
test ! -e "$BACKUP_DIR"
mv "$PLUGIN_DIR" "$BACKUP_DIR"
test -d "$BACKUP_DIR"
test ! -e "$PLUGIN_DIR"
cp -R "$STAGE_DIR/credential-guard" "$PLUGIN_DIR"
test -f "$PLUGIN_DIR/plugin.yaml"
grep -qx 'version: 0.4.4' "$PLUGIN_DIR/plugin.yaml"
test ! -e "$PLUGIN_DIR/credential-guard"
printf '%s\n' "PLUGIN_UPGRADE_OK"
```

> 插件代码目录与凭证 Store 相互独立。升级插件时不要删除或移动 `$PROFILE_ROOT/credential-guard/`，其中可能保存真实凭证。

### 4. 启用插件和工具集

```bash
set -euo pipefail

hermes -p "$PROFILE" plugins enable credential-guard --no-allow-tool-override
hermes -p "$PROFILE" tools enable credential_guard --platform cli
hermes -p "$PROFILE" config set approvals.mode manual
hermes -p "$PROFILE" config set security.redact_secrets true
printf '%s\n' "PLUGIN_ENABLE_OK"
```

安装后删除临时解压目录：

```bash
rm -rf "$STAGE_DIR"
```

# 配置

## 配置文件位置

Credential Guard 使用单一配置文件：

```text
<Profile 根目录>/credential-guard/credential-guard.json
```

创建 Store 并设置权限：

```bash
STORE_DIR="$PROFILE_ROOT/credential-guard"
GUARD_CONFIG="$STORE_DIR/credential-guard.json"
mkdir -p "$STORE_DIR"
chmod 700 "$STORE_DIR"
```

使用本地编辑器创建 `credential-guard.json`，保存后执行：

```bash
chmod 600 "$GUARD_CONFIG"
```

Store 必须是当前用户拥有的普通目录，权限严格为 `0700`；配置必须是当前用户拥有的普通文件，权限严格为 `0600`。目录和文件都不能是 symlink。

不要让 Agent 读取或填写正式配置，不要把真实 Token、密码或配置文件提交 Git。

## 最小配置：只保护，不授权使用

```json
{
  "version": 2,
  "credentials": {
    "service-token": {
      "type": "token",
      "value": "SYNTHETIC_TOKEN_REPLACE_LOCALLY_NOT_REAL"
    }
  },
  "bindings": {}
}
```

将合成值在本地编辑器中替换为真实 Token 后，这条凭证会进入主聊天和主链工具结果保护，但 Hermes 没有使用它执行请求或程序的权限。

Credential 类型严格只有：

```text
token
username_password
```

Binding 类型严格只有：

```text
http
process_env
stdin
```

兼容关系：

| credential 类型 | Bearer | Basic | API Key Header | `process_env` | `stdin` |
|---|:---:|:---:|:---:|:---:|:---:|
| `token` | 支持 | 不支持 | 支持 | 支持 | 支持 |
| `username_password` | 不支持 | 支持 | 不支持 | 不支持 | 不支持 |

## 最全面的完整配置示例

下面这份配置是可删减的全集示例，覆盖：

- 只保护、不授权使用的 `token` 和 `username_password`；
- HTTPS Bearer；
- 明文 HTTP Bearer；
- HTTPS Basic Auth；
- HTTPS API Key Header；
- `process_env`；
- `stdin` 的 `raw` 和 `line` 两种格式；
- HTTP 与程序 binding 的全部可配置资源限制字段。

> 这是一份字段字典，不是建议全部启用。正式使用时应删除不需要的 credential 和 binding，只保留真实业务必需的最小集合。
>
> 所有 `.test` 域名和 `SYNTHETIC_*_NOT_REAL` 都是不可用示例。真实秘密只能由你在本地编辑器中替换。程序路径也必须换成当前用户拥有、本人审核、权限合规的固定可执行文件。
>
> JSON 不支持注释，复制时请保持下面代码块为纯 JSON。每个合成秘密都故意使用不同值，因为不同 credential 不能登记相同的 Token 或密码。

```json
{
  "version": 2,
  "credentials": {
    "protected-only-token": {
      "type": "token",
      "value": "SYNTHETIC_PROTECTED_ONLY_TOKEN_NOT_REAL"
    },
    "protected-only-account": {
      "type": "username_password",
      "username": "protected-demo-user",
      "password": "SYNTHETIC_PROTECTED_ONLY_PASSWORD_NOT_REAL"
    },
    "https-bearer-token": {
      "type": "token",
      "value": "SYNTHETIC_HTTPS_BEARER_TOKEN_NOT_REAL"
    },
    "http-bearer-token": {
      "type": "token",
      "value": "SYNTHETIC_HTTP_BEARER_TOKEN_NOT_REAL"
    },
    "https-basic-account": {
      "type": "username_password",
      "username": "report-reader",
      "password": "SYNTHETIC_HTTPS_BASIC_PASSWORD_NOT_REAL"
    },
    "https-api-key": {
      "type": "token",
      "value": "SYNTHETIC_HTTPS_API_KEY_NOT_REAL"
    },
    "process-env-token": {
      "type": "token",
      "value": "SYNTHETIC_PROCESS_ENV_TOKEN_NOT_REAL"
    },
    "stdin-raw-token": {
      "type": "token",
      "value": "SYNTHETIC_STDIN_RAW_TOKEN_NOT_REAL"
    },
    "stdin-line-token": {
      "type": "token",
      "value": "SYNTHETIC_STDIN_LINE_TOKEN_NOT_REAL"
    }
  },
  "bindings": {
    "external-status-query": {
      "type": "http",
      "credential_ref": "https-bearer-token",
      "target": {
        "scheme": "https",
        "host": "api.example.test",
        "port": 443
      },
      "request": {
        "allowed_methods": [
          "GET",
          "HEAD"
        ],
        "allowed_paths": [
          "/v1/status",
          "/v1/health"
        ],
        "connect_timeout_seconds": 5,
        "total_timeout_seconds": 30,
        "max_response_body_bytes": 65536
      },
      "inject": {
        "type": "bearer",
        "location": "authorization_header"
      },
      "approval": "required"
    },
    "internal-health-query": {
      "type": "http",
      "credential_ref": "http-bearer-token",
      "target": {
        "scheme": "http",
        "host": "test-api.internal.example.test",
        "port": 8080
      },
      "request": {
        "allowed_methods": [
          "GET"
        ],
        "allowed_paths": [
          "/health"
        ],
        "connect_timeout_seconds": 5,
        "total_timeout_seconds": 30,
        "max_response_body_bytes": 65536
      },
      "inject": {
        "type": "bearer",
        "location": "authorization_header"
      },
      "approval": "required"
    },
    "report-health-query": {
      "type": "http",
      "credential_ref": "https-basic-account",
      "target": {
        "scheme": "https",
        "host": "reports.example.test",
        "port": 443
      },
      "request": {
        "allowed_methods": [
          "GET"
        ],
        "allowed_paths": [
          "/health"
        ],
        "connect_timeout_seconds": 5,
        "total_timeout_seconds": 30,
        "max_response_body_bytes": 65536
      },
      "inject": {
        "type": "basic",
        "location": "authorization_header"
      },
      "approval": "required"
    },
    "profile-query": {
      "type": "http",
      "credential_ref": "https-api-key",
      "target": {
        "scheme": "https",
        "host": "platform.example.test",
        "port": 443
      },
      "request": {
        "allowed_methods": [
          "GET"
        ],
        "allowed_paths": [
          "/api/profile"
        ],
        "connect_timeout_seconds": 5,
        "total_timeout_seconds": 30,
        "max_response_body_bytes": 65536
      },
      "inject": {
        "type": "api_key_header",
        "header_name": "X-API-Key"
      },
      "approval": "required"
    },
    "service-status-check": {
      "type": "process_env",
      "credential_ref": "process-env-token",
      "program": "/Users/example/.local/libexec/credential-guard/check-service",
      "argv": [
        "/Users/example/.local/libexec/credential-guard/check-service",
        "--status"
      ],
      "env_name": "SERVICE_TOKEN",
      "timeout_seconds": 30,
      "max_stdout_bytes": 65536,
      "max_stderr_bytes": 65536,
      "approval": "required"
    },
    "artifact-upload-raw": {
      "type": "stdin",
      "credential_ref": "stdin-raw-token",
      "program": "/Users/example/.local/libexec/credential-guard/fixed-upload-raw",
      "argv": [
        "/Users/example/.local/libexec/credential-guard/fixed-upload-raw"
      ],
      "stdin_format": "raw",
      "timeout_seconds": 30,
      "max_stdout_bytes": 65536,
      "max_stderr_bytes": 65536,
      "approval": "required"
    },
    "artifact-upload-line": {
      "type": "stdin",
      "credential_ref": "stdin-line-token",
      "program": "/Users/example/.local/libexec/credential-guard/fixed-upload-line",
      "argv": [
        "/Users/example/.local/libexec/credential-guard/fixed-upload-line"
      ],
      "stdin_format": "line",
      "timeout_seconds": 30,
      "max_stdout_bytes": 65536,
      "max_stderr_bytes": 65536,
      "approval": "required"
    }
  }
}
```

示例能力对应关系：

| credential / binding | 含义 |
|---|---|
| `protected-only-token`、`protected-only-account` | 只保护，没有 binding，Agent 不能使用 |
| `external-status-query` | HTTPS + Bearer，允许固定的 GET/HEAD 和两个精确路径 |
| `internal-health-query` | 明文 HTTP + Bearer，每次审批必须显示明文传输警告 |
| `report-health-query` | HTTPS + Basic Auth |
| `profile-query` | HTTPS + `X-API-Key` |
| `service-status-check` | 把 Token 临时注入固定程序的 `SERVICE_TOKEN` 环境变量 |
| `artifact-upload-raw` | 将 Token 原样写入固定程序 stdin |
| `artifact-upload-line` | 将 Token 加一个换行后写入固定程序 stdin |

裁剪规则：

1. 先删除不需要的 binding；
2. 再删除没有被任何 binding 使用、且也不需要单独保护的 credential；
3. 将 `.test` 目标替换为真实的小写 DNS 域名，不能填写 URL 或 IP；
4. 将程序路径和 `argv[0]` 同时替换为同一个真实绝对路径；
5. method 和 path 只开放实际需要的精确值，不使用“全开放”思路；
6. 在本地编辑器中最后替换合成秘密，绝不把真实配置交给 Agent 或提交 Git；
7. 保存后执行 `chmod 600 "$GUARD_CONFIG"`，再运行 `hermes -p "$PROFILE" credential-guard check`。

## HTTP/HTTPS Bearer 示例

```json
{
  "version": 2,
  "credentials": {
    "internal-test-token": {
      "type": "token",
      "value": "SYNTHETIC_INTERNAL_TEST_TOKEN_NOT_REAL"
    }
  },
  "bindings": {
    "internal-health-query": {
      "type": "http",
      "credential_ref": "internal-test-token",
      "target": {
        "scheme": "https",
        "host": "api.example.test",
        "port": 443
      },
      "request": {
        "allowed_methods": [
          "GET"
        ],
        "allowed_paths": [
          "/health"
        ],
        "connect_timeout_seconds": 5,
        "total_timeout_seconds": 30,
        "max_response_body_bytes": 65536
      },
      "inject": {
        "type": "bearer",
        "location": "authorization_header"
      },
      "approval": "required"
    }
  }
}
```

HTTP 和 HTTPS 都使用 binding 类型：

```json
"type": "http"
```

实际协议由 `target.scheme` 决定，只接受小写 `http` 或 `https`。

使用明文 HTTP 时，审批必须显示：

```text
警告：该目标使用明文 HTTP，凭证在网络传输过程中不会被加密。
```

HTTPS 使用系统信任链和主机名校验；HTTPS 失败后不会自动降级为 HTTP。HTTP/HTTPS 都禁止环境代理和自动重定向。

## `process_env` 示例

`process_env` 把一条 Token、一个固定环境变量名、一个固定程序及固定参数组成一项 binding：

```json
{
  "version": 2,
  "credentials": {
    "service-token": {
      "type": "token",
      "value": "SYNTHETIC_SERVICE_TOKEN_NOT_REAL"
    }
  },
  "bindings": {
    "service-status-check": {
      "type": "process_env",
      "credential_ref": "service-token",
      "program": "/Users/example/.local/libexec/credential-guard/check-service",
      "argv": [
        "/Users/example/.local/libexec/credential-guard/check-service",
        "--status"
      ],
      "env_name": "SERVICE_TOKEN",
      "timeout_seconds": 30,
      "max_stdout_bytes": 65536,
      "max_stderr_bytes": 65536,
      "approval": "required"
    }
  }
}
```

真实 Token 只对本次固定子程序生效，不会永久修改当前 Shell 或系统环境变量。

固定程序必须由当前用户拥有，是不可被 group/other 写入的普通可执行文件，不能是 symlink。Shell、解释器和任意命令入口会被拒绝。

## `stdin` 示例

```json
{
  "version": 2,
  "credentials": {
    "upload-token": {
      "type": "token",
      "value": "SYNTHETIC_UPLOAD_TOKEN_NOT_REAL"
    }
  },
  "bindings": {
    "artifact-fixed-upload": {
      "type": "stdin",
      "credential_ref": "upload-token",
      "program": "/Users/example/.local/libexec/credential-guard/fixed-upload",
      "argv": [
        "/Users/example/.local/libexec/credential-guard/fixed-upload"
      ],
      "stdin_format": "line",
      "timeout_seconds": 30,
      "max_stdout_bytes": 65536,
      "max_stderr_bytes": 65536,
      "approval": "required"
    }
  }
}
```

`stdin_format` 支持：

- `raw`：原样写入 Token，不追加字符；
- `line`：写入 Token 后追加一个换行字节。

# 使用方式

## 只保护凭证

只要真实值已登记在 `credentials` 中，即使 `bindings` 是空对象，主聊天中出现完整真实 Token 或密码时仍会被替换。

不要求固定输入格式。例如，真实密码单独出现、位于普通句子、JSON 或日志文本中，都按完整字符串和受支持的常见可逆变体匹配。

对 `username_password`：

```text
password          → 保护
username:password → 保护
username 单独出现 → 默认不保护
```

## 使用 HTTP binding

日常对话不要求固定口令，但最好明确 binding 名：

```text
请使用 internal-health-query 检查服务健康状态，并返回结果。
```

全新会话或存在歧义时，可以说得更明确：

```text
请使用 internal-health-query 请求 GET /health，凭证使用 internal-test-token，并返回结果。
```

Hermes 最终提交：

```text
target     = internal-health-query
method     = GET
path       = /health
credential = <CREDENTIAL:internal-test-token>
```

## 使用 `process_env` 或 `stdin` binding

```text
请使用 service-status-check 检查服务状态，并返回结果。
```

```text
请使用 artifact-fixed-upload 执行固定上传，并返回结果。
```

Hermes 最终只提交 binding 和逻辑凭证：

```text
target     = service-status-check
credential = <CREDENTIAL:service-token>
```

模型不能提交或修改真实 Token、程序路径、argv、环境变量、stdin 内容或工作目录。

## 审批时检查什么

执行任何 binding 前，确认：

- binding 名是不是你要使用的能力；
- 逻辑 credential 是否正确；
- HTTP method/path 是否符合本次意图；
- 注入方式是否正确；
- 明文 HTTP 是否显示固定风险警告；
- 本次是否只需要执行一次。

真实 Token、密码、完整 Authorization Header 和程序秘密输入不应出现在审批信息中。

# 检查和生效

检查插件、配置、拦截点、工具和保护注册表：

```bash
hermes -p "$PROFILE" credential-guard check
```

成功输出应包含：

```text
credential-guard: enabled
egress_registry=ready
tools: http_credential_request, credential_process_run
```

检查插件和工具集：

```bash
hermes -p "$PROFILE" plugins list --plain --no-bundled
hermes -p "$PROFILE" tools list
```

生效规则：

| 使用方式 | 操作 |
|---|---|
| CLI | 退出旧会话，启动新会话 |
| Gateway | 重启对应 Profile 的 Gateway |

```bash
hermes -p "$PROFILE" gateway restart
```

修改 `credential-guard.json` 后也应开启新 CLI 会话或重启 Gateway，不能用旧运行时证明新配置已生效。

# 更新与回滚

## Git 在线安装更新

```bash
set -euo pipefail

hermes -p "$PROFILE" plugins update credential-guard
hermes -p "$PROFILE" gateway restart
printf '%s\n' "PLUGIN_UPDATE_OK"
```

## ZIP 安装更新

ZIP 安装目录没有 `.git`，不能使用 `plugins update`。下载新版本正式 ZIP，核对 SHA-256，备份旧插件目录，再按“本地 ZIP 安装”替换整个插件目录。

配置 Store 位于：

```text
$PROFILE_ROOT/credential-guard/
```

它不在插件代码目录中。更新或回滚插件时，不要删除 Credential Guard Store。

回滚时：

1. 停止 Gateway；
2. 将当前插件目录移走；
3. 把备份插件目录恢复为 `$PROFILE_ROOT/plugins/credential-guard`；
4. 恢复与旧插件版本兼容的配置；
5. 启动 Gateway 并运行 `credential-guard check`。

# 当前边界

0.4.4 正式保护：

- Hermes 主聊天 conversation loop 的模型请求；
- 主链工具结果；
- 协议骨架字段（`model` / `role` / `name` / `tool_call_id`）命中已登记凭证变体时本机 fail-closed。

0.4.4 不保证覆盖：

- 自动标题；
- 上下文压缩；
- Vision；
- oneshot；
- `session_search`；
- 其他 auxiliary 模型调用。

当前不提供：

- 任意 SQL、任意 SSH、任意 Shell；
- HTTP query string、请求体、文件上传或动态业务 Header；
- Cookie 注入；
- OAuth 自动刷新、AWS SigV4、客户端证书或特殊签名；
- `username_password` 的 env/stdin 注入；
- 自定义保护目录；
- 主机全局 DLP 或操作系统级沙箱。

Credential Guard 不能把恶意本地程序变安全。`process_env` 和 `stdin` 绑定的程序必须由用户本人审核；程序自身写文件、联网或产生业务副作用，不会因为输出被脱敏而撤销。

# 开发与验证

项目单测：

```bash
.venv/bin/python -m pytest tests -q
```

编译检查：

```bash
.venv/bin/python -m compileall credential_guard scripts tests
```

构建正式制品：

```bash
CG_R6_BUILD_AUTHORIZED=1 .venv/bin/python scripts/build_release_artifacts.py
```

当前活动 `dist/` 含已落地的 0.4.4 四制品，并保留历史 0.4.2 / 已 Tag 的 0.4.3：

```text
dist/credential-guard-0.4.4-hermes-plugin.zip
dist/artifact-manifest-0.4.4.json
dist/hermes_credential_guard-0.4.4-py3-none-any.whl
dist/hermes_credential_guard-0.4.4.tar.gz
```

历史 0.4.3 锚点（零漂移保留）：

```text
dist/credential-guard-0.4.3-hermes-plugin.zip
dist/artifact-manifest-0.4.3.json
dist/hermes_credential_guard-0.4.3-py3-none-any.whl
dist/hermes_credential_guard-0.4.3.tar.gz
```

发布构建应在完整测试通过后进行。普通用户安装正式插件 ZIP 后不需要再次构建。

# License

本项目使用 [MIT License](LICENSE)。
