# Hermes Credential Guard

本目录提供 Hermes 独立插件 `credential-guard`：在模型外发前脱敏已登记凭证，并提供经人工审批的本机固定动作（MySQL 只读 / SSH Config 公钥认证）。

## 当前实现范围

- M0：插件骨架、middleware/hook/CLI 注册。
- M1：诱饵凭证注册表、请求/工具结果脱敏、真实 Hermes CLI → 本地假 provider E2E。
- M2：本地 JSON 凭证 + MySQL 只读执行闭环（`mysql_credential_action`）。
- M3：SSH Config 公钥认证闭环（`ssh_credential_action`）+ 敏感路径/私钥内容保护。
- 不含外部 MySQL 凭证后端；不支持 SSH 密码、自由 Shell、端口转发或文件传输。

## Python 版本说明

- 规格：Python 3.11+
- 项目本地 `.venv`：当前可能是 Python 3.9（仅用于跑项目单测）
- 真实 Hermes E2E：必须使用本机 `hermes` 命令自带的 Python 3.11 运行时

## 目录结构

- `plugin.yaml`：插件清单（当前版本 0.4.2）
- `__init__.py`：Hermes 目录插件入口（加载为 `hermes_plugins.credential_guard`）
- `credential_guard/`：生产代码（包内相对导入；**不含** test fixture）
- `tests/`：单元、PluginManager 加载、真实 Hermes CLI E2E
- `tests/companions/credential_guard_test/`：仅测试用 companion（诱饵加载 + 故障注入）
- `tests/support/`：loopback 启动器、MySQL/SSH harness（不进入发布物）
- `scripts/run_canary_e2e.py` / `scripts/run_final_zip_encoding_canary.py`：可独立复跑的 E2E（历史 `run_m2_e2e.py` / `run_m3_e2e.py` 已随旧架构删除）

## 双文件与审批口径

- `credentials.json`：本地秘密库。可信外发守卫在审批前可读，仅用于建立本次外发内存脱敏快照；**执行器**只在 Hermes 标准人工审批通过后，按 target 的 `credential_ref` 解析本次凭据并连接目标系统。
- `targets.json`：本地目标目录（业务名 → MySQL/SSH 执行信息）。Credential Guard 内部可读；外部模型不得通过普通文件/搜索/终端工具整份读取。
- 模型工具参数只有 `target + action`；审批拒绝/超时时 execution secret load / MySQL connect / SSH subprocess = 0。

## 稳定引用格式

```text
<SECRET:cg_<sha256(key\0field)[:16]>>
```

token 与用户输入的 key/field/secret 解耦，保证任意合法输入下 token 都不含秘密原值。本地可通过 registry 的 `token_id` 反查元数据。

## 本地验证

```bash
# 项目单测（可用本地 .venv）
.venv/bin/python -m pytest tests -q
.venv/bin/python -m compileall credential_guard scripts tests

# 真实 Hermes CLI E2E（调用本机 hermes / Python 3.11）
.venv/bin/python scripts/run_canary_e2e.py
.venv/bin/python scripts/build_release_artifacts.py
.venv/bin/python scripts/run_final_zip_encoding_canary.py
```

说明：

- `tests/test_middleware_http_integration.py` 是 middleware + 本地 HTTP 集成单测，**不是**完整 Hermes E2E。
- `tests/test_ac8_ac9_architecture_gate.py` 是 AC8、AC9 **各自独立**的架构门禁（预期 xfail）：本机 log / state·WAL·sessions 明文落盘无统一 fail-closed pre-persist seam。
- 敏感路径保护覆盖标准 `read_file` / `search_files` 与可明确识别的直接 terminal 读取；**不**宣称对任意自定义程序绕过实现 OS 级沙箱。

## 安装关系（隔离环境）

推荐把本仓库作为开发目录，在临时 `HERMES_HOME` 下复制或软链到：

`<TEMP_HERMES_HOME>/plugins/credential-guard`

并在临时 `config.yaml` 中：

```yaml
plugins:
  enabled:
    - credential-guard
approvals:
  mode: manual
```

**不要**在开发和隔离验收阶段改动 worker Profile 中已安装的插件。

## 安全边界

- 真实凭证只存在于本地 JSON 或外部 MySQL；发往外部模型的请求不得出现真实值。
- SSH 认证材料由本机 OpenSSH 读取 `~/.ssh`；Credential Guard 只保存业务目标 → SSH Config 别名映射。
- 不提供显示、导出或打印真实秘密的命令。
- 开发和测试只使用人工生成的诱饵凭证与临时 HOME/sshd，禁止读取真实业务凭证或真实 `~/.ssh`。
