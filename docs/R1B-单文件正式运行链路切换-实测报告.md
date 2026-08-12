# R1B 单文件正式运行链路切换 — 实测报告

> 日期：2026-07-31；最终签收：2026-08-03  
> 范围：正式运行时配置源从双文件切换为 `credential-guard.json`；临时 `HOME` / `HERMES_HOME`；不实现 R2 逻辑引用审批绑定、R3 adapter 注入、R5 删旧；不升版/构建/安装。  
> 判定：**PASS（Hermes 独立执行验收签收）**。三轮 `execute_code` 路径门禁窄修及组合超限证据已收口；R2 尚未开始。

## 0. 威胁边界（沿用 R1A 已批准）

```text
可信：本机 Hermes、Credential Guard、标准人工审批、本机执行环境，以及同一可信用户下的本地文件系统操作
不可信：外部模型、Provider、模型生成参数、Provider 返回内容
```

## 1. 正式运行时 call graph（前后对比）

### 切换前

```text
plugin register
→ middleware on_llm_request / on_llm_execution
→ hooks on_transform_tool_result
→ state.get_egress_registry_snapshot
→ file_backend.build_redaction_registry_snapshot
→ _load_credentials_document(credentials.json)
```

敏感路径仅保护 `credentials.json` / `targets.json`。

### 切换后

```text
plugin register
→ middleware on_llm_request / on_llm_execution
→ hooks on_transform_tool_result
→ state.get_egress_registry_snapshot
→ runtime_config.ensure_published_from_disk
→ CredentialGuardConfig.load(credential-guard.json)
→ build_file_egress_registry + 原子 publish RuntimeView
→ merge(base memory registry, file egress registry)
```

静态证明（`tests/test_runtime_config_v2.py::test_a6`）：`hooks.py` / `middleware.py` / `state.py` 不再 import/call 旧双文件 loader（`build_redaction_registry_snapshot` / `_load_credentials_document` / `_load_targets_document`），也不含双文件名字符串常量。

`file_backend.build_redaction_registry_snapshot` 保留为迁移/旧工具后端专用，文档标明不得再作为正式外发入口。

旧 MySQL/SSH 工具与 `approval` 元数据在 R5 前仍可读双文件（业务语义未改）；正式外发守卫不再回退双文件。

## 2. 基线 / RED / GREEN 真实数字

### 基线（实现前）

```bash
.venv/bin/python -m pytest tests/test_file_backend.py tests/test_plugin_registration.py \
  tests/test_file_registry_bridge.py tests/test_fail_closed.py \
  tests/test_config_v2.py tests/test_config_migration.py tests/test_profile_write_boundary.py \
  -q -p no:cacheprovider
# 227 passed in 0.48s
```

### RED（`tests/test_runtime_config_v2.py` 落地、实现前）

```bash
.venv/bin/python -m pytest tests/test_runtime_config_v2.py -q -p no:cacheprovider --tb=line
# 29 failed, 3 passed in 0.07s
```

关键 RED 类别：

1. 缺少 `runtime_config` 模块 / API  
2. 正式源仍读双文件（仅 v2 / 仅旧双文件 / 新旧并存 / 非法 v2）  
3. 静态 call graph 仍指向 `file_backend`  
4. 原子 publish / reload / 并发代际  
5. 统一配置与 migrate 产物路径未保护  
6. 空 v2 缺失导致普通聊天 fail-closed

### GREEN（实现后专项）

```bash
.venv/bin/python -m pytest tests/test_runtime_config_v2.py -q -p no:cacheprovider
# 32 passed in 0.13s

.venv/bin/python -m pytest tests/test_config_v2.py tests/test_config_migration.py \
  tests/test_profile_write_boundary.py -q -p no:cacheprovider
# 175 passed in 0.40s

.venv/bin/python -m pytest tests/test_file_backend.py tests/test_plugin_registration.py \
  tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# 35 passed in 6.37s

python3 -m compileall -q credential_guard tests
# compileall_ok=true
```

### 全量

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider
# （R1B 主切换轮历史）3 failed, 675 passed, 2 xfailed in 76.90s
# （2026-08-03 execute_code 窄修后，见 §10.4）
# Cursor sandbox: 16 failed, 605 passed, 2 xfailed, 83 errors
# 排除 Hermes venv/发布制品依赖: 520 passed, 2 xfailed
```

全量失败与 R1B 功能无关 / 符合物理边界（主切换轮）：

| 用例 | 说明 |
|---|---|
| `test_hermes_chat_real_cli_e2e_redacts_outbound_http` | sandbox 拒绝 `stat(.../profiles/worker)`（`PermissionError`） |
| `test_hermes_chat_fail_closed_llm_execution_http_zero_exit_zero` | 同上 |
| `test_h9_short_lived_argv_probe_captured` | 既有 argv 探针 flaky，非本轮配置切换 |

`test_hermes_credential_guard_check_exit_zero` 在 v2 fixture 迁移后可通过；AC8/AC9 仍为 2 xfailed（已接受本地残余）。

execute_code 窄修后的最新分类见 **§10.4**。

## 3. 单文件唯一源证明

| 场景 | 结果 |
|---|---|
| 仅合法 `credential-guard.json` | 加载成功；token/password 进入外发脱敏 |
| 仅旧双文件 | `RUNTIME_CONFIG_NOT_FOUND`；Provider 调用 0；不回退 |
| 新旧并存 | 只使用 v2；旧诱饵不进入 registry |
| 非法 v2 + 合法旧双文件 | 固定失败；不回退 |
| 缺失 / 0644 / symlink / 父目录非 0700 / 重复 key / 未知字段 | `RUNTIME_CONFIG_*` 固定失败，无路径/秘密回显 |
| 环境变量开关保留旧路径 | **未实现**（无 fallback 开关） |

## 4. 原子 registry 证据

- 多 credential/binding 一次性构建后发布  
- 构建中途 `CredentialRegistry.register` fault injection：标记 `RUNTIME_CONFIG_UNAVAILABLE`，不发布部分新值；受保护请求 Provider=0  
- reload 成功：`generation` 递增；`config_digest` / `binding_view_digest` / `egress_registry_digest_marker` 同代  
- reload 失败：清空 published，后续请求 fail closed  
- 并发读者仅见完整旧代或完整新代  
- `to_canonical_dict()` 深拷贝；调用方篡改不影响 runtime

## 5. 外发 / 路径 / fail-closed / 非干扰矩阵

### C 外发零泄漏

- token.value、username_password.password（+ 既有 basic_auth 组合规则）登记  
- ssh_config 凭证不产生 secret registry 值、不读 `~/.ssh`  
- 嵌套 dict/list、工具结果、percent/Base64/URL-safe/Basic Auth 变体覆盖  
- loader/registry 异常 → Provider transport 调用数 0  
- 不打印配置正文、路径、host、username、secret、digest

### D 路径保护

统一配置、旧双文件、`.v1.bak`、`.cg-migrate.journal` / `.lock` / `.tmp`：

- `read_file` / `search_files` / `terminal` 直接读取阻断  
- `execute_code`：AST 可静态识别的 Python 文件读取阻断（见 §10）  
- 相对路径 / `..` 变体沿用现有门禁  
- 配置目录枚举经 `search_path_is_protected` 继续阻断

### E 非干扰

- 空 v2 下普通聊天可出站  
- 普通非敏感路径不阻断  
- R0 工具审批注入 spike 仍通过（35 相关回归含 tool_injection）  
- 旧 file_backend / SSH 目标单测仍用双文件 fixture（工具语义 R5 前保留）

### F Profile 边界

- 测试显式临时 `HOME` / `HERMES_HOME`  
- 生产运行模块静态禁止真实 worker/default 管理命令字符串  
- 真实 worker Profile hash/mtime 由 Hermes 主代理核验（Cursor 不读真实路径）

### Adapter

- `require_runtime_adapter` 对已验证 binding 固定 `RUNTIME_ADAPTER_NOT_READY`（R3 前不执行/不注入）

## 6. 修改文件清单

| 路径 | 动作 |
|---|---|
| `credential_guard/runtime_config.py` | **Create** — 单文件快照 → registry/runtime view |
| `credential_guard/state.py` | Modify — 外发改走 runtime_config |
| `credential_guard/sensitive_paths.py` | Modify — 统一配置 + migrate 产物保护 |
| `credential_guard/file_backend.py` | Modify — 正式入口降级说明（保留双文件 API） |
| `tests/test_runtime_config_v2.py` | **Create** — R1B 矩阵 A–F |
| `tests/test_file_registry_bridge.py` | Modify — fixture 迁 v2 |
| `tests/test_fail_closed.py` 等空 store fixture | Modify — 空 `credential-guard.json` |
| `tests/test_plugin_registration.py` | Modify — check 绿路径 v2 |
| `tests/test_request_guard.py` | Modify — 空 v2 |
| `tests/test_tool_result_guard.py` | Modify — 空 v2 |
| `tests/test_middleware_http_integration.py` | Modify — 空 v2 |
| `tests/test_production_no_fixture.py` | Modify — 空 v2 |
| `tests/test_variant_limits.py` | Modify — 空 v2 |
| `tests/test_sensitive_paths.py` | Modify — 空 v2 |
| `tests/test_target_catalog_boundary.py` | Modify — 并存写空 v2 |
| `tests/hermes_e2e_helpers.py` | Modify — 隔离 Hermes 写 v2 canary |
| `docs/R1B-单文件正式运行链路切换-实测报告.md` | **Create** — 本文件 |

未改（冻结，R1B 主切换轮）：`config.py` / `bindings.py` / `migration.py` / `cli.py`；未改工具业务语义：`tools.py` / `mysql_executor.py` / `ssh_tools.py` / `ssh_executor.py`；未改 `plugin.yaml` / 版本 / `dist/` / Hermes 源码。

> 注：§10 execute_code 窄修额外修改了 `approval.py` / `hooks.py` / `sensitive_paths.py`（见下）。

## 7. 候选 manifest（待 Hermes 复审）

```text
credential_guard/runtime_config.py
credential_guard/state.py
credential_guard/sensitive_paths.py
credential_guard/file_backend.py
credential_guard/approval.py
credential_guard/hooks.py
tests/test_runtime_config_v2.py
tests/test_execute_code_sensitive_paths.py
tests/test_file_registry_bridge.py
tests/test_fail_closed.py
tests/test_plugin_registration.py
tests/test_request_guard.py
tests/test_tool_result_guard.py
tests/test_middleware_http_integration.py
tests/test_production_no_fixture.py
tests/test_variant_limits.py
tests/test_sensitive_paths.py
tests/test_target_catalog_boundary.py
tests/hermes_e2e_helpers.py
docs/R1B-单文件正式运行链路切换-实测报告.md
```

## 8. 明确未开始

- **未开始 R2**（逻辑引用审批绑定）  
- **未开始 R3**（通用 HTTP/env/stdin 注入执行）  
- **未开始 R5**（删除旧动作/旧双文件模块）  
- **未升版本、未构建发布物、未安装 worker**  
- **未读取真实 `~/.ssh` / 真实业务凭证 / 真实统一配置正文**

## 9. 结论（R1B 主切换轮，历史）

R1B 正式运行链路已切换为唯一源 `credential-guard.json`，外发/路径/fail-closed/原子 publish 矩阵专项 32 passed，R1A 配置地基 175 passed。全量数字以 §10 本轮实测为准。

**候选待 Hermes 独立复审，不得自行签收。**

## 10. R1B execute_code 敏感配置读取绕过 — 窄修（2026-08-03）

### 10.1 Blocker 根因

- `approval._block_sensitive_path` 对 `execute_code` 复用 `terminal_command_reads_protected()`（仅 Shell 直读）  
- 模型可生成 `Path(...).read_text()` / `open(...).read()` 等 Python，绕过前置门禁  
- `tests/test_runtime_config_v2.py` 错误接受 `None` / `approve`，形成假绿  
- 结果侧同样只看 Shell 检测，canary 可回流

### 10.2 严格 TDD 切片

| 切片 | RED | GREEN | 关键断言 |
|---|---|---|---|
| A 最小明确调用 | **5 failed**（`action==block`） | 5 passed | `open` / `Path.read_text|read_bytes|open().read` / `os.open` |
| B 路径变体 | 实现已覆盖后 12 例随 A 同绿 | 含 basename / SSH / `..` / `Path.home()` / `os.environ` / 常量拼接 / f-string | 动态 f-string 诚实不拦 |
| C 非干扰 | 6 例锁定口径 | 普通读/计算/注释提及/`exists`/`stat`/无读意图语法错误放行；有读意图语法错误 fail-closed | |
| D 结果二次门禁 | **2 failed**（canary 回流） | 3 passed | `on_transform_tool_result` 固定安全 JSON；不依赖 registry |

### 10.3 修改文件

| 路径 | 动作 |
|---|---|
| `credential_guard/sensitive_paths.py` | 新增 `python_code_reads_protected()`（`ast.parse`，复用 `path_is_protected`） |
| `credential_guard/approval.py` | `execute_code` 走 AST（并保留原 Shell 检测作纵深） |
| `credential_guard/hooks.py` | 结果侧对 `execute_code` 同步 AST + Shell 二次门禁 |
| `tests/test_execute_code_sensitive_paths.py` | **Create** — A–D 专项 |
| `tests/test_runtime_config_v2.py` | 假绿改为严格 `action==block` + execute_code 结果门禁 |
| `docs/R1B-单文件正式运行链路切换-实测报告.md` | 本节目 |

### 10.4 验收命令真实结果

```bash
.venv/bin/python -m pytest tests/test_execute_code_sensitive_paths.py -q -p no:cacheprovider
# 26 passed

.venv/bin/python -m pytest tests/test_runtime_config_v2.py -q -p no:cacheprovider
# 32 passed

.venv/bin/python -m pytest tests/test_config_v2.py tests/test_config_migration.py \
  tests/test_profile_write_boundary.py -q -p no:cacheprovider
# 175 passed

.venv/bin/python -m pytest tests/test_file_backend.py tests/test_plugin_registration.py \
  tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# file_backend + plugin_registration: 26 passed
# tool_injection_foundation: 8 failed — Cursor sandbox PermissionError
#   on hardcoded /Users/yelei/.hermes/hermes-agent/venv/bin/python（物理边界禁止本代理触达；
#   与 execute_code AST 改动无关；待 Hermes 主代理在可访问 Hermes venv 的环境复核）

/usr/bin/python3 -m compileall -q credential_guard tests
# compileall_ok=true
```

全量（临时 `HOME`/`HERMES_HOME`，Cursor sandbox）：

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider
# 16 failed, 605 passed, 2 xfailed, 83 errors
```

与本轮无关 / 符合物理边界的失败：

| 类别 | 说明 |
|---|---|
| `test_tool_injection_foundation`（8） | sandbox 拒绝对 `~/.hermes/hermes-agent` 的 `stat` |
| `test_hermes_cli_e2e` / `test_hermes_plugin_load` | 同上 + 真实 Hermes CLI |
| `test_reproducible_release` / `test_production_package_scan` 等 | setup 触达 Hermes venv / dist 制品被 sandbox 拒绝 |
| `test_h9_short_lived_argv_probe_captured` 等 | 既有 flaky / 非本轮 |

排除 Hermes venv / 发布制品依赖后的本机纯单元回归：

```bash
# --ignore tool_injection / hermes_* / reproducible_release / m2_release_blockers /
#   plugin_zip_install / release_artifacts / production_package_scan
# 520 passed, 2 xfailed
```

### 10.5 诚实边界（未扩大为 OS 级 DLP）

只承诺阻断标准 `execute_code` 参数中可静态识别的 Python 文件读取；不承诺运行时动态解密路径、任意解释器、自定义二进制、同 UID 恶意进程。

### 10.6 停止条件

- **未开始 R2 / R3 / R5**  
- **未升版、未构建、未安装 worker**  
- **未提交、未推送**（项目无 Git）  
- **候选结论仍：待 Hermes 独立复审，本代理不得自行签收**

## 11. R1B 第二轮窄修：Hermes 独立探针 AST 绕过（待 Hermes 独立复审）

### 11.1 Hermes 手写绕过探针（本轮关闭）

| # | 探针形态 | 修复前 AST | 修复后 |
|---|---|---|---|
| 1 | `from pathlib import Path as P` → `P(PROTECTED).read_text()` | 漏拦 | block |
| 2 | `import pathlib` → `pathlib.Path(PROTECTED).read_text()` | 漏拦 | block |
| 3 | `import pathlib as pl` → `pl.Path(...)` | 漏拦 | block |
| 4 | `from builtins import open as o` → `o(...)` | 漏拦（极少增量，已纳入） | block |
| 5 | `open(file=PROTECTED)` / `os.open(path=..., flags=...)` | 漏拦 | block |
| 6 | `PROTECTED if True else ordinary` / `ordinary if False else PROTECTED` | 漏拦 | block |
| 7 | `p=PROTECTED; if False: p=ordinary; open(p)` 线性遍历污染 | AST 漏拦（shell 字面量偶发假绿） | AST block |
| 8 | 动态条件任一分支可能绑受保护路径 | 线性覆盖/漏拦 | 保守 block |

### 11.2 严格 TDD

| 切片 | RED | GREEN | 关键断言 |
|---|---|---|---|
| 2A 导入别名/限定名 | **4 failed**（`python_code_reads_protected is True`） | 4+4 ordinary 放行 | 受控 alias 表，不 exec import |
| 2B 关键字参数 | **2 failed** | + ordinary kwargs 放行 | `file=` / `path=` |
| 2C 常量条件/控制流 | **5 failed**（含假绿纠正：强制 AST helper） | + 全普通动态分支放行 + honest non-claim | If 分支快照合并；IfExp 常量折叠 |
| 2D 结果侧同步 | **1 failed**（5 变体 canary） | 固定安全 JSON，canary 不回流 | 与 pre 同 AST |

RED 合计（强化 AST 断言后）：**12 failed, 7 passed**（ordinary / non-claim）。  
GREEN：`tests/test_execute_code_sensitive_paths.py` **45 passed**（原 26 + 本轮 19）。

### 11.3 修改文件

| 路径 | 动作 |
|---|---|
| `credential_guard/sensitive_paths.py` | import alias 表；open/os.open kwargs；If/IfExp 候选集合合并 |
| `tests/test_execute_code_sensitive_paths.py` | 新增 2A–2D；`_assert_ast_and_pre_block` 防 shell 字面量假绿 |
| `docs/R1B-单文件正式运行链路切换-实测报告.md` | 本节 |

未改 `approval.py` / `hooks.py`（既有 `python_code_reads_protected` 门禁已覆盖）。

### 11.4 验收命令真实结果

```bash
# RED（实现前）
.venv/bin/python -m pytest tests/test_execute_code_sensitive_paths.py -k "r2a or r2b or r2c or r2d" -q -p no:cacheprovider
# 12 failed, 7 passed

# GREEN
.venv/bin/python -m pytest tests/test_execute_code_sensitive_paths.py tests/test_runtime_config_v2.py -q -p no:cacheprovider
# 77 passed  (45 + 32)

.venv/bin/python -m pytest tests/test_config_v2.py tests/test_config_migration.py \
  tests/test_profile_write_boundary.py -q -p no:cacheprovider
# 175 passed

.venv/bin/python -m pytest tests/test_file_backend.py tests/test_plugin_registration.py \
  tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# file_backend + plugin_registration: 26 passed
# tool_injection_foundation: 8 failed — Cursor sandbox PermissionError
#   on /Users/yelei/.hermes/hermes-agent/venv/bin/python（物理边界禁止触达；与本轮无关）

/usr/bin/python3 -m compileall -q credential_guard tests
# compileall_exit=0

.venv/bin/python -m pytest -q -p no:cacheprovider
# 17 failed, 623 passed, 2 xfailed, 83 errors
```

与本轮无关 / sandbox 物理边界失败类别同 §10.4（Hermes venv、`test_hermes_*`、release/dist 制品等）。

### 11.5 诚实边界

- 只关闭可静态确定的标准 Python AST 读取绕过（别名、kwargs、常量/最小控制流）。
- **不**承诺：运行时 `input()`/解密路径、任意解释器、自定义 loader、完整 CFG/数据流分析、OS 级 DLP。
- 动态条件：任一可达分支候选为受保护路径 → 保守 block；全部普通 → 允许；纯 unknown → 诚实不拦。

### 11.6 停止条件

- **第二轮窄修完成，立即停止；未开始后续阶段 / R2 / R3 / R5**
- **未升版、未构建、未安装 worker、未提交**
- **候选仍写：待 Hermes 独立复审**

## 12. R1B 第三轮窄修：动态候选在字符串拼接/f-string 中传播（待 Hermes 独立复审）

### 12.1 Blocker（独立复现）

```python
import os
root = os.environ["HERMES_HOME"] + "/credential-guard"
if runtime_condition:
    name = "credential-guard.json"
else:
    name = "ordinary.txt"
print(open(root + "/" + name).read())
```

| 层 | 修复前 | 根因 |
|---|---|---|
| `on_pre_tool_call` | 返回 `None`（漏拦） | 动态 if 合并后 `name` 为多候选 `_PathBinding`；`_static_str(Name).single()` 压成 `None`，`+` / f-string 无法传播候选集合 |
| `on_transform_tool_result` | 偶发 block | 与前置共用 helper；偶发来自 registry fail-closed，**不能**当修复 |

### 12.2 严格 TDD

| 切片 | RED | GREEN | 关键断言 |
|---|---|---|---|
| 3A 字符串拼接候选传播 | **4 failed**（`python_code_reads_protected is True` / `action==block`） | + 全普通放行 | `root+'/'+name`；分支顺序互换；多段拼接 |
| 3B f-string 候选传播 | **3 failed** | + 全普通放行 | `f'{root}/{name}'`；多段；顺序互换 |
| 3C 结果侧 | **1 failed**（5 变体 canary） | 固定安全 JSON；全普通结果不受影响 | 先 `load_and_publish_runtime()` 空 v2 view，防 registry 假绿 |

RED 合计：`8 failed, 3 passed`（ordinary / 放行）。  
关键失败断言：`assert False is True`（`python_code_reads_protected(code) is True`，行 `_assert_ast_and_pre_block`）。  
GREEN：`tests/test_execute_code_sensitive_paths.py` **56 passed**（原 45 + 本轮 11）。

### 12.3 候选传播机制与有界上限

| 项 | 说明 |
|---|---|
| 机制 | `_joined_binding` / `_concat_bindings`：对 `ast.BinOp(Add)` 与静态 `JoinedStr` 用 `_candidates` 取各段绑定，再有界笛卡尔积拼出完整路径候选；`Path`/`/`/`os.path.join` 同步走 `_bounded_product_strings` |
| 判定 | 任一完整候选 `path_is_protected()` → block；`unknown` 与 known 并存时保留 known values（不因 `.single()` 丢弃受保护候选） |
| 上限 | `MAX_PATH_CANDIDATE_COMBOS = 64`；超过 → 抛错 → `python_code_reads_protected` fail closed |
| 未改 | `approval.py` / `hooks.py`（既有门禁已覆盖） |

修改文件：

| 路径 | 动作 |
|---|---|
| `credential_guard/sensitive_paths.py` | 多候选 `+`/f-string/路径组合传播 + 有界积 |
| `tests/test_execute_code_sensitive_paths.py` | 新增 3A–3C；结果侧先 publish 空 runtime view |
| `docs/R1B-单文件正式运行链路切换-实测报告.md` | 本节 |

### 12.4 验收命令真实结果

```bash
# RED（实现前）
.venv/bin/python -m pytest tests/test_execute_code_sensitive_paths.py -k "r3a or r3b or r3c" -q -p no:cacheprovider
# 8 failed, 3 passed

# GREEN
.venv/bin/python -m pytest tests/test_execute_code_sensitive_paths.py tests/test_runtime_config_v2.py -q -p no:cacheprovider
# 88 passed  (56 + 32)

.venv/bin/python -m pytest tests/test_config_v2.py tests/test_config_migration.py \
  tests/test_profile_write_boundary.py -q -p no:cacheprovider
# 175 passed

.venv/bin/python -m pytest tests/test_file_backend.py tests/test_plugin_registration.py \
  tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# file_backend + plugin_registration: 26 passed
# tool_injection_foundation: 8 failed — Cursor sandbox PermissionError
#   on /Users/yelei/.hermes/hermes-agent/venv/bin/python（物理边界禁止触达；与本轮无关）
#   （同文件另有 1 passed 不依赖真实 Hermes venv）

/usr/bin/python3 -m compileall -q credential_guard tests
# compileall_exit=0

.venv/bin/python -m pytest -q -p no:cacheprovider
# 17 failed, 634 passed, 2 xfailed, 83 errors
```

与本轮无关 / sandbox 物理边界失败类别同 §10.4（Hermes venv、`test_hermes_*`、release/dist 制品等）。主代理可在沙箱外复跑 Hermes 相关项；本轮不得触碰真实 Hermes。

### 12.5 诚实边界

- 只关闭：动态分支合并后，多候选路径片段在字符串 `+`、静态 f-string 与最小等价路径组合中的丢失。
- **不**承诺：运行时动态解密路径、任意解释器、自定义二进制、完整 CFG、OS 级 DLP。
- 纯 unknown（无 known 候选）仍诚实不拦；候选积超限 fail closed。

### 12.6 停止条件

- **第三轮窄修完成，立即停止；未开始后续阶段 / R2 / R3 / R5**
- **未升版、未构建、未安装 worker、未提交**
- **候选仍写：待 Hermes 独立复审**

### 12.7 组合超限显式回归（证据收口；待 Hermes 最终签收）

最终复审静态确认第三轮机制正确，但缺「组合超过 `MAX_PATH_CANDIDATE_COMBOS=64`」的显式自动回归。Hermes 主代理已用手写探针（7 个二选一片段 → 128 种拼接候选）实测 fail closed；本轮只把该行为固化为自动测试，**未改任何 `credential_guard/*.py` 生产代码**。

| 项 | 说明 |
|---|---|
| 测试 | `test_r3d_candidate_limit_over_limit_fail_closed`（`tests/test_execute_code_sensitive_paths.py`） |
| 构造 | 7 个动态二分支静态字符串 → `s0+…+s6` 产生 2^7=128 候选，超过真实常量 64（不 monkeypatch） |
| 意图 | 证明组合爆炸本身 fail closed；候选不必指向受保护路径 |
| 断言 | `python_code_reads_protected is True`；`on_pre_tool_call.action == block`；空 runtime view 下结果侧固定安全 JSON、canary/元数据不出现；邻近普通代码 helper=False / pre=None / 结果原样 |
| TDD 诚实 | **测试新增后首次即 GREEN**（固化已独立手写验证通过的行为；禁止伪造 RED） |

```bash
.venv/bin/python -m pytest tests/test_execute_code_sensitive_paths.py tests/test_runtime_config_v2.py -q -p no:cacheprovider
# 89 passed  (原 88 + 本证据 1；56→57 execute_code + 32 runtime_config)

/usr/bin/python3 -m compileall -q credential_guard tests
# compileall_exit=0
```

- **无生产代码改动**；仅改测试与本报告
- **未开始 R2 / R3 / R5**；未升版 / 构建 / 安装 / 提交
- **候选仍写：待 Hermes 最终签收**


## 13. Hermes 最终独立执行验收与签收（2026-08-03）

### 13.1 最终执行证据

Hermes 主代理在编码 Agent 退出后独立复跑，并以当前磁盘字节为准验收：

```text
execute_code 路径门禁专项 + R1B：89 passed
R1A 配置/迁移/Profile 边界回归：175 passed
file_backend + plugin_registration + tool_injection：35 passed
全量 pytest：735 passed, 2 xfailed, 0 failed
compileall：exit 0
```

独立手写探针覆盖：

- `Path` 导入别名、`pathlib.Path`、`builtins.open` 别名；
- `open(file=...)`、`os.open(path=...)`；
- 常量条件、不可达分支、动态分支候选合并；
- 多候选继续经字符串 `+`、f-string、多段路径组合；
- 7 个二选一片段形成 128 种组合，超过上限 64 后 helper、前置门禁、结果门禁三层均 fail closed；
- 有效空 runtime 下普通代码 `helper=False`、前置门禁放行、结果原样返回，证明不是 runtime 不可用造成的假绿。

### 13.2 独立复审结论处理

最后一路 leaf 只读复审静态确认：上一轮多候选丢失机制已在代码层关闭；正式 Provider registry 仍只走 `credential-guard.json`；runtime view 原子同代发布，加载/构建失败后 unavailable、Provider 调用为 0；未发现新的确定性代码绕过。

该 leaf 因执行授权层拒绝，无法自行运行探针，返回的是“复审证据阻塞”而非代码 blocker。Hermes 主代理随后逐项完成其最小接受条件：独立探针、组合超限自动回归、全量测试、候选/worker 指纹复核及报告核对。因此证据阻塞已由真实执行关闭，不伪造 leaf PASS。

### 13.3 身份与边界

最终核心文件 SHA-256：

```text
credential_guard/runtime_config.py  29507f63d25b717c430e6b516fc32daa16d2b975173dffff9b90b51fd51c7467
credential_guard/state.py           c865c115d3f9eb03b5ccce11b5b0f06cc5a210b5fe973a09e9213002005e86ec
credential_guard/sensitive_paths.py db79d741ff896a4808a635f093c98bf10f8726bfb473b556cfa35760431e783a
credential_guard/approval.py        ff6dd39a3494ca4f3e117bfcb0a60107169243e84a2e221dee0e6574dc34e5d3
credential_guard/hooks.py           bd46aff06f28f720ee8e35bc6c84a65f7d0cf17b706b9fb4bf51a102a177beff
tests/test_runtime_config_v2.py      6207108b608cd694e18592983d249430b63eec0b9d3e29544c98754a8bb1452a
tests/test_execute_code_sensitive_paths.py 717dd3fec3e7da690ba7eaa5a32732136b1e1c217f7ac2c663a42882378302b2
```

真实 worker 核心配置在验收前后保持：SHA-256 `14a331256164975805415cd0b64ee294d3716bf8a4d51865875f9f0f52fd5283`、size `19011`、mode `0600`、inode `14683120`、device `16777234`、mtime_ns `1785721366983204070`。该基线由用户确认来自 2026-08-03 Hermes 更新；未读取正文、未修改 worker、未安装/启用本候选。

### 13.4 最终结论

**R1B：PASS，正式签收并关闭。**

正式运行时外发保护与结果保护只读取单一 `credential-guard.json`；旧双文件仅保留为显式迁移输入和 R5 前的历史兼容工具路径，不构成正式 Provider registry 回退。下一重节点为 R2 方案共创；方案和任务清单经用户确认前不编码。
