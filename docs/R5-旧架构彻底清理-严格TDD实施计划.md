# R5 旧架构彻底清理严格 TDD 实施计划

> **For Hermes:** 使用 subagent-driven-development 按切片执行；每一切片严格 RED → 最小 GREEN → mutation。编码 Agent 只能生成待主代理验收候选，不得冻结、签收、升版或构建最终制品。

**Goal:** 删除旧 MySQL/SSH 固定动作及其运行时、依赖和当前测试合同，使 Credential Guard 当前生产源码只保留配置化 HTTP/env/stdin 通用凭证边界，并以语义 residue gate 证明清理完整。

**Architecture:** 先建立会对当前代码变红的旧架构残留门禁，再解耦通用常量和迁移解析器，随后逐层删除旧注册、executor、v1 runtime backend、PyMySQL 和旧测试脚本。正式单文件运行链、显式迁移命令、SSH 非干扰和 R0–R4 安全能力保持不变。

**Tech Stack:** Python 3.9+、pytest、AST/配置语义扫描、Hermes PluginManager、临时 HOME/HERMES_HOME、合成诱饵、loopback；无新增第三方依赖。

---

## 0. 强制边界

- Workdir：`/Users/yelei/data/code/repos/hermes-credential-guard`
- 不访问正式 Profile、真实 `~/.ssh`、真实凭证或非 loopback 目标；
- 不修改 `/Users/yelei/.hermes/hermes-agent`；
- 不修改最终目标 HTML；
- 不覆盖 `dist/`，不构建正式 wheel/sdist/plugin ZIP；
- 不改版本号，不进入 R6；
- 不操作正式 worker；
- 不修改 R3/R4 sidecar；
- 不修改 `scripts/run_r3c_wire_e2e.py`、`tests/test_r3c_evidence_authenticity_gate.py` 或其 canonical AST pin；R3 carrier 只作历史静态证据；
- 项目不是 Git 仓库，使用 allow-list + 规范化 manifest 核对范围；
- 删除文件属于不可逆动作：执行前必须再次获得用户明确审批。

## 1. 允许修改与删除范围

### 1.1 允许新建

- `credential_guard/constants.py`
- `scripts/audit_legacy_residue.py`
- `tests/test_legacy_residue_gate.py`
- `scripts/run_r5_wire_e2e.py`
- `tests/test_r5_wire_e2e.py`
- `tests/test_r5_evidence_authenticity_gate.py`
- `tests/test_r5_topology_gate.py`
- `tests/test_r5_approval_host_posture.py`
- `tests/test_r5_provider_result_closure.py`
- `tests/test_ssh_config_non_interference.py`
- `.r5-tdd-evidence.log`
- `.r5-baseline-manifest.sha256`（删除前的完整路径/内容基线，自身排除）
- `.r5-freeze-evidence.sha256`（仅主代理终验后创建）

### 1.2 允许修改

- `credential_guard/__init__.py`
- `credential_guard/cli.py`
- `credential_guard/approval.py`
- `credential_guard/reference_tools.py`
- `credential_guard/process_tools.py`
- `credential_guard/config.py`
- `credential_guard/bindings.py`
- `credential_guard/runtime_config.py`
- `credential_guard/migration.py`
- `credential_guard/release_identity.py`
- `credential_guard/sensitive_paths.py`（只做旧双文件 allowlist/注释收口，不弱化保护）
- `plugin.yaml`
- `pyproject.toml`
- `requirements.txt`
- `MANIFEST.in`
- `release-metadata.json`
- `scripts/build_release_artifacts.py`
- `SECURITY.md`
- `README.md`
- 下文列出的迁移类测试和 companion
- R5 方案/计划、`CLAUDE.md`、`HANDOVER.md`、实施计划入口（仅候选完成后同步状态）

### 1.3 允许删除

生产模块：

- `credential_guard/tools.py`
- `credential_guard/mysql_executor.py`
- `credential_guard/ssh_tools.py`
- `credential_guard/ssh_executor.py`
- `credential_guard/targets.py`
- `credential_guard/file_backend.py`
- `credential_guard/deps_integrity.py`
- `deps/pymysql/`
- `deps/pymysql-1.2.0.dist-info/`
- `deps/.gitignore`（若 `deps/` 由此变空则删除整个目录）

旧产品测试/脚本：

- `tests/test_mysql_tools.py`
- `tests/test_mysql_executor_docker.py`
- `tests/test_targets.py`
- `tests/test_ssh_tools.py`
- `tests/test_ssh_executor.py`
- `tests/test_ssh_target_backend.py`
- `tests/test_file_backend.py`
- `tests/test_approval_gate.py`（整个文件只验证旧 MySQL 专用审批，删除；通用审批合同由 `test_reference_approval.py` 等保留）
- `tests/test_m2_approval_fix_gates.py`
- `tests/test_m2_release_blockers.py`（拆分后删除：先迁出通用审批/闭包/argv/无第二审批票据合同）
- `tests/test_m2_e2e_gates.py`
- `tests/test_m3_e2e_gates.py`
- `scripts/run_m2_e2e.py`
- `scripts/run_m3_e2e.py`
- `tests/support/mysql_harness.py`
- `tests/support/mysql_write_probe.py`
- `tests/support/ssh_harness.py`

任何扩大到上述范围外的生产代码修改，立即停止并提交审批。

## 2. 基线与证据格式

### Task 1：记录 R5 开工基线

**Objective:** 证明 R5 从已签收 R4 行政快照开始，且历史真源未漂移。

**Files:**
- Create: `.r5-tdd-evidence.log`

**Step 1：双算法复算当前工作区并写删除前完整基线**

记录文件数、manifest bytes、SHA-256；两次必须一致。另创建 `.r5-baseline-manifest.sha256`，逐行记录规范化 `path:sha256:length`，并将该文件自身排除。它是 R5 删除审计真源：后续每个路径只能归入“保留/允许修改/明确删除/明确新增”之一，禁止仅靠总文件数抵消意外删除。

**Step 2：核历史身份**

- `.r3c-freeze-evidence.sha256` SHA-256：`ca0738f16df030e5d0360e51ce7d9f4f678068ea565c9739d32caf8284518002`
- 最终目标 HTML：`4842d642056d7cde84bd5c4cc2b61e97991ce292cc33dc3b090e5d99cb5249d6`
- 0.3.1 历史 dist 四文件逐字节哈希不变

**Step 3：重跑开工非构建基线**

先建立R5专用runner清单，机械排除`tests/test_reproducible_release.py`与`tests/test_production_package_scan.py`中所有可达`build_all()`的测试；静态门扫描pytest收集项和调用图，只要非构建runner可达`build_all()`即RED。运行其余全部当前测试并记录精确统计，当前规划快照的参考值是`1436 passed, 2 xfailed, 0 failed`，但该数字来自历史全量（包含临时构建），不得冒充R5开工非构建统计。R5实施完成后，构建类测试必须已迁为纯静态verifier合同或标记为R6专属，R5全量runner仍机械不可达`build_all()`。

**Step 4：记录而不改历史 sidecar**

`.r5-tdd-evidence.log` 写入命令、退出码和精确统计；不把 R5 状态写进 R4 技术身份。

---

## 3. Slice A：先建立旧架构 residue RED

### Task 2：新增语义化 residue auditor

**Objective:** 当前旧架构必须机械判失败，历史文档/迁移输入不能被误伤。

**Files:**
- Create: `scripts/audit_legacy_residue.py`
- Create: `tests/test_legacy_residue_gate.py`

**Step 1：写失败测试**

覆盖：

1. 当前 `plugin.yaml` 因旧 MySQL/SSH 工具失败；
2. 当前 `credential_guard/__init__.py` 因旧注册失败；
3. 旧生产模块存在失败；
4. `pyproject.toml` / `requirements.txt` / `MANIFEST.in` 含 PyMySQL/deps 失败；
5. 当前候选成员含 `deps/pymysql` 失败；
6. `migration.py` 和历史 docs 中出现旧双文件名允许；
7. hooks/middleware/state/approval/runtime_config 出现旧双文件运行时读取失败。

**Step 2：运行 RED**

Run：
```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_legacy_residue_gate.py -q -p no:cacheprovider
```
Expected：FAIL，至少精确报告旧注册、旧模块和 PyMySQL 三类残留。

**Step 3：实现最小 auditor**

要求：

- 使用 AST 判断生产 import/注册，不用粗暴全仓字符串零命中；
- 解析 YAML/TOML/manifest 成员；
- 双文件allowlist仅限迁移模块中解析旧输入的函数、sensitive-path保护和明确命名的负向测试；不能只按整文件放行；
- AST数据流门证明`approval`、`hooks`、`middleware`、`state`、`runtime_config`、工具handler、release/build代码不可读取/解析旧双文件；
- 输出相对路径、违规类型和安全摘要，不读取任何Profile。

**Step 4：Mutation**

在临时复制树分别注入旧注册、旧 import、PyMySQL dependency、`deps/pymysql`、runtime fallback，全部必须 RED；删除迁移 allowlist 也必须让迁移保留测试 RED。

---

## 4. Slice B：解耦通用常量

### Task 3：把通用工具集常量移出旧 tools.py

**Objective:** 两个正式通用工具不再依赖即将删除的 MySQL 模块。

**Files:**
- Create: `credential_guard/constants.py`
- Modify: `credential_guard/reference_tools.py`
- Modify: `credential_guard/process_tools.py`
- Modify: `credential_guard/__init__.py`
- Test: `tests/test_plugin_registration.py`

**Step 1：RED**

测试临时屏蔽 `credential_guard.tools` 后，`reference_tools` 和 `process_tools` 仍应可导入；当前实现必须失败。

**Step 2：最小 GREEN**

`constants.py` 只定义：

```python
TOOLSET_NAME = "credential_guard"
```

两个通用工具从这里导入。禁止把旧工具 alias 搬进新模块。

**Step 3：Mutation**

将任一通用工具重新 import `tools.py`，测试必须 RED。

---

## 5. Slice C：删除固定动作正式入口和审批分支

### Task 4：PluginManager 只暴露两个通用工具

**Objective:** 当前产品不再注册或健康检查旧动作。

**Files:**
- Modify: `credential_guard/__init__.py`
- Modify: `credential_guard/cli.py`
- Modify: `credential_guard/approval.py`
- Modify: `plugin.yaml`
- Preserve unchanged: `scripts/run_r3c_wire_e2e.py`（历史carrier，禁止修改）
- Create: `scripts/run_r5_wire_e2e.py`
- Create: `tests/test_r5_wire_e2e.py`
- Create: `tests/test_r5_evidence_authenticity_gate.py`
- Modify: `tests/test_plugin_registration.py`
- Modify: `tests/test_check_tool_middlewares.py`
- Delete: `tests/test_approval_gate.py`（旧 MySQL 专用）
- Modify: `tests/test_tool_request_analysis.py`
- Modify: `tests/test_reference_approval.py`
- Preserve/modify: `tests/test_file_registry_bridge.py`
- Preserve/modify: `tests/test_profile_write_boundary.py`
- Modify: `tests/test_r3c_historical_identity_gate.py`（R5 signed add/delete/modify另建独立gate；这里只保持R3/R4历史pin和planning delta分层，不改R3/R4 sidecar）

**Step 1：RED**

新增断言：

- `register()` 工具集精确等于 `{http_credential_request, credential_process_run}`；
- `plugin.yaml` 同样精确为两个；
- CLI check 不寻找旧 handler；
- 旧 tool name 通过 `pre_tool_call` 不触发专用 approve；
- 真实临时PluginManager的注册集精确为两个；
- R3历史carrier的canonical AST digest仍为`5d97004c7a32d0cadbd44a6f163ce49d97a83f014bfccfdfd63a472290763c65`；
- R5当前carrier独立通过真实主链并拥有独立AST pin。

当前候选必须 RED。

**Step 2：最小 GREEN**

删除：

- 旧工具 import/register；
- CLI 旧常量、back-compat alias、旧 handler identity；
- `has_all_production_tools` 改为只检查两个通用工具，并重命名为不含旧语义的名称；
- approval 中 `_CREDENTIAL_TOOLS`、MySQL/SSH 专用文案和专用 rule key 分支。

保留：六个 intercept、引用审批、sensitive-path block、固定安全失败。

**Step 3：Mutation**

重新加入任一旧工具的manifest声明、register_tool或CLI健康条件，residue/registration gate必须RED。修改R3历史carrier任一AST节点必须仍由原R3 gate判RED；删除R5当前carrier的工具集合、来源绑定或任一wire证据也必须由R5真实性gate判RED。

---

## 6. Slice D：收窄单文件 Schema，内聚迁移输入解析

### Task 5：正式 v2 Schema 删除 ssh_config 类型

**Objective:** 当前正式配置只接受有可执行适配器的类型。

**Files:**
- Modify: `credential_guard/config.py`
- Modify: `credential_guard/bindings.py`
- Modify: `credential_guard/runtime_config.py`
- Modify: `tests/test_config_v2.py`
- Modify: `tests/test_runtime_config_v2.py`

**Step 1：RED**

新增负例：`ssh_config` credential 或 binding 必须 `CONFIG_SCHEMA`；当前实现应失败。

**Step 2：最小 GREEN**

- credential 类型仅 `token` / `username_password`；
- binding 类型仅 `http` / `process_env` / `stdin`；
- 删除 v2 SSH alias validator、字段集和 runtime scrub 分支；
- 不改变 HTTP/process 校验。

**Step 3：Mutation**

重新将 `ssh_config` 放回任一 allowed set，负例必须 RED。

### Task 6：迁移模块自带最小 v1 parser

**Objective:** 删除旧 runtime backend，同时保留一次性显式迁移的安全合同。

**Files:**
- Modify: `credential_guard/migration.py`
- Modify: `tests/test_config_migration.py`

**Step 1：RED**

- migration 不得 import `file_backend`；
- 空 v1 双文件可迁移为空 v2；
- v1 MySQL 或 SSH target 均返回 `MIGRATION_REQUIRES_MANUAL_REVIEW`，且源文件指纹不变；
- 权限、symlink、未知字段、重复键、journal、补偿恢复和并发 race 全部保持原合同；
- `tests/test_file_registry_bridge.py` 继续证明只有旧双文件时外发链 fail closed 且不回退；
- `tests/test_profile_write_boundary.py` 继续证明迁移只使用显式临时 HOME/HERMES_HOME，不触碰正式 Profile。

**Step 2：最小 GREEN**

把迁移必要的 v1 字段集、identifier、SSH alias 解析和安全读取内聚到 `migration.py` 私有实现；禁止对外提供旧 runtime backend API。

**Step 3：Mutation**

- 放宽字段集、symlink 或 owner/mode 任一门禁必须 RED；
- 把 SSH/MySQL 自动迁移放行必须 RED；
- 删除迁移命令或让它回退运行时必须 RED。

### Task 7：删除旧 runtime backend 和专用模块

**Objective:** 生产树不再包含旧动作执行能力。

**Files:**
- Delete: `credential_guard/tools.py`
- Delete: `credential_guard/mysql_executor.py`
- Delete: `credential_guard/ssh_tools.py`
- Delete: `credential_guard/ssh_executor.py`
- Delete: `credential_guard/targets.py`
- Delete: `credential_guard/file_backend.py`

**Step 1：运行 residue RED，确认当前仍因文件存在失败。**

**Step 2：删除后运行 import smoke和 Slice B–D 专项。**

**Step 3：Mutation**

在临时复制树恢复任一同名模块或 import，residue gate 必须 RED。

---

## 7. Slice E：删除 PyMySQL 和旧依赖身份

### Task 8：当前候选改为零第三方运行依赖

**Objective:** 当前生产包不再携带或声明 PyMySQL。

**Files:**
- Delete: `credential_guard/deps_integrity.py`
- Delete: `deps/`
- Modify: `requirements.txt`
- Modify: `pyproject.toml`
- Modify: `MANIFEST.in`
- Modify: `release-metadata.json`
- Modify: `credential_guard/release_identity.py`
- Modify: `scripts/build_release_artifacts.py`
- Modify: `tests/test_production_package_scan.py`（迁为纯静态source/package-member合同，不调用`build_all()`）
- Modify: `tests/test_reproducible_release.py`（R5只保留verifier纯fixture合同；双构建测试明确归R6，不进入R5 runner）

**Step 1：RED**

新增断言：

- requirements 为空；
- project dependencies 为空；
- packages.find 不含 `deps*`；
- 无 deps package-data；
- release metadata 不含 PyMySQL/vendored 字段；
- candidate identity 不调用 deps validator；
- builder 不要求 `deps/pymysql`；
- 包成员 gate 将任何 `deps/pymysql` 判为失败。

**Step 2：最小 GREEN**

- 保留空 `requirements.txt`；
- `dependencies = []`；
- package discovery 只含 `credential_guard*`；
- 当前源码`release-metadata.json`精确为`{}`，表达无第三方运行依赖；
- 未来R6 artifact manifest顶层精确删除且只删除`vendored_deps_manifest_sha256`；
- 严格schema、SHA类型、basename/路径逃逸、三制品文件名互异、文件哈希、candidate/builder/source identity和build字段校验全部保留；
- R5发布测试只使用纯内存或临时fixture验证verifier，R5 runner机械不可达`build_all()`；
- builder源码适配为无deps，但本轮不调用`build_all(dist)`。

**Step 3：Mutation**

加回 dependency、package-data、deps 文件或 builder 必含断言，gate 必须 RED。

---

## 8. Slice F：删除过期测试脚本，保留通用性质

### Task 9：清理旧 M2/M3 运行合同

**Objective:** 当前全量不再要求已删除产品存在。

**Files:** 删除 1.3 所列旧测试和脚本；修改 companion 及混合测试。

**Step 1：先建立性质映射表写入 `.r5-tdd-evidence.log`**

每个被删测试至少归类为：

- 旧业务行为，无需迁移；
- 通用安全性质，已由 R0–R4 哪个测试覆盖；
- 历史证据，仅保留 docs/dist。

未映射不得删除。

**Step 2：删除旧文件，迁移混合测试。**

必须保留：

- 标准人工审批和拒绝；
- 同一Provider tool_call_id复用时，宿主`session/always`不得覆盖下一次审批；
- 禁止引入插件侧第二套approval-ticket；
- 短生命周期argv探针必须真实可观测；
- Provider tool-call/result的孤儿、冲突、缺失、额外调用和固定拒绝结果闭包；
- secret resolve=0 / downstream=0；
- 单文件配置与迁移；
- HTTP/env/stdin；
- 私钥/SSH Config 敏感路径保护；
- 结果守卫；
- 普通 SSH 非干扰；
- 0.3.1 历史 dist 不漂移。

同时改写当前`README.md`和`SECURITY.md`：只描述两个通用工具、`credential-guard.json`、显式迁移、HTTP/env/stdin、统一审批与结果守卫；`pyproject.toml` description同步去掉旧MySQL/SSH宣传。旧M2/M3固定动作只允许留在历史报告。

`sensitive_paths.py` 继续保护旧双文件、备份和迁移 journal 路径，但删除无调用 `_credentials_json_path()`；mutation 必须证明删 helper 不会削弱路径保护。

**Step 3：Mutation**

删除上述任一通用性质的现行门禁，coverage mapping 测试必须 RED。

---

## 9. Slice G：全量 residue、死代码和真实性

### Task 10：候选静态与真实 PluginManager 验收

**Objective:** 不靠自报确认旧架构真正消失。

**Files:**
- Create: `tests/test_ssh_config_non_interference.py`

**Checks:**

1. `scripts/audit_legacy_residue.py` exit 0；
2. 所有生产 Python 内存 compile；
3. 生产模块全量 import smoke；
4. AST import graph 无孤立兼容模块；
5. 临时 HOME/HERMES_HOME + 中立 cwd 真实 PluginManager：六 intercept、两工具；
6. callback/handler `__file__` 全来自临时安装树；
7. 旧工具查询不到；
8. `credential-guard check`输出只列两个工具；
9. 临时HOME写入合成SSH alias，运行真实`ssh -G <alias>`仅解析配置不联网；插件启用前后argv及关键解析字段一致，同时`.ssh`/私钥读取仍被拦截；
10. R5当前wire carrier从中立cwd/临时安装根跑通正式PluginManager→AIAgent主链，R3历史carrier只做静态AST身份验证；
11. 历史dist哈希不变。

**Mutation:** 安装树加入旧manifest或旧module，必须在真实PluginManager/residue组合门中RED；篡改SSH alias解析结果、绕过`.ssh`保护、让R5 current carrier回退仓库副本也必须RED。

### Task 10.1：R5 signed topology gate

**Files:**
- Create: `tests/test_r5_topology_gate.py`
- Modify: `tests/test_r3c_historical_identity_gate.py`（仅让其继续验证R3/R4历史pin和规划delta；不拿纯加法计数代表R5最终拓扑）

从`.r5-baseline-manifest.sha256`生成精确`R5_ADDED_PATHS`、`R5_DELETED_PATHS`、`R5_MODIFIED_PATHS`、`R5_PRESERVED_PATHS`。当前路径必须等于`baseline − deleted + added`；modified必须存在且仅它们可变；preserved内容哈希必须不变。漏列新增/删除/修改、伪造exclude、删除preserved、用新增抵消误删均mutation RED。R3/R4 sidecar原字节不改。

---

## 10. Slice H：主代理终验与冻结

### Task 11：专项和全量

顺序运行：

1. residue + registration + CLI check；
2. config + migration；
3. R0/R1/R2通用合同，加迁移后的approval host posture/provider result closure/argv probe；
4. R3历史carrier静态真实性与R5当前wire主链；
5. R4 result guard + NI E2E；
6. R5 signed topology、SSH Config真实解析非干扰、release verifier纯静态合同；
7. R5非构建全量pytest，必须`0 failed`且机械不可达`build_all()`；
8. 所有生产Python内存compile；
9. 0.3.1 dist哈希、R3/R4 sidecar、最终目标哈希。

不得用 exit code 0 代替精确统计。

### Task 12：冻结

主代理创建 `.r5-freeze-evidence.sha256`：

- 技术候选 files / manifest bytes / SHA-256；
- 删除前 `.r5-baseline-manifest.sha256` 与最终路径集合逐项对账：每个消失/新增/修改路径都必须命中经用户批准的 allow-list；
- 两套算法各两次；
- 测试统计；
- 删除/修改 allow-list；
- 历史 R3/R4/0.3.1/最终目标身份；
- `STATUS=technical candidate pending three final reviews`。

freeze sidecar 自身排除，避免自引用。

### Task 13：三路最终只读复审

1. Cursor：旧架构残留、死代码、产品语义；
2. Hermes：安全边界、迁移能力、普通 SSH 非干扰；
3. Hermes：证据真实性、冻结身份、修改范围和 R6 边界。

三路均必须首行 `PASS`。任何 `BLOCKING` 先关闭再重冻结；进程 exit 0 不等于 PASS。

### Task 14：行政签收

三路全 PASS 后才：

- `.r5-freeze-evidence.sha256` 追加行政状态；
- 更新 `CLAUDE.md`、`HANDOVER.md`、实施计划与当前项目情况 MD/HTML；
- 明确 R5 完成、R6 未开始；
- 停在 R6 方案门前，不自动构建或升版。

## 11. 最终自审清单

- [ ] 删除范围经过用户明确审批；
- [ ] 没有 deprecated/compat 壳；
- [ ] 迁移能力没有误删；
- [ ] 正式 v2 不接受不可执行 `ssh_config` binding；
- [ ] 普通 SSH 有真实`ssh -G`配置解析非干扰证据，且敏感路径保护仍在；
- [ ] R3历史wire carrier/AST pin原字节不改，R5当前carrier独立验真；
- [ ] R5 signed topology逐项覆盖added/deleted/modified/preserved；
- [ ] `test_m2_release_blockers.py`中的通用审批、闭包、argv和无第二票据合同已迁移并有mutation；
- [ ] R5 runner机械不可达`build_all()`，通用release verifier安全合同未误删；
- [ ] 当前生产只注册两个通用工具；
- [ ] PyMySQL/deps 不在源码候选和包定义中；
- [ ] 历史 0.3.1 dist 原字节不变；
- [ ] 未构建新 dist、未升版、未操作 worker；
- [ ] 全量 0 failed；
- [ ] 三路最终复审全 PASS。
