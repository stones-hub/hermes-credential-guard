# Credential Guard 通用凭证边界实施计划

> **For Hermes:** 使用严格 TDD 分阶段执行；每个阶段完成后由 Hermes 独立复跑和只读复审。禁止连接真实目标、读取真实凭证或升级 worker。

**目标：** 将 Credential Guard 从固定 MySQL/SSH 动作插件重构为“外发脱敏 + 审批后通用本地注入 + 结果脱敏”的通用凭证边界，并在最终候选中清理全部旧架构无用代码。

**架构：** 复用 Hermes 已有 `llm_request`、`llm_execution`、`tool_request`、`pre_tool_call`、`tool_execution` 和 `transform_tool_result` 接口。插件使用单一 `credential-guard.json`，模型只在工具参数中使用逻辑引用；人工审批前不解析真值，审批通过后在 `tool_execution` 中校验配置摘要、工具、参数位置和目标，再以结构化 HTTP、单次环境变量或 stdin 注入。

**技术栈：** Python 3.9+、Hermes Plugin API、pytest、loopback 假 Provider/HTTP 服务、可复现 wheel/sdist/plugin ZIP。

---

## 0. 开源复用与自研边界

| 组件 | 使用什么 | 自研范围 |
|---|---|---|
| 插件发现、启停、CLI | ◎ Hermes Plugin API | 仅注册和自检 |
| 模型外发边界 | ◎ Hermes `llm_request` / `llm_execution` | 精确登记脱敏和 fail-closed |
| 工具参数改写 | ◎ Hermes `tool_request` | 引用识别与安全摘要 |
| 人工审批 | ◎ Hermes `pre_tool_call` + manual approval | 生成不含真值的审批指令 |
| 审批后执行包装 | ◎ Hermes `tool_execution` | 配置摘要复核、真值解析与注入 |
| HTTP 请求 | ◎ Python 标准库或项目已有客户端 | 目标绑定、重定向校验、Header 注入 |
| 环境变量/stdin | ◎ Hermes 现有 terminal 结构 | 单次子进程注入适配 |
| 配置后端 | ◉ Credential Guard | 单文件严格 Schema、迁移、原子写入 |
| 旧固定动作 | 不复用 | 最终全部删除 |

## 1. 执行纪律

1. 项目不是 Git 仓库；每轮开始和结束生成规范化全树内容 manifest，不能依赖 `git diff`。
2. 0.3.1 的三个制品和正式哈希保持冻结，重构构建输出使用独立目录，未最终签收前不得覆盖 `dist/`。
3. 所有测试使用临时 HOME/HERMES_HOME、合成诱饵、loopback；禁止真实 `~/.ssh`、业务凭证和生产目标。
4. 每个功能严格 RED → GREEN → REFACTOR；Cursor 自报不作为验收结论。
5. 每轮均验证 Hermes 源码 `git status --porcelain` 为 0，worker 内容身份未变化。
6. 任一安全边界故障必须 fail closed，不允许异常后继续调用下游工具或 Provider。
7. R0 未通过前不得写 R1-R5 生产实现。
8. 真实 Profile 是受保护对象，不是测试环境：禁止运行任何会写入真实 worker/default 的 `plugins enable/disable/install/remove`、`tools enable/disable`、`config set` 或等效命令。
9. 每轮开始前记录 worker `config.yaml` 的 SHA-256、mtime、size、mode；结束后只读复核。用户在 2026-08-03 更新 Hermes 后确认的新基线为 sha256=`14a331256164975805415cd0b64ee294d3716bf8a4d51865875f9f0f52fd5283`、mtime_ns=`1785721366983204070`、size=`19011`、mode=`0600`、inode=`14683120`、device=`16777234`。任何变化立即停止，不自动恢复。
10. 真实插件目录与 state 只作只读边界核验；全部安装、启用、CLI、PluginManager 和 E2E 必须在临时 HOME/HERMES_HOME 中完成。最终版本完成并经用户单独确认后，才另立“worker 升级”步骤。

## 2. 里程碑总览

| 阶段 | 产出 | 退出条件 |
|---|---|---|
| R0 | Hermes 接口命门实测 | 证明审批前引用、审批后注入；拒绝时解析/执行均为 0 |
| R1 | 单文件配置和迁移 | 严格 Schema、外发快照、双文件原子迁移全绿 |
| R2 | 引用与审批绑定 | 引用、工具、参数、目标、配置摘要全部绑定，TOCTOU 全阻断 |
| R3 | 通用注入适配器 | HTTP Header、单次 env、stdin 正反例全绿 |
| R4 | 回流保护与非干扰 | 结果 fail-closed，现有编码/SSH部署/普通工具不受影响 |
| R5 | 旧架构清理 | 旧动作、executor、PyMySQL、双文件运行路径和无用测试全部删除 |
| R6 | 发布收口 | 全量/E2E/双构建/最终 ZIP/双重只读复审 PASS |
| R7 | 外发兼容性 | 长文本误阻断与 LocalBlockRequest 本地终止；披露 auxiliary 宿主边界 |

当前状态（2026-08-11）：**R0–R6 技术侧已按既有签收/收口状态保留。R7 两个插件兼容性 Bug 已行政签收 PASS**（两路独立只读复审局部 PASS；全量 1616 passed / 3 xfailed）。Hermes `auxiliary_client` 绕过 middleware 记为宿主插件接口能力边界，不在 Credential Guard 内 monkey patch；R8 统一拦截方案已否决、禁止执行。0.4.1 为当前产品版本候选，历史 0.4.0/0.3.1 制品与报告原样保留。

## 3. R0：Hermes 接口命门验证

### Task R0.1：建立隔离 Spike

**目标：** 不修改生产代码，验证 Hermes 中间件真实调用顺序。

**文件：**
- Create: `spikes/tool-injection-proof/plugin.yaml`
- Create: `spikes/tool-injection-proof/__init__.py`
- Create: `spikes/tool-injection-proof/run_proof.py`
- Create: `tests/test_tool_injection_foundation.py`

**步骤：**

1. 写失败测试：注册 `tool_request`、`pre_tool_call`、`tool_execution` 和假工具，记录每个阶段实际看到的参数。
2. 运行专项测试，确认当前项目尚无该验证并 RED。
3. 实现最小 spike：
   - 模型/假调用输入为 `<CREDENTIAL:decoy>`；
   - `tool_request` 保持引用，不解析真值；
   - `pre_tool_call` 返回 `approve`；
   - `tool_execution` 才把引用换成运行时合成诱饵并调用假工具。
4. 分别运行批准和拒绝路径。
5. 输出机器可读证据，不打印诱饵正文。

**完成判据：**

```text
approve.before_execution_plain_count=0
approve.tool_received_plain_count=1
approve.downstream_call_count=1
deny.secret_resolve_count=0
deny.downstream_call_count=0
approval_payload_plain_count=0
middleware_trace_plain_count=0
```

### Task R0.2：验证异常语义

**目标：** 确认插件 middleware 抛错时 Hermes 是否会旁路继续执行。

**文件：**
- Modify: `tests/test_tool_injection_foundation.py`
- Modify: `spikes/tool-injection-proof/run_proof.py`

**步骤：**

1. 对 `tool_request`、`pre_tool_call`、`tool_execution` 分别注入异常。
2. 断言 Provider/假工具副作用是否为 0。
3. 如果 Hermes 主机默认吞掉异常并继续执行，spike 必须用插件自己的“固定阻断结果，不调用 `next_call`”实现 fail-closed。
4. 若现有公开接口无法区分审批通过与拒绝后的执行，R0 判 BLOCKING，停止后续编码。

**R0 交付：** `docs/R0-Hermes工具参数审批后注入-实测报告.md`，只写真实执行结果。

## 4. R1：单文件配置与迁移

### Task R1.1：新建严格配置模型

**文件：**
- Create: `credential_guard/config.py`
- Create: `credential_guard/bindings.py`
- Test: `tests/test_config_v2.py`

**TDD 切片：**

1. RED：缺文件、0644、symlink、错误 owner、错误 version、未知字段仍被接受。
2. GREEN：实现 `CredentialGuardConfig.load()`，固定读取 `credential-guard.json`。
3. RED：重复 credential、悬空 `credential_ref`、重复 placeholder、非法名称、空凭证、类型不匹配未拒绝。
4. GREEN：一次性构造不可变 credentials/bindings 快照；失败不产生部分状态。
5. RED：host 通配过宽、HTTP 非 https、非法端口、approval 非 required 被接受。
6. GREEN：第一版按方案严格限制。

### Task R1.2：接入单文件外发快照

**文件：**
- Modify: `credential_guard/state.py`
- Modify: `credential_guard/middleware.py`
- Modify: `credential_guard/hooks.py`
- Modify: `credential_guard/registry.py`
- Test: `tests/test_single_file_registry_bridge.py`
- Test: `tests/test_request_guard.py`
- Test: `tests/test_tool_result_guard.py`

**完成判据：**

- 明文、percent、quote-plus、Base64、URL-safe Base64、Basic Auth、JSON escape 的 Provider wire 计数全部为 0；
- 配置读/校验/变体构造失败时 Provider 调用为 0；
- 每次请求使用独立快照；凭证轮换不污染并发请求。

### Task R1.3：实现安全迁移命令

**文件：**
- Create: `credential_guard/migration.py`
- Modify: `credential_guard/cli.py`
- Test: `tests/test_config_migration.py`

**命令：**

```text
hermes credential-guard migrate-config
```

**完成判据：**

- 旧双文件只读；
- 先写同目录 `.tmp`，fsync、严格复读校验后原子 rename；
- 正式文件已存在时拒绝覆盖；
- 旧文件只重命名备份，不删除；
- 任一步失败时正式新文件和旧文件均不变；
- stdout/stderr 不含诱饵真值、用户名、host 或本地路径。

## 5. R2：逻辑引用、审批绑定与 TOCTOU

详细方案真源：`docs/R2-逻辑引用审批绑定与防偷换-落地方案.md`。

关键语义：

- `<CREDENTIAL:name>` 的 `name` 是 credential 名，不是 binding 或 target 名；
- 模型分别提交业务 `target` 与逻辑 `credential` 引用；
- 本机 binding 验证 target、credential、工具、参数位置、协议和注入规则是否构成唯一合法组合；
- 引用只能占据配置允许的完整结构化参数值，普通聊天和自由文本永不还原；
- R2 只生成、审批、复核和一次性消费 `InjectionPlan`，不读取真值、不连接目标、不调用带引用的下游工具；
- 验证成功仍固定返回 `RUNTIME_ADAPTER_NOT_READY`，真实注入属于 R3。

### Task R2.1：宿主审批姿态与稳定逻辑引用

**文件：**
- Create: `credential_guard/references.py`
- Test: `tests/test_credential_references.py`
- Test/Spike: 临时 Hermes PluginManager 下的 manual/YOLO/off 真实行为

**完成判据：**

- 格式固定 `<CREDENTIAL:name>`，名称必须来自当前配置；
- 引用必须是完整参数值；未登记、嵌套、截断、编码、多引用 fail closed；
- 普通聊天、LLM 输出文本和工具结果都不还原；
- 正式引用调用要求 manual，YOLO/off 下 block；无法可靠确认宿主姿态则 R2 BLOCKING。

### Task R2.2：不可变 InjectionPlan 与有界 store

**文件：**
- Create: `credential_guard/injection_plan.py`
- Test: `tests/test_injection_plan.py`

**完成判据：**

- plan 绑定 session/turn/tool_call_id、tool、args digest、reference arg path、credential、target、binding、config/binding/target digest、config_file_identity 和 nonce（**不**绑定 runtime generation；generation 仅为 R1B 发布观测值）；
- plan 不含真值和完整原始参数；
- 状态单向、一次性消费、monotonic 过期、容量有界、并发隔离；
- TTL/容量以 Hermes 审批超时事实和隔离 E2E 决定，不凭空写值；超限 fail closed。

### Task R2.3：tool_request 只分析并匹配 binding

**文件：**
- Create: `credential_guard/tool_request.py`
- Modify: `credential_guard/__init__.py`
- Test: `tests/test_tool_request_analysis.py`

**完成判据：**

- 注册 `tool_request` middleware；
- target、credential 与本机 binding 必须唯一匹配；
- 返回参数仍含引用，不含真值；
- middleware trace 只含固定 source/reason/name，不含 plan 正文或真值；
- 无引用工具参数语义与结构等价；内部异常登记 fail-closed，不能裸抛后被宿主旁路。

### Task R2.4：统一审批与审批后复核门

**文件：**
- Refactor: `credential_guard/approval.py`
- Create: `credential_guard/tool_execution.py`
- Modify: `credential_guard/__init__.py`
- Test: `tests/test_reference_approval.py`
- Test: `tests/test_injection_toctou.py`

**完成判据：**

- 保留 R1B 敏感路径门禁和 R5 前旧动作兼容；
- 审批只显示工具、业务 target、逻辑 credential、操作摘要、注入类型和风险，不显示真值/真实 host/配置路径；
- `rule_key` 绑定 nonce + tool_call_id + tool + args/config/binding digest；
- tool_execution 重新校验配置、目标、凭证引用、工具、参数、调用身份；任一变化作废；
- 有效 plan 原子消费后仍不解析真值、不调用下游，固定返回 `RUNTIME_ADAPTER_NOT_READY`；
- 拒绝、超时、异常、重放、过期、并发串单均 secret resolve=0、downstream=0；
- 无引用普通工具 `next_call` 恰好一次且结果不变。

## 6. R3：通用安全注入

### Task R3.1：tool_execution 注入框架

**文件：**
- Create: `credential_guard/injection.py`
- Modify: `credential_guard/__init__.py`
- Test: `tests/test_tool_execution_injection.py`

**完成判据：**

- 注册 `tool_execution` middleware；
- 未持有有效、当前且一次性的 `InjectionPlan` 时不调用 `next_call`；
- 仅加载本次引用所需凭证；
- 在参数深拷贝中注入，不修改模型原始参数；
- `next_call` 只能执行一次；
- 执行完成或异常后 plan 立即销毁。

### Task R3.2：结构化 HTTP Header 注入

**文件：**
- Create: `credential_guard/adapters/http.py`
- Test: `tests/test_http_injection.py`
- Test: `tests/test_http_redirect_boundary.py`

**第一版支持：**

- Bearer；
- Basic；
- 自定义 API-Key Header；
- https + 精确 host/port；
- 相对 path、query、body；
- 默认不跟随重定向；若以后允许，每一跳重新校验。

**反例：** 攻击者 host、userinfo URL、IP/域名混淆、非 443、重定向、Header 注入换行、Token 放 query/body、DNS/Host 不一致。

### Task R3.3：单次环境变量注入

**文件：**
- Create: `credential_guard/adapters/process_env.py`
- Test: `tests/test_process_env_injection.py`

**完成判据：**

- 只对支持独立 `env` 参数的执行结构注入；
- 不修改 `os.environ`；
- 子进程退出后不可见；
- 参数、审批、日志、trace 不含真值；
- 任意 env 名、覆盖 PATH/HOME/HERMES_HOME、换行/NUL 均拒绝；
- 第一版只允许配置中明确登记的 env 名。

### Task R3.4：stdin 注入

**文件：**
- Create: `credential_guard/adapters/stdin.py`
- Test: `tests/test_stdin_injection.py`

**完成判据：**

- 只对工具 Schema 明确支持 stdin 的字段生效；
- 不把真值拼入 command/argv；
- stdout/stderr 回流前再次脱敏；
- 工具不支持 stdin 时 fail closed，不退回 argv。

## 7. R4：结果守卫与现有能力非干扰

详细方案真源：`docs/R4-统一结果守卫与非干扰-落地方案.md`。  
严格 TDD 计划：`docs/R4-统一结果守卫与非干扰-严格TDD实施计划.md`。

### Task R4.1：统一结果守卫

**生产边界：**

- Create: `credential_guard/result_guard.py`
- Refactor: `credential_guard/hooks.py`
- Refactor: `credential_guard/adapters/http.py`
- Refactor: `credential_guard/adapters/process.py`
- Test: `tests/test_injected_result_guard.py`
- Authenticity: `tests/test_result_guard_authenticity_gate.py`

**完成判据：**

- 所有正式工具结果通过 Hermes 真实 `transform_tool_result` Hook 进入一个权威守卫；
- 干净文本、JSON、日志、表格原样放行，不 parse/serialize 重排；
- 已登记真值及支持编码变体替换为对应 `<CREDENTIAL:name>`；
- Authorization、认证 Cookie、明确 secret/token/password 字段和 PEM 按高置信度规则处理；
- 脱敏后对最终待发送结果做零残留复查；
- 守卫异常或仍有残留时，整份结果替换为固定安全文本，不返回固定安全 JSON；
- HTTP/子进程即使可能已产生副作用，也不虚构成功、失败或回滚，不自动重试；
- HTTP/process 仅复用同一权威规则，不继续定义 `***` 或整份 leak error 等不同产品语义。

固定安全文本：

```text
工具可能已经执行，但返回内容未通过安全检查，原始结果未返回。请独立核验目标系统的真实状态。
```

### Task R4.2：非干扰矩阵

**文件：**

- Create: `tests/test_non_interference_v2.py`
- Create: `scripts/run_v2_non_interference_e2e.py`

**场景：**

- 本地临时目录代码/文件读写与搜索；
- pytest、Python 内存 compile；
- 临时 Git 仓库 status/diff/log；
- 普通无凭证 terminal、execute_code；
- 临时 HOME 下的 SSH Config 与 loopback 假 SSH 结果；
- Docker/systemd 仅使用合成参数和输出，不连接真实 daemon/服务；
- JSON、Markdown、表格、中文、普通 Base64、Git SHA、SHA-256、UUID、Request ID、Trace ID；
- 接近现有安全上限的大字符串首部、中部、尾部完整检查。

**完成判据：**

- 干净结果处理前后逐字一致；
- 只有敏感片段变化；
- 不增加审批，不改变工具调用次数、退出码或真实副作用；
- 无引用工具调用与未安装插件时的安全结果一致；
- 不连接真实目标，不读取真实凭证、真实 `~/.ssh` 或正式 Profile；
- 不新增流式平台、独立日志/数据库、第二套审批、自动重试或回滚；
- R4 全量、冻结和三路只读复审全部 PASS 后才签收。

## 8. R5：旧架构彻底清理

### Task R5.1：建立旧架构引用清单

**文件：**
- Create: `scripts/audit_legacy_residue.py`
- Create: `tests/test_legacy_residue_gate.py`

**扫描对象：**

- `mysql_credential_action`
- `ssh_credential_action`
- `check_connection`
- `show_effective_grants`
- `show_remote_identity`
- `credentials.json`
- `targets.json`
- `mysql_executor`
- `ssh_executor`
- PyMySQL/deps package data

允许位置仅限：历史 0.3.1 文档、迁移模块、明确的负向兼容测试。任何生产注册、import 或包成员命中即退出非 0。

### Task R5.2：删除固定动作生产链

**删除：**

- `credential_guard/tools.py`
- `credential_guard/mysql_executor.py`
- `credential_guard/ssh_tools.py`
- `credential_guard/ssh_executor.py`
- `credential_guard/targets.py`（若引用分析证明仅服务旧架构）
- `credential_guard/deps_integrity.py`（若仅服务 PyMySQL）
- `deps/pymysql/`
- `deps/pymysql-1.2.0.dist-info/`

**修改：**

- `credential_guard/__init__.py`
- `credential_guard/cli.py`
- `credential_guard/approval.py`
- `credential_guard/sensitive_paths.py`
- `pyproject.toml`
- `requirements.txt`
- `plugin.yaml`
- `release-metadata.json`

删除后立即运行 import smoke、旧接口不存在测试和 R1-R4 全套回归。

### Task R5.3：删除过期测试和脚本

**处理原则：**

- 只验证旧动作行为的测试删除；
- 仍验证通用安全边界的测试迁移到新模块后再删除旧文件；
- 旧 M2/M3 历史报告保留为历史证据，但不得被当前版本测试当成现行契约；
- 旧 MySQL/SSH E2E 脚本从当前发布 gate 中移除，历史文件是否保留由“是否仍有文档证据价值”决定，绝不进入生产 ZIP。

### Task R5.4：死代码和制品成员门禁

**验证：**

- Python import 图；
- 未引用生产模块；
- CLI/PluginManager 实际注册列表；
- wheel/sdist/plugin ZIP 成员清单；
- `pyproject.toml` 依赖和 package-data；
- `release-metadata.json` 与 manifest。

任何“deprecated 但仍打包”“无调用但保留”“仅未来可能使用”均为 BLOCKING。

## 9. R6：发布和独立验收

### Task R6.1：全量执行验收

顺序：

1. 全量 pytest：0 failed；AC8/AC9 各自 strict-xfail；
2. compileall：exit 0；
3. 外发 canary：exit 0；
4. R0 审批后注入 E2E：exit 0；
5. 单文件迁移 E2E：exit 0；
6. HTTP Header/env/stdin E2E：exit 0；
7. 非干扰 E2E：exit 0；
8. 旧架构残留 gate：exit 0；
9. Hermes 源码和 worker non-interference：通过。

### Task R6.2：可复现发布

- 全量绿后再确定新版本号；
- 两个独立输出目录连续构建；
- wheel、sdist、plugin ZIP 字节一致；
- 最终 ZIP 从隔离目录真实加载；
- 最终 ZIP 不含 tests、companions、spikes、旧 executor、PyMySQL 和旧动作；
- 生成新 candidate/artifact manifest；
- 0.3.1 原制品哈希保持不变。

### Task R6.3：双重最终只读复审

两路独立复审都必须覆盖：

1. 凭证外发 wire 0 泄漏；
2. 审批前真值解析 0；
3. 审批后目标绑定与 TOCTOU；
4. HTTP redirect/host/header 边界；
5. env/stdin 生命周期；
6. 结果回流保护；
7. 现有 Hermes 使用能力非干扰；
8. 旧架构残留和死代码扫描；
9. 源码、文档、manifest、最终 ZIP 身份一致。

任一路 BLOCKING 都不得发布。

## 10. 文档同步

最终实现完成后更新：

- `docs/Credential-Guard-通用凭证边界重构方案.md`：状态和真实结果；
- `docs/plan.md`：新产品方向和里程碑；
- `HANDOVER.md`：当前版本、制品和 worker 状态；
- `CLAUDE.md`：新边界和文档入口；
- 新安装/迁移/使用指南：只保留当前版本，不把旧动作写成现行功能；
- 历史 M2/M3 报告保持历史身份，不改旧哈希凑绿。

## 11. 当前下一步（2026-08-05）

R0、R1A、R1B、R2、R3A、R3B、R3C、R4 已完成并正式签收：

1. 所有正式工具结果统一进入一个权威结果守卫；
2. 已登记凭证、支持编码变体、Authorization/Cookie、异常栈和 PEM 残余均按统一语义处理；
3. 守卫失败固定 fail closed，不虚构目标副作用回滚，不自动重试；
4. 聚合凭证数和总变体字符预算与外发守卫复用同一上限；
5. 真实 `discover_plugins → PluginManager → AIAgent.run_conversation → Provider` 链在中立 cwd 和临时安装插件下通过；
6. R4 专项 55 passed、非干扰 E2E 10 passed、全量 1435 passed / 2 xfailed / 0 failed；
7. 技术候选冻结为 283 files / 29059 manifest bytes / `226fb1999179d17020ed2f05d7834cfaa63279d294ada3c64d3de9620d29717e`，Cursor 与两路 Hermes 最终终审全部 PASS。

当前下一步是与用户共创 R5 旧架构清理方案；未经批准不自动删除旧代码。R4 签收不代表 R5 清理、R6 发布物构建或正式 worker 升级已经完成。