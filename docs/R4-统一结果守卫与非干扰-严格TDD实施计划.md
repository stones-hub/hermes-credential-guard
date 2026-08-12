# R4 统一结果守卫与非干扰严格 TDD 实施计划

> **For Hermes:** 使用 subagent-driven-development 按切片执行；每个切片严格 RED → 最小 GREEN → mutation。编码 Agent 只能交付待主代理验收候选，不得冻结或签收。

**目标：** 在不修改 Hermes 核心、不改变工具真实执行语义的前提下，让所有正式工具结果通过同一个权威结果守卫；能安全脱敏则保持原格式返回，不能确认安全则固定文本失败关闭，并证明日常工具无干扰。

**架构：** 复用 Hermes 正式 `transform_tool_result` Hook、现有 registry/redactor/private-key 检测；新增一个无状态 `result_guard.py` 作为唯一权威实现。HTTP/process 只复用同一规则作为执行边界保险，不再定义独立脱敏格式。

**技术栈：** Python 3.9+、Hermes Plugin API、pytest、临时 HOME/HERMES_HOME、合成诱饵、loopback 假 Provider/目标；无新增第三方依赖。

---

## 0. 复用与自研边界

| 组件 | 复用 | 自研 |
|---|---|---|
| Hook 调度 | ◎ Hermes `transform_tool_result` | 0 行宿主改动 |
| 已登记凭证与编码变体 | ◎ `redactor.py` / registry | 仅补结果语义 |
| 私钥检测 | ◎ `sensitive_paths.py` | 不扩建通用 DLP |
| 外发零泄漏兜底 | ◎ 现有 `llm_request` / `llm_execution` | 不新增第三道门 |
| 统一结果守卫 | ◉ Credential Guard | 新建一个小型无状态模块 |
| 非干扰 E2E | ◉ Credential Guard | 临时环境与合成输出 |

## 1. 强制范围

### 允许修改

- `credential_guard/result_guard.py`（新建）
- `credential_guard/hooks.py`
- `credential_guard/adapters/http.py`
- `credential_guard/adapters/process.py`
- `tests/test_injected_result_guard.py`（新建）
- `tests/test_non_interference_v2.py`（新建）
- `tests/test_result_guard_authenticity_gate.py`（新建）
- `scripts/run_v2_non_interference_e2e.py`（新建）
- R4 任务书、证据、报告和最终冻结 sidecar

### 默认禁止修改

- Hermes 源码和正式 Profile
- R0–R3 已冻结生产语义与历史 sidecar
- `dist/`、版本号、发布 metadata
- R5/R6 文件、旧架构注册与依赖
- 真实 `~/.ssh`、真实业务凭证和真实目标

任何超范围生产修改必须先返回 BLOCKING，由主代理决定，不得自行扩展。

## 2. 共同产品常量

固定失败文本唯一为：

```text
工具可能已经执行，但返回内容未通过安全检查，原始结果未返回。请独立核验目标系统的真实状态。
```

未知高置信度秘密占位符唯一为：

```text
<REDACTED_SECRET>
```

已登记凭证继续使用现有稳定逻辑代号：

```text
<CREDENTIAL:name>
```

不得同时保留旧固定安全 JSON 作为 R4 正常产品语义；历史测试如依赖旧文案，必须按职责判断是迁移还是历史保留，不能通过兼容双输出绕开。

## 3. 切片 A：建立格式保持基线

**目标：** 先证明现有 Hook 会重排 JSON，建立明确 RED。

**测试：** `tests/test_injected_result_guard.py`

### RED

1. 干净普通文本必须逐字相同；
2. 带空白、字段顺序和缩进的干净 JSON 必须逐字相同；
3. JSON 字符串中命中已登记凭证时，只替换值片段，其他字节保持不变；
4. Markdown、表格、中文、数字、布尔值保持不变。

运行：

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest \
  tests/test_injected_result_guard.py -k 'preserve or registered' -q -p no:cacheprovider
```

期望：现有 `hooks.py` 的 JSON parse/serialize 用例 RED。

### 最小 GREEN

新建 `result_guard.py`：

- 接收字符串和 registry 快照；
- 对已登记凭证调用现有长度降序变体替换；
- 不 parse/serialize JSON；
- 替换后做已登记变体零残留复查；
- 返回字符串或固定失败文本。

`hooks.py` 调用该权威函数，保持现有受保护路径前置阻断。

### Mutation

- 把 JSON parse/serialize 加回去，格式保持测试必须 RED；
- 删除零残留复查，残留 mutation 必须 RED；
- comment/format-only 测试代码变化不得影响健康 carrier。

## 4. 切片 B：高置信度未知秘密

**目标：** 在不构建通用 DLP 的前提下覆盖最终目标明确要求。

**测试：** `tests/test_injected_result_guard.py`

### RED 矩阵

对文本、JSON 格式字符串和异常文本分别覆盖：

- `Authorization: Bearer ...`
- `Authorization: Basic ...`
- `Proxy-Authorization: ...`
- `Cookie: session=...`
- `Set-Cookie: session=...; Path=/; Secure`
- JSON/日志中的明确 `password`、`token`、`secret` 字段
- 私钥 PEM、percent/Base64/URL-safe Base64/JSON escape 现有支持形态

期望：

- 认证 Header/Cookie 值整段替换为 `<REDACTED_SECRET>`；
- 明确字段只替换字段值，结构不变；
- 私钥可完整定位时替换；无法可靠定位时固定文本阻断；
- Request ID、Trace ID、UUID 保留。

### 最小 GREEN

只实现有界、固定的高置信度识别器：

- 固定 Header 名集合；
- 固定敏感字段名集合；
- 复用 private-key detector；
- 禁止熵检测、通用 JWT/云 Key/Webhook 库和可配置正则引擎。

### Mutation

每种类型单因子弱化，必须由对应测试杀死；不得依赖无关异常假红。

## 5. 切片 C：异常、失败关闭与副作用语义

**目标：** 真实错误可排障，守卫错误不泄漏、不冒充工具失败。

### RED

1. 安全异常文本保留错误类型、错误码、Request ID、Trace ID；
2. 异常中的凭证定点替换；
3. 注入 `redactor`、unknown-secret scanner、private-key scanner、零残留 checker 异常；
4. 所有守卫异常均返回唯一固定安全文本；
5. 固定文本不含 `ok=false`、`failed`、`success`、`rollback` 等工具结论；
6. 结果守卫阻断后，下游工具调用计数不增加，且没有第二次调用；
7. 日志只允许固定告警与安全原因码，不允许原文、异常对象或替换片段。

### 最小 GREEN

- `result_guard.py` 内部统一捕获并返回固定文本；
- `hooks.py` 只记录固定警告；
- 不引入重试器、回滚器或结果状态数据库。

### Mutation

- 恢复旧安全 JSON；
- 把原始异常拼入日志/结果；
- 守卫失败后重调一次工具；
- 任一 mutation 必须 RED。

## 6. 切片 D：HTTP/process 复用同一标准

**目标：** 关闭 `***`、`PROCESS_OUTPUT_LEAK` 与统一 Hook 语义不一致。

### RED

1. HTTP body/Header 回显本次 token/password/Basic 组合时，适配器输出使用 `<CREDENTIAL:name>`；
2. process stdout/stderr 回显本次 token 时，保留业务输出，只替换秘密，不整份改为 `PROCESS_OUTPUT_LEAK`；
3. 随后再进入 Hook 结果不变（幂等）；
4. `SecretLease` 关闭后不可读；
5. 不新增持久快照、TTL、缓存文件或全局真值表。

### 最小 GREEN

- 权威函数允许显式传入本次短期 `(credential_name, secret material)`；
- HTTP/process 在 lease 关闭前调用；
- 现有 registry 与本次短期 material 合并为本次函数内替换视图；
- 完成后不保留引用；
- 适配器原有执行、timeout、body/output 上限和进程组语义不变。

### Mutation

- 适配器改回 `***`；
- process 改回整份 leak error；
- Hook 二次处理改变结果；
- mutation 必须 RED。

## 7. 切片 E：大结果与零残留完整性

**目标：** 证明实际待发送完整字符串被检查，不预建流式平台。

### RED

- 使用接近现有安全上限的大字符串；
- 敏感值分别放首部、中部、尾部；
- 敏感值跨测试构造的常见缓冲边界位置；
- 干净大日志必须完整原样；
- 扫描异常或复查异常必须固定文本阻断。

### 最小 GREEN

仅在现有字符串 Hook 上做有界完整扫描；不得新增临时文件、队列、后台任务或跨块状态机。

### Mutation

- 只扫描前 N 字节；
- 只复查首尾；
- 尾部凭证必须杀死假实现。

## 8. 切片 F：正式 Hook 真实性

**目标：** 证明不是直接调用函数或测试 wrapper 冒充全局保护。

**测试：** `tests/test_result_guard_authenticity_gate.py`

### RED

- 使用真实 PluginManager 加载插件；
- 不替换 callback 列表、不重注册 handler、不调用本地 wrapper；
- 通过公开 AIAgent 工具结果回流链观察 `transform_tool_result → result_guard`；
- 普通工具和注入工具均进入同一个生产函数身份；
- Provider 原始请求中所有合成真值、支持编码变体、认证 Header 原值、PEM 计数为 0；
- 机械拒绝 hardcoded evidence、fake hook、transport override 充当 R4 证据。

### Mutation

- 绕过 Hook；
- Hook 返回原始结果；
- evidence 计数硬编码为 0；
- 删除权威函数进入证据；
- 每项必须 RED。

## 9. 切片 G：非干扰矩阵

**测试：** `tests/test_non_interference_v2.py`  
**E2E：** `scripts/run_v2_non_interference_e2e.py`

### 场景

- 普通聊天和无凭证工具；
- 临时目录文件读写/搜索；
- 临时测试 Git 仓库的 status/diff/log；
- pytest 与 Python 内存 compile；
- terminal、execute_code 合成输出；
- 临时 HOME 的 SSH Config 与 loopback 假 SSH 结果；
- Docker/systemd 只做合成参数/输出与命令结果转换，不连接 daemon/真实服务；
- JSON、Markdown、表格、中文、普通 Base64、Git SHA、SHA-256、UUID、Request ID、Trace ID。

### 完成判据

- 干净结果前后逐字相同；
- 不增加审批；
- 工具调用次数、退出码、临时文件内容和副作用不变；
- 未安装插件与安装插件的安全结果一致；
- 禁止真实网络、真实 `~/.ssh`、Docker daemon、systemd、正式 Profile 和真实目标。

## 10. 切片 H：主代理验收、冻结与复审

### 主代理独立运行

1. R4 专项；
2. R4 正式 Hook E2E；
3. R4 非干扰 E2E；
4. R0–R3 全部回归；
5. 当前全量 pytest，必须 0 failed；
6. 所有 Python 文件内存 compile；
7. 历史 0.3.1 dist 四个 SHA-256 不漂移；
8. 正式 Hermes 源码 `git status --short` 无输出；
9. 不读取或指纹核验正式 worker 配置正文，由用户保留正式 worker non-interference 证据。

### 候选冻结

仓库无 Git：

- 使用候选外固定规范化 manifest；
- sidecar self-exclude；
- 两套独立枚举器路径集、manifest bytes、SHA-256 一致；
- 复审前后候选身份稳定。

### 三路最终只读复审

- Cursor：规格与代码范围；
- Hermes 1：安全边界与真实 Hook；
- Hermes 2：证据真实性、非干扰和冻结身份。

三路均明确 PASS 后才：

- 将 R4 标记完成；
- 更新 CLAUDE.md、HANDOVER.md、实施计划和当前情况 HTML；
- 停在 R5 方案门前，不自动进入 R5 编码。

## 11. 计划自审

- 无待定占位；
- 无新第三方依赖；
- 无独立日志、数据库、审批、重试、回滚或流式平台；
- 未扩展为通用 DLP；
- 未修改最终目标；
- 未混入 R5/R6；
- 每个生产切片均有 RED、最小 GREEN 和 mutation；
- 任何 reviewer BLOCKING 都不得签收。
