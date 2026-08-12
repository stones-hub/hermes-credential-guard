# HANDOVER

## 当前状态（2026-08-12）

**R8 / 0.4.2：技术签收与发布收口均 PASS（HTTP+HTTPS 统一凭证请求）** — `http_credential_request` 单一
binding 的 `target.scheme` 精确接受小写 `http`/`https`；共用禁代理、禁重定向、timeout、
响应上限与统一结果守卫；HTTP 审批固定明文传输警告；HTTPS TLS 校验保留；无第二套执行器、
无 CIDR/`network_policy`。方案：`docs/R8-0.4.2-HTTP与HTTPS统一凭证请求方案.md`；
designated 报告：`docs/R8-0.4.2-验收报告.md`。当前活动 `dist/` 只保留 0.4.2 四制品，候选身份
`97280c65…b43c`；`main` 已提交并推送到 `origin/main`。本轮已为 README 本地 ZIP 安装补上自动
SHA-256 校验、解压/安装/升级失败关闭与安装后根目录/版本检查，并以错误 ZIP、`mv` 失败及正常
升级行为门禁实测 13 passed（已覆盖在线安装、启用和更新失败关闭）；当前快照全量非构建 1718 passed / 3 xfailed / 0 failed，ZIP E2E
2 passed，在线安装当前远程 `main` 也已在临时 Hermes Home 中重验为 0.4.2 且工具集 enabled；
compileall 与 `git diff --check` 通过。发布收口安全/安装复审与规格/证据/稳定身份复审均明确
PASS。随后捕获的 1 次 `concurrent_no_cross=False` 已由 200 次压力测试稳定复现 5 次，根因是
R0 测试 Harness 在两个线程中嵌套 process-global `unittest.mock.patch`；生产 `credential_guard`
未参与。现已改为父线程单一 patch scope，并断言两个并发调用均返回成功；修复后累计 900 次压力
复验零失败，专项 248 passed、全量 1718 passed / 3 xfailed / 0 failed，最终增量独立只读终审
明确 PASS。未操作真实 default/worker；本轮发布收口改动尚未 commit/push。

**R7：PASS（行政签收）** — 两个插件兼容性 Bug 已关闭，并获两路独立只读复审局部 PASS：
（1）超长普通文本内嵌完全 Unicode-escape 合成 PEM 由有界 JSON-escape 子候选检出，
长普通提示词不再误阻断；（2）本地阻断改为 `LocalBlockRequest` 带外状态，Provider=0，
合法模型名/旧 marker 不碰撞；（3）长文本整段跳过 / JSON-escape 提取 / LocalBlockRequest
消费三类 load-bearing mutation 承重。主代理独立全量：`1616 passed, 3 xfailed, 0 failed`，
compileall exit 0。

**产品覆盖边界（最终拍板）**：Credential Guard 只是独立插件。主聊天 `conversation loop`
与主链工具结果受保护；`auxiliary_client.call_llm`（title/compression/vision/oneshot/
session_search 等）属于 Hermes 当前插件接口不覆盖的宿主能力边界，**不是**本插件待修 Bug。
关闭 `auxiliary.title_generation` 只能减少一条暴露路径，不能等同于全覆盖。不修改 Hermes、
不 monkey patch、不声称覆盖全部模型外发。否决的「统一拦截全部模型外发」方案保持禁止执行；
本里程碑的 R8 仅指 HTTP/HTTPS 统一凭证请求，与该否决项无关。
方案：`docs/R7-Hermes当前版本真实外发兼容性修复方案.md`。

**0.4.1 属于已签收的历史发布候选**：见 `docs/R7-0.4.1-验收报告.md`。当前活动版本与发布目录统一为 0.4.2。

Credential Guard 已完成从 0.3.1 固定 MySQL/SSH 动作架构到“外发脱敏 + 审批后通用本地注入 + 结果脱敏”配置化凭证边界的重构。

现行路线真源：

- `docs/Credential-Guard-通用凭证边界重构方案.md`
- `docs/Credential-Guard-通用凭证边界实施计划.md`

已签收：

- **R0：PASS** — Hermes `tool_request → pre_tool_call → tool_execution` 审批后注入命门已实测成立。
- **R1A：PASS** — 单一 `credential-guard.json` 的严格 Schema、安全迁移、原子写入和故障恢复已签收。
- **R1B：PASS** — 正式 Provider 外发与工具结果保护已唯一切到 `credential-guard.json`；旧双文件不回退。最终报告：`docs/R1B-单文件正式运行链路切换-实测报告.md`。

**R2：PASS（2026-08-03 正式签收）** — 第八轮关闭最终双审两个 blocker：（1）有界 `InvalidMarkerStore` 替换无界 `_INVALID`；（2）冻结集合纳入 `r2_freeze_evidence.py`。主代理独立验收为专项 22 passed、真实性门禁 + 主 Agent + E2E 37 passed、全量 1025 passed / 2 xfailed / 0 failed、compileall 通过；技术终审前代码复审 workspace 摘要 `53b17f9d7aee659b47a0258e0c1532ee1cbb178042581449d23231d7d3369264`（209 文件，当时复算两次一致）；行政回填完成后的当前 workspace 身份记录在递归排除的 `.r2-freeze-evidence.sha256`（209 文件，连续复算一致），Cursor 与两路 Hermes 最终只读复审均 PASS。旧摘要 `4c4b4113…` 已作废。报告：`docs/R2-逻辑引用审批绑定与防偷换-实测报告.md` §16–§17。未修改 Hermes 核心。

**R3A：PASS（2026-08-04 正式签收）** — 已完成注入内核和 HTTP Header 审批后本地短注入闭环。真实主 Agent 顺序为 `tool_request → tool_execution → pre_tool_call → approval_gate → handler → consume → resolve → adapter`；正式 HTTPS transport 禁止环境代理和重定向、保持 TLS 校验，并对正常响应及 `HTTPError` 的真实嵌套 socket 执行总 deadline。主代理非沙箱验收：transport + evidence hygiene 18 passed、R3A + 历史身份 78 passed、R2 主链 48 passed、全量 1099 passed / 2 xfailed / 0 failed、compileall 通过。Cursor 与 Hermes 安全复审 PASS；冻结排序口径纠正后独立 reviewer 最终 PASS。最终冻结身份：231 文件，`f79169208799cffd15f617e62fa5d2073e830df1e8be2fdb67f5d8a07fd5ba80`，记录于递归排除的 `.r3a-freeze-evidence.sha256`。

**R3B：PASS（2026-08-04 正式签收）** — 已完成固定本地程序 env/stdin 审批后单次注入。结构化工具仅暴露 `target + credential`；程序、argv、env 名和 stdin 格式均由本地 binding 固定。进程执行使用不可变身份副本、非阻塞统一 deadline I/O、Popen 后立即建立合同 PGID，timeout/超限/异常会 TERM→KILL 整组并 reap。公开 AIAgent + loopback provider 证明 Provider/审批/结果真值计数为 0；真实 PluginManager 主链无自注册。主代理非沙箱验收：R3B 125 passed、R3A 27、R2 主链 48、全量 1225 passed / 2 xfailed / 0 failed、compileall 通过。Cursor、Hermes 安全和证据/冻结复审均 PASS。最终冻结身份：252 文件，`f9eef16355baf7b1210eed3f11756fbead68c50f9e8a2efadef26844ded01952`。

**R3C / 整个 R3：PASS（2026-08-04 正式签收）** — 已完成 HTTP Header、固定程序 env、固定程序 stdin 三适配器在真实公开 AIAgent + PluginManager 主循环下的总验收。公开 wire 覆盖 approve/deny/mutate/replay/timeout，same-turn replay 四元身份机械一致，宿主 timeout 只认不可变 raw 与真实 `_await_gateway_decision`；Provider/审批/trace/result 真值计数均为 0；父环境与后续子进程无残留；manifest 原样加载且四工具与 registry 一致。主代理非沙箱终验：真实性+wire 57 passed、R3C 72、R3B 125、R3A 27、R2 48、全量 1297 passed / 2 xfailed / 0 failed、compileall 通过、正式 Hermes 源码干净。Cursor、Hermes 安全、Hermes 证据/冻结三路最终复审全部 PASS。最终技术冻结：263 文件、manifest 26,816 bytes、`15ad9c20c8b7e0da1653e3b3e3813cc2042470c5192027aa2eabb41648b0be28`。

**R4：PASS（2026-08-05 正式签收）** — 已完成所有正式工具结果回流前的统一权威守卫：已登记凭证保留 `<CREDENTIAL:name>` 身份，未知高置信秘密使用 `<REDACTED_SECRET>`，认证 Header/Cookie 整值脱敏，无法确认安全时返回固定安全文本且不自动重试或虚构回滚。registry 与本次 session material 共用凭证数量和总变体字符聚合预算。真实证据从中立 cwd 加载临时安装插件，经 `discover_plugins → PluginManager → AIAgent.run_conversation → Provider`，callback/hooks/result_guard 的 `__file__` 均绑定安装树，破坏安装副本的 mutation 证明不会回落源码树。主代理终验：关键集合 93 passed、非干扰 E2E 10 passed、R2–R3 回归 401 passed、全量 1435 passed / 2 xfailed / 0 failed、165 个 Python 文件内存编译通过。最终技术候选：283 文件、manifest 29,059 bytes、`226fb1999179d17020ed2f05d7834cfaa63279d294ada3c64d3de9620d29717e`；Cursor 与两路 Hermes 最终终审全部 PASS。R3 sidecar、最终目标和历史 0.3.1 dist 未改；正式 worker 未操作。

历史窄修保留：第七轮证据假绿窄修（§15）；第六轮 plan-key insert-only + tombstone（§13）；第五轮 config lock（§12）；第三轮正式引用工具（§10）。

R1B 最终独立执行证据：

```text
execute_code 路径门禁专项 + R1B：89 passed
R1A 配置/迁移/Profile 边界回归：175 passed
file_backend + plugin_registration + tool_injection：35 passed
全量 pytest：735 passed, 2 xfailed, 0 failed
compileall：exit 0
```

**R5：PASS（2026-08-06 正式签收）** — 旧架构彻底清理完成，两套架构并存的问题解决。

删除 **50 个批准文件，精确命中**（批准 50 = 实际消失 50，超范围 0，漏删 0，经三方独立对账）：
7 个生产模块（`tools.py` / `mysql_executor.py` / `ssh_tools.py` / `ssh_executor.py` /
`targets.py` / `file_backend.py` / `deps_integrity.py`）、整个 vendored PyMySQL（`deps/` 25 个文件）、
17 个旧测试与 E2E 脚本。工具集从四个固定动作收到两个通用外壳
（`http_credential_request` / `credential_process_run`）。另清理 `approval.py` 四个零调用者死函数
（`_normalize_args` / `_args_digest` / `_approval_rule_key` / `_scrub_message`，355→320 行）——
现役审批绑定是 `_reference_rule_key`（绑 nonce | tool_call_id | tool_name | args_digest |
config_digest | binding_digest 六项）加 `canonical_args_digest`，严格强于被删的旧实现
（后者只绑两项且显式丢弃 `tool_call_id`）。

auditor 旧架构残留 **520 → 38**；8 个旧类别（`old_registration` / `old_module` / `old_tool_name` /
`vendored_pymysql` / `pymysql_dependency` / `pymysql_import` / `pymysql_package_data` /
`builder_legacy_dependency`）全部零出现，剩余 38 条（26 `dual_file_runtime` + 12
`unresolved_dynamic_sink`）全在 tests/ 与 migration 域且在 `_EXPLAINED_RESIDUE_PATHS` 白名单内。

主代理终验：全量非构建 **1504 passed / 4 xfailed / 0 failed**；三类 R5 门禁 + R3 两门
**328 passed**；compileall exit 0；phase `final`、`classify_workspace` 零错误。
`dist/` 四个 0.3.1 制品、五份历史冻结证据、R3 carrier `scripts/run_r3c_wire_e2e.py`
（`82deddbd…`）与 canonical AST pin（`5d97004c…`）全程零漂移，全量跑完确认未触发构建。

**三路最终只读复审全部 PASS、零 BLOCKING**，均绑定同一候选身份并各自独立复算：
Cursor 综合复审（11 条产品边界逐条保留）、Hermes 证据真实性与假绿复审（7 项 mutation 全 RED、
用删除前快照硬证 `.r5-tdd-evidence.log` 追加式未篡改）、Hermes 安全边界复审
（17 行「快照行号 → live 承担者行号」对照表证明无独有安全逻辑丢失，另实测陈旧 `.pyc` 无法复活
被删模块）。安全边界路认定四处 live **更严**：新增文件大小上限、target 整类
`MANIFEST_REQUIRES_MANUAL_REVIEW` 拒绝优于值域校验、`validate_fixed_argv` 禁解释器 basename、
整个 registry 零残留断言优于单值 substring 检查。

最终技术冻结身份：**270 文件 / 27928 manifest bytes /
`c8a60656fa397c26e65137ba20e64d05ee5ad6ea02b9ffd207a59fad50eb17d8`**，
记录于递归排除的 `.r5-freeze-evidence.sha256`（旧身份 `0830183d…`（269 文件）已由
`SUPERSEDES` 行标记作废，作废原因为死代码清理）。删除唯一退路是 repo 外快照
`/Users/yelei/data/code/snapshots/cg-pre-r5-delete-20260805.tar.gz`
（1141258 字节 / `ab7b500c…` / 326 成员）。

**R5 遗留三项已知缺口 —— R6 后的最新状态（2026-08-06）**：

1. `KNOWN_GAP_1` — **已关闭（R6 slice 4b）**。原缺口：A2 决策退役了 R3 wire E2E 的 5 条
   live 断言，退役根因是 carrier 的 `_FORMAL_PROVIDED_TOOLS` 硬编码四工具而 Slice C 后
   只剩两个，且 carrier AST 已冻结不可改。**注意缺口范围比字面更窄**：`_assert_replay()`
   的约 25 条断言全程未退，实际只退役了 `manifest_registry_tools_match` 一项。
   4b 的关闭方式是**不动历史 carrier**，改在 0.4.0 已安装 ZIP 上重建该性质
   （manifest 从 ZIP 内 `plugin.yaml` 读、registry 从装出来的模块 `register()` 后读，
   两边都是 0.4.0 故不再有四/二工具冲突），并建立 15 格矩阵
   （http/env/stdin × approve/deny/timeout/mutate/replay）。
   原 `test_r5_wire_full_main_chain_placeholder`（`assert False`）已翻面为
   `test_r5_wire_full_main_chain_matrix_closed`；那 5 条 R3 测试**仍保持退役状态**
   （历史证据，docstring 已指向 `tests/r6_installed_zip_wire_matrix.py`）。
2. `KNOWN_GAP_2` — **仍未关闭**。`MIGRATION_V2_INVALID` 防御性兜底无测试覆盖
   （该错误码仅出现于 `credential_guard/migration.py:957,959`）。兜底保留，覆盖延后，
   不阻塞 R6 交付。
3. `KNOWN_GAP_3` — **已关闭（R6 slice 3）**。原缺口：
   `tests/test_production_package_scan.py` 仅为静态源码/包成员契约，从不打开真实制品。
   slice 3 建立了真实制品成分审计（逐成员打开 ZIP/wheel/sdist），
   0.4.0 plugin ZIP 实测 **35 成员**（0.3.1 为 48，↓13 = 删掉的 `deps/pymysql` 19 个
   与 7 个旧模块），七类禁止项（旧模块/pymysql/测试/scripts/密钥材料/任务证据/pyc）
   全部命中 0，并含私钥 PEM 头逐成员字节扫描。

非阻断观察项：`release_identity.verify_artifact_manifest()` 无参调用抛 `ValueError`
—— **已在 R6 slice 1 修复**：`vendored_deps_manifest_sha256`（及历史第二键名
`vendored_tree_manifest_sha256`）已从 manifest 键集合与 `release_identity.py`
的 4 处引用中精确删除，顶层键集合收缩为 6 键。

**R6 状态（2026-08-06 收尾复核后）**：技术侧 slice 1–5 完成，但 **R6 未交付完成**——
完成标准第 10 条（0.4.0 的独立安全复审）与第 12 条（用户亲自安装验收）均未执行。
详见本文件末「下一步」与「R6 收尾复核」两节。

## 当前里程碑

**R3A、R3B、R3C：PASS（2026-08-04 正式签收）；整个 R3 已关闭。**

R2 只负责：

1. 定义 `<CREDENTIAL:name>` 的严格逻辑引用语义；
2. 在 `tool_request` 阶段只分析引用，复用 R1B 已发布 snapshot，不解析本次执行真值；
3. 生成不可变、一次性的 `InjectionPlan`；
4. 将引用、工具、参数位置、业务目标、配置摘要、参数摘要、`session/turn/tool_call_id` 和 nonce 绑定到本次人工审批；
5. 审批后任一绑定项或 lstat 身份变化即作废，要求重新审批；
6. 普通聊天、模型输出和工具结果中的引用永不还原；
7. 正式注册结构化外壳 `http_credential_request`（schema/handler defence-in-depth；R3 前固定 adapter-not-ready）；
8. 跨进程协作 config lock；
9. 同 `(session_id, tool_call_id)` insert-only + 有界 tombstone；
10. 主 Agent Framework E2E 与备用 dispatcher 兼容路径分层证据。

R2 **不**实现 HTTP Header、env 或 stdin 的真实注入；这些属于 R3。

## 已确认产品边界

1. 可信区：本机 Hermes、Hermes 标准人工审批、Credential Guard、本地配置与本地执行器。
2. 不可信区：外部模型、Provider、模型生成参数和 Provider 返回内容。
3. 不实现第二套审批票据；复用 Hermes 标准审批。
4. 不把占位符全局还原成真实凭证；仅允许审批后的结构化本地执行边界解析。
5. 不复制 MySQL GRANT、Linux 权限、Jenkins Role、API Scope 等目标系统权限。
6. 不承诺 OS 级 DLP、同 UID 恶意进程防御或本机日志/WAL 永久零明文。
7. 所有开发和测试只使用临时 HOME/HERMES_HOME、合成诱饵和 loopback 假目标；不读取真实凭证和真实 `~/.ssh`。
8. 正式 worker 不由 Agent 安装、启用、配置、重启或验收；最终由用户按指南手工执行。
9. 0.3.1 三个历史制品保持冻结；重构完成前不覆盖 `dist/`。
10. 项目没有 Git 仓库；每轮以规范化文件 manifest 和核心 SHA-256 判断候选身份。

## 正式 worker 基线

用户于 2026-08-03 更新 Hermes 后确认的新基线：

```text
config.yaml SHA-256：14a331256164975805415cd0b64ee294d3716bf8a4d51865875f9f0f52fd5283
size：19011
mode：0600
mtime_ns：1785721366983204070
inode：14683120
device：16777234
```

只允许核对元数据和哈希；禁止读取正文或自动恢复。

## 下一步

1. R2、R3A、R3B、R3C、R4、R5 已签收，不再回改其冻结安全语义。
2. **R6 技术侧（slice 1–5）已完成**：0.4.0 制品在 `dist/`；designated 报告
   `docs/R6-0.4.0-验收报告.md`；用户指南 `docs/R6-0.4.0-安装与运维指南.md`。
   `KNOWN_GAP_1` / `KNOWN_GAP_3` 已关；`KNOWN_GAP_2`（`MIGRATION_V2_INVALID`）仍开。
3. **第 10 条已于 2026-08-06 关闭，现仅剩第 12 条（用户亲自在正式 worker 安装验收）。**
   （本节保留完整推进记录。注意：2026-08-06 收尾复核曾更正过一次口径 —— 此前写「只剩第 12 条」
   是验收报告完成标准表格漏列第 10 条导致的误判；那次误判与本次第 10 条真实关闭是两件事。）
   - **第 10 条：已关闭（2026-08-06，按原文口径两路 PASS；用户拍板路线乙）。**
     路 1 cursor-agent PASS + 路 2 Hermes 安全边界 PASS，均绑第 1 轮身份 `c1f7c91b…`。
     第 3 路证据真实性跑三轮未取得 PASS：第 1 轮 429 限流无结论、第 2 轮 BLOCKING×1、
     第 2b 轮 BLOCKING×2 —— **3 条 BLOCKING 全是主 Agent 冻结证据的文字笔误，产品侧零缺陷**。
     每修一次笔误就动身份、就得再复审一轮，形成自指循环（累计 7 身份 / 4 次派发）。
     用户拍板不再阻塞第 12 条，记为行政类遗留。未取得的是「第三方为侧车文字自洽签 PASS」，
     残余风险在文档表述层、不在代码或制品层。治根办法（未执行）：把叙述文字剥离到
     独立 `.r6-review-log.md`，侧车只留机器可校验键值。详见验收报告「尚存边界」第 1 条。

   - 以下为第 10 条推进过程的历史记录：
     身份锚点已建：`.r6-freeze-evidence.sha256` =
     **291 文件 / 30161 bytes / `c1f7c91b164dcab4aa89e8da5cf4da8baf5f83bec3c9dd9092d522ffb7978766`**，
     两次连续复算一致，侧车在自身 `EXCLUDES` 内故自排除自洽。
     复审任务书 `.r6-final-review-task.md`（五条禁令 + 九方面 + 900s 止损策略）。

     ```text
     路 1  cursor-agent            PASS       九方面齐全，零 BLOCKING
     路 2  Hermes 安全边界子代理     PASS       1–8 条齐全，零 BLOCKING
     路 3  Hermes 证据真实性子代理   未出结论    620s 死于 HTTP 429 + 迭代预算耗尽
     ```

     三路各自独立复算身份均得同值、`MATCHES_SIDECAR=True`，全程仓库零改动
     （主 Agent 每轮离场后独立复算复核，恒为 `c1f7c91b…`）。
     第 1 轮身份下全量读数被四个互不相干的执行体跑出同值：**1585 passed / 3 xfailed / 0 failed**
     （173.80s / 179.21s / 182.66s / 187.27s），五门禁 **317 passed**，ZIP 矩阵 **35 passed**。
     每份复审任务书本身都是一条已登记台账路径，各贡献 1 个 omit-mutation 参数化用例，
     故每加一份任务书全量与五门禁各 +1：第 2 轮（292 文件 / `f204b64f…`）**1586 / 318**，
     第 2b 轮（293 文件，身份哈希见侧车 `R6_TECHNICAL_CANDIDATE_SHA256`，不在此写死）
     **1587 / 319**。第 2 轮复审已用 `--collect-only`
     独立核实这个 +1 的来源。**两项读数必须同批更新**——第 2 轮的 BLOCKING 就是漏改全量造成的。

     **第 2 轮结论：BLOCKING（唯一一条，判定成立，已修）。** 七项必查里六项 PASS：
     身份复算、门禁 mutation 六例（它独立重做且把 neg4/neg5 换成了不同样本）、
     空集 vacuous（并纠正主 Agent 一处口径：台账基数 63 而非 62，62 是 round-1 口径）、
     xfail/skip 滥用（查出 `test_r5_provider_live_wire_decoy_count_zero` 的 body 是
     `assert False` 故永久不可 XPASS；用 `hasattr` 逐个验证 `not yet defined` 那批 skip
     的目标符号全为 True，确认零次触发）、证据日志两个前缀哈希逐字一致、基线复跑。
     唯一 BLOCKING = 侧车 `FULL_NOBUILD_PYTEST` 停在 1585 而同身份实测 1586 ——
     主 Agent 更新 `FIVE_GATES` 时漏了同步全量，属笔误非产品假绿。已修并派第 2b 轮复核。

     **两路各自独立发现同样两处主 Agent 笔误**（均非产品缺陷，已在本轮修正）：
     ① 残留审计实测 39 项，侧车/任务书初稿写 38 —— 照抄了 R5 侧车旧值。多出的一项是
     `scripts/build_release_artifacts.py` 的 `<module>` 级 sink（R5 只登记了同文件的
     `find_build_python`）。门禁按 kind + path 判定、从不看总数，
     `_ELIMINATED_RESIDUE_KINDS` 零命中，`tests/test_legacy_residue_gate.py` **73 passed**；
     该文件是构建器，不进最终制品。CLI exit 1 是「有任何残留项即非零」的设计。
     ② 侧车初稿记 `FULL_NOBUILD_PYTEST=1583` / `FIVE_GATES=315`，实测 1585/317 ——
     初稿采集时侧车自身与复审任务书尚未登记进台账，两者各贡献 1 个 omit-mutation
     参数化用例；collect-only 验证侧车 1 例 + 任务书 1 例 = 正好 +2。因侧车在
     `EXCLUDES` 内，身份哈希不受影响。

     **路 3 的核心验证由主 Agent 独立重做，六例全部通过**（参数注入，不往仓库写文件）：

     ```text
     control  健康 live 集合                errors=0  GREEN
     neg1     塞入未登记文件                 errors=2  RED
     neg2     从台账撤销 backfill 那条登记    errors=2  RED   ← 登记是承重的
     neg3     从台账撤销侧车那条登记          errors=2  RED
     neg4     已声明新增文件在 live 中缺失    errors=2  RED
     neg5     已声明删除的旧模块复活          errors=2  RED
     台账基数  ADDED 62 / DELETED 25 / PREFIXES 2 / MODIFIED 44，全部非空
     ```

     `neg2` 是判据核心：若那次台账登记属于「放宽门禁」，撤掉它应当仍绿；它转红，
     说明门禁在真判、登记只是精确补齐分类。台账基数全非空排除 vacuous 空集绿。

     按完成标准原文（「两路独立」）第 10 条已达成；按本项目里程碑三路惯例仍缺一份
     正式第三方结论，故记为进行中，正换内核重派路 3。
   - **第 12 条**：用户按安装运维指南亲自在正式 worker 上安装验收。Agent 不代操作。
4. 本刀未连接正式系统业务目标、未升级 worker、未改 `dist/` 八成员。

## R6 收尾复核（2026-08-06）—— 台账遗漏修复 + 口径更正

**发现**：slice 5 验收读数在 17:29 采集（当时全绿），**17:42** 落地的
`.r6-progress-html-backfill-task.md` 未登记进拓扑台账，此后全量转红且无人复跑。
本轮独立复跑实测：

```text
修复前   2 failed, 1580 passed, 3 xfailed
  test_r5_topology_gate::test_live_workspace_uses_phase_detector_and_classify
    → unclassified live paths: ['.r6-progress-html-backfill-task.md']
  test_r3c_historical_identity_gate::test_r3c_reclosure_identity_is_layered_from_r4_workspace
    → assert 292 == ((271 + 70) - 50)

修复后   1583 passed, 3 xfailed, 0 failed（174.24s）
五门禁   314 → 315 passed, 0 failed（34.66s）
compileall exit 0
```

**修复方式**：把该文件登记进 `R5_ADDED_PATHS`（`tests/test_r5_topology_gate.py`）与
`_R5_PLANNING_DELTA_PATHS`（`tests/test_r3c_historical_identity_gate.py`），
与前七个 slice 简报同一处理。**未删文件**——非 Git 仓库删除不可逆，登记可回退。
只改这两个 list 的成员，零逻辑、零生产代码改动。

**门禁未放宽的 negative 证明**：造未登记的 `.r6-negative-probe-unclassified.md`，
两条断言同时 RED、退出码 1；删除探针后恢复绿。计数 +1/+3 全部来自新登记路径在
omit-mutation 参数化集合中生成的用例（新条目真进了 mutation 覆盖，不是死条目）。

**本轮同时实测确认为真**（非照抄文档）：0.4.0 ZIP 35 成员逐成员与源码字节一致、
sha256 `1fbc8c38…` 与 versioned manifest 一致；双构建 3 passed 且 `dist/` 零漂移；
隔离安装 ZIP 15 格 wire 矩阵 35 passed（每格五种编码计数全 0）；非干扰 14 passed；
六份历史冻结侧车 + R3 carrier `82deddbd…` 逐个重算零漂移。

**教训**：验收报告里的绿只对采集那一刻成立。此后任何新增文件都必须复跑全量；
报告读数不可当作现时状态引用。另：完成标准表格必须逐条列全 12 项，
漏列一行就会在结论里变成「已通过」的错觉。

## 正式 worker 实况（2026-08-06 用户授权下只读核实）

**升级跨度比 `dist/` 与源码的差距更大 —— 正式 worker 装的是 `0.2.0`，比 `dist/` 里的
`0.3.1` 还旧一代，等于三代并存：**

| 位置 | 版本 | 形态 |
|---|---|---|
| 正式 worker（在跑） | **0.2.0** | 仅 1 个工具 `mysql_credential_action`；`deps/pymysql` + `pymysql-1.2.0.dist-info` 在位；旧模块仍在。配置店已有单文件但缺 HTTP `request` 块（0.4.0 会 `CONFIG_SCHEMA`） |
| `dist/`（当前可安装物） | **0.4.1** + 历史 0.4.0 + 冻结 0.3.1 | 现行安装用 `credential-guard-0.4.1-hermes-plugin.zip`；0.4.0 / 0.3.1 四成员各组保持历史冻结 |
| repo 源码（R7 / 0.4.1） | **0.4.1** | R7 插件兼容性修复 + 覆盖边界披露；历史 R6 0.4.0 报告与制品原样保留 |

**推论一 —— R0–R5 的安全能力在正式 worker 上一项都没生效。** 外发脱敏的编码变体覆盖、
单文件配置、审批绑定六项哈希、HTTP/env/stdin 三类通用注入、统一结果守卫，全部只存在于
repo 源码与测试中；正式 worker 仍停在项目最早期只能 `check_connection` 的形态。因此
「差多少才到最终目标」的准确答案不是「差一次打包」，而是**差一次跨两代的升级**
（0.2.0 → R6 新版本，中间跳过从未在用户机器上安装过的 0.3.1）。

**推论二 —— 配置路径比「换目录」更细。** R6 第五刀在禁 1 下实测：worker 店已是单文件
（缺 `request`）；机器上真实双文件对在临时副本上跑 0.4.0 `migrate-config` 得到按设计的
`MIGRATION_REQUIRES_MANUAL_REVIEW`。指南见 `docs/R6-0.4.0-安装与运维指南.md`。

本次第五刀核实边界：只读键名结构与元数据；未读凭证值、未读 `config.yaml`、未碰
`~/.ssh`、未改 worker 任何文件。

## 历史状态说明

- M1/M2/M3/M3.1 与 0.3.1 报告属于旧架构历史证据，保持原文件和哈希，不改写凑绿。
- 旧 `credentials.json + targets.json` 仅保留为显式迁移输入和 R5 前的兼容代码；正式外发运行链路已不再读取或回退它们。
- 旧 MySQL/SSH 四个固定动作将在 R5 删除，不再作为未来扩展模型。
