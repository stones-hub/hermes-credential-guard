# Hermes Credential Guard

## 项目定位

为 Hermes Agent 提供本机凭证安全边界：

1. 真实凭证只保存在本机受保护配置中；
2. 发往外部模型的完整请求中不出现真实凭证；
3. 工具结果进入模型上下文前再次脱敏；
4. 模型只在结构化工具参数中提交逻辑引用；
5. 人工审批通过后，本机执行边界才解析并短暂注入真实凭证；
6. 新业务目标主要通过配置扩展，不为每个业务场景新增固定动作；
7. 不复制目标系统权限，实际权限以 MySQL、Linux/SSH、Jenkins、API 等目标系统为唯一事实来源。

## 当前产品路线

现行方案真源：

- `docs/Credential-Guard-通用凭证边界重构方案.md`
- `docs/Credential-Guard-通用凭证边界实施计划.md`

当前状态（2026-08-12）：

```text
R0：PASS
R1A：PASS
R1B：PASS
R2：PASS（2026-08-03 正式签收；第八轮主代理验收、外部冻结和三路最终只读复审全部通过）
R3A：PASS（2026-08-04 正式签收；HTTP Header 审批后本地短注入闭环）
R3B：PASS（2026-08-04 正式签收；固定本地程序 env/stdin 审批后单次注入闭环）
R3C：PASS（2026-08-04 正式签收；真实主 Agent 三适配器总验收、全量、冻结及三路终审通过）
R4：PASS（2026-08-05 正式签收；统一结果守卫、非干扰、冻结及三路终审通过）
R5：PASS（2026-08-06 正式签收；旧架构彻底清理、50 个文件删除、三路终审通过）
R6：技术侧完成（slice 1–5）。第 10 条已于 2026-08-06 关闭 —— 按完成标准原文两路独立复审
PASS（cursor-agent 综合 + Hermes 安全边界，均绑身份 `c1f7c91b…8766`）；第三路证据真实性跑三轮
未取得 PASS，3 条 BLOCKING 全为主 Agent 冻结证据文字笔误、产品侧零缺陷，用户拍板记为行政遗留。
身份锚点 `.r6-freeze-evidence.sha256`（当前值见其 `R6_TECHNICAL_CANDIDATE_SHA256`）。
**仅剩第 12 条：用户亲自在正式 worker 安装验收。**
R7：PASS（2026-08-11 行政签收）—— 两个插件兼容性 Bug 已关闭并获两路独立只读复审局部 PASS：
（1）长普通提示词不再误阻断；完全 Unicode/JSON-escape 私钥仍可检出；
（2）local block 改为 LocalBlockRequest 带外状态，Provider=0，合法模型名/旧 marker 不碰撞。
主代理独立全量 1616 passed / 3 xfailed / 0 failed；compileall exit 0；既有 mutation 承重。
Hermes auxiliary_client.call_llm（title/compression/vision/oneshot/session_search 等）
绕过 plugin middleware 是当前 Hermes 插件接口不覆盖的宿主能力边界，不是本插件待修 Bug；
主聊天 conversation loop 与主链工具结果受保护；关闭自动标题只能减少一条暴露路径。
插件不修改 Hermes、不 monkey patch、不声称覆盖全部模型外发。
详见 docs/R7-Hermes当前版本真实外发兼容性修复方案.md；R8 统一拦截方案已否决禁止执行。
0.4.1 发布候选见 docs/R7-0.4.1-验收报告.md。
R8 / 0.4.2：HTTP 与 HTTPS 统一凭证请求（技术候选）—— `target.scheme` 精确接受
小写 `http`/`https`；共用禁代理/禁重定向/deadline/结果脱敏；HTTP 审批固定明文风险提示；
HTTPS TLS 校验保留。方案：docs/R8-0.4.2-HTTP与HTTPS统一凭证请求方案.md；
验收：docs/R8-0.4.2-验收报告.md。未签收发布；未操作正式 worker。
```

R5 关键事实：删除 50 个批准文件（7 个生产模块 + 整个 vendored PyMySQL + 17 个旧测试脚本），
工具集从四个收到两个（`http_credential_request` / `credential_process_run`），
auditor 旧架构残留 520 → 38（8 个旧类别全部消失，剩余全在 tests/ 与 migration 域）。
技术冻结身份：270 文件、27928 manifest bytes、
`c8a60656fa397c26e65137ba20e64d05ee5ad6ea02b9ffd207a59fad50eb17d8`，
记录于递归排除的 `.r5-freeze-evidence.sha256`。

**R5 遗留缺口状态（R6 收口）**：

1. `KNOWN_GAP_1` — **已关闭（R6 4b）**。在 0.4.0 已安装 ZIP 上重建
   manifest↔registry 一致 + 3×5 wire 矩阵（opt-in：
   `tests/r6_installed_zip_wire_matrix.py` /
   `scripts/run_r6_installed_zip_tests.py`）；占位符翻为
   `test_r5_wire_full_main_chain_matrix_closed`。R3 五条退役测试保持
   RETIRED 历史证据，不翻面。
2. `KNOWN_GAP_2` — `MIGRATION_V2_INVALID` 防御性兜底无测试覆盖（该错误码仅出现于
   `credential_guard/migration.py`）；兜底保留，覆盖延后。
3. `KNOWN_GAP_3` — **已关闭（R6 slice 3）**：真实制品成分审计见
   `tests/test_r6_artifact_composition.py`（`tests/test_production_package_scan.py`
   仍为静态源码/包成员契约）。

另有 1 项非阻断观察项：`release_identity.verify_artifact_manifest()` 无参调用会抛
`ValueError`（L333-337 仍取 `vendored_deps_manifest_sha256`，而 R5 后 `measured_release_fields()`
已不产此键）。方向为 fail-closed、零生产调用点，manifest 键集合调整已划归 R6。

R1B 最终报告：`docs/R1B-单文件正式运行链路切换-实测报告.md`。
R2 实测报告：`docs/R2-逻辑引用审批绑定与防偷换-实测报告.md`。
R3 方案：`docs/R3-通用本地凭证注入-落地方案.md`；R3A、R3B、R3C 已 PASS，整个 R3 正式签收。R4 也已完成并正式签收：统一结果守卫、聚合资源预算、真实 AIAgent 安装来源、完整非干扰、稳定冻结及 Cursor + 两路 Hermes 最终终审均 PASS。R4 方案与证据入口：`docs/R4-统一结果守卫与非干扰-落地方案.md`、`docs/R4-统一结果守卫与非干扰-严格TDD实施计划.md`、`.r4-tdd-evidence.log`、`.r4-freeze-evidence.sha256`。

R5 已完成并正式签收：旧架构彻底清理。方案与证据入口：`docs/R5-旧架构彻底清理-落地方案.md`、`docs/R5-旧架构彻底清理-严格TDD实施计划.md`、`docs/R5-门禁收口方案与绕过清单.md`、`.r5-tdd-evidence.log`（3300+ 行，追加式，已用删除前快照硬证前缀未被篡改）、`.r5-baseline-manifest.sha256`（294 条对账基线，自哈希 `696dd6e0…`）、`.r5-freeze-evidence.sha256`（技术冻结身份）。删除唯一退路是 repo 外快照 `/Users/yelei/data/code/snapshots/cg-pre-r5-delete-20260805.tar.gz`（1141258 字节、`ab7b500c…`、326 成员）—— 本项目非 Git 仓库，baseline manifest 只存 `path:sha256:len` 无法恢复内容。

## 威胁边界

```text
可信：本机 Hermes、Hermes 标准审批机制、Credential Guard、本地 credential-guard.json、本地执行器
不可信：外部模型、模型供应商、模型生成参数、Provider 返回内容
```

插件不负责防御 Hermes 宿主审批调度自身缺陷，不实现第二套审批票据。产品契约：审批前只分析逻辑引用，不解析本次执行真值；拒绝或超时则真值解析和下游执行均为 0；批准后才在受控本地执行边界复核并注入。

## 强制边界

- 不修改 Hermes 源码，优先使用独立插件接口。
- 正式运行配置唯一真源为 `credential-guard.json`；旧双文件仅作显式迁移输入，禁止运行时回退。
- 不使用环境变量作为长期业务凭证存储后端；R3 的 env 仅是单次子进程注入通道。
- 不做占位符全局替换；普通聊天、模型输出、工具结果中的 `<CREDENTIAL:name>` 永不还原。
- 不保存第二套 `permissions`、`allowed_actions`、`allowed_sql` 或 `allowed_commands`。
- 不提供显示、导出或打印真实秘密的命令。
- 不宣称 OS 级 DLP；本机日志/WAL 残余明文是已接受的可信区后续加固项。
- 开发和测试只使用合成诱饵、临时 HOME/HERMES_HOME 和 loopback 假目标；禁止读取真实业务凭证或真实 `~/.ssh`。
- 插件代码位于本目录，不初始化 Git，不推送远程仓库。
- 当前 Hermes 保持 `approvals.mode: manual`。
- Agent 不安装、启用、配置或重启正式 worker；最终由用户按指南手工验收。
- 0.3.1 历史制品保持冻结，R6 前不得覆盖 `dist/`。

## 文档入口

- 现行重构方案：`docs/Credential-Guard-通用凭证边界重构方案.md`
- 现行实施计划：`docs/Credential-Guard-通用凭证边界实施计划.md`
- R7 外发兼容性修复：`docs/R7-Hermes当前版本真实外发兼容性修复方案.md`
- R4 落地方案：`docs/R4-统一结果守卫与非干扰-落地方案.md`
- R4 严格 TDD 计划：`docs/R4-统一结果守卫与非干扰-严格TDD实施计划.md`
- R5 落地方案：`docs/R5-旧架构彻底清理-落地方案.md`
- R5 严格 TDD 计划：`docs/R5-旧架构彻底清理-严格TDD实施计划.md`
- R5 门禁收口方案与绕过清单：`docs/R5-门禁收口方案与绕过清单.md`
- R5 TDD 证据日志：`.r5-tdd-evidence.log`（追加式，含性质映射表、逐刀读数、三路终审前的全部实测）
- 当前进度：`HANDOVER.md`
- R0 实测报告：`docs/R0-Hermes工具参数审批后注入-实测报告.md`
- R1A 实测报告：`docs/R1A-单文件配置地基与迁移-实测报告.md`
- R1B 实测报告：`docs/R1B-单文件正式运行链路切换-实测报告.md`
- 历史总控计划：`docs/plan.md`（已置顶标明旧路线）
- M0-M3.1 文档：仅作为 0.3.1 历史证据，不代表现行产品方向。
