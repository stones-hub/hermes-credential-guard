# R1A 单文件配置地基与迁移 — 实测报告

> 日期：2026-07-31  
> 范围：仅 allowlist 内新建/修改；临时 `HOME` / `HERMES_HOME`；不接入运行链路、不删旧动作、不升版/构建/安装。  
> 判定：**PASS（按既定可信本机边界签收）**。第五轮身份绑定原子清理已完成；独立复审最后提出的“同一 uid 恶意进程在身份检查与 pathname 操作之间替换 inode”属于 OS 级敌对本机进程防御，不在本产品已批准威胁模型内，不阻塞进入 R1B。

## 0. 历史与独立复核（不得隐藏）

| 轮次 | 结果 | 说明 |
|---|---|---|
| 首轮专项 | 曾报 **81 passed** | 行为回归曾报 **35 passed**；独立读码与手工探针判定证据不足，**不得签收** |
| 后续独立复审 | **8 failed / 89 passed** | 暴露 B1–B4 及并发修复未完成窗口 |
| 第二轮 GREEN（假稳） | **114 passed** | 锁文件存在即锁、journal 无 ownership、`raise from None` 残留 `__context__`、frozen 仍有可写 `__dict__` 等；**独立对抗复审否决** |
| 第三轮 RED（A–G 失败测试落地后） | **30 failed / 111 passed** | 精确暴露：实例 `__dict__` 可写、`__context__` 非空、父目录未校验、O_EXCL 锁非 flock、journal v1 无 txid/ownership、隔离/补偿协议缺口 |
| 第三轮 GREEN（事务协议重构后） | **141 passed** | 见历史；**候选待复审，仍被第四轮对抗否决** |
| 第四轮 RED（5 个最终阻塞） | **11 failed / 153 passed** | 公开构造器绕过、嵌套 except 异常图、外国锁竞态、journal/temp ownership、最终旧名重建 |
| 第四轮 GREEN | **164 passed** | **候选待复审，被第五轮身份绑定清理否决** |
| 第五轮 RED（本轮 3 组阻塞） | **10 failed / 165 passed** | journal check→replace/unlink、exact-name temp、recovery 假 RECOVERED |
| 第五轮 GREEN（本轮） | **175 passed** | 见第 3 节；**候选待复审，未签收** |

首轮假绿原因摘要：

| 阻塞 | 首轮假绿原因 |
|---|---|
| B1 配置对象可篡改 | 仅测嵌套 mapping；私有字段曾可写 |
| B2 异常链泄露路径 | 仅查外层 `str/repr`；未扫完整 traceback / `__cause__` |
| B3 补偿吞恢复失败 | 可留半迁移 |
| B4 迁移源缺读后/备份前复核 | loader 有 post-read；迁移备份前身份未闭合 |
| B5 非原子 no-clobber | `exists()` + `os.replace()` 可覆盖竞争窗口 |
| B6 版本类型不严 | `2.0 == 2` / `True == 1` 静默放行 |

第三轮否决原因摘要（114 pass 仍被否决）：

| 阻塞 | 问题 |
|---|---|
| A 不可变绕过 | `@dataclass(frozen=True)` 实例仍有可写 `__dict__` |
| B 异常对象图 | `raise ... from None` 仅抑制打印；`__context__` 仍挂 OS/JSON 异常 |
| C 锁语义 | 以锁文件存在代表活锁；崩溃不自动释放；遗留锁阻断 recovery |
| D journal ownership | 仅 phase；恢复时把当前路径字节当 owned，可删竞争者 |
| E 事务顺序 | hardlink 已发布但 temp unlink 失败时 ownership 不清；旧源直接 unlink 有 TOCTOU |
| G 父目录 | 统一配置为秘密文件，父目录未强制 0700 |

第四轮否决原因摘要（141 pass 仍被否决）：

| 阻塞 | 问题 |
|---|---|
| 1 公开构造器 | `__init__(credentials, bindings, digest)` 接受未校验 mapping 与伪造 digest |
| 2 异常对象图 | 嵌套 `except` 内直接 `raise` 公开异常，`__context__` 挂带路径的 OSError |
| 3 外国锁竞态 | `_exists` 后 `O_CREAT` + 无条件 `fchmod`，可把 0644 外国锁改成 0600 并 flock |
| 4 journal/temp | `os.replace` 可覆盖外国 journal；recovery 前缀扫描删除外国 `.cg-migrate-*.tmp` |
| 5 最终旧名重建 | 首个旧源隔离后竞争者重建 `credentials.json` 仍可能 `ok=True` |

第五轮否决原因摘要（164 pass 仍被否决）：

| 阻塞 | 问题 |
|---|---|
| 1 Journal 更新/删除 TOCTOU | `_stat_journal_identity` 后 `os.replace` / pathname `unlink`；竞争者可在两步间替换 inode |
| 2 Temp 清理 TOCTOU | hardlink 发布后 / 写失败清理仍 pathname `_try_unlink`；exact-name 可被外国 inode 占据 |
| 3 恢复假 RECOVERED | 正式名“存在”即跳过，不验证 source digest；外国 formal + owned bak 仍清 journal 并报 `MIGRATION_RECOVERED` |

**本轮未读取或验证真实 worker 配置正文；未安装、启用或测试正式 worker。**

## 1. 目标

关闭第五轮 3 组已复现阻塞（身份绑定原子清理与精确 pre-state 恢复）；保持第四轮门禁；按 H 绑定候选 manifest。**不开始 R1B。**

## 2. TDD RED（本轮 identity-bound barrier，实现前）

```bash
.venv/bin/python -m pytest tests/test_config_v2.py tests/test_config_migration.py tests/test_profile_write_boundary.py -q -p no:cacheprovider --tb=line
# 10 failed, 165 passed
```

关键失败类别：

1. journal `os.replace` / pathname unlink 窗口植入外国 journal 后被覆盖或删除，迁移仍可能成功
2. exact-name / link-then-temp / recovery-listed temp / write-fail cleanup 删除外国 inode
3. 外国 formal + owned bak、owned residual、清 journal 前替换仍返回 `MIGRATION_RECOVERED`

## 3. GREEN（本轮候选快照）

```bash
.venv/bin/python -m pytest tests/test_config_v2.py tests/test_config_migration.py tests/test_profile_write_boundary.py -q -p no:cacheprovider
# 175 passed in 0.41s
```

## 4. 现有行为回归

```bash
.venv/bin/python -m pytest tests/test_file_backend.py tests/test_plugin_registration.py tests/test_tool_injection_foundation.py -q -p no:cacheprovider
# 35 passed in 6.58s

.venv/bin/python -m compileall -q credential_guard tests
# compileall_ok=true
```

全量 pytest：

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider
# 3 failed（边界预期）+ 既有 flaky / 1 曾因 docstring “Delete” 触发包扫描误报（已改措辞）后包扫描通过
# 以收口复跑为准：hermes_cli_e2e×2（sandbox PermissionError）、h9 argv probe flaky
```

全量失败与本轮 R1A 无关，且符合物理边界预期：

- `tests/test_hermes_cli_e2e.py`×2：sandbox 拒绝 `stat('/Users/yelei/.hermes/profiles/worker')`（`PermissionError`）
- `tests/test_m2_release_blockers.py::test_h9_short_lived_argv_probe_captured`：既有 argv 探针 flaky，非配置/迁移改动

## 5. 修改文件清单（本轮允许集）

| 路径 | 动作 |
|---|---|
| `credential_guard/migration.py` | Modify — identity-bound isolate/verify/delete；journal 无 replace；temp 身份记录；`_verify_exact_prestate` |
| `tests/test_config_migration.py` | Modify — 第五轮 barrier/exact-temp/pre-state 对抗测试；旧探针适配新协议 |
| `docs/R1A-单文件配置地基与迁移-实测报告.md` | Modify — 本文件 |
| `credential_guard/config.py` | （本轮未改） |
| `tests/test_config_v2.py` | （本轮未改） |
| `tests/test_profile_write_boundary.py` | （本轮未改） |

未改 `bindings.py` / `cli.py` 逻辑。未修改 `plugin.yaml` / 版本 / `dist/` / Hermes 源码。**未开始 R1B。**

## 6. Schema / 快照要点

| 项 | 行为 |
|---|---|
| v2 `version` | 仅 `type(version) is int and version == 2` |
| 快照 | `__slots__`；公开 `__init__(data)` / `from_mapping` / `load` 语义一致；深拷贝+深冻结+canonical SHA-256；拒绝外部 digest |
| 异常 | 所有 `except` 内只写错误码；离开动态上下文后再抛；`__cause__ is None` 且 `__context__ is None` |
| 父目录 | `load` / `migrate_config` 要求直接父（store）为普通目录、非 symlink、owner=euid、mode 0700 |

## 7. 迁移事务协议（本轮）

```text
fcntl.flock(.cg-migrate.lock)：
  O_CREAT|O_EXCL|O_NOFOLLOW 新建 → 仅新建 inode 可 fchmod(0600)
  EEXIST → O_NOFOLLOW 打开已有；校验 lstat/fstat 同 inode、普通文件、owner、mode==0600 后才 flock
  release 只 LOCK_UN+close，不 unlink

journal v2：txid + digests + source identity + published + temps(精确身份)
  首次创建：link no-clobber + identity-bound temp cleanup
  后续更新：isolate expected journal → verify → link no-clobber 发布新 journal
            → 身份绑定清理 isol 旧 journal；禁止 os.replace 覆盖共享 journal
  清理：isolate → verify expected → 仅删 isol；正式名被重建则 RECOVERY_REQUIRED
  temp：_OwnedArtifactIdentity(name/dev/ino/sha256/mode/owner/purpose)
        一律 identity-bound isolate→verify→delete；禁止 pathname unlink 共享名
  恢复：统一 _verify_exact_prestate（formals digest/mode/owner、无 new/bak/isol/temp、
        journal 仍为 expected）后才 _clear_journal；否则保留证据并 RECOVERY_REQUIRED

成功契约（清 journal 前与后再验证）：
  新正式配置 + 两个 .v1.bak 存在且验证通过
  两个旧正式名不存在
  无自有 isolation/temp/journal
  竞争者重建旧正式名 → 绝不删其字节；保留 journal/bak 证据；不得返回 ok
```

### 静态搜索 `os.replace` / `os.unlink` / `_try_unlink`

| 位点 | 为何不是共享对象的 check→path mutation |
|---|---|
| `_try_unlink` 定义 | 仅服务于已隔离的高熵 isol 名或失败写路径上已证明同 inode 的 isol |
| `_identity_bound_delete_isolated` | 先对 isol 做完整 identity 匹配，再 unlink **不可猜测** isol 名 |
| `_cleanup_failed_temp_inode` | O_EXCL 创建后仅当 isol 仍为同一 dev/ino 才 unlink isol |
| `_atomic_rename_no_clobber` 非 Darwin fallback | link 后核验 src/dst 同 inode，再 unlink **src 名**；Darwin 走 `renamex_np(RENAME_EXCL)` |
| journal / publish 路径 | **无** `os.replace`；发布一律 `os.link` no-clobber |

## 8. 完成判据（候选证据）

```text
journal_update_barrier_preserves_foreign=true
journal_delete_barrier_preserves_foreign=true
journal_publish_conflict_never_clobbers=true
exact_temp_replacement_never_deleted=true
link_then_temp_replacement_never_deleted=true
recovery_exact_temp_replacement_never_deleted=true
recovered_only_on_exact_prestate=true
foreign_formal_with_owned_backup_keeps_journal=true
all_previous_fourth_round_gates_still_true=true
direct_constructor_validates_and_recomputes=true
config_exception_graph_clean_for_all_os_branches=true
migration_exception_graph_clean_for_all_os_branches=true
foreign_lock_race_never_mutates_or_acquires=true
journal_replacement_never_overwrites_foreign=true
foreign_prefixed_temp_never_deleted=true
final_old_name_recreation_never_returns_success=true
competitor_bytes_preserved=true
```

专项 **175 passed**（含上述断言）。

## 9. 报告写入前代码候选 manifest（SHA-256）

> 报告自身不自哈希。Hermes 最终复核请再计算全树身份。

| 文件 | SHA-256 |
|---|---|
| `credential_guard/config.py` | `d26734a74aaa5be54a902f82cee34338fa29879db200a6495a0d4b085de3a23b` |
| `credential_guard/bindings.py` | `8ce5794429f4d5a65adb71a9151ab5af9cac55d43d49d498611d6396baba92cc` |
| `credential_guard/migration.py` | `18692d66a1cbc45e395a6816a92516c6d0577ff20f83c5ede5a58a58edebe801` |
| `credential_guard/cli.py` | `eeb33f0cf9ecc62b5ef53db33b3c55a9e20eed9047c760a2859f2e31b620f640` |
| `tests/test_config_v2.py` | `1805ce7d5df14800d1ab0ffc6513f3a8e8a9c59e8f74867b60770048710a9517` |
| `tests/test_config_migration.py` | `be36ecc53a53b68cba85bc258c053e3e86d5017687fc133a901c7f555ff11c12` |
| `tests/test_profile_write_boundary.py` | `e4830e2ea8db923a41283a4006f22fbf5763fabbb0ad42490c033998ffb83697` |

## 10. 本轮明确未做

- 未接入 middleware / hooks / state / registry 现行生产运行路径
- 未删除旧 `credentials.json` / `targets.json` 生产支持
- 未升版本、未构建发布物、未安装/启用 worker
- 未读取真实 worker/default Profile 正文，未读 `~/.ssh`
- **未开始 R1B**
- **已按既定可信本机边界签收** — 同 uid 敌对本机进程/OS 级 DLP 不在本轮威胁模型内

## 11. Profile / worker 说明

本轮全部配置与迁移测试使用 pytest 临时目录，并显式 monkeypatch `HOME` / `HERMES_HOME`。  
**不得**仅凭本轮断言真实 worker「从未被修改」；worker 基线须由 Hermes 人工复核。

R1A 第五轮身份绑定原子清理已按既定可信本机威胁边界正式签收；R1B 已另立任务开始实施。
