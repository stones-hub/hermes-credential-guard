# Credential Guard 通用凭证边界重构 — 暂停交接

> 暂停日期：2026-07-31  
> 计划恢复：2026-08-02（用户回来后手工继续，不创建定时任务）

## 当前执行状态

正在运行且允许自然结束的唯一开发任务：

```text
阶段：R1B 单文件正式运行链路切换
进程：proc_20f3ebe5c12f
状态：completed，exit code 0
结果：候选完成，待后天由 Hermes 独立验收；未开始 R2
```

该任务结束后必须暂停：

- 不自动启动独立复审；
- 不开始 R2；
- 不构建、不升版、不安装；
- 不操作真实 worker。

## 已签收

```text
R0：PASS
R1A：PASS（按既定可信本机威胁边界）
```

R1A 最后独立主代理验证：

```text
专项：175 passed
相关回归：35 passed
compileall：PASS
```

R1A 报告：

```text
docs/R1A-单文件配置地基与迁移-实测报告.md
```

边界决定：同 uid 恶意本机进程在身份检查与 pathname 操作之间替换 inode，属于 OS 级敌对本机进程/DLP 防御，不在已批准产品威胁模型，不继续作为 R1A 阻塞。

## R1B 任务

任务文件：

```text
.r1b-runtime-switch-task.md
```

目标：正式运行时只读取 `credential-guard.json`，不回退 `credentials.json + targets.json`；旧双文件仅供显式迁移命令使用。

任务结束后需要恢复的验收步骤：

1. 读取 Cursor 完整输出和报告；
2. 审阅实际修改文件和 call graph；
3. 独立复跑 R1B 专项、R1A 回归、相关回归和全量测试；
4. 对抗验证：旧双文件不回退、非法新配置 fail closed、registry 原子同代、Provider transport 0 泄漏、敏感路径阻断；
5. 核对真实 worker 基线；
6. 仅在独立复审 PASS 后签收 R1B；
7. 然后再开始 R2。

## 真实 worker 只读基线

```text
路径：/Users/yelei/.hermes/profiles/worker/config.yaml
SHA-256：2bad7d2dd9746d5d6283fc0e99b010212261dae713624089bf8754cd59337977
mtime：2026-07-31 16:47:08
size：19011
mode：0600
```

严禁读取正文或修改。恢复工作前后只核对 SHA-256、mtime、size、mode。

## 后续阶段

```text
R1B：候选已完成；待后天独立验收
R2：逻辑引用、审批绑定、TOCTOU
R3：HTTP Header / 单次 env / stdin 通用注入
R4：结果保护与现有能力非干扰
R5：删除旧动作、旧 executor、双文件正式路径和专用依赖
R6：发布制品、双构建、隔离 E2E、双重复审、正式 worker 手工测试指南
```

## 正式 worker 分工

开发、隔离测试、打包和指南由 Agent 完成。最终正式 worker 的安装、启用、配置、测试和回滚由用户手工执行；Agent 不直接修改正式 Profile。
