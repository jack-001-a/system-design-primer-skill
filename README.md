# System Design Primer — Agent Skill

一套面向多种 AI 编程 Agent 的可安装系统设计 Skill。知识框架参考 Donne Martin 的 System Design Primer，并补充现代软件工程实践。

## 目录

```text
system-design-primer-skill/
├── SKILL.md
├── README.md
├── ATTRIBUTION.md
├── LICENSE
├── MANIFEST.sha256.json
├── references/       # 按需加载的知识库（12 份）
├── templates/        # 架构设计、审查和 ADR 模板
└── scripts/          # macOS/Linux 与 Windows 安装脚本及校验器
```

## 支持方式

本包采用 Agent Skills 的通用目录格式：一个技能目录包含 `SKILL.md` 和可选 `references/`、`templates/`、`scripts/`。不同宿主工具会从不同目录发现技能，因此安装时把同一份技能目录复制到宿主认可的位置。

推荐安装：

- Codex：`.agents/skills/`（项目）或 `~/.agents/skills/`（用户级）
- Claude Code：`.claude/skills/` 或 `~/.claude/skills/`
- Cursor：`.agents/skills/`、`.cursor/skills/` 或对应用户级目录
- GitHub Copilot：`.agents/skills/`、`.github/skills/` 或用户级 Copilot Skills 目录

## macOS / Linux

先下载并解压仓库 ZIP。然后在**目标代码仓库根目录**执行以下命令（把脚本路径替换成你实际解压的位置）；安装脚本以当前工作目录作为项目根目录：

```bash
# 当前项目：同时安装到 Codex/Cursor/Copilot 通用目录和 Claude Code 目录
bash /path/to/system-design-primer-skill/scripts/install.sh --agent all --scope project

# 只安装 Codex（项目级）
bash scripts/install.sh --agent codex --scope project

# 用户级，当前账号下所有项目可用
bash scripts/install.sh --agent all --scope user

# 查看计划而不写文件
bash scripts/install.sh --agent all --scope project --dry-run

# 已存在时，明确允许覆盖
bash scripts/install.sh --agent all --scope project --force
```

## Windows PowerShell

```powershell
# 当前项目，通用目录 + Claude Code（从目标代码仓库根目录运行）
& "C:\path\to\system-design-primer-skill\scripts\install.ps1" -Agent all -Scope project

# 用户级
.\scripts\install.ps1 -Agent all -Scope user

# 预览
.\scripts\install.ps1 -Agent all -Scope project -WhatIf

# 明确覆盖已存在目录
.\scripts\install.ps1 -Agent all -Scope project -Force
```

## 官方目录依据

- [Agent Skills format](https://github.com/agentskills/agentskills)
- [Codex: Build skills](https://learn.chatgpt.com/docs/build-skills)
- [Claude Code / Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
- [Cursor: Skills](https://cursor.com/help/customization/skills)
- [GitHub Copilot: Add agent skills](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/add-skills)

`--agent all` 会安装两份相同内容：`.agents/skills`（Codex、Cursor、Copilot 的共享目录）和 `.claude/skills`（Claude Code 目录）。Cursor 会扫描多个兼容目录；如果它因此显示重复 Skill，请在 Cursor 项目中只保留 `.agents/skills` 版本，并保留 `.claude/skills` 供 Claude Code 使用，或改用单独的 `--agent cursor` 安装。

## 手动安装

将整个 `system-design-primer` 技能目录（必须包含 SKILL.md 与 references）复制到对应位置：

```text
项目级 Codex / Cursor / Copilot：
<repo>/.agents/skills/system-design-primer/

项目级 Claude Code：
<repo>/.claude/skills/system-design-primer/

Cursor 专用目录：
<repo>/.cursor/skills/system-design-primer/

GitHub Copilot 专用目录：
<repo>/.github/skills/system-design-primer/

用户级 Codex / Cursor 通用目录：
~/.agents/skills/system-design-primer/

用户级 Claude Code：
~/.claude/skills/system-design-primer/
```

不要只复制 `SKILL.md`；参考文件会被 Skill 按需读取。

## 使用示例

自然语言即可触发，或在支持显式调用的 Agent 中点名：

```text
使用 system-design-primer Skill，为这个仓库审查整体架构。
重点检查数据模型、事务边界、缓存、异步任务、可靠性和安全性。
所有发现请附文件路径和严重程度，不要先修改代码。
```

```text
使用 system-design-primer Skill，为新增的多租户订阅计费功能设计方案。
先明确需求、容量假设、数据模型、幂等与失败恢复，再输出架构图和 ADR。
```

```text
使用 system-design-primer Skill，分析当前 API 的 P95 延迟问题。
先从代码和配置中找证据，给出测量方案和可验证假设，不要先引入缓存。
```

```text
使用 system-design-primer Skill，规划从模块化单体迁移到独立服务的路线。
请证明拆分必要性，比较不拆分的替代方案，并包含数据迁移和回滚计划。
```

## 运行安全

- 安装脚本默认不覆盖已存在的 Skill；需要覆盖时显式传 `--force` / `-Force`。
- Skill 是指导 AI 的文档，不是自动化架构扫描器。Review 结论必须从仓库证据得出。
- 不要把未经审查的第三方 Skill 直接用于包含生产密钥或敏感数据的环境。
- 对具体云服务、框架版本和安全控制，查阅官方最新文档；本知识包不替代产品文档。

## 验证

在解压后的技能包目录运行结构检查：

```bash
python scripts/validate.py
```

安装后，在 Agent 中显式调用一次，并确认它能读取 `references/` 中的文件。若未显示，检查目录位置、重启/刷新 Agent，并确认技能目录名与 frontmatter `name` 一致。

版本：1.0.0