# System Design Primer — Agent Skill

![CI](https://github.com/jack-001-a/system-design-primer-skill/actions/workflows/ci.yml/badge.svg) ![Latest Release](https://img.shields.io/github/v/release/jack-001-a/system-design-primer-skill)

面向软件架构设计、架构审查、性能优化、技术选型和迁移规划的可安装 Agent Skill。以 Donne Martin 的 System Design Primer 为知识主题起点，并补充现代生产工程实践。

- **版本：** 1.2.0
- **语言：** 中文说明，保留常用英文技术术语
- **运行依赖：** Skill 本身无第三方运行依赖；安装/校验仅需 Bash、PowerShell 或 Python 3

## 内容结构

    system-design-primer/
    ├── SKILL.md
    ├── README.md / ATTRIBUTION.md / LICENSE / VERSION
    ├── references/      13 份渐进式知识参考
    ├── templates/       架构设计、架构审查、ADR 模板
    └── scripts/         Linux/macOS、Windows 安装器和校验器

## 下载

推荐从 [GitHub Releases](https://github.com/jack-001-a/system-design-primer-skill/releases) 下载版本化 ZIP。仓库主分支源码 ZIP 也可从 [main.zip](https://github.com/jack-001-a/system-design-primer-skill/archive/refs/heads/main.zip) 获取。

发布 ZIP 内含 system-design-primer/ 目录、嵌入式 MANIFEST.sha256.json 和同名 .sha256 校验文件。校验文件按 SHA-256 生成；Release 只会在 Git tag 与 VERSION 一致、CI 通过后发布。

## 支持的 Agent 目录

| Agent | 项目级目录 | 用户级目录 |
|---|---|---|
| OpenAI Codex | .agents/skills/ | ~/.agents/skills/ |
| Claude Code | .claude/skills/ | ~/.claude/skills/ |
| Cursor | .cursor/skills/ 或 .agents/skills/ | ~/.cursor/skills/ 或 ~/.agents/skills/ |
| GitHub Copilot | .github/skills/、.claude/skills/ 或 .agents/skills/ | ~/.copilot/skills/ 或 ~/.agents/skills/ |

Cursor Cloud Agents 个人 Skill 应安装到 `~/.cursor/skills/` 并在 Cursor Settings → Agents 中开启 Sync Skills。`~/.agents/skills/` 可用于本地 Cursor 兼容发现，但不要据此假定个人 Skill 会自动同步到 Cloud Agents。项目级 Skill 可放在仓库的 `.cursor/skills/` 或 `.agents/skills/`。Copilot 云端使用还需遵循其 dotfiles/云端环境配置要求，不能假设所有本地用户级目录都会自动进入云端会话。

目录依据：[Codex Skill 指南](https://learn.chatgpt.com/docs/build-skills)、[Claude Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)、[Cursor Skills](https://cursor.com/docs/skills)、[GitHub Copilot Skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills)。

## 安装

先解压 ZIP。**在目标代码仓库根目录执行安装命令**；脚本会根据当前目录决定项目级安装位置。示例假设解压后的文件夹为 /opt/system-design-primer。

### macOS / Linux

    cd /path/to/your-project

    # 只装 Codex
    bash /opt/system-design-primer/scripts/install.sh --agent codex --scope project

    # 只装 Claude Code
    bash /opt/system-design-primer/scripts/install.sh --agent claude --scope project

    # 只装 Cursor（使用 Cursor 专用目录）
    bash /opt/system-design-primer/scripts/install.sh --agent cursor --scope project

    # 只装 GitHub Copilot
    bash /opt/system-design-primer/scripts/install.sh --agent copilot --scope project

    # 一次安装多种宿主目录
    bash /opt/system-design-primer/scripts/install.sh --agent all --scope project

    # 安装到当前用户目录
    bash /opt/system-design-primer/scripts/install.sh --agent all --scope user

### Windows PowerShell

    Set-Location C:\path\to\your-project

    # 根据需要选择 codex、claude、cursor、copilot 或 all
    & C:\path\to\system-design-primer\scripts\install.ps1 -Agent codex -Scope project

    # 安装到用户级目录
    & C:\path\to\system-design-primer\scripts\install.ps1 -Agent all -Scope user

## 安装器行为与安全

- 默认不覆盖已存在的 Skill；需要更新时显式使用 --force 或 -Force。
- --dry-run / -WhatIf 仅预览目标路径，不创建或修改文件。
- 安装器先检查全部目标，再使用同目录 staging 目录替换；失败时尽力恢复原目录。
- 只复制 SKILL.md、references、templates、scripts、ATTRIBUTION.md、LICENSE 和 VERSION，不复制 .git、GitHub Actions、测试或开发工具。
- --agent all 的项目级目标为 .agents/skills、.claude/skills、.github/skills；用户级目标为 ~/.agents/skills、~/.claude/skills、~/.copilot/skills。
- Cursor 也会兼容发现 .agents/skills 和 .claude/skills。若同时启用多个宿主，建议用对应的单宿主安装参数，避免同一 Skill 被重复发现。
- 安装脚本不会安装依赖，也不会自动执行 Skill 中的脚本。

## 校验与开发

在仓库根目录运行：

    python scripts/validate.py
    python -m unittest discover -s tests -v
    bash -n scripts/install.sh
    bash tests/test_install.sh
    python tools/package.py --output-dir dist

Windows 还可运行：

    .\tests\test_install.ps1

GitHub Actions 会在 Ubuntu、macOS 和 Windows 上运行校验/测试。正式发布仅由版本 Tag 触发：先更新 VERSION 和 CHANGELOG.md，合并到 main 并等待 CI 通过，再创建与 VERSION 完全一致的 v* Tag。Release 工作流会在三个平台完成验证后构建 ZIP、SHA-256 并发布 GitHub Release；release/** 分支不会直接触发正式发布。

## 使用示例

    使用 system-design-primer Skill 审查此仓库的整体架构。
    重点分析关键业务流、数据模型、事务边界、缓存、异步任务、
    可靠性、安全和可观测性。按严重程度排序，每条发现附文件证据。
    先只审查，不要修改代码。

    使用 system-design-primer Skill 设计多租户订阅计费系统。
    先明确 FR/NFR、容量假设、数据模型、幂等、对账和失败恢复，
    再给出架构图、替代方案、ADR 和分阶段上线计划。

## 归属与许可

本项目为独立、非官方 Skill。知识主题参考 [Donne Martin/System Design Primer](https://github.com/donnemartin/system-design-primer)，并加入原创工作流与现代工程实践。原创说明、模板和参考文字采用 CC BY 4.0；第三方链接内容保留其各自版权和许可，详见 ATTRIBUTION.md。

AI 系统架构的深入内容见 [references/12-ai-systems-architecture.md](references/12-ai-systems-architecture.md)。

更多信息见 [CHANGELOG.md](CHANGELOG.md)、[CONTRIBUTING.md](CONTRIBUTING.md) 和 [SECURITY.md](SECURITY.md)。
