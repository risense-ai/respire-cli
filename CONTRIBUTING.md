# Contributing / 贡献指南

English and 中文 are welcome. Keep one issue or PR focused on one problem; search existing issues/PRs and link related work before opening a duplicate. / 欢迎中英文；一次提交聚焦一个问题，先搜索已有 Issue/PR 并关联相关工作。

## Issues / 问题报告

Use the bug or feature form. Installation and performance problems fit the bug form; fill conditional fields only when relevant. Blank issues remain available for other topics. Give a minimal reproduction with synthetic data, expected/actual behavior and the relevant versions/platform. / 使用缺陷或功能表单；安装与性能问题使用缺陷表单，仅填写适用上下文。其他事项可用空白 Issue。提供虚构数据最小复现、期望/实际及版本/平台。

For CLI/runtime reports, include exact sanitized commands, exit codes/JSON error reasons, launcher and runtime versions, install entry, OS/architecture and Linux libc if known. Performance reports need workload, model/engine, background indexing/downloads, concurrent requests and measured memory/latency. / CLI/Runtime 报告提供脱敏命令、退出码/JSON 错误、启动器与运行时版本、安装入口、系统/架构及 Linux libc。性能问题补充负载、引擎、后台索引/下载、并发与测量结果。

## Pull requests / 合并请求

Use a small branch against `main` and the PR template. Explain the problem and resulting behavior, link related issues (use `Fixes #...` only when fully resolved), and include actual test commands/results. Mark checks N/A with a reason when irrelevant; say explicitly when CI or platform tests did not run or were skipped. / 从 `main` 建立小分支，使用 PR 模板说明问题和行为变化、关联 Issue 并记录真实测试；不适用项说明原因，明确 CI/平台测试未运行或跳过。

Preserve CLI flags, JSON/MCP/HTTP contracts, stored data/index/config formats, prompt constraints in [AGENTS.md](AGENTS.md), and third-party notices. Explain compatibility, migration and rollback for any affected boundary. / 保留命令参数、协议、数据/索引/配置格式、AGENTS.md 提示约束与第三方声明；相关变更说明兼容、迁移与回退。

## Validation / 验证

Follow [README.md](README.md) and existing [CI](.github/workflows/ci.yml); use isolated test data. Run checks relevant to the changed behavior and record limitations instead of claiming untested platforms passed. No new coverage threshold is introduced. / 遵循 README 与现有 CI，使用隔离资料；运行相关检查并如实记录限制，勿将未测试平台写为通过；不新增覆盖率门槛。

For Rust behavior changes, the existing baseline is the pinned toolchain, matching Core SDK, and `RSRS_CORE_TEST_MODE=1 cargo test --locked --workspace` (PowerShell: set `$env:RSRS_CORE_TEST_MODE='1'` first). See [SDK setup](crates/core-sdk/README.md) and [command checks](docs/command-regression.md). Runtime/performance changes also need relevant foreground/background and concurrency evidence; report measurement methods and before/after results without relaxing existing acceptance gates. / Rust 行为变更遵循固定工具链与匹配 SDK，运行现有测试；运行时/性能变更提供适用前后台、并发、测量方法和前后结果，不放宽已有验收规则。

Documentation/template-only changes can use syntax, path/link and diff review; state explicitly if product tests were not run. / 纯文档/模板变更可做语法、路径/链接和差异检查，明确未运行产品测试。

Template and Markdown-only changes are excluded by the current automatic Release workflow's path filters. Do not dispatch publishing workflows for contribution-only changes. / 当前 Release 路径过滤排除模板与 Markdown 变更；仅贡献规范变更不要手动触发发布。

## Private data and security / 私密数据与安全

Use English or 中文. Search existing issues first. Never post passwords, API keys/tokens, databases/backups, private memories, account identifiers or unredacted logs/screenshots. / 可用中英文；先搜索现有问题。不要提交密码、密钥/token、数据库/备份、私密记忆、账户标识或未脱敏日志/截图。

Security vulnerabilities: do not disclose details in a public Issue or PR. Check this repository's Security tab for a private reporting option; if none is offered, ask maintainers to establish a private channel without including vulnerability details. No security email or private channel is currently documented. / 安全漏洞不要公开披露；查看本仓库 Security 页是否提供私密报告入口。若没有，只请求维护者建立私密渠道，不附漏洞细节。目前未公布安全邮箱或私密渠道。
