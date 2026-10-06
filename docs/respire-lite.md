# Respire lightweight workflow

Recall titles first and read selected records in JSON. Load the complete `rsrs prompt` before storage or maintenance; this summary does not replace the full policy.

| Contract | Requirement |
| --- | --- |
| Sandbox | Host loopback runtime without a token; no lifecycle changes or direct execution |
| Compatibility | Preserve Chinese body markers, taxonomy names and injection markers |
| Complete policy | Apply the English rules here together with the existing Chinese workflow below |
| Credential references | Inspect content before writing or sharing; omit plaintext passwords, API tokens and private keys, and store only a safe purpose/location reference. Keep secrets out of recall queries. This is an agent rule, not an automatic CLI scanner. |
| Task conditions | Include a `【触发】` line with a confirmed date (and time zone if needed) or verifiable prerequisite. Ask if unclear; check dates and prerequisite evidence when recalling the task, then mention due conditions. There is no automatic validation or background reminder. |
| Importance | Use `--importance important` for reusable findings or `--importance trivial` for diary entries; do not use numeric scores. |

## Related recall

Start routine searches with `rsrs recall "project name + key terms" --titles --json`, which returns up to 20 titles by default. Read selected records with `show --json`, usually within two rounds. `related` contains separate lookup hints, not primary hits. If `superseded_by` points to a live newer record, read it first and treat the old record as historical evidence.

Use `remember ... --importance important --supersedes <old-id>` when a new conclusion replaces an old decision, and retain the reason for replacement. Use `--see-also <id,id>` for necessary cross-references. Choose edits or merges based on the facts; do not create duplicates just to add a relation. Enable relation writes only after every writer for the library is upgraded; older writers may drop fields when resealing.

## 中文完整规则

# rsrs 记忆工作流

- In a sandbox, use `rsrs --client-only <command>` to connect only to the host loopback HTTP runtime (default `127.0.0.1:15169`) without a token. Non-loopback access requires a token. Do not start, stop, copy or upgrade the service, or use `--direct`. Report connection or authentication failures for the host operator to resolve.

先查后做，所得归档，遇障先翻忆。详细规则由 `rsrs prompt` 提供；本回合首次存储、修改或整理前必须读取全文，不能凭本摘要省略规则。

- 每轮先 `rsrs recall "项目名+核心词" --titles --json`。默认返回 20 个标题；按相关性选中后用 `show <id> --json` 读取全文。读记忆命令使用 `--json`，先核对记录设备，不能照搬其他设备的路径和环境。
- 无相关结果换关键词再查；报错或异常先查相关记忆，再定位根因。记忆仅作参考，以当前用户指令和现场证据为准。
- 回答引用已核实事实，明确未验证内容；不要把召回分数当作事实可信度。
- 存储顺序为改、并、挂、新存。判重须阅读候选全文；修改长文先备份。合并前备份并检查子孙；新条挂在同题条下，不创建散根。
- 可复用结论为 important，普通过程写 trivial 日记。正文分【前因】【行为】【后果】，一条记一件事；保留关联事实、实体、日期及必要上下文，避免过度碎片化和堆同义词标签。相对时间只有参考日期明确时才转为绝对日期，不猜测。
- 收尾检查本轮工作是否落库，简短说明查忆依据和存储结果。所有细节、例外、判树与维护规则遵循全文。
- 快速模式在本地检索；高质量模式需用户在 TUI 启用，查询和候选标题会发送到配置的模型服务。服务失败时明确报告并使用本地结果。不要擅自切换模式。
