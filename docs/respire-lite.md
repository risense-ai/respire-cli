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

## 关联召回

日常先用 `rsrs recall "项目名+核心词" --titles --json`，默认 20 条标题；按相关性用 `show` 读全文，通常最多两轮点深。`related` 是独立关联候选，不是原命中；标题和关系只作查阅线索。`superseded_by` 指向仍活跃的新版时，先读新版，旧版只作历史依据。

新结论替代旧决策并需保留弃因时，用 `remember ... --importance important --supersedes <旧id>`；确需横向关系时用 `--see-also <id,id>`。与修改/合并按事实选择，不为增加关联而新建重复条。库中所有写入端升级后才启用关系写入；旧版重写可能丢字段。

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
