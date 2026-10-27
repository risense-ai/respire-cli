# 独立日记片段检索

日记可能包含提议、失败尝试与未确认结论。本入口只提供可定位的历史参考，不改变普通 `recall`，不自动提升日记、不改写主记忆，也不根据正文中的“验证通过”等字样认定事实可信。

## 命令与返回

```text
rsrs --client-only --json diary-search "物联网接入" --mode hybrid --limit 5 --max-chars 4000
rsrs --client-only --json diary-search "港珠澳" --mode lexical --limit 5 --max-chars 4000
rsrs --client-only --json diary-fragment <source-id> <fragment-id> --neighbors 1 --max-chars 4000
```

MCP 对应 `memory_diary_search`（query、mode、limit、max_chars）及 `memory_diary_fragment`（source_id、fragment_id、neighbors、max_chars）。只读模式允许读取，暂停模式仍拒绝读取；既有授权策略不变。旧 Runtime 不识别新命令时会报错，调用方应明确提示能力尚未安装，不应把旧的整日输出包装成片段语义检索。

JSON 信封中的 `details.items` 是结果。每项包含：

- `source_kind=diary`、`evidence_state=reference`：来源和保守的参考状态，不是验证凭据。
- `source_id`、`fragment_id`、`source_version`：原记忆 ID、片段定位 ID、当前加密记录的 SHA-256 版本指纹。
- `date`、`title`、`project`：本地日期与有限长度的出处信息。
- `start`、`end`：原文 Unicode 标量的半开区间；不是 UTF-8 字节或 JavaScript UTF-16 下标。
- `text`、`truncated`、`score`：有界正文、是否截断和排序分数。分数只表示相关性，不表示可信度。

`details.semantic_ready` 和 `pending_fragments` 区分语义索引完整或待建立；索引缺失时仍可返回词面命中，并通知既有后台索引器。查询不在前台为整年日记生成全部向量。读取片段最多包含前后各一段，先为目标片段分配预算，再按剩余预算读取邻段；输出恢复原文顺序，省略或截断邻段时标记 `truncated=true`。公开定位 ID 绑定来源版本及 Unicode 范围；任何原文或元数据更新（包括尾部追加）都会使旧定位失效，须重新搜索。内部索引键另行绑定片段内容与检索元数据，允许未变片段复用派生工件。邻段按来源中紧邻的前一开始位置和后一结束位置选取，包含 80 字符重叠；动态词面窗口也以此规则补充左右上下文，不跳过相邻重叠片。

`limit` 为 1–20，`max_chars` 为 512–12000，默认分别 5、4000。预算约束紧凑序列化后的 `details` 字符数，包含片段元数据和 JSON 转义；外层标准信封另有固定开销。这是字符预算，不是精确 token 数。预算不足时可能无可容纳的结果，`truncated=true`。非 JSON 模式直接输出相同的紧凑有界结果。

## 检索与派生索引

独立检索仅扫描当前账号中有效的 `trivial` 日记，不读取删除记录。词面检索先对权威全文匹配所有查询词，再将命中位置映射到原文 Unicode 标量并选取有界窗口；不会因索引分片边界漏掉长关键词，也不会只检查前 500 字符。多个词可在同一来源的标题、项目或正文中匹配，预算内的片段不保证显示全文的所有命中。长记录按最多 800 个 Unicode 标量切分，优先换行，保留 80 字符重叠。词面查询仍会在本地扫描全部日记，磁盘和本地计算成本与数据量有关；完整日记不会因此返回给对话模型。

语义路径调用公开 Core SDK 的 BGE-M3 `prepare`、`query` 与索引状态接口。后台索引器在既有取消、账号切换与前台让路机制下更新派生缓存。当前账号数据目录中的 `diary-fragments-v1.db` 只保存来源版本与 Core 不透明索引定位，不保存额外的日记明文。Core 派生工件继续由其现有本地索引机制管理。新增/修改/删除、模型代际变化和失效工件会触发重建；最后一条日记被删除或升格后可不加载模型清理空源缓存。词面模式不打开派生缓存；混合模式遇缺失或损坏缓存明确返回 semantic_ready=false 和待准备数量。损坏的已识别派生库在受控后台提交中移到诊断副本并重建；符号链接、硬链接和无关数据库拒绝改写。模型准备在锁外进行，持久提交由运行时写门、生命周期所有权、取消确认锁及主库版本事务共同校验，不改变原记忆、同步历史或日记父节点。

已有 `diary --contains` 是全库时间链（包含主记忆与日记），与上述仅日记入口不同。它现改为解密全文过滤，并返回命中附近最多 500 字符摘要；原有日期、排序与数量语义保持。

## 当前验证边界

公开源码可以修改分段、CLI/MCP、返回边界、缓存和 SDK 调用编排；不可编辑闭源 Core 内部的向量算法与模型实现。构建必须提供仓库锁定的匹配 SDK，不能绕过 manifest 校验。

仓库内 `crates/app/src/diary_tests.rs`、MCP 工具测试和运行时路由测试覆盖全文匹配、Unicode 位置、JSON 预算、来源失效、缓存损坏/重建及取消提交边界。词面与提交故障测试使用显式测试 provider，不能冒充真实语义检索成绩。匹配 SDK 的真实 BGE-M3、CLI/Runtime/MCP 往返、后台并发/重启和跨账号隔离须另外执行；完整发布还保留已有自启、真实模型、升级与迁移门禁。规模测量采用脱敏合成日记，只说明对应夹具的耗时与内存，不代表真实用户年度库性能或检索收益。

## 可复跑验收

在已按锁文件准备匹配 SDK 和已校验 CPU 模型的隔离测试环境中，构建当前 `rsrs` 与探针，运行真实模型用例（不设置 `RSRS_CORE_TEST_MODE`）：

```sh
cargo build --locked -p respire --bin rsrs --example feedback_contract_probe --example ablation_bench
RSRS_ENGINE=cpu RSRS_M3_DIR=/path/to/verified/model \
  target/debug/examples/feedback_contract_probe --diary-only
```

探针拒绝测试 provider，复用 CPU 模型大小和 SHA-256 校验，使用临时库、合成会话和合成日记，覆盖缺索引词面回退、无词面命中的语义查询、CLI/runtime/MCP stdio 往返、重启、readonly 读取、off 拒绝、追加后旧定位失效和删除清理。完整 `feedback_contract_probe` 在已有反馈及两种 benchmark 路径验收后也运行这些日记检查，因此现有四平台无令牌模型验收会覆盖新增入口。单个同义句命中只是功能检查，不代表日记检索题集收益；较宽泛的 `cycling equipment maintenance` 在当前合成夹具和既有 Core 阈值下没有返回候选，此结果未通过降低阈值掩盖。

`diary_scale_probe <每篇字符数> <篇数>` 使用显式合成测试 provider，只测词面扫描，不包含建模质量。2026-10-27 云端 debug 构建的单次测量如下，耗时是建库后的连续三次搜索总和，RSS 为整个夹具进程的峰值：

| 合成规模 | 原 PR `611b4da`：耗时 / RSS | 修复版：耗时 / RSS |
| --- | --- | --- |
| 单篇 10 万字符 | 194.7 ms / 15,120 KiB | 195.6 ms / 15,300 KiB |
| 单篇 100 万字符 | 2,078.7 ms / 31,212 KiB | 1,881.9 ms / 31,084 KiB |
| 365 篇，各 5,000 字符 | 4,028.2 ms / 21,196 KiB | 3,748.5 ms / 19,212 KiB |

测试机有并行任务，尚无多轮置信区间；两版边界/去重/预算结果也有变化（多日夹具原版返回 4 条，修复版 5 条）。这些数据只证明对应规模已实际运行，不能据此宣称稳定提速，更不是原科研题集复现。修复版仍须全文解密和线性扫描；避免逐片克隆全年正文、逐篇重复读取全库不等于消除了全部大库成本。
