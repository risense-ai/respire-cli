# 日记同步冲突与本地工作副本

## 问题和修复范围

v2 同步使用服务端 revision/CAS。一个本地日记 append 可以先成功写入并被独立读回，随后因另一设备已推进服务端 head 而收到 `conflict_saved`。该回执表示版本已保存为冲突，不表示当前正文已被服务端接受。

此前客户端在回执后清除 pending，再把 canonical head 作为 authoritative 写入当前记录，绕过时间戳 LWW。这能把刚确认的日记正文替换为时间戳更早的另一分支。原 append 仍在冲突历史中，但后续 show/diary-search 只看到被换回的正文。派生日记索引不是复现该问题的必要条件。

修复只保护**仍为当前工作副本、未删除、importance=trivial，且精确对应未处理冲突版本**的日记。接收另一份活跃日记 head 时，客户端保留当前正文、时间戳和设备元数据；服务端 head、原冲突密文、真实冲突计数仍然保存。清理 outbox 后仍能从未处理 inbox 识别该分支，重启和后续 pull 不会解除保护。普通重要记录的既有同步策略不变；远端删除和升格仍按原规则处理。

没有自动重发、拼接正文、修改远端胜出规则或将冲突标为已解决。`pending=0` 仅说明传输队列已确认，不代表 `conflicts=0` 或两端正文相同。

## 显式处理边界

`sync-conflicts.current` 是**服务端 canonical head**，输出新增 `current_scope=remote_canonical` 标记。在保护生效时，它可以与 `show` 的本地工作副本不同。

- `keep-current` 保留已审阅的服务端 canonical head，可能舍弃本地冲突分支中的事件。只有收到 processed resolution 后才释放保护。
- `take-incoming` 选取整个冲突候选版本，可能覆盖远端另一分支的新增事件，不能把它当成无损追加。
- `merge` 只使用用户明确审阅并提供的正文，不自动计算文本并集。
- 对受保护日记的显式 take/merge，只有新建且尚未对外发送的操作使用用户审阅的 head revision 做 CAS；不伪造已应用的 sync_base，不放宽 epoch、head、pending 或幂等检查。
- resolution 回执处理完成后，同一次同步重新 materialize，使明确选择及时生效；较晚的本地 pending 写入仍受原保护。

此修复不会自动恢复升级前已经被 canonical head 替换的日记，也不会修改已有冲突历史。已有冲突须在本机比较双方完整记录、备份并确认授权后单独处理；重新 remember 一次、sync-reset 或替换原库均不是此问题的修复验收步骤。

## 隔离验证

所有夹具只使用合成账号、合成密钥和合成日记，不读取或上传真实记忆。

```sh
cargo test --locked -p respire_storage transport::local::sync::diary_tests
cargo test --locked -p respire_app sync::
```

storage 用例使用显式测试 provider，覆盖回执后的工作副本、outbox 清理、重启、后续 head、旧索引工件、显式 take/merge/keep-current，以及删除/升格边界；不能把它们当作真实模型或真实服务验收。

真实服务/模型探针需要锁定 SDK、经校验的 CPU M3 模型和**可销毁的本机 API/PostgreSQL 服务**。探针只接受独立的 `http://127.0.0.1:<port>`，拒绝宿主记忆 Runtime 默认端口，注册新的随机合成账号，使用临时客户端库；服务和数据库必须由测试运行者独立创建与清理。

```sh
cargo build --locked -p respire --example diary_sync_probe
# 如 SDK 的运行时尚未放到 examples 目录，先用现有 stage-core-runtime.mjs 准备。
RSRS_ENGINE=cpu RSRS_M3_DIR=/path/to/verified/model \
RSRS_CPU_OWNED_ORT_FILE=/path/to/verified/model/onnx/model_quantized.cpu-v1.ort \
  target/debug/examples/diary_sync_probe http://127.0.0.1:<disposable-port> \
  --confirm-disposable-server
```

探针拒绝 `RSRS_CORE_TEST_MODE`，使用真实 M3 prepare，并在后台工件准备后、提交前协调一次真实双客户端 HTTP 同步冲突。之后重复四轮同步、清理、数据库重开和真实重索引，检查正文及版本保持；最后执行明确提供正文的 merge，再检查两端收敛。该协调点用于稳定触发竞争窗口，不代替真实推理，也不是年度库性能或语义检索质量基准。

本机集成使用现有 server 源码 `d8bb056423a6ff1c0452601467af1cf30ce2beef` 的隔离副本与 PostgreSQL 17；仅将该测试副本的公开 app 依赖接到当前 CLI 工作区和锁定 SDK，server 仓库及 HTTP/CAS 实现未修改。此结果不代表已在用户设备或生产数据库部署修复。

维护隔离验收已实际执行：DEV9 基线 `5a0c086afb67b250956bcbb02616585f6f2381d7` 在同一真实服务/M3 探针中因 confirmed diary regressed after sync/restart 失败；修复版通过，包括四轮持久性检查和最后的显式合并收敛。按仓库 CI 的串行设置，全工作区（不含 CLI 包）258 项通过、1 项原有 ignored，其中 app 166 项、storage 59 项。首次默认并行全量 app 曾出现登录事务夹具的进程级环境干扰；未修改该测试，串行复跑通过。

新增日记 storage 回归已加入现有 token-free 四平台源码验收的 native/musl 步骤；原有真实模型和 snapshot/runtime/MCP 门禁保留。

首轮四平台中，macOS 的后台 fence 探针在真正进入日记工作前，仍在对两个约 569 MB 的模型容器做校验而超时。探针将模型准备作为独立的最多 300 秒前置条件；准备后的实际日记工作观察仍限 120 秒，仍必须观察到 `diary-fragments`，并验证 readonly 回执后的两表摘要、data_version 与 drain 不再写入。随后一轮 macOS 已通过该 fence，但切换另一密钥账号后的 semantic_ready 等待超时；账号切换使用同一模型准备路径，因此两处等待共用同一有界准备规则，并在未就绪时保留 model_operation/retrieval_index 诊断。另一账号仍必须真实语义就绪、返回自身正文且排除旧账号正文。没有跳过模型校验或把准备状态当作实际日记推理通过。

## 发布状态

本修复尚未发布。正式 `1.0.17-dev.9` 是受影响版本。源码与隔离测试通过不能替代最终 SHA 的正常 CI、跨平台和发布门禁；插件的原生新会话跨同步持久化验收仍需在修复版部署后另外执行。
