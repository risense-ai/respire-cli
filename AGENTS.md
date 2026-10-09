# Repository instructions

## Preserve mandatory prompt constraints

The mandatory workflow in `docs/respire-lite.md` is the default injected policy. `docs/respire.md` is the complete policy. `crates/app/src/inject.rs` also contains the size-limited WorkBuddy reference block. All three are release behavior, not disposable documentation.

- Do not remove, weaken, defer, or replace mandatory rules with vague summaries to save tokens. Preserve the trigger, required action, prohibition, exception, and completion check. Loading `rsrs prompt` later does not compensate for a missing default rule.
- Keep the three anchors: recall before answering/acting, archive each round's findings before finishing, and recall immediately after errors. The first tool action of each round is recall; after it, read the complete policy before other work. Each new user message resets the recall gate.
- Preserve title-first JSON retrieval, selected-record full reads, device checks, alternate keyword searches, evidence in the answer, and honest reporting of failed recall or unverified facts.
- Preserve error-time recall as the next tool action, hypothesis-based investigation, bounded retries, repeat recall after two attempts without progress, and a concrete blocker report.
- Preserve update > merge > attach > new record; full candidate reads, no unresolved candidate output, no duplicate sibling records, taxonomy/tree search and `--parent` for new important records. Diary entries remain exempt from parent/taxonomy requirements.
- Preserve event-based titles and simultaneous `--title` for body updates, the three Chinese body markers, one fact per record, persistent nonempty backups before long rewrites/merges, descendant checks and read-back verification.
- Preserve important/trivial classification, the prohibition on downgrading reusable findings to avoid tree placement, credential inspection, confirmed task trigger conditions and due-condition checks. Do not claim numeric importance, automatic credential scanning/redaction, or automatic reminders unless implemented and verified.
- Preserve the twelve work rules, anti-shortcut rules, scope/authorization boundaries, dependency ordering, actual validation including relevant failure paths, and the final recall/storage/error gates. Read-only and off modes must retain their explicit no-write/no-memory exceptions; mandatory storage never grants extra authority.
- WorkBuddy's size limit permits a reference plus explicit mandatory gates, not deletion of those gates. Its policy load must follow the first recall. Keep JSON examples and update-first deduplication consistent with the default policy.
- Keep current runtime security semantics, relationship compatibility checks, injection markers, taxonomy names, and existing user-owned content. Never import stale ports, product markers, or unsupported features from a reference prompt.
- Prompt changes require a before/after semantic comparison and existing injection tests, including stale replacement, preservation, idempotence and removal. Validate the actual packaged `prompt` and injection preview in an isolated workspace. Do not add tests unless the user requests them.
- A future reduction in these constraints requires explicit user authorization for the named rules. Record the reason and behavior impact in the change description. Routine refactoring, translation, formatting, or token reduction is not authorization.

## 中文保留约定

默认注入必须常驻强约束。禁止以精简、翻译、节省 token 或“全文仍有”为由删除或软化首工具查忆、每轮重置、遇障下一工具查忆、两试再查、每轮必存、改并挂存、挂点深搜、标题规则、备份复验、认真勤勉周全十二条、反偷懒总则及查存障三闸。只有用户明确授权具体规则的削弱，才可改变其强度。只读/暂停模式及用户授权边界优先，禁止虚构产品能力。
