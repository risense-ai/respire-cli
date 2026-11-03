# Domain / effect: read-time projection of the taxonomy tree

`respire::domain` labels every recall result with **where it hangs** (domain)
and **what it is for** (effect), so a consumer can tell rules, procedures,
facts and running context apart without re-reading the tree.

The projection is deliberately inert: it never stores, never filters, never
reorders, and never reaches injected prompt text. This document records the
model, the measured reason for that restraint, and what is and is not
implemented.

## Model

### Domain — a read-time projection

A record's domain is resolved by walking `parent_id` up to a taxonomy root
(`taxonomy::CATALOG`, 23 built-in outlines) and folding the roots into five
behaviour domains. Nothing is written back: the same record projects the same
domain on every device, and a record outside the catalog projects
`unassigned`.

| Domain | Catalog roots |
| --- | --- |
| `work` | 编程开发, 职业工作, 任务计划 |
| `ai_flow` | 技能库 |
| `ai_norm` | 经验库, 踩坑录 |
| `finance` | 财务理财 |
| `learn` | 灵感创意, 学习成长 |
| `life` | the remaining 14 human roots (family, health, home, travel, …) |
| `unassigned` | anything not under a built-in root, or an unresolvable chain |

### Effect — what the record is served as

| Effect | Meaning |
| --- | --- |
| `norm` | a rule to obey — how the agent must behave |
| `procedure` | a repeatable how-to — how to do the thing |
| `material` | fact/reference — what is true |
| `stream` | running context — cheap to show, cheap to drop |

`effect(kind, domain)` is the S1 proxy: `kind` carries the role until a stored
role field exists.

1. `skill` → `procedure`
2. `decision`, `preference` → `norm`
3. otherwise `default_effect(domain)`:

| Domain | default |
| --- | --- |
| `ai_flow` | `procedure` |
| `ai_norm` | `norm` |
| `work`, `finance`, `learn` | `material` |
| `life`, `unassigned` | `stream` |

A future stored `role` plugs in as `effective_effect = role ?? default_effect(domain)`
without touching callers.

## Why labels only — measured

On a 62-query slice of a real library (4,923 rows), re-slicing an already
ranked top-30 under four arms (respire-benchmark repo, test
`tests/28-domain-effect-slicing-20261103.md`):

| Arm (emit 5) | hit@5 | norm visible | proc visible | mat visible |
| --- | ---: | ---: | ---: | ---: |
| flat (current behaviour) | **0.710** | 0.806 | 0.613 | 0.758 |
| additive reserve, 1 seat | 0.694 | **1.000** | **0.919** | **0.887** |
| additive reserve, 2 seats | 0.694 | **1.000** | **0.984** | **1.000** |
| effect-block reorder | **0.306** | 1.000 | 0.210 | 0.177 |

Three consequences:

1. **Domain must not be a sort key.** Any reordering away from Core's scored
   order collapses hit@5 (0.710 → 0.306); sweeping the reorder window degrades
   monotonically. Sorting is Core's job.
2. **Reserving emission seats is nearly free.** Evicting only a slot whose
   effect already holds two seats buys full norm visibility for one lost hit.
   That belongs to the emission layer, which this change does not touch.
3. **The recall ceiling is `limit`, not the domain split.** The flat top-5
   spends 294 of the 1500 injection characters (20%), 11 targets sit at rank
   6–30, and hit@10 on the same ranking is 0.806.

Reproduction (offline, no query-log writes; harness lives in the
respire-benchmark repo under `scripts/domain/`):

```bash
rsrs bench run <evalset.jsonl> --json --verbose --topk 30 > bench.json
rsrs list --limit 6000 --json                              > rows.json
python3 scripts/domain/domain_slice_ab.py --bench bench.json --rows rows.json \
    --taxonomy crates/app/src/taxonomy.rs --topk 5 --json out.json
```

## What ships here

- `cli/src/domain.rs` — `Domain`, `Effect`, `domain_of_root`,
  `default_effect`, `effect`, and `Index` (an in-memory parent/title index
  over the catalog recall already loaded; resolution costs map lookups, no
  store reads, no decryption).
- `recall` output, additive keys only:
  - `details[].domain` and `details[].effect` on every result row
    (`--titles` and full form),
  - `summary.slices` — `{ "domain": {…counts}, "effect": {…counts} }` over the
    returned set.
- Documented in [`json-output.md`](json-output.md).

## Guarantees and non-goals

- **Not stored, not synced.** The projection is recomputed at read time; it is
  not a field on the entry, not a tag, and never leaves the machine as data
  other than the JSON labels above.
- **Not a filter, not a permission, not an ordering.** Recall returns exactly
  the same candidates in exactly the same order with or without this module.
- **Not prompt content.** Domain/effect names exist only in JSON; injected
  text is unchanged.
- **Degrades, never panics.** Missing rows, empty titles and parent cycles
  resolve to `unassigned` (same 64-hop cap as `LocalStore::ancestor_chain`).

## Known issue: taxonomy root id prefix

Stored catalog roots were created under a `1memory-taxonomy-v1:` digest, while
`taxonomy::root_id` now hashes `respire-taxonomy-v1:`. Consequently
`rsrs taxonomy --json` matches **0 of 23** stored roots, and `--ensure` would
create duplicate outlines instead of adopting the existing ones.

This projection resolves roots **by title**, not by id, so it is unaffected.
The id mismatch itself needs a separate decision (revert the code prefix vs
migrate stored ids); until then do not run `rsrs taxonomy --ensure`.

## Follow-ups (not in this change)

1. Reserve-seat emission at the hook (the additive arm above): keep flat
   order, guarantee one seat for a missing effect when the budget allows.
2. A stored `role` field so `effective_effect = role ?? default_effect(domain)`
   replaces the kind proxy.
3. `limit` 5 → 10 A/B: +9.6pp hit on the same ranking, and the top-5 uses only
   20% of the character budget today.
4. The existing `--intent howto` extra skill pass is the half-built
   procedure channel; wiring it onto the default path would raise procedure
   visibility without any reordering.
