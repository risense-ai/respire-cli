# Encoder flywheel (frozen embeddings + periodic LoRA retrain)

The product embeds with a **frozen** encoder and adapts cheaply in the reranker.
The encoder itself is retrained only in batches, then the whole dense index is
rebuilt and atomically swapped.

```
query -> frozen encoder -> dense cosine ─┐
                                         ├─ fusion -> topK
query -> BM25 top100 --------------------┘
              daily: rsrs learn train --from-labels (residual reranker)
              weekly: LoRA contrastive train -> reembed -> gate -> swap
```

## Components

- `encoder_pipeline.py prepare` — reads `query_log.adopted/good_ids`, builds BM25
  top-100 candidates, keeps deep negatives (rank >= 20), writes a 90/10 time
  split of query -> positive/hard-negative pairs. The DB is opened read-only.
- `encoder_pipeline.py train` — manual LoRA (no `peft` dependency) on the last
  N attention layers of Granite 97M R2; InfoNCE over query, one positive and
  hard negatives plus in-batch negatives.
- `encoder_pipeline.py reembed` — embeds every memory with base+adapter, writes
  `index/<version>/{docs.npy,ids.json,meta.json}`, evaluates dense hit@10/20/MRR
  on the held-out split, and swaps `index/current` only when the new score does
  not fall below `--min-hit20` or the current index by more than `--tolerance`.
- `encoder_pipeline.py query|status` — inspect the current side index.
- `daily_rerank.sh` — one residual reranker epoch from real adoption labels.
- `weekly_encoder.sh` — prepare -> train -> reembed -> gate -> swap.

## Measured baseline (2026-11-03, full 4862-doc library, 191-query time holdout)

| path | hit@10 | hit@20 | MRR@20 |
|---|---:|---:|---:|
| BM25 | .6963 | .7853 | .3440 |
| Granite dense | .6230 | .7225 | .3134 |
| Granite dense + BM25 top100 (lambda 0.5) | .7592 | **.8743** | .3798 |
| Granite CE rerank | .7211 | .8368 | .3362 |
| BGE hybrid (reference, 188-query split) | .9149 | .9628 | .4284 |

Granite dense **alone is worse than BM25** on the full library. Its value is as a
frozen semantic axis on the BM25 pool. Do not switch the default embedder until
the weekly LoRA improves the full-corpus/hybrid number; keep BGE-M3 as the
precision pack and the side index as an experiment until Core gains a Granite
embedding profile.

## Schedule (crontab)

```cron
30 3 * * *  /path/to/respire-cli/scripts/encoder/daily_rerank.sh >> $HOME/.rsrs/logs/cron-rerank.log 2>&1
0 2 * * 0   /path/to/respire-cli/scripts/encoder/weekly_encoder.sh >> $HOME/.rsrs/logs/cron-encoder.log 2>&1
```

Daily is cheap (one residual epoch, no model weights). Weekly is CPU-heavy:
LoRA training plus ~12 minutes of document embedding on this machine.

## Environment

- `RSRS_BIN` default `~/.rsrs/bin/rsrs`
- `RSRS_DATA_DIR` default `~/.rsrs`
- `RSRS_ENCODER_BASE` default `~/.rsrs/models/granite-97m-r2`
- `RSRS_ENCODER_STATE` default `~/.rsrs/encoder`
- `RSRS_ENCODER_INDEX` default `$STATE/index`
- `RSRS_ENCODER_MIN_HIT20` default `0.70` (current Granite dense baseline; the
  relative gate still protects against regression)
- `RSRS_ENCODER_EPOCHS` default `3`

## Safety

- `prepare`/`train`/`reembed` open the store read-only; only the side index and
  adapter files are written.
- Index swap is a symlink rename (`index/current`), old versions are kept (3).
- If the gate fails, the new version stays for inspection but is not served.
- The daily reranker writes `learned_reranker` in the local store; it is never
  synced and `rsrs learn reset` returns to pure BM25.
