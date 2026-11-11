#!/usr/bin/env python3
"""Local encoder flywheel: frozen embeddings + periodic LoRA contrastive retrain + reindex.

Subcommands
  prepare  build query -> positive/hard-negative pairs from query_log (read-only)
  train    LoRA contrastive fine-tune of the Granite encoder on those pairs
  reembed  rebuild a versioned dense index, evaluate hit@20, atomically swap
  query    query the current dense index (for checks)
  status   show current index metadata

Design: the product embeds with a frozen encoder; online adaptation lives in the
cheap reranker (`rsrs learn train --from-labels`). The encoder itself is only
retrained in weekly batches, then the whole index is rebuilt and swapped.
"""
import argparse, json, math, os, re, sqlite3, sys, time, shutil
from collections import defaultdict
from datetime import datetime, timezone
import numpy as np
import torch
from torch import nn
from transformers import AutoModel, AutoTokenizer

DEFAULT_DATA = os.environ.get('RSRS_DATA_DIR') or os.path.expanduser('~/.rsrs')
DEFAULT_DB = os.path.join(DEFAULT_DATA, 'rsrs.db')
if not os.path.isfile(DEFAULT_DB) and os.path.isfile(os.path.join(DEFAULT_DATA, 'onememory.db')):
    DEFAULT_DB = os.path.join(DEFAULT_DATA, 'onememory.db')
DEFAULT_BASE = os.path.expanduser('~/.rsrs/models/granite-97m-r2')
DEFAULT_STATE = os.path.expanduser('~/.rsrs/encoder')
CJK = re.compile(r'[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF]')


def is_cjk(c):
    o = ord(c)
    return 0x3400 <= o <= 0x4DBF or 0x4E00 <= o <= 0x9FFF or 0xF900 <= o <= 0xFAFF


def tokenize(text):
    out, ascii_buf, cjk = [], '', []

    def flush_ascii():
        nonlocal ascii_buf
        t = ascii_buf.strip('_-')
        if len(t) >= 2:
            out.append(t)
        ascii_buf = ''

    def flush_cjk():
        nonlocal cjk
        if len(cjk) == 1:
            out.append(cjk[0])
        elif len(cjk) > 1:
            out.extend(''.join(cjk[i:i+2]) for i in range(len(cjk)-1))
        cjk = []

    for c in text.lower():
        if c.isascii() and (c.isalnum() or c in '_-'):
            if cjk: flush_cjk()
            ascii_buf += c
        elif is_cjk(c):
            if ascii_buf: flush_ascii()
            cjk.append(c)
        else:
            if ascii_buf: flush_ascii()
            if cjk: flush_cjk()
    if ascii_buf: flush_ascii()
    if cjk: flush_cjk()
    return out


class BM25:
    """Mirror of the CLI Bm25Index: title x3, tags x2, head x1, k1=1.2, b=0.75."""
    K1, B = 1.2, 0.75
    W = {'title': 3.0, 'tags': 2.0, 'head': 1.0}

    def __init__(self, docs):
        self.ids, self.doc_tokens = [], {}
        self.tf, self.df = {}, defaultdict(int)
        self.dl = {}
        for did, d in docs.items():
            tf = defaultdict(float)
            length = 0.0
            for field, weight in self.W.items():
                toks = tokenize(d.get(field, ''))
                for t in toks:
                    tf[t] += weight
                length += len(toks) * weight
            self.ids.append(did)
            self.doc_tokens[did] = tf
            self.dl[did] = length
            for t in tf:
                self.df[t] += 1
        self.n = max(1, len(self.ids))
        self.avgdl = sum(self.dl.values()) / self.n or 1.0
        self.idf = {t: math.log(1 + (self.n - df + 0.5) / (df + 0.5)) for t, df in self.df.items()}

    def candidates(self, query, topk=100):
        qt = list(dict.fromkeys(tokenize(query)))
        scored = []
        for did in self.ids:
            tf = self.doc_tokens[did]
            dl = self.dl[did]
            s = 0.0
            for t in qt:
                n = tf.get(t, 0.0)
                if not n:
                    continue
                s += self.idf.get(t, 0.0) * n * (self.K1 + 1) / (n + self.K1 * (1 - self.B + self.B * dl / self.avgdl))
            if s > 0:
                scored.append((s, did))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return scored[:topk]


def load_store(db):
    con = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    docs = {}
    for r in con.execute("select id,title,content_head,tags,project,created_at,kind from memories where deleted=0"):
        docs[r[0]] = {'title': r[1] or '', 'head': r[2] or '', 'tags': r[3] or '',
                      'project': r[4] or '', 'created_at': r[5] or '', 'kind': r[6] or ''}
    labels = {}
    for ts, q, project, adopted, good in con.execute(
            "select ts_unix,query,project,adopted,good_ids from query_log "
            "where adopted!='[]' or good_ids!='[]' order by ts_unix,id"):
        try:
            pos = set(json.loads(adopted or '[]')) | set(json.loads(good or '[]'))
        except Exception:
            continue
        pos = {p for p in pos if p in docs}
        if not pos:
            continue
        e = labels.setdefault(q, {'ts': ts, 'project': project or '', 'positives': set()})
        e['positives'] |= pos
        e['ts'] = min(e['ts'], ts)
    con.close()
    return docs, labels


def cmd_prepare(args):
    docs, labels = load_store(args.db)
    print(f'docs {len(docs)} labeled queries {len(labels)}', flush=True)
    index = BM25(docs)
    rows = []
    for q, e in labels.items():
        cand = index.candidates(q, args.candidates)
        pos = [did for _, did in cand if did in e['positives']]
        if not pos:
            continue
        deep = [did for rank, (_, did) in enumerate(cand) if rank >= args.deep and did not in e['positives']]
        negatives = deep[:args.negatives]
        if not negatives:
            continue
        rows.append({'query': q, 'project': e['project'], 'ts': e['ts'],
                     'positives': sorted(e['positives']), 'negatives': negatives})
    rows.sort(key=lambda r: (r['ts'], r['query']))
    cut = max(1, int(len(rows) * (1 - args.holdout)))
    for i, r in enumerate(rows):
        r['split'] = 'test' if i >= cut else 'train'
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    print(f'pairs {len(rows)} train {cut} test {len(rows)-cut} -> {args.out}', flush=True)


class LoRALinear(nn.Module):
    def __init__(self, base, rank, alpha):
        super().__init__()
        self.base = base
        self.rank = rank
        self.scale = alpha / rank
        self.A = nn.Parameter(torch.empty(rank, base.in_features))
        self.B = nn.Parameter(torch.zeros(base.out_features, rank))
        nn.init.kaiming_uniform_(self.A, a=math.sqrt(5))
        for p in self.base.parameters():
            p.requires_grad = False

    def forward(self, x):
        return self.base(x) + (x @ self.A.t() @ self.B.t()) * self.scale


def apply_lora(model, layers, rank, alpha):
    wrapped = {}
    for i in layers:
        layer = model.layers[i]
        for name in ('Wqkv', 'Wo'):
            mod = getattr(layer.attn, name)
            if isinstance(mod, LoRALinear):
                continue
            setattr(layer.attn, name, LoRALinear(mod, rank, alpha))
            wrapped[f'layers.{i}.attn.{name}'] = getattr(layer.attn, name)
    return wrapped


def resolve_layers(model, spec):
    total = len(model.layers)
    if spec == 'all':
        return list(range(total))
    n = int(spec)
    return list(range(max(0, total - n), total))


def encode(model, tok, texts, max_len, batch=32):
    out = []
    model.eval()
    with torch.inference_mode():
        for i in range(0, len(texts), batch):
            b = tok(texts[i:i+batch], padding=True, truncation=True, max_length=max_len, return_tensors='pt')
            h = model(**b).last_hidden_state[:, 0]
            out.append(nn.functional.normalize(h, dim=-1).cpu().numpy())
    return np.vstack(out)


def doc_text(d):
    return (d['title'] + '\n' + d['head'])[:1200]


def load_pairs(path, split=None):
    rows = []
    for line in open(path):
        r = json.loads(line)
        if split and r.get('split') != split:
            continue
        rows.append(r)
    return rows


def cmd_train(args):
    torch.set_num_threads(args.threads)
    pairs = load_pairs(args.pairs, 'train')
    print(f'train queries {len(pairs)}', flush=True)
    docs = {}
    con = sqlite3.connect(f'file:{args.db}?mode=ro', uri=True)
    for r in con.execute("select id,title,content_head from memories where deleted=0"):
        docs[r[0]] = {'title': r[1] or '', 'head': r[2] or ''}
    con.close()
    pairs = [p for p in pairs if p['positives'] and p['negatives']]
    tok = AutoTokenizer.from_pretrained(args.base)
    model = AutoModel.from_pretrained(args.base).float()
    for p in model.parameters():
        p.requires_grad = False
    layers = resolve_layers(model, args.lora_layers)
    wrapped = apply_lora(model, layers, args.rank, args.alpha)
    params = [p for m in wrapped.values() for p in (m.A, m.B)]
    print(f'lora modules {len(wrapped)} params {sum(p.numel() for p in params)} layers {layers}', flush=True)
    opt = torch.optim.AdamW(params, lr=args.lr, weight_decay=0.01)
    rng = np.random.default_rng(args.seed)
    for epoch in range(1, args.epochs + 1):
        rng.shuffle(pairs)
        total, steps = 0.0, 0
        t0 = time.time()
        for start in range(0, len(pairs), args.batch):
            batch = pairs[start:start+args.batch]
            if len(batch) < 2:
                continue
            queries, docs_flat, targets = [], [], []
            for k, p in enumerate(batch):
                pos = p['positives'][0]
                if pos not in docs:
                    continue
                sel = [pos] + [n for n in p['negatives'] if n in docs][:args.negatives]
                queries.append(p['query'])
                targets.append(len(docs_flat))
                docs_flat.extend([doc_text(docs[n]) for n in sel])
            if len(queries) < 2:
                continue
            qb = tok(queries, padding=True, truncation=True, max_length=args.max_len, return_tensors='pt')
            db = tok(docs_flat, padding=True, truncation=True, max_length=args.max_len, return_tensors='pt')
            qh = nn.functional.normalize(model(**qb).last_hidden_state[:, 0], dim=-1)
            dh = nn.functional.normalize(model(**db).last_hidden_state[:, 0], dim=-1)
            logits = (qh @ dh.t()) / args.temperature
            target = torch.tensor(targets, dtype=torch.long)
            loss = nn.functional.cross_entropy(logits, target)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += float(loss.detach())
            steps += 1
            if steps % 20 == 0:
                print(f'epoch {epoch} step {steps} loss {total/steps:.4f} {time.time()-t0:.0f}s', flush=True)
        print(f'epoch {epoch} done loss {total/max(1,steps):.4f} {time.time()-t0:.0f}s', flush=True)
        state = {name: {'A': m.A.detach().cpu(), 'B': m.B.detach().cpu()} for name, m in wrapped.items()}
        torch.save({'base': args.base, 'layers': layers, 'rank': args.rank, 'alpha': args.alpha,
                    'max_len': args.max_len, 'state': state}, args.out)
        print(f'saved {args.out}', flush=True)


def load_tuned(base, adapter):
    state = torch.load(adapter, map_location='cpu')
    tok = AutoTokenizer.from_pretrained(base)
    model = AutoModel.from_pretrained(base).float()
    for p in model.parameters():
        p.requires_grad = False
    wrapped = apply_lora(model, state['layers'], state['rank'], state['alpha'])
    for name, m in wrapped.items():
        saved = state['state'].get(name)
        if saved is not None:
            m.A.data.copy_(saved['A']); m.B.data.copy_(saved['B'])
    model.eval()
    return tok, model, state


def dense_metrics(docs, ids, E, tok, model, rows, max_len, topk=20):
    if not rows:
        return None
    Q = encode(model, tok, [r['query'] for r in rows], max_len)
    ranks = []
    for qi, r in enumerate(rows):
        scores = E @ Q[qi]
        order = np.argsort(-scores)[:topk]
        found = next((k for k, idx in enumerate(order) if ids[idx] in r['positives']), None)
        ranks.append(found)
    n = len(ranks)
    return {'n': n,
            'hit10': round(sum(1 for x in ranks if x is not None and x < 10)/n, 4),
            'hit20': round(sum(1 for x in ranks if x is not None and x < 20)/n, 4),
            'mrr20': round(sum(0 if x is None or x >= 20 else 1/(x+1) for x in ranks)/n, 4)}


def cmd_reembed(args):
    torch.set_num_threads(args.threads)
    docs, _ = load_store(args.db)
    ids = list(docs.keys())
    if args.limit_docs:
        ids = ids[:args.limit_docs]
    if args.adapter:
        tok, model, state = load_tuned(args.base, args.adapter)
        max_len = args.max_len
    else:
        tok = AutoTokenizer.from_pretrained(args.base)
        model = AutoModel.from_pretrained(args.base).float().eval()
        max_len = args.max_len
    print(f'embedding {len(ids)} docs with {args.base} adapter={args.adapter}', flush=True)
    t0 = time.time()
    E = encode(model, tok, [doc_text(docs[d]) for d in ids], max_len)
    print(f'embedded {E.shape} {time.time()-t0:.0f}s', flush=True)
    version = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    vdir = os.path.join(args.index_dir, version)
    os.makedirs(vdir, exist_ok=False)
    np.save(os.path.join(vdir, 'docs.npy'), E)
    json.dump(ids, open(os.path.join(vdir, 'ids.json'), 'w'), ensure_ascii=False)
    test_rows = load_pairs(args.pairs, 'test') if args.pairs and os.path.exists(args.pairs) else []
    metrics = dense_metrics(docs, ids, E, tok, model, test_rows, args.max_len) if test_rows else None
    meta = {'version': version, 'base': args.base, 'adapter': args.adapter,
            'docs': len(ids), 'dim': int(E.shape[1]), 'max_len': max_len,
            'test': metrics, 'created_at': datetime.now(timezone.utc).isoformat()}
    json.dump(meta, open(os.path.join(vdir, 'meta.json'), 'w'), ensure_ascii=False, indent=1)
    print('metrics', metrics, flush=True)
    current = os.path.join(args.index_dir, 'current')
    old = None
    if os.path.islink(current):
        try:
            old = json.load(open(os.path.join(current, 'meta.json'))).get('test')
        except Exception:
            old = None
    gate = True
    if args.min_hit20 is not None:
        if not metrics:
            gate = False
            print('gate: --min-hit20 requires nonempty test metrics', flush=True)
        elif metrics['hit20'] < args.min_hit20:
            gate = False
    if gate and old and metrics and metrics['hit20'] < old['hit20'] - args.tolerance:
        gate = False
        print(f'gate: new {metrics["hit20"]} < current {old["hit20"]} - {args.tolerance}', flush=True)
    if gate:
        tmp = current + '.tmp'
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink(version, tmp)
        os.replace(tmp, current)
        print(f'swapped current -> {version}', flush=True)
    else:
        print('gate: index not swapped; version kept for inspection', flush=True)
    index_root = os.path.realpath(args.index_dir)
    current_target = os.path.realpath(current)
    versions = sorted(d for d in os.listdir(index_root)
                      if not os.path.islink(os.path.join(index_root, d))
                      and os.path.isdir(os.path.join(index_root, d)))
    for v in versions[:-args.keep]:
        path = os.path.join(index_root, v)
        target = os.path.realpath(path)
        if v == version or target == current_target or current_target.startswith(target + os.sep):
            continue
        if os.path.islink(path) or os.path.commonpath([index_root, target]) != index_root:
            raise ValueError(f'refusing to remove index version outside {index_root}: {path}')
        shutil.rmtree(path)


def cmd_query(args):
    tok = AutoTokenizer.from_pretrained(args.base)
    model = AutoModel.from_pretrained(args.base).float().eval()
    cur = os.path.join(args.index_dir, 'current')
    E = np.load(os.path.join(cur, 'docs.npy'))
    ids = json.load(open(os.path.join(cur, 'ids.json')))
    q = encode(model, tok, [args.query], args.max_len)[0]
    scores = E @ q
    for idx in np.argsort(-scores)[:args.topk]:
        print(f'{ids[idx]} {scores[idx]:.4f}')


def cmd_status(args):
    cur = os.path.join(args.index_dir, 'current')
    print(json.dumps(json.load(open(os.path.join(cur, 'meta.json'))), ensure_ascii=False, indent=1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default=DEFAULT_DB)
    ap.add_argument('--base', default=DEFAULT_BASE)
    ap.add_argument('--index-dir', default=os.path.join(DEFAULT_STATE, 'index'))
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('prepare')
    p.add_argument('--out', default=os.path.join(DEFAULT_STATE, 'pairs.jsonl'))
    p.add_argument('--holdout', type=float, default=0.1)
    p.add_argument('--candidates', type=int, default=100)
    p.add_argument('--deep', type=int, default=20)
    p.add_argument('--negatives', type=int, default=8)

    t = sub.add_parser('train')
    t.add_argument('--pairs', default=os.path.join(DEFAULT_STATE, 'pairs.jsonl'))
    t.add_argument('--out', default=os.path.join(DEFAULT_STATE, 'adapter.pt'))
    t.add_argument('--epochs', type=int, default=3)
    t.add_argument('--batch', type=int, default=8)
    t.add_argument('--negatives', type=int, default=4)
    t.add_argument('--max-len', type=int, default=128)
    t.add_argument('--lora-layers', default='2')
    t.add_argument('--rank', type=int, default=8)
    t.add_argument('--alpha', type=int, default=16)
    t.add_argument('--lr', type=float, default=1e-3)
    t.add_argument('--temperature', type=float, default=0.05)
    t.add_argument('--threads', type=int, default=6)
    t.add_argument('--seed', type=int, default=0)

    r = sub.add_parser('reembed')
    r.add_argument('--adapter', default='')
    r.add_argument('--pairs', default=os.path.join(DEFAULT_STATE, 'pairs.jsonl'))
    r.add_argument('--max-len', type=int, default=256)
    r.add_argument('--threads', type=int, default=6)
    r.add_argument('--limit-docs', type=int, default=0)
    r.add_argument('--min-hit20', type=float, default=None)
    r.add_argument('--tolerance', type=float, default=0.005)
    r.add_argument('--keep', type=int, default=3)

    q = sub.add_parser('query')
    q.add_argument('query')
    q.add_argument('--topk', type=int, default=10)
    q.add_argument('--max-len', type=int, default=128)

    sub.add_parser('status')
    args = ap.parse_args()
    {'prepare': cmd_prepare, 'train': cmd_train, 'reembed': cmd_reembed,
     'query': cmd_query, 'status': cmd_status}[args.cmd](args)


if __name__ == '__main__':
    main()
