#!/usr/bin/env python3
"""E3 — evaluation-protocol effect.

Same models (RF/XGB/LogReg/MLP), 3 seeds, 66 features, under three protocols:
  (a) random stratified split,
  (b) random stratified split AFTER removing exact duplicate feature rows,
  (c) session-based split (reference sessions 3,7,11).
Goal: quantify how the ~27% exact-duplicate rows inflate random-split scores.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C
from sklearn.model_selection import train_test_split

plt = C.setup_mpl()
df, X, y, sid, feats = C.load_ml_v11()
y = y.values
classes = C.classes_sorted(y)

# dedup mask on the 66 features (keep first)
dup_mask = X.duplicated(keep="first").values
n_dup = int(dup_mask.sum())
keep = ~dup_mask
dedup_size = int(keep.sum())

PROTO = {}
# (a) random stratified on all data
idx = np.arange(len(y))
ra_tr, ra_te = train_test_split(idx, test_size=0.3, random_state=42, stratify=y)
PROTO["a_random"] = (ra_tr, ra_te)
# (b) random stratified on deduped data
idx_d = np.where(keep)[0]
rb_tr, rb_te = train_test_split(idx_d, test_size=0.3, random_state=42, stratify=y[idx_d])
PROTO["b_random_dedup"] = (rb_tr, rb_te)
# (c) session-based
te = np.isin(sid, C.REF_TEST_SESSIONS)
PROTO["c_session"] = (np.where(~te)[0], np.where(te)[0])

rows = []
raw = open(C.RESULTS / "e3_protocol_raw.jsonl", "w")
for proto, (tr, teidx) in PROTO.items():
    for model in C.MODEL_NAMES:
        for seed in C.SEEDS:
            yp = C.train_predict(model, seed, X.iloc[tr], y[tr], X.iloc[teidx], trees=200)
            m = C.metrics(y[teidx], yp, labels=classes)
            rec = {"protocol": proto, "model": model, "seed": seed,
                   "macro_f1": m["macro_f1"], "accuracy": m["accuracy"], "binary_far": m["binary_far"]}
            rows.append(rec); raw.write(json.dumps(rec) + "\n"); raw.flush()
            print(f"[E3] {proto:16s} {model:12s} seed={seed} macroF1={m['macro_f1']:.4f}", flush=True)
raw.close()
R = pd.DataFrame(rows)

# table: protocol x model -> macro-F1 mean±std
labels_proto = {"a_random": "Random", "b_random_dedup": "Random (dedup)", "c_session": "Session"}
tbl = {}
for model in C.MODEL_NAMES:
    tbl[model] = {}
    for proto in PROTO:
        sub = R[(R.protocol == proto) & (R.model == model)]
        tbl[model][labels_proto[proto]] = f"{sub.macro_f1.mean():.3f} ± {sub.macro_f1.std():.3f}"
T = pd.DataFrame(tbl).T
T.index.name = "Model"
T = T[[labels_proto[p] for p in PROTO]]
T.to_csv(C.RESULTS / "e3_protocol_macroF1.csv")
C.write_table(T, "e3_protocol_macroF1", floatfmt="%s",
              caption=f"Macro-F1 (mean +/- std, 3 seeds) by evaluation protocol. "
                      f"Exact duplicate rows removed in 'dedup': {n_dup:,} of {len(y):,} "
                      f"({100*n_dup/len(y):.1f}%) -> {dedup_size:,} rows.")

# grouped bar figure
fig, ax = plt.subplots(figsize=(6.8, 3.6))
protos = list(PROTO); xp = np.arange(len(C.MODEL_NAMES)); w = 0.26
for k, proto in enumerate(protos):
    means = [R[(R.protocol == proto) & (R.model == m)].macro_f1.mean() for m in C.MODEL_NAMES]
    errs = [R[(R.protocol == proto) & (R.model == m)].macro_f1.std() for m in C.MODEL_NAMES]
    ax.bar(xp + (k - 1) * w, means, w, yerr=errs, capsize=2,
           label=labels_proto[proto], color=C.TOL_MUTED[[6, 5, 0][k]])
ax.set_xticks(xp); ax.set_xticklabels(C.MODEL_NAMES)
ax.set_ylabel("macro-F1"); ax.set_ylim(0.9, 1.0)
ax.set_title("Evaluation protocol effect (66 features, 3 seeds)")
ax.legend(frameon=False)
C.savefig(fig, "e3_protocol_macroF1")

json.dump({"n_duplicate_rows": n_dup, "pct_duplicate": round(100*n_dup/len(y), 2),
           "dedup_size": dedup_size,
           "macroF1": {m: {labels_proto[p]: round(R[(R.protocol==p)&(R.model==m)].macro_f1.mean(), 4)
                           for p in PROTO} for m in C.MODEL_NAMES},
           "outputs": ["e3_protocol_raw.jsonl", "e3_protocol_macroF1.{csv,md,tex}",
                       "e3_protocol_macroF1.{pdf,png}"]},
          open(C.RESULTS / "e3_meta.json", "w"), indent=2)
print("[E3] DONE")
