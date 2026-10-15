#!/usr/bin/env python3
"""E2 — cross-session generalization (main baseline).

Group-based CV: 4 folds x 3 test sessions (common.CV_FOLDS). Models RF/XGB/LogReg/MLP,
3 seeds, feature sets {66 (ML), 62 (portable)}. Reports macro-F1/accuracy/binary-FAR and
per-class F1 as mean +/- std over folds x seeds. Normalized confusion matrix on the
reference 3/7/11 split (RF). Writes a JSONL of every fit for provenance.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C
from sklearn.metrics import confusion_matrix

TREES = 200
plt = C.setup_mpl()
df, X66, y, sid, feats66 = C.load_ml_v11()
portable = [f for f in C.portable_features() if f in feats66]
classes = C.classes_sorted(y)
FSETS = {"66": feats66, "62": portable}

raw_path = C.RESULTS / "e2_cv_raw.jsonl"
rows = []
missing_report = []
with open(raw_path, "w") as jf:
    for fset_name, fset in FSETS.items():
        Xf = X66[fset]
        for fi, test_sessions in enumerate(C.CV_FOLDS):
            te = np.isin(sid, test_sessions)
            tr = ~te
            # report classes missing from this fold's test (expected: none)
            miss = [c for c in classes if c not in set(y[te])]
            if miss:
                missing_report.append({"fold": fi, "test_sessions": test_sessions, "missing": miss})
            for seed in C.SEEDS:
                for model in C.MODEL_NAMES:
                    yp = C.train_predict(model, seed, Xf[tr], y[tr], Xf[te], trees=TREES)
                    m = C.metrics(y[te], yp, labels=classes)
                    rec = {"fset": fset_name, "fold": fi, "seed": seed, "model": model,
                           "accuracy": m["accuracy"], "macro_f1": m["macro_f1"],
                           "binary_far": m["binary_far"], **{f"f1_{k}": v for k, v in m["per_class_f1"].items()}}
                    rows.append(rec)
                    jf.write(json.dumps(rec) + "\n"); jf.flush()
                    print(f"[E2] fset={fset_name} fold={fi} seed={seed} {model:12s} "
                          f"macroF1={m['macro_f1']:.4f}", flush=True)

R = pd.DataFrame(rows)


def ms(series):
    return f"{series.mean():.3f} ± {series.std():.3f}"


# -------- summary table: model x (metric, fset) mean±std over folds*seeds
summ = []
for model in C.MODEL_NAMES:
    d = {}
    for fs in FSETS:
        sub = R[(R.model == model) & (R.fset == fs)]
        d[f"Macro-F1 ({fs})"] = ms(sub.macro_f1)
        d[f"Acc ({fs})"] = ms(sub.accuracy)
        d[f"FAR ({fs})"] = ms(sub.binary_far)
    summ.append(pd.Series(d, name=model))
summ = pd.DataFrame(summ)
summ.index.name = "Model"
summ.to_csv(C.RESULTS / "e2_cv_summary.csv")
C.write_table(summ, "e2_cv_summary", floatfmt="%s",
              caption="Cross-session CV (4 folds x 3 seeds): mean +/- std. 66 = ML features, 62 = portable subset.")

# -------- per-class F1 (66 feats) across models, mean±std
pc = {}
for model in C.MODEL_NAMES:
    sub = R[(R.model == model) & (R.fset == "66")]
    pc[model] = {c: ms(sub[f"f1_{c}"]) for c in classes}
pcdf = pd.DataFrame(pc)
pcdf.index.name = "Class"
pcdf.to_csv(C.RESULTS / "e2_per_class_f1.csv")
C.write_table(pcdf, "e2_per_class_f1", floatfmt="%s",
              caption="Per-class F1 (66 features), cross-session CV mean +/- std.")

# -------- confusion matrix on reference 3/7/11 split (RF, 66 feats, seed 0), normalized
te = np.isin(sid, C.REF_TEST_SESSIONS); tr = ~te
yp = C.train_predict("RandomForest", 0, X66[tr], y[tr], X66[te], trees=TREES)
cm = confusion_matrix(y[te], yp, labels=classes, normalize="true")
fig, ax = plt.subplots(figsize=(6.6, 5.6))
im = ax.imshow(cm, cmap="viridis", vmin=0, vmax=1)
ax.set_xticks(range(len(classes))); ax.set_yticks(range(len(classes)))
ax.set_xticklabels(classes, rotation=45, ha="right"); ax.set_yticklabels(classes)
ax.set_xlabel("Predicted"); ax.set_ylabel("True")
ax.set_title("Confusion matrix — RF, reference split (sessions 3,7,11), row-normalized")
for i in range(len(classes)):
    for j in range(len(classes)):
        if cm[i, j] >= 0.005:
            ax.text(j, i, f"{cm[i,j]:.2f}", ha="center", va="center",
                    color="white" if cm[i, j] < 0.6 else "black", fontsize=7)
fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Recall (row-normalized)")
C.savefig(fig, "e2_confusion_matrix_ref")

json.dump({"n_fits": len(R), "trees": TREES, "folds": C.CV_FOLDS, "seeds": C.SEEDS,
           "missing_classes_in_folds": missing_report or "none",
           "outputs": ["e2_cv_raw.jsonl", "e2_cv_summary.csv", "e2_per_class_f1.csv",
                       "e2_cv_summary.{md,tex}", "e2_per_class_f1.{md,tex}",
                       "e2_confusion_matrix_ref.{pdf,png}"]},
          open(C.RESULTS / "e2_meta.json", "w"), indent=2)
print("[E2] DONE", len(R), "fits")
