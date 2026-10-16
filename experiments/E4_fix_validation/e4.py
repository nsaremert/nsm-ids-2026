#!/usr/bin/env python3
"""E4 — validation of the v1.0 -> v1.1 fix.

(a) Single-feature decision tree on each of the 12 corrupted v1.0 columns, under random vs
    session split -> shows the broken Idle columns leak under random splits.
(b) Per-class fraction of rows with Idle Mean > 1e14 in v1.0 (class-dependent corruption).
(c) Session-based RF: v1.0 (78 feats) vs v1.1 (66 feats): macro-F1 + per-class recall.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score, recall_score
from sklearn.model_selection import train_test_split

plt = C.setup_mpl()
# v1.2 (session_id + Label + 66, ALL rows) and v1.0 ML (78 + Label), row-aligned.
# This experiment isolates the Active/Idle/Subflow COLUMN fix, so it keeps all rows and
# uses one consistent target (v1.2 labels) for both the 78- and 66-feature matrices.
df11, X66, y, sid, feats66 = C.load_ml(exclude_fragments=False)
v10 = pd.read_csv(C.ML_V10)
_ndiff = int((v10["Label"].astype(str).values != y.values).sum())
assert len(v10) == len(df11), "v1.0 ve v1.2 satır sayısı farklı"
assert _ndiff <= 893, f"beklenmeyen etiket farkı ({_ndiff}); v1.2 FIX A yalnız 893 akışı değiştirir"
y = y.values
classes = C.classes_sorted(y)
feats78 = [c for c in v10.columns if c != "Label"]
X78 = v10[feats78].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)

CORRUPTED = ["Active Mean", "Active Std", "Active Max", "Active Min",
             "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
             "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes"]

# splits
te_sess = np.isin(sid, C.REF_TEST_SESSIONS)
s_tr, s_te = np.where(~te_sess)[0], np.where(te_sess)[0]
idx = np.arange(len(y))
r_tr, r_te = train_test_split(idx, test_size=0.3, random_state=42, stratify=y)


def single_feat_mf1(col, tr, te):
    Xc = X78[[col]].values
    clf = DecisionTreeClassifier(max_depth=4, random_state=0).fit(Xc[tr], y[tr])
    return float(f1_score(y[te], clf.predict(Xc[te]), average="macro", zero_division=0))


# (a) single-feature leakage
rows = []
for col in CORRUPTED:
    r = single_feat_mf1(col, r_tr, r_te)
    s = single_feat_mf1(col, s_tr, s_te)
    rows.append({"feature": col, "random_macroF1": round(r, 4), "session_macroF1": round(s, 4),
                 "delta_rnd_minus_sess": round(r - s, 4)})
sf = pd.DataFrame(rows).set_index("feature")
sf.to_csv(C.RESULTS / "e4_single_feature_corrupted.csv")
C.write_table(sf, "e4_single_feature_corrupted", floatfmt="%.4f",
              caption="Single-feature decision-tree macro-F1 on the 12 corrupted v1.0 columns (random vs session split).")

fig, ax = plt.subplots(figsize=(7.4, 3.6))
xp = np.arange(len(CORRUPTED))
ax.bar(xp - 0.2, sf["random_macroF1"], 0.4, label="random split", color=C.TOL_MUTED[6])
ax.bar(xp + 0.2, sf["session_macroF1"], 0.4, label="session split", color=C.TOL_MUTED[0])
ax.set_xticks(xp); ax.set_xticklabels(CORRUPTED, rotation=45, ha="right")
ax.set_ylabel("single-feature macro-F1"); ax.set_title("Corrupted v1.0 columns: random vs session split")
ax.legend(frameon=False)
C.savefig(fig, "e4_single_feature_corrupted")

# (b) Idle>1e14 fraction by class (v1.0)
idle = pd.to_numeric(X78["Idle Mean"], errors="coerce")
bad = (idle > 1e14)
by = pd.DataFrame({"frac_idle_gt_1e14": pd.Series(bad).groupby(pd.Series(y)).mean()})
by["percent"] = (100 * by["frac_idle_gt_1e14"]).round(1)
by = by[["percent"]].sort_values("percent", ascending=False)
by.index.name = "Class"
by.to_csv(C.RESULTS / "e4_idle_leak_by_class.csv")
C.write_table(by, "e4_idle_leak_by_class", floatfmt="%.1f",
              caption="v1.0: fraction of rows with 'Idle Mean' > 1e14 (corrupted), by class.")

fig, ax = plt.subplots(figsize=(6.4, 3.2))
ax.bar(range(len(by)), by["percent"].values, color=C.TOL_MUTED[7])
ax.set_xticks(range(len(by))); ax.set_xticklabels(by.index, rotation=45, ha="right")
ax.set_ylabel("% rows Idle>1e14"); ax.set_title("v1.0 class-dependent Idle corruption")
C.savefig(fig, "e4_idle_leak_by_class")

# (c) session-based RF: v1.0 (78) vs v1.1 (66)
res = {}
for tag, Xf in [("v1.0 (78)", X78), ("v1.2 (66)", X66)]:
    yp = C.train_predict("RandomForest", 0, Xf.iloc[s_tr], y[s_tr], Xf.iloc[s_te], trees=200)
    rec = recall_score(y[s_te], yp, average=None, labels=classes, zero_division=0)
    res[tag] = {"macro_F1": round(f1_score(y[s_te], yp, average="macro"), 4),
                **{c: round(v, 3) for c, v in zip(classes, rec)}}
cmp = pd.DataFrame(res)
cmp.index.name = "metric / per-class recall"
cmp.to_csv(C.RESULTS / "e4_v10_vs_v12_rf.csv")
C.write_table(cmp, "e4_v10_vs_v12_rf", floatfmt="%.3f",
              caption="Session-based RandomForest (sessions 3,7,11 test): v1.0 78 feats vs v1.2 66 feats.")

json.dump({"single_feature": rows,
           "idle_leak_by_class": by["percent"].to_dict(),
           "v10_vs_v12_macroF1": {k: res[k]["macro_F1"] for k in res},
           "outputs": ["e4_single_feature_corrupted.{csv,md,tex,pdf,png}",
                       "e4_idle_leak_by_class.{csv,md,tex,pdf,png}", "e4_v10_vs_v12_rf.{csv,md,tex}"]},
          open(C.RESULTS / "e4_meta.json", "w"), indent=2)
print("[E4] DONE  v10_vs_v12 macroF1:", {k: res[k]["macro_F1"] for k in res})
