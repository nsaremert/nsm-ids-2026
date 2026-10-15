#!/usr/bin/env python3
"""E5 — feature analysis.

(a) RF permutation importance (session split, measured on the test fold), top-20 figure.
(b) Lab-topology features (Destination Port, Init_Win_bytes_forward/backward,
    min_seg_size_forward): class-wise boxplots + standalone single-feature macro-F1.
(c) Ablation: 66 vs 62 (portable) per-class F1 difference (RF, session split).
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score

plt = C.setup_mpl()
df, X, y, sid, feats = C.load_ml_v11()
y = y.values
classes = C.classes_sorted(y)
LABTOPO = ["Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "min_seg_size_forward"]

te = np.isin(sid, C.REF_TEST_SESSIONS); tr = ~te
Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]

# (a) permutation importance
rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0).fit(Xtr, ytr)
pi = permutation_importance(rf, Xte, yte, n_repeats=10, random_state=0, n_jobs=-1,
                            scoring="f1_macro")
imp = pd.DataFrame({"feature": feats, "importance": pi.importances_mean,
                    "std": pi.importances_std}).sort_values("importance", ascending=False)
imp.to_csv(C.RESULTS / "e5_permutation_importance.csv", index=False)
top = imp.head(20).iloc[::-1]
fig, ax = plt.subplots(figsize=(6.6, 5.2))
ax.barh(range(len(top)), top["importance"], xerr=top["std"], color=C.TOL_MUTED[2], capsize=2)
ax.set_yticks(range(len(top))); ax.set_yticklabels(top["feature"])
ax.set_xlabel("permutation importance (drop in macro-F1)")
ax.set_title("RF permutation importance (session split, top 20)")
C.savefig(fig, "e5_permutation_top20")

# (b) lab-topology boxplots + single-feature power
fig, axes = plt.subplots(2, 2, figsize=(9.5, 7.0))
for ax, feat in zip(axes.ravel(), LABTOPO):
    data = [pd.to_numeric(X[feat], errors="coerce")[y == c].values for c in classes]
    bp = ax.boxplot(data, vert=True, showfliers=False, patch_artist=True)
    for patch, c in zip(bp["boxes"], classes):
        patch.set_facecolor(C.class_colors(classes)[c]); patch.set_alpha(0.8)
    ax.set_xticks(range(1, len(classes) + 1)); ax.set_xticklabels(classes, rotation=45, ha="right", fontsize=7)
    ax.set_title(feat); ax.set_ylabel("value")
fig.suptitle("Lab-topology features: class-wise distribution (outliers hidden)")
fig.tight_layout()
C.savefig(fig, "e5_labtopo_boxplots")

sfp = []
for feat in LABTOPO:
    Xc = pd.to_numeric(X[feat], errors="coerce").fillna(0).values.reshape(-1, 1)
    clf = DecisionTreeClassifier(max_depth=4, random_state=0).fit(Xc[tr], ytr)
    sfp.append({"feature": feat,
                "single_feature_macroF1_session": round(f1_score(yte, clf.predict(Xc[te]), average="macro"), 4),
                "perm_importance": round(float(imp.set_index("feature").loc[feat, "importance"]), 5)})
sfpdf = pd.DataFrame(sfp).set_index("feature")
sfpdf.to_csv(C.RESULTS / "e5_labtopo_single_feature.csv")
C.write_table(sfpdf, "e5_labtopo_single_feature", floatfmt="%.4f",
              caption="Lab-topology features: standalone single-feature macro-F1 (session split) and RF permutation importance.")

# (c) ablation 66 vs 62, per-class F1
portable = [f for f in C.portable_features() if f in feats]
res = {}
for tag, cols in [("F1_66", feats), ("F1_62", portable)]:
    yp = C.train_predict("RandomForest", 0, X[cols][tr], ytr, X[cols][te], trees=200)
    res[tag] = dict(zip(classes, f1_score(yte, yp, average=None, labels=classes, zero_division=0)))
abl = pd.DataFrame(res)
abl["delta(66-62)"] = abl["F1_66"] - abl["F1_62"]
abl.index.name = "Class"
abl = abl.sort_values("delta(66-62)", ascending=False)
abl.to_csv(C.RESULTS / "e5_ablation_66_vs_62.csv")
C.write_table(abl, "e5_ablation_66_vs_62", floatfmt="%.4f",
              caption="Ablation: per-class F1 with 66 vs 62 (portable) features (RF, session split).")

json.dump({"top5_importance": imp.head(5)[["feature", "importance"]].to_dict("records"),
           "labtopo_single_feature": sfp,
           "ablation_macroF1": {"F1_66": round(f1_score(yte, C.train_predict("RandomForest",0,X[feats][tr],ytr,X[feats][te]),average="macro"),4)},
           "outputs": ["e5_permutation_importance.csv", "e5_permutation_top20.{pdf,png}",
                       "e5_labtopo_boxplots.{pdf,png}", "e5_labtopo_single_feature.{csv,md,tex}",
                       "e5_ablation_66_vs_62.{csv,md,tex}"]},
          open(C.RESULTS / "e5_meta.json", "w"), indent=2)
print("[E5] DONE")
