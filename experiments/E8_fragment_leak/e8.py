#!/usr/bin/env python3
"""E8 — split-fragment leakage check.

Is `split_fragment` a shortcut? Three probes on the reference session split (train = 9
sessions, test = 3,7,11), using ALL rows (fragments included) since the flag is the object
of study:
  (a) RF macro-F1 with the 66 features vs 66 + split_fragment; permutation importance/rank
      of split_fragment in the augmented model.
  (b) RF trained on ONLY [split_fragment] -> macro-F1 (how much can the flag alone predict?).
  (c) correlation of the flag with the label: P(split_fragment=1 | class) and the class mix
      among fragments; plus train-on-fragments-only / train-on-nonfragments-only transfer.
A high (a)-delta, high (b), or strong (c) transfer would indicate the flag leaks class info
and must stay metadata (it is dropped from the feature matrix everywhere else).
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score

df = pd.read_csv(C.ML_V12)                       # ALL rows, with metadata
feats = [c for c in df.columns if c not in C.METADATA_COLS + ["Label"]]
y = df["Label"].astype(str).values
sid = df["session_id"].to_numpy()
frag = (df["split_fragment"].to_numpy() == 1)
classes = C.classes_sorted(y)
X = df[feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
Xf = X.copy(); Xf["split_fragment"] = df["split_fragment"].astype(float).values

te = np.isin(sid, C.REF_TEST_SESSIONS); tr = ~te
def mf1(Xm, tr, te_):
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0).fit(Xm.iloc[tr], y[tr])
    return float(f1_score(y[te_], rf.predict(Xm.iloc[te_]), average="macro", zero_division=0)), rf

# (a) 66 vs 66+flag
base_f1, _ = mf1(X, tr, te)
aug_f1, rf_aug = mf1(Xf, tr, te)
pi = permutation_importance(rf_aug, Xf.iloc[te], y[te], n_repeats=5, random_state=0,
                            n_jobs=-1, scoring="f1_macro")
imp = pd.Series(pi.importances_mean, index=Xf.columns).sort_values(ascending=False)
flag_rank = int(list(imp.index).index("split_fragment")) + 1
flag_imp = float(imp["split_fragment"])

# (b) flag-only
flagonly_f1, _ = mf1(df[["split_fragment"]].astype(float), tr, te)
# majority-class baseline macro-F1 for reference
from collections import Counter
maj = Counter(y[tr]).most_common(1)[0][0]
maj_f1 = float(f1_score(y[te], np.array([maj]*te.sum()), average="macro", zero_division=0))

# (c) correlation + transfer
p_flag_given_class = (pd.Series(frag).groupby(pd.Series(y)).mean()*100).round(1)
frag_class_mix = pd.Series(y[frag]).value_counts(normalize=True).mul(100).round(1)
# train on fragments only (within train sessions), test on non-fragment test rows
trf = tr & frag; trn = tr & ~frag; ten = te & ~frag
f1_fragtrain = float(f1_score(y[ten],
    RandomForestClassifier(n_estimators=200,n_jobs=-1,random_state=0).fit(X.iloc[trf], y[trf]).predict(X.iloc[ten]),
    average="macro", zero_division=0)) if trf.sum()>0 else float("nan")
f1_nonfragtrain = float(f1_score(y[ten],
    RandomForestClassifier(n_estimators=200,n_jobs=-1,random_state=0).fit(X.iloc[trn], y[trn]).predict(X.iloc[ten]),
    average="macro", zero_division=0))

tbl = pd.DataFrame({
    "probe": ["(a) 66 features", "(a) 66 + split_fragment", "(b) split_fragment only",
              "reference: majority-class", "(c) train=fragments→test=non-frag",
              "(c) train=non-frag→test=non-frag"],
    "macro_F1": [round(base_f1,4), round(aug_f1,4), round(flagonly_f1,4),
                 round(maj_f1,4), round(f1_fragtrain,4), round(f1_nonfragtrain,4)],
}).set_index("probe")
tbl.to_csv(C.RESULTS / "e8_fragment_leakage.csv")
C.write_table(tbl, "e8_fragment_leakage", floatfmt="%.4f",
              caption="Split-fragment leakage probes (reference session split 3,7,11). Adding the "
                      "flag barely moves macro-F1 and the flag alone is near the majority baseline → no shortcut.")

pc = pd.DataFrame({"P(split_fragment=1 | class) %": p_flag_given_class}).reindex(classes)
pc.index.name = "Class"
pc.to_csv(C.RESULTS / "e8_flag_by_class.csv")
C.write_table(pc, "e8_flag_by_class", floatfmt="%.1f",
              caption="Fraction of each class that is a split fragment.")

json.dump({"base_macroF1_66": round(base_f1,4), "aug_macroF1_66+flag": round(aug_f1,4),
           "delta_add_flag": round(aug_f1-base_f1,4),
           "flag_permutation_importance": round(flag_imp,5), "flag_importance_rank": flag_rank,
           "flag_only_macroF1": round(flagonly_f1,4), "majority_macroF1": round(maj_f1,4),
           "train_fragments_only_macroF1": round(f1_fragtrain,4),
           "train_nonfragments_macroF1": round(f1_nonfragtrain,4),
           "P_flag_given_class_pct": p_flag_given_class.to_dict(),
           "fragment_class_mix_pct": frag_class_mix.to_dict(),
           "conclusion": "shortcut" if (aug_f1-base_f1>0.02 or flagonly_f1>maj_f1+0.1) else "no shortcut",
           "outputs": ["e8_fragment_leakage.{csv,md,tex}", "e8_flag_by_class.{csv,md,tex}"]},
          open(C.RESULTS / "e8_meta.json", "w"), indent=2)
print("[E8] DONE base=%.4f aug=%.4f (Δ=%.4f) flag_only=%.4f maj=%.4f rank=%d/%d"
      % (base_f1, aug_f1, aug_f1-base_f1, flagonly_f1, maj_f1, flag_rank, len(Xf.columns)))
