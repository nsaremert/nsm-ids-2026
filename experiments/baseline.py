#!/usr/bin/env python3
"""baseline.py — NSM-IDS-2026 baseline IDS classifier (v1.1).

Loads the v1.1 ML table (`session_id` + 66 CICIDS2017 features + `Label`), trains a
RandomForest (and XGBoost if installed), and reports accuracy, macro-F1, a binary
false-alarm rate (FAR), a per-class classification report, and a confusion matrix.

By default it uses a **session-based split** (the honest evaluation for this dataset),
reading the `session_id` column directly — no timestamp parsing needed. `session_id` is
treated as metadata and is never used as a feature.

Usage
-----
  python baseline.py                                        # NSM-IDS-2026_ML_v1.1.csv, session split
  python baseline.py --data NSM-IDS-2026_ML_v1.1.csv
  python baseline.py --features portable                    # only the 62 portable features
  python baseline.py --split random --model rf              # random stratified split
  python baseline.py --test-sessions 3,7,11 --trees 300

Dependencies: pandas, scikit-learn (xgboost optional).

Evaluation: `--split session` (default) holds out `--test-sessions` (default 3,7,11) and is
leakage-aware; `--split random` is a stratified split, kept only as an optimistic reference
(≈27% of rows are exact duplicates, so random splits can leak identical rows across folds).
"""
from __future__ import annotations
import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split


def load(path: str):
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        sys.exit(f"Veri bulunamadı: {path}  (--data ile yol ver)")
    if "Label" not in df.columns:
        sys.exit("CSV'de 'Label' kolonu yok.")
    y = df["Label"].astype(str)
    sid = df["session_id"].to_numpy() if "session_id" in df.columns else None
    meta = [c for c in ("Label", "session_id") if c in df.columns]  # session_id metadata, öznitelik DEĞİL
    X = df.drop(columns=meta).apply(pd.to_numeric, errors="coerce")
    # Bu sürümde inf/NaN yok; yeniden-üretilen veride olabilir diye güvenlik için temizle.
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X, y, sid


def binary_far(y_true, y_pred) -> float:
    """İkili yanlış-alarm oranı: BENIGN örneklerin 'saldırı' tahmin edilme oranı."""
    y_true = np.asarray(y_true); y_pred = np.asarray(y_pred)
    benign = y_true == "BENIGN"
    if benign.sum() == 0:
        return float("nan")
    return float(((y_pred != "BENIGN") & benign).sum() / benign.sum())


def report(name: str, y_true, y_pred) -> float:
    mf1 = f1_score(y_true, y_pred, average="macro")
    print(f"\n==== {name} ====")
    print(f"accuracy={accuracy_score(y_true, y_pred):.4f}  "
          f"macro-F1={mf1:.4f}  binary-FAR={binary_far(y_true, y_pred):.4f}")
    print(classification_report(y_true, y_pred, digits=3, zero_division=0))
    cm = pd.crosstab(pd.Series(np.asarray(y_true), name="true"),
                     pd.Series(np.asarray(y_pred), name="pred"))
    print("confusion matrix (true × pred):")
    print(cm.to_string())
    return mf1


def main() -> int:
    ap = argparse.ArgumentParser(description="NSM-IDS-2026 baseline classifier")
    ap.add_argument("--data", default="NSM-IDS-2026_ML_v1.1.csv")
    ap.add_argument("--features", choices=["all", "portable"], default="all",
                    help="portable: yalnız NSM-IDS-2026_portable_features.txt sütunlarını kullan")
    ap.add_argument("--portable-file", default="NSM-IDS-2026_portable_features.txt")
    ap.add_argument("--model", choices=["rf", "xgb", "both"], default="both")
    ap.add_argument("--split", choices=["session", "random"], default="session",
                    help="session: oturum-bazlı (önerilen, session_id gerekir); random: stratified")
    ap.add_argument("--test-sessions", default="3,7,11", help="session bölmede test oturumları")
    ap.add_argument("--test-size", type=float, default=0.3, help="random bölmede test oranı")
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--sample", type=int, default=0, help="hız için N satır örnekle (yalnız random)")
    a = ap.parse_args()

    X, y, sid = load(a.data)
    if a.features == "portable":
        pf = a.portable_file
        if not os.path.isabs(pf) and not os.path.exists(pf):
            pf = os.path.join(os.path.dirname(os.path.abspath(a.data)), a.portable_file)
        try:
            cols = [ln.strip() for ln in open(pf) if ln.strip()]
        except FileNotFoundError:
            sys.exit(f"portable öznitelik dosyası bulunamadı: {pf}")
        keep = [c for c in cols if c in X.columns]
        X = X[keep]
        print(f"portable alt küme: {len(keep)} öznitelik ({os.path.basename(pf)})")

    print(f"veri: {X.shape[0]:,} satır × {X.shape[1]} öznitelik, {y.nunique()} sınıf")
    print("sınıflar:", ", ".join(f"{k}({v})" for k, v in y.value_counts().items()))

    if a.split == "session" and sid is None:
        print("(session_id yok → rastgele bölmeye düşülüyor)")
        a.split = "random"

    if a.split == "session":
        test = {int(s) for s in a.test_sessions.split(",")}
        mask = np.isin(sid, list(test))
        Xtr, Xte, ytr, yte = X[~mask], X[mask], y[~mask], y[mask]
        print(f"oturum-bazlı bölme: test oturumları {sorted(test)} "
              f"(train {len(ytr):,} / test {len(yte):,})")
    else:
        if a.sample and a.sample < len(X):
            idx = X.sample(a.sample, random_state=a.seed).index
            X, y = X.loc[idx], y.loc[idx]
        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=a.test_size, random_state=a.seed, stratify=y)
        print(f"rastgele (stratified) bölme: test_size={a.test_size}")

    results: dict[str, float] = {}

    if a.model in ("rf", "both"):
        rf = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=a.seed)
        rf.fit(Xtr, ytr)
        results["RandomForest"] = report("RandomForest", yte, rf.predict(Xte))

    if a.model in ("xgb", "both"):
        try:
            from sklearn.preprocessing import LabelEncoder
            from xgboost import XGBClassifier
            le = LabelEncoder()
            ytr_e = le.fit_transform(ytr)
            xgb = XGBClassifier(n_estimators=a.trees, tree_method="hist",
                                n_jobs=-1, random_state=a.seed, eval_metric="mlogloss")
            xgb.fit(Xtr, ytr_e)
            pred = le.inverse_transform(xgb.predict(Xte))
            results["XGBoost"] = report("XGBoost", yte, pred)
        except ImportError:
            print("\n(XGBoost kurulu değil — atlandı; `pip install xgboost`)")

    print("\n=== özet (macro-F1) ===")
    for k, v in results.items():
        print(f"  {k}: {v:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
