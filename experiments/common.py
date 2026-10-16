"""common.py — shared infrastructure for NSM-IDS-2026 technical-validation experiments.

Deterministic (fixed seeds, saved to results/seeds.json). No data is modified; all
outputs go to experiments/{results,figures,tables}/. Publication figures are saved as
both PDF (vector) and 300-dpi PNG with a colourblind-safe palette (Paul Tol 'muted').
"""
from __future__ import annotations
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd

# ----------------------------------------------------------------------------- paths
ROOT = Path(__file__).resolve().parent.parent          # ~/ids-pilot
DATA = ROOT / "dataset"
EXP = ROOT / "experiments"
# Output dirs carry an optional suffix so the fragment-sensitivity run (set
# NSM_OUT_SUFFIX=_withfrag) writes beside, not over, the main (fragment-excluded) run.
OUT_SUFFIX = os.environ.get("NSM_OUT_SUFFIX", "")
RESULTS = EXP / f"results{OUT_SUFFIX}"
FIGURES = EXP / f"figures{OUT_SUFFIX}"
TABLES = EXP / f"tables{OUT_SUFFIX}"
for _d in (RESULTS, FIGURES, TABLES):
    _d.mkdir(parents=True, exist_ok=True)

ML_V12 = DATA / "NSM-IDS-2026_ML_v1.2.csv"
FULL_V12 = DATA / "NSM-IDS-2026_full_v1.2.csv"
ML_V11 = DATA / "NSM-IDS-2026_ML_v1.1.csv"
FULL_V11 = DATA / "NSM-IDS-2026_full_v1.1.csv"
ML_V10 = DATA / "NSM-IDS-2026_ML.csv"
FULL_V10 = DATA / "NSM-IDS-2026_full.csv"
PORTABLE = DATA / "NSM-IDS-2026_portable_features.txt"
SPLIT = DATA / "NSM-IDS-2026_split_sessions.csv"
WAZUH = ROOT / "data" / "wazuh_logs"
GROUND_TRUTH = ROOT / "data" / "scenarios"

# v1.2 metadata columns — never model inputs. split_fragment marks CICFlowMeter
# reverse-direction continuation flows (first-FIN split); see data_dictionary / README.
METADATA_COLS = ["session_id", "split_fragment", "parent_label"]
FRAG_TOL_MS = 2000      # split-fragment time tolerance (= §1.4 window tolerance)
# Main analysis excludes split fragments; set NSM_INCLUDE_FRAGMENTS=1 for the sensitivity run.
EXCLUDE_FRAGMENTS = os.environ.get("NSM_INCLUDE_FRAGMENTS", "0") != "1"

# ----------------------------------------------------------------------------- seeds
SEEDS = [0, 1, 2]
REF_TEST_SESSIONS = [3, 7, 11]          # reference split (matches v1.1 split file)
# 4 folds x 3 test sessions (contiguous, deterministic); every fold's test has all 10 classes
CV_FOLDS = [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11]]


def save_seeds():
    (RESULTS / "seeds.json").write_text(json.dumps(
        {"seeds": SEEDS, "ref_test_sessions": REF_TEST_SESSIONS, "cv_folds": CV_FOLDS},
        indent=2))


# ----------------------------------------------------------------------------- data
IDENTIFIERS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"]


def load_ml(exclude_fragments=None):
    """Load the v1.2 ML table. session_id/split_fragment/parent_label are METADATA (never
    features). By default (main analysis) rows with split_fragment==1 are dropped; pass
    exclude_fragments=False to keep all rows (e.g. E1 describe). The env var
    NSM_INCLUDE_FRAGMENTS=1 flips the session-wide default (sensitivity run).
    Returns (df, X(66 feats, DataFrame), y(Series), sid(np.array), feats66(list))."""
    if exclude_fragments is None:
        exclude_fragments = EXCLUDE_FRAGMENTS
    df = pd.read_csv(ML_V12)
    if exclude_fragments and "split_fragment" in df.columns:
        df = df[df["split_fragment"] == 0].reset_index(drop=True)
    feats = [c for c in df.columns if c not in METADATA_COLS + ["Label"]]
    X = df[feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df, X, df["Label"].astype(str), df["session_id"].to_numpy(), feats


# back-compat alias: all modeling scripts call load_ml_v11(); it now serves v1.2.
load_ml_v11 = load_ml


def portable_features():
    return [ln.strip() for ln in open(PORTABLE) if ln.strip()]


def classes_sorted(y):
    return sorted(pd.Series(y).unique())


# ----------------------------------------------------------------------------- models
MODEL_NAMES = ["RandomForest", "XGBoost", "LogReg", "MLP"]


def make_estimator(name, seed, trees=200):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    if name == "RandomForest":
        return RandomForestClassifier(n_estimators=trees, n_jobs=-1, random_state=seed)
    if name == "XGBoost":
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=trees, tree_method="hist", n_jobs=-1,
                             random_state=seed, eval_metric="mlogloss")
    if name == "LogReg":
        return Pipeline([("sc", StandardScaler()),
                         ("lr", LogisticRegression(max_iter=1000, random_state=seed))])
    if name == "MLP":
        return Pipeline([("sc", StandardScaler()),
                         ("mlp", MLPClassifier(hidden_layer_sizes=(64,), max_iter=120,
                                               early_stopping=True, n_iter_no_change=8,
                                               random_state=seed))])
    raise ValueError(name)


def train_predict(name, seed, Xtr, ytr, Xte, trees=200):
    """Fit and predict, returning string-label predictions. Handles XGBoost label encoding."""
    est = make_estimator(name, seed, trees=trees)
    if name == "XGBoost":
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        est.fit(Xtr, le.fit_transform(ytr))
        return le.inverse_transform(est.predict(Xte))
    est.fit(Xtr, ytr)
    return est.predict(Xte)


# ----------------------------------------------------------------------------- metrics
def binary_far(y_true, y_pred):
    y_true = np.asarray(y_true); y_pred = np.asarray(y_pred)
    benign = y_true == "BENIGN"
    return float(((y_pred != "BENIGN") & benign).sum() / max(benign.sum(), 1))


def metrics(y_true, y_pred, labels=None):
    from sklearn.metrics import accuracy_score, f1_score
    labels = labels or classes_sorted(y_true)
    per = dict(zip(labels, f1_score(y_true, y_pred, average=None, labels=labels, zero_division=0)))
    return {"accuracy": float(accuracy_score(y_true, y_pred)),
            "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "binary_far": binary_far(y_true, y_pred),
            "per_class_f1": {k: float(v) for k, v in per.items()}}


# ----------------------------------------------------------------------------- plotting
# Paul Tol 'muted' qualitative palette (colourblind-safe) + grey
TOL_MUTED = ["#332288", "#88CCEE", "#44AA99", "#117733", "#999933",
             "#DDCC77", "#CC6677", "#882255", "#AA4499", "#BBBBBB"]


def setup_mpl():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.dpi": 120, "savefig.dpi": 300, "savefig.bbox": "tight",
        "font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 8.5,
        "axes.grid": True, "grid.alpha": 0.3, "axes.axisbelow": True,
        "font.family": "DejaVu Sans", "pdf.fonttype": 42, "ps.fonttype": 42,
    })
    return plt


def class_colors(labels):
    labels = list(labels)
    return {lab: TOL_MUTED[i % len(TOL_MUTED)] for i, lab in enumerate(labels)}


def savefig(fig, name):
    """Save a figure as both PDF and 300-dpi PNG under experiments/figures/."""
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"{name}.{ext}")
    import matplotlib.pyplot as plt
    plt.close(fig)
    return [str(FIGURES / f"{name}.{ext}") for ext in ("pdf", "png")]


# ----------------------------------------------------------------------------- tables
def _fmt_cell(v, floatfmt):
    if isinstance(v, (float, np.floating)):
        return floatfmt % v
    if isinstance(v, (int, np.integer)):
        return str(int(v))
    return str(v)


def _format_df(df: pd.DataFrame, floatfmt):
    """Format each column by its own dtype (avoids row-wise float upcast)."""
    out = {}
    for c in df.columns:
        col = df[c]
        if pd.api.types.is_integer_dtype(col):
            out[c] = col.map(lambda v: str(int(v)))
        elif pd.api.types.is_float_dtype(col):
            out[c] = col.map(lambda v: "" if pd.isna(v) else floatfmt % v)
        else:
            out[c] = col.astype(str)
    return pd.DataFrame(out, index=df.index)


def _df_to_md(df: pd.DataFrame, floatfmt, index):
    s = _format_df(df, floatfmt)
    cols = ([df.index.name or ""] if index else []) + [str(c) for c in s.columns]
    lines = ["| " + " | ".join(cols) + " |",
             "| " + " | ".join("---" for _ in cols) + " |"]
    for idx, row in s.iterrows():
        cells = ([str(idx)] if index else []) + [str(v) for v in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _tex_esc(s):
    s = str(s)
    for a, b in (("\\", r"\textbackslash "), ("_", r"\_"), ("%", r"\%"),
                 ("&", r"\&"), ("#", r"\#"), ("$", r"\$")):
        s = s.replace(a, b)
    return s


def _df_to_latex(df: pd.DataFrame, floatfmt, index, caption, label):
    ncols = (1 if index else 0) + len(df.columns)
    colspec = "l" + "r" * (ncols - 1)
    header = ([df.index.name or ""] if index else []) + [str(c) for c in df.columns]
    s = _format_df(df, floatfmt)
    lines = [r"% requires \usepackage{booktabs}", r"\begin{table}[htbp]", r"\centering",
             rf"\caption{{{_tex_esc(caption)}}}", rf"\label{{tab:{label}}}",
             rf"\begin{{tabular}}{{{colspec}}}", r"\toprule",
             " & ".join(_tex_esc(h) for h in header) + r" \\", r"\midrule"]
    for idx, row in s.iterrows():
        cells = ([str(idx)] if index else []) + [str(v) for v in row]
        lines.append(" & ".join(_tex_esc(c) for c in cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines) + "\n"


def write_table(df: pd.DataFrame, name, floatfmt="%.4f", caption="", index=True):
    """Write a DataFrame as both Markdown (.md) and LaTeX (.tex) — no external deps."""
    md = _df_to_md(df, floatfmt, index)
    (TABLES / f"{name}.md").write_text((f"**{caption}**\n\n" if caption else "") + md + "\n")
    (TABLES / f"{name}.tex").write_text(_df_to_latex(df, floatfmt, index, caption or name, name))
    return [str(TABLES / f"{name}.md"), str(TABLES / f"{name}.tex")]
