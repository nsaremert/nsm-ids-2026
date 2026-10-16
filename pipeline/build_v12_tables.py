#!/usr/bin/env python3
"""build_v12_tables.py — assemble the NSM-IDS-2026 v1.2 ML/full tables.

Input: the 12 re-labeled per-session CICIDS CSVs produced by `label_cic.py` with the v1.2
ground truth (Infiltration on ports 21,22,80 — FIX A). Each file is one capture session.

Adds three METADATA columns (never model inputs):
  - session_id    : capture-session index 0..11 (sorted chronological = concat order)
  - split_fragment: 1 iff this flow is the reverse-direction continuation of an EARLIER flow
                    (reversed 5-tuple, same protocol, started within --tol-ms; the forward /
                    SYN-bearing half is the parent). Marks CICFlowMeter first-FIN split tails.
  - parent_label  : the parent (forward half) Label when split_fragment==1, else "".

Writes:
  dataset/NSM-IDS-2026_full_v1.2.csv  (6 identifiers + 3 metadata + 78 features + Label, 88 cols)
  dataset/NSM-IDS-2026_ML_v1.2.csv    (3 metadata + 66 features + Label, 70 cols)

Deterministic; modifies no input file; no network.

  python pipeline/build_v12_tables.py --glob 'data/cicids/cicids_v12_*.csv'
"""
from __future__ import annotations
import argparse, bisect, glob
from pathlib import Path
import numpy as np, pandas as pd

ROOT = Path(__file__).resolve().parent.parent
# the 12 upstream-corrupted columns dropped from the ML table in v1.1 (kept in full for parity)
CORRUPTED12 = ["Active Mean", "Active Std", "Active Max", "Active Min",
               "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
               "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes"]
IDENTIFIERS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"]


def compute_split_fragment(df: pd.DataFrame, tol_ms: int):
    """Return (split_fragment int8 array, parent_label object array)."""
    N = len(df)
    start = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
    start_ms = ((start - pd.Timestamp("1970-01-01")).dt.total_seconds() * 1000.0).fillna(0).to_numpy()
    sip = df["Source IP"].astype(str).to_numpy(); dip = df["Destination IP"].astype(str).to_numpy()
    spt = pd.to_numeric(df["Source Port"], errors="coerce").fillna(-1).astype(int).to_numpy()
    dpt = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(-1).astype(int).to_numpy()
    pro = pd.to_numeric(df["Protocol"], errors="coerce").fillna(-1).astype(int).to_numpy()
    lab = df["Label"].astype(str).to_numpy()
    syn = (pd.to_numeric(df["SYN Flag Count"], errors="coerce").fillna(0).to_numpy() > 0).astype(int)

    fwd = lambda i: (sip[i], spt[i], dip[i], dpt[i], pro[i])
    rev = lambda i: (dip[i], dpt[i], sip[i], spt[i], pro[i])
    # process by (start_ms, SYN-first, row): among a reverse pair the SYN/initiator is the parent
    order = np.lexsort((np.arange(N), -syn, start_ms))
    frag = np.zeros(N, dtype=np.int8)
    parent = np.array([""] * N, dtype=object)
    starts, labels = {}, {}                      # directed_key -> parallel sorted lists
    for i in order:
        rk = rev(i)
        ss = starts.get(rk)
        if ss:
            lo = bisect.bisect_left(ss, start_ms[i] - tol_ms)
            hi = bisect.bisect_right(ss, start_ms[i])     # earlier-or-equal-start flows only
            if hi > lo:
                frag[i] = 1
                parent[i] = labels[rk][hi - 1]            # closest (max start <= this) parent
        fk = fwd(i)
        starts.setdefault(fk, []).append(start_ms[i])
        labels.setdefault(fk, []).append(lab[i])
    return frag, parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default=str(ROOT / "data/cicids/cicids_v12_*.csv"),
                    help="per-session re-labeled CICIDS CSVs (one file = one session)")
    ap.add_argument("--out-full", default=str(ROOT / "dataset/NSM-IDS-2026_full_v1.2.csv"))
    ap.add_argument("--out-ml", default=str(ROOT / "dataset/NSM-IDS-2026_ML_v1.2.csv"))
    ap.add_argument("--tol-ms", type=int, default=2000, help="split-fragment time tolerance")
    a = ap.parse_args()

    files = sorted(glob.glob(a.glob))             # sorted = chronological => session_id order
    if not files:
        print(f"no files matched {a.glob}"); return 1
    frames, sid = [], []
    for s, f in enumerate(files):
        d = pd.read_csv(f, skipinitialspace=True); d.columns = [c.strip() for c in d.columns]
        frames.append(d); sid.extend([s] * len(d))
    full = pd.concat(frames, ignore_index=True)
    full.columns = [c.strip() for c in full.columns]
    N = len(full)
    assert list(full.columns[:6]) == IDENTIFIERS and full.columns[-1] == "Label", "unexpected schema"

    frag, parent = compute_split_fragment(full, a.tol_ms)
    full.insert(6, "session_id", np.array(sid, dtype=int))
    full.insert(7, "split_fragment", frag)
    full.insert(8, "parent_label", parent)

    feats78 = [c for c in full.columns if c not in IDENTIFIERS + ["session_id", "split_fragment", "parent_label", "Label"]]
    feats66 = [c for c in feats78 if c not in CORRUPTED12]
    assert len(feats66) == 66, len(feats66)
    ml = full[["session_id", "split_fragment", "parent_label"] + feats66 + ["Label"]]

    Path(a.out_full).parent.mkdir(parents=True, exist_ok=True)
    full.to_csv(a.out_full, index=False)
    ml.to_csv(a.out_ml, index=False)
    print(f"[v1.2] {N} flows, {len(files)} sessions → {Path(a.out_full).name} ({full.shape[1]} cols), "
          f"{Path(a.out_ml).name} ({ml.shape[1]} cols)")
    print(f"[v1.2] split_fragment=1: {int(frag.sum())} ({100*frag.mean():.1f}%); "
          f"Infiltration: {int((full['Label']=='Infiltration').sum())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
