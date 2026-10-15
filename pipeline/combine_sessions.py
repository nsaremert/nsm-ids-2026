#!/usr/bin/env python3
"""
combine_sessions.py — birden çok oturum datasetini tek büyük dataset'te birleştir.

Her `run_session.sh` çalıştırması `data/labeled/dataset_<TS>.parquet` üretir.
Bu betik hepsini birleştirir → hacim artar, sınıf dengesi iyileşir. Sonra
train_baseline ile birleşik veri üzerinde model eğitilir.

Kullanım:
  python pipeline/combine_sessions.py                 # tüm oturumları birleştir
  python pipeline/combine_sessions.py --glob 'data/labeled/dataset_2026*.parquet'
"""
import argparse
import glob
from pathlib import Path
import pandas as pd


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default="data/labeled/dataset_*.parquet")
    ap.add_argument("--out", default="data/labeled/dataset_combined.parquet")
    args = ap.parse_args()

    files = sorted(f for f in glob.glob(args.glob) if "combined" not in f)
    if not files:
        print(f"Oturum dataseti bulunamadı: {args.glob}")
        print("(Önce ./run_session.sh ile en az bir oturum koş.)")
        return 1

    frames = []
    for f in files:
        d = pd.read_parquet(f)
        d["session"] = Path(f).stem.replace("dataset_", "")
        frames.append(d)
        print(f"  {f}: {len(d)} akış")

    comb = pd.concat(frames, ignore_index=True, sort=False)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    comb.to_parquet(out, index=False)

    print(f"\n[combine] {len(files)} oturum → **{len(comb)} akış** → {out}")
    print("[combine] birleşik sınıf dağılımı:")
    for k, v in comb["label"].value_counts().items():
        print(f"    {k:16s} {v:6d}  ({100*v/len(comb):5.1f}%)")
    print(f"\nEğit: ./.venv/bin/python models/train_baseline.py "
          f"--dataset {out} --report models/report_combined.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
