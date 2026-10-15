#!/usr/bin/env python3
"""
label_cic.py — kanonik CIC-IDS2017 CSV'yi ground_truth ile etiketle.

Girdi: cic_to_cicids çıktısı (IDENTIFIERS + 78 öznitelik + boş Label) veya ham
CICFlowMeter V4 CSV (bu durumda önce cic_to_cicids uygulanır).
Eşleşme: akışın zaman damgası [start_ts, end_ts] aralığında VE Source IP==saldırgan,
Destination IP==kurban, Destination Port eşleşmesi → ilgili CICIDS etiketi; yoksa BENIGN.

CICFlowMeter 'Timestamp' YEREL saat dizgesidir → epoch'a çevrilir (host offset).

Kullanım:
  python pipeline/label_cic.py --cic flows_cic.csv --ground-truth gt.csv \
     --out labeled.csv [--tz-offset-hours auto] [--tolerance-ms 2000]
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cic_to_cicids as cic


def _port_wild(v) -> bool:
    s = str(v).strip().lower()
    return s in ("", "*", "0", "any", "nan", "none")


def parse_ts_to_epoch_ms(series: pd.Series, offset_s: float) -> pd.Series:
    """CICFlowMeter damgası ('dd/MM/yyyy hh:mm:ss AM/PM') → epoch ms.
    Docker container TZ=UTC olduğundan damga UTC'dir (offset_s=0). Yerel tz'de
    çalışan bir CICFlowMeter için --tz-offset-hours ile düzeltilir."""
    dt = pd.to_datetime(series, format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
    if dt.isna().mean() > 0.5:                      # format tutmadı → esnek
        dt = pd.to_datetime(series, errors="coerce", dayfirst=True)
    # çözünürlükten bağımsız epoch ms (pandas2 us/ns resolution farkına karşı)
    epoch = pd.Timestamp("1970-01-01")
    return (dt - epoch).dt.total_seconds() * 1000.0 - offset_s * 1000.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cic", required=True, help="CIC CSV (kanonik veya ham V4)")
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tz-offset-hours", default="0",
                    help="CIC damgasının UTC ofseti (saat). CICFlowMeter-Docker UTC üretir → 0.")
    ap.add_argument("--tolerance-ms", type=int, default=2000)
    args = ap.parse_args()

    df = pd.read_csv(args.cic, skipinitialspace=True)
    # ham V4 ise kanoniğe çevir (identifiers + 78 + Label)
    if "Source IP" not in df.columns and "Src IP" in df.columns:
        df = cic.to_cicids(df)
    df.columns = [str(c).strip() for c in df.columns]
    if len(df) == 0:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.out, index=False)
        print("UYARI: boş CIC tablosu."); return 0

    offset_s = float(args.tz_offset_hours) * 3600.0

    flow_ms = parse_ts_to_epoch_ms(df["Timestamp"], offset_s)
    n_bad = int(flow_ms.isna().sum())
    if n_bad:
        print(f"UYARI: {n_bad} akışın zaman damgası çözümlenemedi (BENIGN kalır).")

    gt = pd.read_csv(args.ground_truth)
    need = {"label", "start_ts", "end_ts", "src_ip", "dst_ip", "dst_port"}
    miss = need - set(gt.columns)
    if miss:
        print(f"HATA: ground_truth eksik sütun: {miss}", file=sys.stderr); return 1

    labels = pd.Series(["BENIGN"] * len(df), index=df.index)
    src = df["Source IP"].astype(str)
    dst = df["Destination IP"].astype(str)
    dport = pd.to_numeric(df["Destination Port"], errors="coerce")
    tol = args.tolerance_ms

    for _, r in gt.iterrows():
        w0, w1 = int(r["start_ts"]) - tol, int(r["end_ts"]) + tol
        time_ok = flow_ms.between(w0, w1)
        ip_ok = (src == str(r["src_ip"])) & (dst == str(r["dst_ip"]))
        port_ok = pd.Series(True, index=df.index) if _port_wild(r["dst_port"]) \
            else (dport == float(r["dst_port"]))
        m = time_ok.fillna(False) & ip_ok & port_ok
        apply = m & (labels == "BENIGN")
        labels[apply] = str(r["label"])

    df["Label"] = labels.values
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)

    dist = df["Label"].value_counts()
    print(f"[label-cic] {len(df)} akış → {out}")
    for k, v in dist.items():
        print(f"    {str(k):18s} {v:6d}  ({100*v/len(df):5.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
