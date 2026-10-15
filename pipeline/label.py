#!/usr/bin/env python3
"""
label.py — akışları ground_truth ile etiketle (Doc Bölüm 8).

Kural (yer-gerçeği penceresi + 5'li eşleşme):
  Bir akış, bir ground_truth satırına ait sayılır ⇔
    (1) zaman: akış [first_seen, last_seen] ile [start_ts-tol, end_ts+tol] kesişir
    (2) kaynak IP: akış.src_ip == gt.src_ip   (saldırgan başlatır)
    (3) hedef IP: akış.dst_ip == gt.dst_ip
    (4) hedef port: gt.dst_port boş/"*"/0 ise herhangi; değilse eşit
  Hiçbir pencereye düşmeyen akış → 'benign'.

ÖNEMLİ: Normal (benign) trafik HOST'tan (10.10.10.1) üretilir; saldırılar
attacker'dan (10.10.10.20). Böylece src_ip benign ile saldırıyı ayırır ve
eşzamanlı benign trafik yanlışlıkla saldırı etiketlenmez.

Kullanım:
  python pipeline/label.py --flows data/features/flows_X.parquet \
      --ground-truth scenarios/ground_truth.csv \
      --out data/labeled/flows_labeled_X.parquet [--tolerance-ms 2000] [--sample 50]
"""
import argparse
import sys
from pathlib import Path
import pandas as pd


def _port_wild(v) -> bool:
    s = str(v).strip().lower()
    return s in ("", "*", "0", "any", "nan", "none")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tolerance-ms", type=int, default=2000,
                    help="Zaman penceresi toleransı (ms, ±). Varsayılan 2000.")
    ap.add_argument("--sample", type=int, default=50,
                    help="Elle doğrulama için örneklem satır sayısı (CSV).")
    args = ap.parse_args()

    flows = pd.read_parquet(args.flows)
    if len(flows) == 0:
        print("UYARI: akış tablosu boş; etiketli boş tablo yazılıyor.")
        flows["label"] = []
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        flows.to_parquet(args.out, index=False)
        return 0

    gt = pd.read_csv(args.ground_truth)
    need = {"label", "start_ts", "end_ts", "src_ip", "dst_ip", "dst_port"}
    missing = need - set(gt.columns)
    if missing:
        print(f"HATA: ground_truth eksik sütun: {missing}", file=sys.stderr)
        return 1

    # zaman sütunları (nfstream ms epoch)
    f_start = flows["bidirectional_first_seen_ms"].astype("int64")
    f_end = flows["bidirectional_last_seen_ms"].astype("int64") if \
        "bidirectional_last_seen_ms" in flows.columns else f_start
    tol = args.tolerance_ms

    labels = pd.Series(["benign"] * len(flows), index=flows.index)
    matched_run = pd.Series([""] * len(flows), index=flows.index)

    for _, r in gt.iterrows():
        w0 = int(r["start_ts"]) - tol
        w1 = int(r["end_ts"]) + tol
        # zaman kesişimi: f_start <= w1 AND f_end >= w0
        time_ok = (f_start <= w1) & (f_end >= w0)
        ip_ok = (flows["src_ip"].astype(str) == str(r["src_ip"])) & \
                (flows["dst_ip"].astype(str) == str(r["dst_ip"]))
        if _port_wild(r["dst_port"]):
            port_ok = pd.Series(True, index=flows.index)
        else:
            port_ok = flows["dst_port"].astype("int64") == int(r["dst_port"])
        m = time_ok & ip_ok & port_ok
        # yalnız hâlâ benign olanlara ata (ilk eşleşen kazanır; pencereler ayrık olmalı)
        apply = m & (labels == "benign")
        labels[apply] = str(r["label"])
        matched_run[apply] = str(r.get("run_id", r["label"]))

    flows = flows.copy()
    flows["label"] = labels.values
    flows["gt_run_id"] = matched_run.values

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    flows.to_parquet(out, index=False)

    dist = flows["label"].value_counts()
    print(f"[label] {len(flows)} akış etiketlendi → {out}")
    print("[label] sınıf dağılımı:")
    for k, v in dist.items():
        print(f"    {k:16s} {v:6d}  ({100*v/len(flows):5.1f}%)")

    # elle doğrulama örneklemi (dengeli): her sınıftan ~eşit
    if args.sample > 0:
        per = max(1, args.sample // max(1, flows["label"].nunique()))
        samp = (flows.groupby("label", group_keys=False)
                .apply(lambda d: d.sample(min(len(d), per), random_state=42)))
        cols = [c for c in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                            "bidirectional_first_seen_ms", "bidirectional_packets",
                            "bidirectional_bytes", "label", "gt_run_id") if c in samp.columns]
        sp = out.parent / "label_sample.csv"
        samp[cols].to_csv(sp, index=False)
        print(f"[label] elle doğrulama örneklemi ({len(samp)} satır) → {sp}")
        print("        (manuel kontrol sonrası 'label_verified' sütunu ekleyip "
              "train_baseline'a verebilirsin → etiket hata oranı)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
