#!/usr/bin/env python3
"""fill_dataset_stats.py — build edilmiş CSV'den istatistikleri hesaplayıp
zenodo/README.md ve zenodo/DATASHEET.md içindeki <!-- AUTOFILL:KEY --> bloklarını
gerçek değerlerle doldurur. Kolon/yapıya dayalı, tekrarlanabilir.

  ./.venv/bin/python pipeline/fill_dataset_stats.py \
      --ml zenodo/NSM-IDS-2026_ML.csv --full zenodo/NSM-IDS-2026_full.csv

İnsan-dolduracak alanları (PLACEHOLDER_*) ELLEMEZ.
"""
from __future__ import annotations
import argparse
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def replace_block(text: str, key: str, body: str) -> str:
    pat = re.compile(
        r"(<!--\s*AUTOFILL:" + re.escape(key) + r"\s*-->)(.*?)(<!--\s*/AUTOFILL:"
        + re.escape(key) + r"\s*-->)",
        re.DOTALL,
    )
    if not pat.search(text):
        print(f"[fill] UYARI: '{key}' bloğu bulunamadı", file=sys.stderr)
        return text
    return pat.sub(lambda mt: mt.group(1) + "\n" + body.strip() + "\n" + mt.group(3), text)


def parse_ts(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, format="%d/%m/%Y %I:%M:%S %p", errors="coerce")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml", default=str(ROOT / "zenodo/NSM-IDS-2026_ML.csv"))
    ap.add_argument("--full", default=str(ROOT / "zenodo/NSM-IDS-2026_full.csv"))
    ap.add_argument("--readme", default=str(ROOT / "zenodo/README.md"))
    ap.add_argument("--datasheet", default=str(ROOT / "zenodo/DATASHEET.md"))
    ap.add_argument("--gt-glob", default="data/scenarios/ground_truth_*.csv",
                    help="oturum sayısını saymak için")
    ap.add_argument("--cfm-image", default="ids-cfm")
    args = ap.parse_args()

    ml = Path(args.ml)
    full = Path(args.full)
    if not ml.exists():
        print(f"[fill] HATA: {ml} yok — önce build_cicids_dataset.sh", file=sys.stderr)
        return 1

    df = pd.read_csv(ml)
    n = len(df)
    nfeat = df.shape[1] - 1  # minus Label
    vc = df["Label"].value_counts()

    # --- class distribution table ---
    rows = ["| Label | Flows | % |", "|---|---:|---:|"]
    for lab, cnt in vc.items():
        rows.append(f"| `{lab}` | {cnt:,} | {100.0*cnt/n:.1f}% |")
    rows.append(f"| **Total** | **{n:,}** | **100.0%** |")
    class_tbl = "\n".join(rows)

    # --- sessions + timeframe (from full csv timestamps) ---
    n_sessions = len(list(ROOT.glob(args.gt_glob)))
    tf_line = f"- Capture sessions: **{n_sessions}**"
    date_line = ""
    if full.exists():
        try:
            tscol = pd.read_csv(full, usecols=["Timestamp"])  # only the column
            ts = parse_ts(tscol["Timestamp"]).dropna()
            if len(ts):
                date_line = (f"- Capture window (UTC): **{ts.min():%Y-%m-%d %H:%M}** "
                             f"to **{ts.max():%Y-%m-%d %H:%M}**")
        except Exception as e:  # noqa: BLE001
            print(f"[fill] timestamp okunamadı: {e}", file=sys.stderr)

    summary = "\n".join([
        f"- Total flows: **{n:,}**",
        f"- Features: **{nfeat}** (CICIDS2017 MachineLearningCVE schema) + `Label`",
        tf_line,
        date_line,
    ]).strip()

    comp = "\n".join([f"- Total flows: **{n:,}** across **{n_sessions}** sessions.", "", class_tbl])

    # --- file hashes ---
    files_to_hash = [ml, full, ROOT / "zenodo/data_dictionary.csv",
                     ROOT / "zenodo/LICENSE.txt", ROOT / "zenodo/CITATION.cff",
                     ROOT / "zenodo/baseline.py"]
    hrows = ["| File | SHA-256 |", "|---|---|"]
    for p in files_to_hash:
        if p.exists():
            hrows.append(f"| `{p.name}` | `{sha256(p)}` |")
    hashes = "\n".join(hrows)

    # --- provenance ---
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    prov = "\n".join([
        "**Provenance**",
        "",
        f"- Generated (UTC): {today}",
        f"- Feature extractor: Java CICFlowMeter (Docker image `{args.cfm_image}`)",
        "- Label cross-check: Suricata (independent sensor on the same capture)",
        "- Collection: scripted, isolated KVM/libvirt lab (no Internet forwarding)",
    ])

    # --- apply to README ---
    r = Path(args.readme).read_text()
    r = replace_block(r, "class_distribution", class_tbl)
    r = replace_block(r, "summary_stats", summary)
    r = replace_block(r, "file_hashes", hashes)
    r = replace_block(r, "provenance", prov)
    Path(args.readme).write_text(r)

    # --- apply to DATASHEET ---
    d = Path(args.datasheet).read_text()
    d = replace_block(d, "composition_counts", comp)
    tf = tf_line + ("\n" + date_line if date_line else "")
    d = replace_block(d, "timeframe", tf)
    Path(args.datasheet).write_text(d)

    print(f"[fill] README + DATASHEET güncellendi: {n:,} akış, {n_sessions} oturum, "
          f"{len(vc)} sınıf.")
    print("[fill] Not: label_quality, author, doi, maintainer, funding alanları "
          "elle/ayrı doldurulacak.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
