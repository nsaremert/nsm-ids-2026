#!/usr/bin/env python3
"""
merge_hostlogs.py — host olaylarını (Wazuh alarmları) akış tablosuyla birleştir.

Doc Bölüm 8: Wazuh alarmlarını zaman penceresiyle eşle; her akışa, o pencerede
victim host'unda görülen alarm ÖZETLERİNİ ekle → çok modlu satırlar
(ağ öznitelikleri + host alarm sayısı/şiddeti). Çıktı: dataset.parquet (nihai).

host alarm kaynağı yoksa (veya 'light' modda boşsa) host sütunları 0 olur ve
host_available=0 işaretlenir; pipeline yine çalışır (yalnız-ağ ayarı anlamlı kalır).

Kullanım:
  python pipeline/merge_hostlogs.py --flows-labeled data/labeled/flows_labeled_X.parquet \
      --hostlog data/wazuh_logs/alerts.json --victim-ip 10.10.10.30 \
      --window-sec 60 --out data/labeled/dataset.parquet
"""
import argparse
import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd

HOST_COLS = ["host_alert_count", "host_alert_level_max", "host_alert_level_sum",
             "host_alert_level_mean", "host_distinct_rules", "host_available"]


def parse_hostlog(path: Path) -> pd.DataFrame:
    """Wazuh/generic JSON-lines → DataFrame[ts_ms, level, rule]."""
    rows = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = o.get("timestamp") or o.get("@timestamp") or o.get("ts")
            if ts is None:
                continue
            rule = o.get("rule", {})
            if isinstance(rule, dict):
                level = rule.get("level", o.get("level", 1))
                rid = rule.get("id") or rule.get("description") or ""
            else:
                level = o.get("level", 1)
                rid = str(rule)
            rows.append((ts, level, rid))
    if not rows:
        return pd.DataFrame(columns=["ts_ms", "level", "rule"])
    df = pd.DataFrame(rows, columns=["ts_raw", "level", "rule"])
    # ts → epoch ms. Hem sayısal epoch hem ISO8601 string desteklenir.
    # (np.issubdtype pandas StringDtype'ta patlar → pd.to_numeric ile ayır.)
    ts_num = pd.to_numeric(df["ts_raw"], errors="coerce")
    if ts_num.notna().mean() > 0.9:          # çoğunlukla sayısal → epoch (sn/ms)
        tsm = ts_num.astype("float64")
        df["ts_ms"] = np.where(tsm < 1e12, tsm * 1000.0, tsm)
    else:                                     # ISO8601 string (Wazuh) → tz-aware
        dt = pd.to_datetime(df["ts_raw"], utc=True, errors="coerce")
        epoch = pd.Timestamp("1970-01-01", tz="UTC")
        df["ts_ms"] = (dt - epoch).dt.total_seconds() * 1000.0
    df = df.dropna(subset=["ts_ms"]).copy()
    df["ts_ms"] = df["ts_ms"].astype("int64")
    df["level"] = pd.to_numeric(df["level"], errors="coerce").fillna(1).astype(int)
    return df[["ts_ms", "level", "rule"]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows-labeled", required=True)
    ap.add_argument("--hostlog", default="", help="Wazuh alerts.json (opsiyonel)")
    ap.add_argument("--victim-ip", required=True)
    ap.add_argument("--window-sec", type=int, default=60)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    flows = pd.read_parquet(args.flows_labeled)
    # host sütunlarını 0 ile başlat
    for c in HOST_COLS:
        flows[c] = 0
    if len(flows) == 0:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        flows.to_parquet(args.out, index=False)
        print("UYARI: boş akış tablosu; dataset boş yazıldı.")
        return 0

    alerts = pd.DataFrame(columns=["ts_ms", "level", "rule"])
    if args.hostlog and Path(args.hostlog).exists() and Path(args.hostlog).stat().st_size > 0:
        alerts = parse_hostlog(Path(args.hostlog))
        print(f"[merge] {len(alerts)} host alarmı okundu: {args.hostlog}")
    else:
        print("[merge] host log yok/boş → host sütunları 0 (host_available=0)")

    if len(alerts):
        a_ts = alerts["ts_ms"].to_numpy()
        a_lv = alerts["level"].to_numpy()
        a_rule = alerts["rule"].to_numpy()
        order = np.argsort(a_ts)
        a_ts, a_lv, a_rule = a_ts[order], a_lv[order], a_rule[order]

        W = args.window_sec * 1000
        f_start = flows["bidirectional_first_seen_ms"].astype("int64").to_numpy()
        f_end = (flows["bidirectional_last_seen_ms"].astype("int64").to_numpy()
                 if "bidirectional_last_seen_ms" in flows.columns else f_start)
        involves_victim = ((flows["dst_ip"].astype(str) == args.victim_ip) |
                           (flows["src_ip"].astype(str) == args.victim_ip)).to_numpy()

        cnt = np.zeros(len(flows), int)
        lmax = np.zeros(len(flows), int)
        lsum = np.zeros(len(flows), int)
        ndistinct = np.zeros(len(flows), int)
        for i in range(len(flows)):
            if not involves_victim[i]:
                continue
            lo = np.searchsorted(a_ts, f_start[i] - W, "left")
            hi = np.searchsorted(a_ts, f_end[i] + W, "right")
            if hi <= lo:
                continue
            lv = a_lv[lo:hi]
            cnt[i] = len(lv)
            lmax[i] = int(lv.max())
            lsum[i] = int(lv.sum())
            ndistinct[i] = len(set(a_rule[lo:hi]))
        flows["host_alert_count"] = cnt
        flows["host_alert_level_max"] = lmax
        flows["host_alert_level_sum"] = lsum
        flows["host_alert_level_mean"] = np.where(cnt > 0, lsum / np.maximum(cnt, 1), 0.0)
        flows["host_distinct_rules"] = ndistinct
        flows["host_available"] = 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    flows.to_parquet(out, index=False)
    nhost = int((flows["host_alert_count"] > 0).sum())
    print(f"[merge] {len(flows)} satır → {out}  (host alarmı olan akış: {nhost})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
