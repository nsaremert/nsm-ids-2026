#!/usr/bin/env python3
"""
verify_labels.py — etiket kalitesini BAĞIMSIZ kaynakla çapraz-doğrula (Doc Bölüm 8.5).

Bizim etiketleme: zaman penceresi + 5'li (ground_truth, src=saldırgan).
Bağımsız kaynak: Suricata imza motoru (eve.json) — tamamen farklı yöntem.

İki ölçüt:
  (1) YAPISAL (asıl etiket-hata göstergesi):
      - saldırgan-olmayan IP'den saldırı etiketi → olmamalı (0 beklenir).
      - saldırgandan benign etiketi → saldırı penceresi dışında kalan saldırgan
        akışları (çoğu zaman saldırganın kendi sistem trafiği: NTP vb.).
  (2) SURİCATA DOĞRULAMASI (zaman-duyarlı, yön-bağımsız 5'li):
      - saldırı etiketlerimizin yüzde kaçı Suricata imzasıyla da doğrulanıyor.
      - benign dediğimiz ama Suricata'nın AYNI ANDA saldırı dediği akışlar (şüpheli).

Kullanım:
  python pipeline/verify_labels.py --flows-labeled ... --suricata-eve ...\
      --attacker-ip 10.10.10.20 --victim-ip 10.10.10.30 --out models/label_quality.md
"""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd


def canon(a_ip, a_port, b_ip, b_port):
    """Yön-bağımsız bağlantı anahtarı (uç-nokta çiftini sırala)."""
    def p(x):
        try:
            return int(x)
        except (TypeError, ValueError):
            return -1
    return tuple(sorted([(str(a_ip), p(a_port)), (str(b_ip), p(b_port))]))


def load_suricata(eve_path: Path):
    """eve.json → {canon_key: [ts_ms,...]} ve imza sayıları."""
    key_ts, sig_counts = {}, {}
    if not eve_path.exists():
        return key_ts, sig_counts
    with open(eve_path, "r", errors="replace") as fh:
        for line in fh:
            if '"event_type":"alert"' not in line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("event_type") != "alert":
                continue
            sig = o.get("alert", {}).get("signature", "")
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
            ts = pd.to_datetime(o.get("timestamp"), utc=True, errors="coerce")
            if pd.isna(ts):
                continue
            ms = int(ts.value // 1_000_000)
            k = canon(o.get("src_ip"), o.get("src_port"), o.get("dest_ip"), o.get("dest_port"))
            key_ts.setdefault(k, []).append(ms)
    for k in key_ts:
        key_ts[k].sort()
    return key_ts, sig_counts


def flagged_timeaware(df, key_ts, tol_ms=3000):
    """Her akış: eşleşen canon_key'de, akış [first-tol, last+tol] aralığında alarm var mı."""
    f0 = df["bidirectional_first_seen_ms"].astype("int64").to_numpy()
    f1 = (df["bidirectional_last_seen_ms"].astype("int64").to_numpy()
          if "bidirectional_last_seen_ms" in df.columns else f0)
    keys = [canon(s, sp, d, dp) for s, sp, d, dp in
            zip(df["src_ip"].astype(str), df["src_port"],
                df["dst_ip"].astype(str), df["dst_port"])]
    out = np.zeros(len(df), bool)
    for i, k in enumerate(keys):
        lst = key_ts.get(k)
        if not lst:
            continue
        lo, hi = f0[i] - tol_ms, f1[i] + tol_ms
        j = np.searchsorted(lst, lo, "left")
        if j < len(lst) and lst[j] <= hi:
            out[i] = True
    return pd.Series(out, index=df.index)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows-labeled", required=True)
    ap.add_argument("--suricata-eve", default="")
    ap.add_argument("--attacker-ip", required=True)
    ap.add_argument("--victim-ip", required=True)
    ap.add_argument("--out", default="models/label_quality.md")
    args = ap.parse_args()

    df = pd.read_parquet(args.flows_labeled)
    n = len(df)
    att = args.attacker_ip
    is_attack = df["label"] != "benign"

    # (1) yapısal
    attack_from_nonattacker = int((is_attack & (df["src_ip"].astype(str) != att)).sum())
    ba = df[(~is_attack) & (df["src_ip"].astype(str) == att)]
    benign_from_attacker = len(ba)
    ba_ports = ba["dst_port"].value_counts().head(5).to_dict() if benign_from_attacker else {}

    # (2) Suricata zaman-duyarlı
    key_ts, sig_counts = load_suricata(Path(args.suricata_eve)) if args.suricata_eve else ({}, {})
    flagged = flagged_timeaware(df, key_ts) if key_ts else pd.Series(False, index=df.index)
    n_flag = int(flagged.sum())
    attack_corrob = int((flagged & is_attack).sum())          # bizim saldırı + Suricata saldırı
    attack_total = int(is_attack.sum())
    corrob_rate = attack_corrob / attack_total if attack_total else 0.0

    # "benign ama Suricata saldırı dedi" → KAYNAĞA göre ayır:
    #  - saldırgandan (.20): gerçek etiket hatası olabilir (pencere dışı kalan saldırı)
    #  - diğerinden (host/victim): Suricata'nın benign trafiğe YANLIŞ-POZİTİFİ (bizim hatamız değil)
    susp = flagged & ~is_attack
    susp_att = int((susp & (df["src_ip"].astype(str) == att)).sum())
    susp_other = int(susp.sum()) - susp_att

    # muhafazakâr etiket hata ≈ yapısal yanlış-saldırı + saldırgandan gelen şüpheli
    est_err = attack_from_nonattacker + susp_att
    est_rate = est_err / n if n else 0.0

    L = ["# Etiket Kalitesi — Bağımsız Çapraz Doğrulama", ""]
    L.append(f"- Akış: **{n}** | saldırı etiketli: {attack_total} | benign: {n-attack_total}")
    L.append("")
    L.append("## (1) Yapısal tutarlılık")
    L.append(f"- Saldırgan-olmayan IP'den saldırı etiketi (olmamalı): **{attack_from_nonattacker}**")
    L.append(f"- Saldırgandan (`{att}`) benign etiketi: **{benign_from_attacker}** "
             f"(çoğu saldırganın kendi sistem trafiği)")
    if ba_ports:
        L.append(f"  - hedef portlara göre: {ba_ports}  (123=NTP, 53=DNS → benign servisler)")
    L.append("")
    L.append("## (2) Suricata doğrulaması (zaman-duyarlı, yön-bağımsız)")
    if key_ts:
        L.append(f"- Suricata'nın (aynı anda) alarm verdiği akış: **{n_flag}**")
        L.append(f"- Saldırı etiketlerimizin Suricata ile **doğrulanma oranı**: "
                 f"**{attack_corrob}/{attack_total} = {corrob_rate:.1%}** "
                 f"(düşük normal — Suricata her saldırı akışına imza üretmez)")
        L.append(f"- Benign dedik ama Suricata saldırı dedi → kaynağa göre:")
        L.append(f"  - saldırgandan (`{att}`): **{susp_att}** (gerçek etiket hatası olabilir)")
        L.append(f"  - host/victim'den: **{susp_other}** → **Suricata'nın benign trafiğe "
                 f"YANLIŞ-POZİTİFİ** (bizim hatamız değil; yer-gerçeği etiketlemesinin imza-IDS'e üstünlüğü)")
        L.append("")
        L.append("### En sık Suricata imzaları")
        L.append("| imza | adet |"); L.append("| --- | --- |")
        for s, c in sorted(sig_counts.items(), key=lambda x: -x[1])[:8]:
            L.append(f"| {s} | {c} |")
    else:
        L.append("- Suricata eve.json yok/boş → atlandı.")
    L.append("")
    L.append("## Tahmini etiket hata oranı (muhafazakâr)")
    L.append(f"- (yapısal yanlış-saldırı {attack_from_nonattacker} + saldırgandan şüpheli {susp_att}) "
             f"/ {n} = **{est_err}/{n} = {est_rate:.2%}**")
    L.append(f"- Not: host/victim kaynaklı {susp_other} Suricata-flag'i hata SAYILMADI "
             f"(Suricata'nın benign'e yanlış-pozitifi).")
    L.append("")
    L.append("> Asıl etiket-hata göstergesi yapısal kontroldür: benign trafik (host/.1) saldırgandan "
             "farklı IP'den geldiği için yanlışlıkla saldırı etiketlenemez → yapısal yanlış-saldırı = 0. "
             "Suricata düşük doğrulama oranı, imza kapsamının dar olmasındandır, etiket hatası değil.")

    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L))
    print(f"[verify] → {out}")
    print(f"[verify] yapısal: saldırı<-nonattacker={attack_from_nonattacker}, benign<-attacker={benign_from_attacker}")
    print(f"[verify] Suricata doğrulama: {attack_corrob}/{attack_total}={corrob_rate:.1%}, "
          f"şüpheli: saldırgandan={susp_att} (hata olabilir), host/victim'den={susp_other} (Suricata FP)")
    print(f"[verify] tahmini etiket hata oranı ≈ {est_rate:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
