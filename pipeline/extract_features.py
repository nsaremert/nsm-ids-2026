#!/usr/bin/env python3
"""
extract_features.py — PCAP → bidirectional akış öznitelikleri (nfstream).

Doc Bölüm 8.1: nfstream PCAP'i akışlara böler (5'li + istatistiksel öznitelikler;
Java gerektirmez). Çıktı parquet: her satır bir akış, 5'li + zaman damgaları +
istatistiksel öznitelikler.

Kullanım:
  python pipeline/extract_features.py --pcap data/pcap/session_X.pcap \
                                      --out  data/features/flows_X.parquet
"""
import argparse
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="PCAP → akış öznitelikleri (nfstream)")
    ap.add_argument("--pcap", required=True, help="Girdi PCAP dosyası")
    ap.add_argument("--out", required=True, help="Çıktı parquet (akış tablosu)")
    args = ap.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        print(f"HATA: PCAP yok: {pcap}", file=sys.stderr)
        return 1

    try:
        from nfstream import NFStreamer
    except ImportError:
        print("HATA: nfstream kurulu değil (.venv aktif mi? pip install -r requirements.txt)",
              file=sys.stderr)
        return 1

    print(f"[extract] nfstream ile işleniyor: {pcap}")
    # statistical_analysis=True → paket uzunluğu/IAT istatistikleri (min/max/mean/std...)
    streamer = NFStreamer(
        source=str(pcap),
        statistical_analysis=True,
        accounting_mode=3,          # tüm katman (L2..L7) bayt sayımı
        idle_timeout=30,
        active_timeout=300,
    )
    df = streamer.to_pandas()
    if df is None or len(df) == 0:
        print("UYARI: Hiç akış üretilmedi (PCAP boş olabilir). Boş tablo yazılıyor.")
        # yine de şema tutarlılığı için boş yaz
        import pandas as pd
        df = pd.DataFrame()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"[extract] {len(df)} akış → {out}")
    if len(df):
        # kısa özet
        cols = [c for c in ("src_ip", "dst_ip", "dst_port", "protocol",
                            "bidirectional_packets", "bidirectional_bytes") if c in df.columns]
        print(df[cols].head(5).to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
