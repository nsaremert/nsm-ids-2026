"""
cic_to_cicids.py
================
CICFlowMeter V4.0 ``*_Flow.csv`` (Java ``cic.cs.unb.ca.ifm.Cmd``, hamelin Docker)
çıktısını kanonik CIC-IDS2017 "MachineLearningCVE" şemasına çevirir.

Neden gerekli: Ne Java V4 ne Python port tam CICIDS2017 isimlerini üretir. V4 çok
sayıda özniteliği yeniden adlandırdı ("Total Fwd Packet" vs "Total Fwd Packets",
"CWR" vs "CWE", "FWD Init Win Bytes" vs "Init_Win_bytes_forward", ...) ve 2017
setindeki yinelenen "Fwd Header Length.1" sütununu DÜŞÜRDÜ. Bu modül V4->kanonik
yeniden adlandırır, yineleneni kanonik konumuna (#56) geri ekler ve 78-öznitelik
kanonik sırasına dizer.

Not: V4 başlığında baştaki boşluk yok; gerçek 2017 *_ISCX.csv'de tutarsız baştaki
boşluklar var. Buradaki anahtar/değerler boşluksuzdur.
"""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd


# --- 1. V4 -> kanonik isim haritası (anahtarlar: V4 başlık token'ları) ------
V4_TO_CANONICAL = {
    # Anahtarlar = CanadianInstituteForCybersecurity/CICFlowMeter'ın GERÇEK
    # (kısaltılmış) _Flow.csv başlıkları; gerçek çıktıyla doğrulandı.
    # 7 identifier
    "Flow ID": "Flow ID",
    "Src IP": "Source IP",
    "Src Port": "Source Port",
    "Dst IP": "Destination IP",
    "Dst Port": "Destination Port",
    "Protocol": "Protocol",
    "Timestamp": "Timestamp",
    # flow istatistikleri
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label",
}


# --- 2. Kanonik sütun listeleri ---------------------------------------------
CICIDS_78 = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

IDENTIFIERS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"]

_DUP_COL = "Fwd Header Length.1"
_DUP_SRC = "Fwd Header Length"


# --- 3. Dönüştürücü ----------------------------------------------------------
def to_cicids(df_v4: pd.DataFrame) -> pd.DataFrame:
    """CICFlowMeter V4 DataFrame -> kanonik CIC-IDS2017 (IDENTIFIERS + 78 + Label)."""
    df = df_v4.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns={k: v for k, v in V4_TO_CANONICAL.items() if k in df.columns})

    if _DUP_SRC in df.columns:
        df[_DUP_COL] = df[_DUP_SRC]
    else:
        warnings.warn(f"'{_DUP_SRC}' yok; '{_DUP_COL}' NaN.", stacklevel=2)
        df[_DUP_COL] = np.nan

    df["Label"] = pd.NA

    target = IDENTIFIERS + CICIDS_78 + ["Label"]
    _derived = {_DUP_COL, "Label"}
    missing = [c for c in target if c not in df.columns and c not in _derived]
    if missing:
        warnings.warn("Eksik sütun(lar), NaN dolduruldu: " + ", ".join(missing), stacklevel=2)
        for c in missing:
            df[c] = np.nan

    if df.columns.duplicated().any():
        dupes = df.columns[df.columns.duplicated()].unique().tolist()
        warnings.warn(f"Yinelenen sütunlar: {dupes}", stacklevel=2)
        df = df.loc[:, ~df.columns.duplicated()]

    return df.reindex(columns=target)


def ml_ready(df_canonical: pd.DataFrame) -> pd.DataFrame:
    """79 sütun (78 öznitelik + Label)."""
    return df_canonical.reindex(columns=CICIDS_78 + ["Label"])


def full_labelled(df_canonical: pd.DataFrame) -> pd.DataFrame:
    """identifiers + 78 öznitelik + Label."""
    return df_canonical.reindex(columns=IDENTIFIERS + CICIDS_78 + ["Label"])


def convert_csv(in_path, ml_out=None, full_out=None) -> pd.DataFrame:
    df_v4 = pd.read_csv(in_path, skipinitialspace=True)
    df = to_cicids(df_v4)
    if ml_out:
        ml_ready(df).to_csv(ml_out, index=False)
    if full_out:
        full_labelled(df).to_csv(full_out, index=False)
    return df


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="CICFlowMeter V4 _Flow.csv -> kanonik CIC-IDS2017")
    ap.add_argument("input")
    ap.add_argument("--ml-out")
    ap.add_argument("--full-out")
    args = ap.parse_args()
    out = convert_csv(args.input, args.ml_out, args.full_out)
    print(f"Çevrildi {args.input}: {out.shape[0]} akış, {out.shape[1]} sütun")
