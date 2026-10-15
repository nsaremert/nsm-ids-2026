#!/usr/bin/env python3
"""gen_data_dictionary.py — zenodo/data_dictionary.csv üretir.

Kolon sırasını doğrudan cic_to_cicids modülünden alır (6 kimlik + 78 öznitelik +
Label = 85), böylece sözlük pipeline'ın ürettiği CSV ile birebir aynıdır.
CICIDS2017 MachineLearningCVE şemasıyla uyumlu adlar; açıklamalar CICFlowMeter
öznitelik tanımlarına dayanır.

  ./.venv/bin/python pipeline/gen_data_dictionary.py [--out zenodo/data_dictionary.csv]
"""
from __future__ import annotations
import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
import cic_to_cicids as m  # noqa: E402

# group, unit, description per canonical column name
DESC: dict[str, tuple[str, str, str]] = {
    # --- identifiers ---
    "Flow ID": ("identifier", "", "Flow identifier: SrcIP-DstIP-SrcPort-DstPort-Protocol"),
    "Source IP": ("identifier", "", "Source IPv4 address (attacker=10.10.10.20; benign host generator=10.10.10.1)"),
    "Source Port": ("identifier", "port", "Source transport-layer port"),
    "Destination IP": ("identifier", "", "Destination IPv4 address (victim=10.10.10.30)"),
    "Protocol": ("identifier", "", "IANA L4 protocol number (6=TCP, 17=UDP, 0=other)"),
    "Timestamp": ("identifier", "UTC", "Flow start time in UTC, format dd/MM/yyyy hh:mm:ss AM/PM"),
    # --- counts / volume ---
    "Destination Port": ("basic", "port", "Destination transport-layer port"),
    "Flow Duration": ("timing", "microseconds", "Duration of the flow"),
    "Total Fwd Packets": ("volume", "packets", "Total packets in the forward (src->dst) direction"),
    "Total Backward Packets": ("volume", "packets", "Total packets in the backward (dst->src) direction"),
    "Total Length of Fwd Packets": ("volume", "bytes", "Total payload bytes in the forward direction"),
    "Total Length of Bwd Packets": ("volume", "bytes", "Total payload bytes in the backward direction"),
    # --- per-direction packet size ---
    "Fwd Packet Length Max": ("pktsize", "bytes", "Maximum packet size, forward direction"),
    "Fwd Packet Length Min": ("pktsize", "bytes", "Minimum packet size, forward direction"),
    "Fwd Packet Length Mean": ("pktsize", "bytes", "Mean packet size, forward direction"),
    "Fwd Packet Length Std": ("pktsize", "bytes", "Std. dev. of packet size, forward direction"),
    "Bwd Packet Length Max": ("pktsize", "bytes", "Maximum packet size, backward direction"),
    "Bwd Packet Length Min": ("pktsize", "bytes", "Minimum packet size, backward direction"),
    "Bwd Packet Length Mean": ("pktsize", "bytes", "Mean packet size, backward direction"),
    "Bwd Packet Length Std": ("pktsize", "bytes", "Std. dev. of packet size, backward direction"),
    # --- rates ---
    "Flow Bytes/s": ("rate", "bytes/s", "Flow byte rate"),
    "Flow Packets/s": ("rate", "packets/s", "Flow packet rate"),
    # --- inter-arrival times ---
    "Flow IAT Mean": ("iat", "microseconds", "Mean inter-arrival time between packets in the flow"),
    "Flow IAT Std": ("iat", "microseconds", "Std. dev. of inter-arrival time in the flow"),
    "Flow IAT Max": ("iat", "microseconds", "Maximum inter-arrival time in the flow"),
    "Flow IAT Min": ("iat", "microseconds", "Minimum inter-arrival time in the flow"),
    "Fwd IAT Total": ("iat", "microseconds", "Total inter-arrival time, forward direction"),
    "Fwd IAT Mean": ("iat", "microseconds", "Mean inter-arrival time, forward direction"),
    "Fwd IAT Std": ("iat", "microseconds", "Std. dev. of inter-arrival time, forward direction"),
    "Fwd IAT Max": ("iat", "microseconds", "Maximum inter-arrival time, forward direction"),
    "Fwd IAT Min": ("iat", "microseconds", "Minimum inter-arrival time, forward direction"),
    "Bwd IAT Total": ("iat", "microseconds", "Total inter-arrival time, backward direction"),
    "Bwd IAT Mean": ("iat", "microseconds", "Mean inter-arrival time, backward direction"),
    "Bwd IAT Std": ("iat", "microseconds", "Std. dev. of inter-arrival time, backward direction"),
    "Bwd IAT Max": ("iat", "microseconds", "Maximum inter-arrival time, backward direction"),
    "Bwd IAT Min": ("iat", "microseconds", "Minimum inter-arrival time, backward direction"),
    # --- flags per direction ---
    "Fwd PSH Flags": ("flags", "count", "Number of packets with PSH set, forward direction"),
    "Bwd PSH Flags": ("flags", "count", "Number of packets with PSH set, backward direction"),
    "Fwd URG Flags": ("flags", "count", "Number of packets with URG set, forward direction"),
    "Bwd URG Flags": ("flags", "count", "Number of packets with URG set, backward direction"),
    # --- header lengths / rates ---
    "Fwd Header Length": ("header", "bytes", "Total bytes used for headers, forward direction"),
    "Bwd Header Length": ("header", "bytes", "Total bytes used for headers, backward direction"),
    "Fwd Packets/s": ("rate", "packets/s", "Forward packet rate"),
    "Bwd Packets/s": ("rate", "packets/s", "Backward packet rate"),
    # --- flow-wide packet size ---
    "Min Packet Length": ("pktsize", "bytes", "Minimum packet size in the flow"),
    "Max Packet Length": ("pktsize", "bytes", "Maximum packet size in the flow"),
    "Packet Length Mean": ("pktsize", "bytes", "Mean packet size in the flow"),
    "Packet Length Std": ("pktsize", "bytes", "Std. dev. of packet size in the flow"),
    "Packet Length Variance": ("pktsize", "bytes^2", "Variance of packet size in the flow"),
    # --- TCP flag counts (flow) ---
    "FIN Flag Count": ("flags", "count", "Number of packets with FIN set"),
    "SYN Flag Count": ("flags", "count", "Number of packets with SYN set"),
    "RST Flag Count": ("flags", "count", "Number of packets with RST set"),
    "PSH Flag Count": ("flags", "count", "Number of packets with PSH set"),
    "ACK Flag Count": ("flags", "count", "Number of packets with ACK set"),
    "URG Flag Count": ("flags", "count", "Number of packets with URG set"),
    "CWE Flag Count": ("flags", "count", "Number of packets with CWR set (CICIDS2017 names this column 'CWE'; it counts the CWR flag)"),
    "ECE Flag Count": ("flags", "count", "Number of packets with ECE set"),
    # --- ratios / segment sizes ---
    "Down/Up Ratio": ("ratio", "", "Ratio of backward (download) to forward (upload) packets"),
    "Average Packet Size": ("pktsize", "bytes", "Mean size over all packets in the flow"),
    "Avg Fwd Segment Size": ("segment", "bytes", "Mean TCP segment size, forward direction"),
    "Avg Bwd Segment Size": ("segment", "bytes", "Mean TCP segment size, backward direction"),
    "Fwd Header Length.1": ("header", "bytes", "Duplicate of 'Fwd Header Length' (CICIDS2017 schema artifact; retained for drop-in compatibility)"),
    # --- bulk transfer ---
    "Fwd Avg Bytes/Bulk": ("bulk", "bytes", "Average bytes per bulk, forward direction"),
    "Fwd Avg Packets/Bulk": ("bulk", "packets", "Average packets per bulk, forward direction"),
    "Fwd Avg Bulk Rate": ("bulk", "bytes/s", "Average bulk rate, forward direction"),
    "Bwd Avg Bytes/Bulk": ("bulk", "bytes", "Average bytes per bulk, backward direction"),
    "Bwd Avg Packets/Bulk": ("bulk", "packets", "Average packets per bulk, backward direction"),
    "Bwd Avg Bulk Rate": ("bulk", "bytes/s", "Average bulk rate, backward direction"),
    # --- subflows ---
    "Subflow Fwd Packets": ("subflow", "packets", "Average packets per subflow, forward direction"),
    "Subflow Fwd Bytes": ("subflow", "bytes", "Average bytes per subflow, forward direction"),
    "Subflow Bwd Packets": ("subflow", "packets", "Average packets per subflow, backward direction"),
    "Subflow Bwd Bytes": ("subflow", "bytes", "Average bytes per subflow, backward direction"),
    # --- TCP window / payload ---
    "Init_Win_bytes_forward": ("tcpwin", "bytes", "Initial TCP window size, forward direction"),
    "Init_Win_bytes_backward": ("tcpwin", "bytes", "Initial TCP window size, backward direction"),
    "act_data_pkt_fwd": ("payload", "packets", "Forward packets carrying >=1 byte of TCP payload"),
    "min_seg_size_forward": ("segment", "bytes", "Minimum forward TCP segment size observed"),
    # --- active / idle ---
    "Active Mean": ("activity", "microseconds", "Mean time a flow was active before idle"),
    "Active Std": ("activity", "microseconds", "Std. dev. of active time"),
    "Active Max": ("activity", "microseconds", "Maximum active time"),
    "Active Min": ("activity", "microseconds", "Minimum active time"),
    "Idle Mean": ("activity", "microseconds", "Mean time a flow was idle before becoming active"),
    "Idle Std": ("activity", "microseconds", "Std. dev. of idle time"),
    "Idle Max": ("activity", "microseconds", "Maximum idle time"),
    "Idle Min": ("activity", "microseconds", "Minimum idle time"),
    # --- label ---
    "Label": ("label", "", "Ground-truth class: BENIGN or an attack type (see README taxonomy). Auto-labeled from ground-truth time windows + 5-tuple."),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "zenodo/data_dictionary.csv"))
    args = ap.parse_args()

    cols = list(m.IDENTIFIERS) + list(m.CICIDS_78) + ["Label"]
    missing = [c for c in cols if c not in DESC]
    if missing:
        print(f"[gen] UYARI: açıklaması olmayan kolon: {missing}", file=sys.stderr)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "column", "group", "unit", "description"])
        for i, c in enumerate(cols):
            g, u, d = DESC.get(c, ("", "", ""))
            w.writerow([i, c, g, u, d])
    print(f"[gen] {len(cols)} kolon → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
