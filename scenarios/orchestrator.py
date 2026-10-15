#!/usr/bin/env python3
"""
orchestrator.py — saldırı senaryolarını sırayla çalıştırır ve ground_truth yazar.

Doc Bölüm 7: her saldırı ayrı betik; aralarında 30-60 sn sessizlik; her
çalıştırmanın başlangıç/bitiş zamanı (host saati, epoch ms) kaydedilir.

Saldırılar attacker VM'de (ssh) çalışır, hedef victim. Betikler scp ile
/tmp/ids_attacks altına kopyalanır.

Kullanım:
  python scenarios/orchestrator.py [--gap 45] [--dos-duration 8] [--dry-run]
"""
import argparse
import csv
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_config(path):
    cfg = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.split("#", 1)[0].strip().strip('"').strip("'")
    return cfg


def now_ms():
    return int(time.time() * 1000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config.env"))
    ap.add_argument("--out", default=str(ROOT / "scenarios/ground_truth.csv"))
    ap.add_argument("--gap", type=int, default=None)
    ap.add_argument("--dos-duration", type=int, default=None)
    ap.add_argument("--logdir", default=str(ROOT / "data/scenarios"))
    ap.add_argument("--dry-run", action="store_true", help="ssh çalıştırma; sadece GT şemasını/zamanlamayı dene")
    args = ap.parse_args()

    cfg = load_config(args.config)
    VIC, ATT = cfg["VICTIM_IP"], cfg["ATTACKER_IP"]
    gap = args.gap if args.gap is not None else int(cfg.get("GAP_SECONDS", 45))
    dosdur = args.dos_duration if args.dos_duration is not None else int(cfg.get("DOS_DURATION", 8))
    bruser, brpass = cfg.get("BRUTE_USER", "svc"), cfg.get("BRUTE_PASSWORD", "CHANGE_ME_weak_lab_password")
    key = str(ROOT / cfg["SSH_KEY"])
    auser = cfg["ATTACKER_USER"]
    Path(args.logdir).mkdir(parents=True, exist_ok=True)

    S = ["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", f"{auser}@{ATT}"]

    slowdur = str(cfg.get("SLOW_DOS_DURATION", "25"))
    # (run_id, CICIDS-label, script, args, dst_port, tool)
    # Araç kurulu değilse ilgili betik kibarca atlar (o etiket için akış üretilmez).
    ALL_ATTACKS = [
        ("r01", "PortScan",         "01_recon_scan.sh",     [VIC],                 "*",  "nmap"),
        ("r02", "SSH-Patator",      "02_bruteforce_ssh.sh", [VIC, bruser, brpass], "22", "hydra"),
        ("r03", "Web Attack",       "03_web_attack.sh",     [VIC],                 "80", "sqlmap"),
        ("r04", "DoS SYN",          "04_dos.sh",            [VIC, str(dosdur)],    "80", "hping3"),
        ("r05", "Infiltration",     "05_exploit.sh",        [VIC],                 "21", "metasploit"),
        ("r06", "FTP-Patator",      "06_ftp_patator.sh",    [VIC, bruser, brpass], "21", "hydra"),
        ("r07", "DoS Slowloris",    "07_dos_slowloris.sh",  [VIC, slowdur],        "80", "slowhttptest"),
        ("r08", "DoS Slowhttptest", "08_dos_slowhttp.sh",   [VIC, slowdur],        "80", "slowhttptest"),
        ("r09", "DoS GoldenEye",    "09_dos_goldeneye.sh",  [VIC, slowdur],        "80", "goldeneye"),
        ("r10", "DoS Hulk",         "10_dos_hulk.sh",       [VIC, slowdur],        "80", "hulk"),
    ]
    # ATTACKS env değişkeniyle alt küme seçilebilir (ör. "r01,r02,r04"); yoksa hepsi
    sel = os.environ.get("ATTACKS", "").replace(" ", "")
    attacks = [a for a in ALL_ATTACKS if (not sel or a[0] in sel.split(","))]

    if not args.dry_run:
        print("[orch] saldırı betikleri attacker'a kopyalanıyor")
        subprocess.run(S + ["rm -rf /tmp/ids_attacks && mkdir -p /tmp/ids_attacks"], check=False)
        scp = (["scp", "-i", key, "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null"]
               + [str(p) for p in sorted((ROOT / "scenarios/attacks").glob("*.sh"))]
               + [f"{auser}@{ATT}:/tmp/ids_attacks/"])
        subprocess.run(scp, check=False)
        subprocess.run(S + ["chmod +x /tmp/ids_attacks/*.sh"], check=False)

    rows = []
    print(f"[orch] {len(attacks)} saldırı | gap={gap}s | dos={dosdur}s | hedef={VIC}")
    print(f"[orch] başlangıç sessizliği {gap}s (benign trafik akıyor)...")
    if not args.dry_run:
        time.sleep(gap)

    for i, (rid, label, script, sargs, dport, tool) in enumerate(attacks):
        print(f"\n[orch] === {label}  ({script}) ===")
        t0 = now_ms()
        if not args.dry_run:
            argstr = " ".join(f"'{a}'" for a in sargs)
            logf = Path(args.logdir) / f"{label}.log"
            with open(logf, "w") as fh:
                subprocess.run(S + [f"bash /tmp/ids_attacks/{script} {argstr}"],
                               stdout=fh, stderr=subprocess.STDOUT, check=False)
        else:
            time.sleep(0.05)
        t1 = now_ms()
        rows.append(dict(run_id=rid, label=label, start_ts=t0, end_ts=t1,
                         src_ip=ATT, dst_ip=VIC, dst_port=dport, tool=tool, notes=""))
        print(f"[orch] {label}: süre={(t1-t0)/1000:.1f}s  pencere=[{t0}..{t1}]")
        if i < len(attacks) - 1 and not args.dry_run:
            print(f"[orch] sessizlik {gap}s...")
            time.sleep(gap)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["run_id", "label", "start_ts", "end_ts",
                                           "src_ip", "dst_ip", "dst_port", "tool", "notes"])
        w.writeheader()
        w.writerows(rows)
    print(f"\n[orch] ground_truth → {out}  ({len(rows)} satır)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
