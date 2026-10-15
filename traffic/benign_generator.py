#!/usr/bin/env python3
"""
benign_generator.py — normal (benign) trafik üreticisi.

ÖNEMLİ: Trafik HOST'tan (10.10.10.1) victim'e üretilir → kaynak IP saldırgandan
(10.10.10.20) farklıdır, böylece etiketlemede saldırılarla karışmaz (hepsi
'benign' kalır). Doc Bölüm 7.

Üretilen: web gezinme (curl), ssh oturumları, scp dosya aktarımı, MySQL sorgusu.
Saldırılarla eşzamanlı çalışır; --duration saniye sonra ya da SIGTERM ile durur.

Kullanım:
  python traffic/benign_generator.py --duration 600
"""
import argparse
import os
import random
import signal
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_STOP = False


def _stop(*_):
    global _STOP
    _STOP = True


def load_config(path):
    cfg = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.split("#", 1)[0].strip().strip('"').strip("'")
    return cfg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config.env"))
    ap.add_argument("--duration", type=int, default=0, help="saniye (0 = SIGTERM'e kadar)")
    args = ap.parse_args()
    cfg = load_config(args.config)
    VIC = cfg["VICTIM_IP"]
    key = str(ROOT / cfg["SSH_KEY"])
    vuser = cfg.get("VICTIM_USER", "analyst")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    SSH = ["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", f"{vuser}@{VIC}"]
    SCP = ["scp", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    DN = subprocess.DEVNULL

    have_mysql = subprocess.run(["bash", "-c", "command -v mysql"], stdout=DN, stderr=DN).returncode == 0
    tmpf = Path(tempfile.mkstemp(prefix="benign_", suffix=".dat")[1])
    tmpf.write_bytes(os.urandom(64 * 1024))  # 64KB scp yükü

    web_paths = ["/", "/login.php", "/index.php", "/dvwa/", "/setup.php", "/favicon.ico"]

    def web():
        p = random.choice(web_paths)
        subprocess.run(["curl", "-s", "-m", "5", "-o", "/dev/null", f"http://{VIC}{p}"],
                       stdout=DN, stderr=DN)

    def ssh_sess():
        subprocess.run(SSH + [random.choice(["uptime", "ls -la /tmp", "whoami; date", "df -h /"])],
                       stdout=DN, stderr=DN, timeout=15)

    def scp_xfer():
        subprocess.run(SCP + [str(tmpf), f"{vuser}@{VIC}:/tmp/benign_up.dat"], stdout=DN, stderr=DN, timeout=20)
        subprocess.run(SSH + ["rm -f /tmp/benign_up.dat"], stdout=DN, stderr=DN, timeout=10)

    def db_query():
        if have_mysql:
            subprocess.run(["mysql", "-h", VIC, "-ulabuser", "-plabpass", "labdb",
                            "-e", "SELECT * FROM items; SELECT COUNT(*) FROM items;"],
                           stdout=DN, stderr=DN, timeout=10)
        else:
            web()  # mysql istemcisi host'ta yoksa web ile telafi

    actions = [web, web, web, ssh_sess, scp_xfer, db_query]  # web ağırlıklı
    t_end = time.time() + args.duration if args.duration > 0 else None
    n = 0
    print(f"[benign] host→{VIC} benign trafik başladı "
          f"({'süresiz' if not t_end else str(args.duration)+'s'}; mysql={'var' if have_mysql else 'yok'})")
    try:
        while not _STOP and (t_end is None or time.time() < t_end):
            a = random.choice(actions)
            try:
                a()
            except Exception:
                pass
            n += 1
            time.sleep(random.uniform(0.15, 0.8))  # daha yüksek benign hacmi
    finally:
        try:
            tmpf.unlink()
        except OSError:
            pass
    print(f"[benign] durdu ({n} eylem)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
