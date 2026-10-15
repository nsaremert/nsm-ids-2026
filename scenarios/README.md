# scenarios/ — attacks, orchestration and ground truth

The orchestrator runs each attack from the attacker VM against the victim, with a timed
silence (`GAP_SECONDS`) between them, and records a **ground-truth CSV** of exactly what ran
and when. These windows drive the automatic labeling in `pipeline/`.

| File | Purpose |
|------|---------|
| `orchestrator.py` | Copies the attack scripts to the attacker, runs them in order, writes `ground_truth.csv`. Subset selection via `ATTACKS=r01,r02,...`. |
| `attacks/01..10_*.sh` | One script per attack (see taxonomy below). |
| `example_ground_truth.csv` | A real ground-truth file from one session (schema example). |

## Attack taxonomy (CICIDS labels)
`01` PortScan (nmap) · `02` SSH-Patator (hydra) · `03` Web Attack (sqlmap) · `04` DoS SYN (hping3) ·
`05` Infiltration (Metasploit) · `06` FTP-Patator (hydra) · `07` DoS Slowloris · `08` DoS Slowhttptest ·
`09` DoS GoldenEye · `10` DoS Hulk (HULK not installed by default → ~0 flows).

## Ground-truth CSV schema (`ground_truth.csv`)
One row per attack run. Timestamps are **epoch milliseconds, UTC**.

| column | meaning |
|--------|---------|
| `run_id` | run identifier (`r01`…`r10`) |
| `label` | CICIDS class label (e.g. `SSH-Patator`) |
| `start_ts` | attack start (epoch ms, UTC) |
| `end_ts` | attack end (epoch ms, UTC) |
| `src_ip` | source = attacker (`10.10.10.20`) |
| `dst_ip` | destination = victim (`10.10.10.30`) |
| `dst_port` | attacked port (`*` for multi-port scans) |
| `tool` | tool used (nmap, hydra, sqlmap, …) |
| `notes` | free text (optional) |

## Run (from the repository root)
```bash
python3 scenarios/orchestrator.py --out scenarios/ground_truth.csv        # all attacks
ATTACKS=r01,r02 python3 scenarios/orchestrator.py --out scenarios/gt.csv   # subset
```
Config vars: `ATTACKER_IP`, `VICTIM_IP`, `GAP_SECONDS`, `DOS_DURATION`, `SLOW_DOS_DURATION`,
`BRUTE_USER`, `BRUTE_PASSWORD`, `SSH_KEY`.
