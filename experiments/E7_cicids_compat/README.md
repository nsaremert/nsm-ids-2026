# E7 — CICIDS2017 compatibility & transfer (SKIPPED)

E7 is **optional** and was **skipped**: no CICIDS2017 *MachineLearningCVE* CSV files were
found on this machine, and the operator chose not to download them (the CIC/UNB release is
licence-gated and large, ~600 MB).

## What E7 would produce (when the CSVs are available)
1. **Schema check** — confirm NSM-IDS-2026 column names/order match CICIDS2017
   *MachineLearningCVE* exactly (the 66 ML features are a subset of the shared 78).
2. **Distribution comparison** — for the shared classes (BENIGN, PortScan, DoS Slowloris,
   DoS Slowhttptest, DoS GoldenEye, SSH-Patator, FTP-Patator, Web Attack): median/IQR table
   per feature + density plots for a few features.
3. **Transfer use-case** — train on CICIDS2017, test on NSM-IDS-2026 (shared classes),
   using the 62 portable features vs 66; reported strictly as a usage example, not a benchmark.

## How to enable it later
Place the CICIDS2017 *MachineLearningCVE* CSVs under a directory and point an `e7.py`
(to be added) at it, then re-run `bash experiments/run_all.sh`. `run_all.sh` runs E7
automatically if `experiments/E7_cicids_compat/e7.py` exists.
