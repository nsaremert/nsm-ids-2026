# pipeline/ — PCAP → features → labels → tables

Turns raw captures into the published CSVs. The flow-feature extractor is the **Java
CICFlowMeter** run via Docker (not the Python port — the port fakes CWR/bulk/subflow/segment
features).

| File | Purpose |
|------|---------|
| `cicflowmeter/` + `setup_cicflowmeter.sh` | Build the `ids-cfm` Docker image (CICFlowMeter, commit `acaf8bea…`). |
| `extract_features_cic.sh` | `pcap → CICFlowMeter V4 CSV` (abbreviated headers), via `ids-cfm`. |
| `cic_to_cicids.py` | Rename V4 columns → exact CICIDS2017 *MachineLearningCVE* 78-feature schema. |
| `label_cic.py` | Label a CIC CSV from ground-truth windows + 5-tuple (CIC timestamp is UTC). |
| `build_cicids_dataset.sh` | Batch all session PCAPs → `dataset/<NAME>_full.csv` (85) + `_ML.csv` (79). |
| `gen_data_dictionary.py` | Emit the 85-column data dictionary. |
| `fill_dataset_stats.py` | Fill README/DATASHEET statistics tables from the built CSV. |
| `verify_cicids_labels.py` | Independent label cross-check (structural + Suricata) on the CICIDS CSV. |
| `extract_features.py`, `label.py`, `merge_hostlogs.py`, `combine_sessions.py`, `verify_labels.py` | nfstream multimodal variant (per-flow features + host-log merge) used by `run_session.sh`. |

## Run (from the repository root, after a capture)
```bash
./pipeline/setup_cicflowmeter.sh                       # once: build the ids-cfm image
./pipeline/build_cicids_dataset.sh NSM-IDS-2026        # all PCAPs -> CICIDS CSVs
python3 pipeline/verify_cicids_labels.py --full dataset/NSM-IDS-2026_full.csv
```
Docker without sudo: scripts use `sg docker -c "docker …"` where possible.

> **CICFlowMeter pin (reviewer-requested):** CanadianInstituteForCybersecurity/CICFlowMeter,
> commit `acaf8bea8611fb4b996b4d33964dfd9155d9efdf` (2026 build from the official repo).
> The v1.0→v1.1 data fix documents an upstream bug in this tool's `Active`/`Idle`/`Subflow`
> columns; those 12 columns are dropped from the ML table (see the dataset README Changelog).
