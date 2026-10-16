# NSM-IDS-2026 — production & analysis code

Reproducible code that generates the **NSM-IDS-2026** intrusion-detection dataset end to end
in a fully **isolated** KVM/libvirt lab, and runs its technical-validation experiments.

> **Dataset:** NSM-IDS-2026 (v1.2) — Zenodo DOI (CC BY 4.0); the concept DOI resolves to the
> latest version. This repository is the companion **software** (MIT). See *Citation* below.
>
> **v1.2 changes:** (1) **FIX A** — the Infiltration ground truth now lists ports **21,22,80**
> (its `nmap -p 21,22,80` NSE recon), so `label_cic.py` (which now accepts a comma-separated
> `dst_port`) labels the HTTP/SSH recon as Infiltration instead of BENIGN (+893 flows).
> (2) **`split_fragment`/`parent_label`** metadata (built by `pipeline/build_v12_tables.py`)
> mark CICFlowMeter reverse-direction continuation flows; the experiments and `baseline.py`
> exclude them by default. (3) A fragment-leakage check (`experiments/E8_fragment_leak/`).

The pipeline is: **isolated testbed → scheduled attacks with ground truth + benign traffic →
packet & host-log capture → CICFlowMeter features → CICIDS2017-schema labeling → validation
experiments.** Network flows use the exact CICIDS2017 *MachineLearningCVE* schema, so the data
is a drop-in companion to CICIDS2017/2018.

---

## Repository structure
```
nsm-ids-2026-code/
├── config.env.example      # central config template (copy to config.env; .gitignored)
├── requirements.txt        # pinned Python deps (Python 3.12)
├── environment.yml         # conda equivalent
├── Makefile                # one-entry orchestration (make help)
├── run_all.sh              # non-Make equivalent of the full flow
├── run_session.sh          # one full capture+label session
├── run_campaign.sh         # N sessions back-to-back (dataset volume)
├── testbed/                # isolated libvirt net, VM provisioning (cloud-init), isolation check
├── scenarios/              # attack scripts + orchestrator + ground-truth schema/example
├── traffic/                # benign traffic generator
├── capture/                # tcpdump/Zeek/Suricata + Wazuh host-IDS
├── pipeline/               # PCAP → CICFlowMeter → CICIDS labeling + verification
└── experiments/            # E1–E6 technical-validation scripts + baseline.py (see experiments/README.md)
```
Each folder has its own `README.md`. **Run all commands from the repository root.**

---

## Requirements
- **Host:** Ubuntu 24.04, KVM/QEMU + libvirt, Docker; ≥ 32 GB RAM and ~100 GB free disk for a full
  campaign (a `light` Wazuh mode exists for < 32 GB — see `config.env.example`).
- **Python 3.12** with the **pinned** `requirements.txt`:
  ```bash
  python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
  ```
- **CICFlowMeter (Java, via Docker)** — the flow-feature extractor. **Pinned to commit**
  **`acaf8bea8611fb4b996b4d33964dfd9155d9efdf`** of
  `github.com/CanadianInstituteForCybersecurity/CICFlowMeter` (built into image `ids-cfm` by
  `pipeline/setup_cicflowmeter.sh`). The Python `cicflowmeter` port is **not** used (it stubs
  CWR/bulk/subflow/segment features).

---

## How to reproduce
```bash
# 0. configure + lab SSH key
cp config.env.example config.env && $EDITOR config.env
ssh-keygen -t ed25519 -N '' -f keys/id_ids

# 1. build the isolated testbed  (Internet only for image/tool download, then detached)
sudo ./testbed/setup_host.sh
./testbed/provision_vms.sh
./testbed/attacker_install_tools.sh && ./testbed/victim_setup_dvwa.sh
sudo ./capture/setup_wazuh.sh
./testbed/isolation_check.sh            # MUST print ISOLATION OK before any capture

# 2. collect data
./pipeline/setup_cicflowmeter.sh        # build the CICFlowMeter image (once)
./run_campaign.sh 12                    # 12 capture+attack sessions (or ./run_session.sh for one)

# 3. build the CICIDS dataset + verify labels
./pipeline/build_cicids_dataset.sh NSM-IDS-2026
python3 pipeline/verify_cicids_labels.py --full dataset/NSM-IDS-2026_full.csv

# 3b. build the v1.2 ML/full tables (session_id + split_fragment + parent_label)
python3 pipeline/build_v12_tables.py --glob 'data/cicids/cicids_*.csv'
python3 pipeline/verify_cicids_labels.py --full dataset/NSM-IDS-2026_full_v1.2.csv --out label_quality.md

# 4. technical-validation experiments (tables + figures); add the fragment-sensitivity run:
bash experiments/run_all.sh                                   # main (split fragments excluded)
NSM_INCLUDE_FRAGMENTS=1 NSM_OUT_SUFFIX=_withfrag bash experiments/run_all.sh   # sensitivity
```
Or use the Makefile: `make help`, then e.g. `make testbed`, `make campaign N=12`, `make dataset`, `make experiments`.

---

## What produces what (file-production map)
| Step | Script | Produces |
|------|--------|----------|
| Host + network | `testbed/setup_host.sh`, `testbed/net-isolated.xml` | isolated libvirt net, Docker, host sensor IP |
| VMs | `testbed/provision_vms.sh` (+ `cloud-init/`) | `images/*.qcow2` (attacker, victim) |
| Isolation | `testbed/isolation_check.sh` | kill-switch verification (no file; gates capture) |
| Attacks + ground truth | `scenarios/orchestrator.py` (+ `attacks/`) | `scenarios/ground_truth.csv` → per-session `data/scenarios/ground_truth_<TS>.csv` |
| Benign traffic | `traffic/benign_generator.py` | benign flows (feeds capture) |
| Capture | `capture/start_capture.sh` | `data/pcap/session_<TS>.pcap`, `data/zeek_logs/<TS>/`, `data/suricata_logs/<TS>/eve.json` |
| Host IDS | `capture/setup_wazuh.sh` | `data/wazuh_logs/alerts_<TS>.json` (JSON Lines) |
| Flow features | `pipeline/extract_features_cic.sh` (`ids-cfm`) | `data/cicids/cic_raw_<TS>.csv` (CICFlowMeter V4) |
| Schema + labels | `pipeline/cic_to_cicids.py`, `label_cic.py` (via `build_cicids_dataset.sh`) | `data/cicids/cicids_<TS>.csv` → `dataset/NSM-IDS-2026_full.csv` (85) + `_ML.csv` (79) |
| v1.2 tables + flags | `pipeline/build_v12_tables.py` | `dataset/NSM-IDS-2026_full_v1.2.csv` (88) + `_ML_v1.2.csv` (70) with `session_id`/`split_fragment`/`parent_label` |
| Label quality | `pipeline/verify_cicids_labels.py` | `label_quality.md` |
| Data dictionary | `pipeline/gen_data_dictionary.py` | `data_dictionary.csv` |
| nfstream multimodal | `run_session.sh` → `pipeline/{extract_features,label,merge_hostlogs,verify_labels}.py` | `data/labeled/dataset_<TS>.parquet`, `models/report.md` |
| Validation (E1–E6, E8) | `experiments/E*/e*.py`, `experiments/baseline.py` | `experiments/{results,figures,tables}[_withfrag]/` |

Raw PCAPs and intermediate `data/` are **not** in this repo (regenerated by the lab above, and the
published flow/host tables are on Zenodo). `data/`, `dataset/`, `images/`, `keys/`, `config.env`
are `.gitignored`.

---

## Security & ethics
- **Fully isolated** network (`10.10.10.0/24`, no NAT/forward), verified by `isolation_check.sh`
  before every capture. Attacks never leave the lab; all targets are author-controlled VMs on
  private RFC1918 addresses. No real user data, PII, or third-party systems.
- **No secrets in the repo.** `keys/` (private SSH key) and `config.env` are git-ignored; generate
  your own key (`ssh-keygen … -f keys/id_ids`). All credentials in `config.env.example` are
  **synthetic lab-only** values (the weak `BRUTE_PASSWORD` is the deliberate target of the in-lab
  brute-force scenario). Do **not** run the attack recipes against systems you do not own.

## Citation
Cite the software (`CITATION.cff`, MIT) **and** the dataset (DOI `10.5281/zenodo.23392184`, CC BY 4.0).
Authors: Necibe Sare Mert, Buğra Yılmaz, Fatih Şahin — Istanbul Topkapi University, Faculty of
Engineering and Natural Sciences.
