# NSM-IDS-2026 — one-entry orchestration. Run from the repository root.
# Usage: make help ; make deps ; make testbed ; make campaign N=12 ; make dataset ; make experiments
.DEFAULT_GOAL := help
SHELL := /bin/bash

NAME ?= NSM-IDS-2026
N    ?= 12
PY   ?= $(shell [ -x ./.venv/bin/python ] && echo ./.venv/bin/python || echo python3)

.PHONY: help deps testbed cicflowmeter session campaign dataset verify experiments reproduce all clean

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

deps:  ## install pinned Python dependencies into .venv
	python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

testbed:  ## build the isolated lab (sudo; Internet only for downloads, then detached)
	sudo ./testbed/setup_host.sh
	./testbed/provision_vms.sh
	./testbed/attacker_install_tools.sh && ./testbed/victim_setup_dvwa.sh
	sudo ./capture/setup_wazuh.sh
	./testbed/isolation_check.sh

cicflowmeter:  ## build the pinned CICFlowMeter Docker image (ids-cfm)
	./pipeline/setup_cicflowmeter.sh

session:  ## run one capture + label session
	./run_session.sh

campaign:  ## run N capture sessions back-to-back (default N=12)
	./run_campaign.sh $(N)

dataset:  ## build the CICIDS dataset CSVs from captured PCAPs
	./pipeline/build_cicids_dataset.sh $(NAME)

verify:  ## independent label-quality cross-check on the built dataset
	$(PY) pipeline/verify_cicids_labels.py --full dataset/$(NAME)_full.csv

experiments:  ## run the E1-E6 technical-validation experiments
	bash experiments/run_all.sh

reproduce: cicflowmeter campaign dataset verify experiments  ## data + analysis (lab must be up)

all: deps testbed reproduce  ## everything (interactive: sudo + image downloads)

clean:  ## remove generated outputs (keeps keys/, config.env, source)
	rm -rf data/ dataset/ experiments/results experiments/figures experiments/tables experiments/all_results models/ images/
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
