# capture/ — packet and host-log capture

Captures all modalities simultaneously on the host sensor during a session.

| File | Purpose |
|------|---------|
| `start_capture.sh` | Starts **tcpdump** (full PCAP on `virbr-ids`, via `aa-exec -p unconfined` so it can be stopped), **Zeek**, and **Suricata** (eve.json) for one session timestamp. |
| `stop_capture.sh` | Stops the three capturers (with a pkill-by-interface fallback). |
| `setup_wazuh.sh` | Deploys the **Wazuh** host-IDS: a single-node manager (Docker) on the host and an agent on the victim (installed during the temporary-NAT phase), clock-synced. Produces host alerts (`alerts_<ts>.json`, JSON Lines). |

## Run (from the repository root)
```bash
sudo ./capture/setup_wazuh.sh               # once, during lab setup
sudo ./capture/start_capture.sh <TS>        # begin a session capture (TS = timestamp id)
# ... run benign traffic + scenarios ...
sudo ./capture/stop_capture.sh
```
Config vars: `CAPTURE_IFACE`, `NET_BRIDGE`, `WAZUH_*`, `VICTIM_IP`, `HOST_IP`.

Outputs (git-ignored; regenerated per run): `data/pcap/`, `data/zeek_logs/`,
`data/suricata_logs/`, `data/wazuh_logs/`.

> tcpdump is launched unconfined because Ubuntu's tcpdump AppArmor profile (enforce, no signal
> rule) otherwise blocks the stop signal.
