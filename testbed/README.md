# testbed/ — isolated lab provisioning

Builds the fully **isolated** KVM/libvirt environment: one attacker VM (Kali or Ubuntu),
one victim VM (Ubuntu + DVWA), on a private network `10.10.10.0/24` with **no NAT/forward**.
The host (`10.10.10.1`) is the sensor. Internet is only used briefly to download VM images and
install tools, then NAT is detached and isolation is re-verified.

| File | Purpose |
|------|---------|
| `net-isolated.xml` | libvirt network definition (no `<forward>`; isolated bridge `virbr-ids`). |
| `setup_host.sh` | Host prerequisites: libvirt/KVM, Docker, the isolated network, host sensor IP. |
| `provision_vms.sh` | Download cloud images, render `cloud-init/*.tmpl` from `config.env` + the SSH public key, create the VMs. |
| `cloud-init/*.tmpl` | cloud-init templates (placeholders `__ATTACKER_USER__`, `__SSH_PUBKEY__`, `__HOST_IP__`, `__BRUTE_PASSWORD__`, …). |
| `attacker_install_tools.sh` | Install attack tools on the attacker VM (temporary NAT → apt/metasploit → detach NAT). |
| `victim_setup_dvwa.sh` | Deploy DVWA + services on the victim VM (same temporary-NAT pattern). |
| `isolation_check.sh` | Kill-switch verification: VMs must NOT reach `8.8.8.8`, `1.1.1.1`, the host LAN gateway, or DNS; attacker↔victim must work. |

## Run (from the repository root)
```bash
cp config.env.example config.env                # edit values
ssh-keygen -t ed25519 -N '' -f keys/id_ids      # lab SSH key (keys/ is .gitignored)
sudo ./testbed/setup_host.sh
./testbed/provision_vms.sh
./testbed/attacker_install_tools.sh && ./testbed/victim_setup_dvwa.sh
./testbed/isolation_check.sh                    # must print ISOLATION OK before capturing
```

Config vars used: `NET_*`, `*_IP`, `*_NAME`, `ATTACKER_DISTRO`, `*_USER`, `BRUTE_PASSWORD`,
`SSH_KEY`, `*_IMG_URL`, `LAN_GW`. **Never commit `keys/` or `config.env`.**
