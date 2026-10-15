# traffic/ — benign background traffic

`benign_generator.py` produces continuous, labelable **benign** traffic from the host
(`10.10.10.1`) to the victim (`10.10.10.30`) for the whole capture: HTTP requests, SSH
sessions (key-based), and MySQL queries. It runs in the background during a session and is
stopped when capture stops; everything it generates is outside the attack windows, so it is
labeled `BENIGN`.

## Run (from the repository root)
```bash
python3 traffic/benign_generator.py   # runs until killed; started/stopped by run_session.sh
```
Config vars: `HOST_IP`, `VICTIM_IP`, `VICTIM_USER`, `SSH_KEY`.

> Limitation (documented in the dataset DATASHEET): benign traffic is synthetically generated
> over a few protocols; it is not a behavioural model of enterprise background traffic.
