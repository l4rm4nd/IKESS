# IKE-Security-Scanner
A Python3 Script for Auditing IKE VPN Servers

## Features

- Detects IKEv2 VPN servers
- Detected IKEv1 VPN servers + Aggressive Mode
- Detects supported transforms (ENC, HASH, AUTH)
- Saves results as JSON, XML and HTML report
- Risk rates findings with summary and recommendations
- Optional support for fingerprinting via backoff pattern (beta)

## Usage

```bash
usage: iker-new.py [-h] [-t THREADS] [--fullalgs] [--fingerprint] targets [targets ...]

ikess v1.1 - IKE Security Scanner

positional arguments:
  targets               One or more target IP addresses or hostnames

options:
  -h, --help            show this help message and exit
  -t, --threads THREADS
                        Number of concurrent threads (default: 1)
  --fullalgs            Use a broader transform search set (more enc/hash/auth/group combinations)
  --fingerprint         Run --showbackoff fingerprinting (and retry with a known accepted transform if available)

Scans for IKE/IPsec VPNs and presents enhanced, readable reports.
```

## Screenshots

<img width="1571" height="979" alt="image" src="https://github.com/user-attachments/assets/9c11fd9e-6e7f-47fa-a469-46c2feb80fff" />
