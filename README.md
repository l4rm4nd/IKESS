# IKE Security Scanner (IKESS)
A Python3 Script for Auditing IKE VPN Servers

<img width="1571" height="979" alt="image" src="https://github.com/user-attachments/assets/9c11fd9e-6e7f-47fa-a469-46c2feb80fff" />

## Features

- Detects IKEv2 VPN servers
- Detected IKEv1 VPN servers + Aggressive Mode
- Detects supported transforms (ENC, HASH, AUTH)
- Saves results as JSON, XML and HTML report
- Risk rates findings with summary and recommendations
- Optional support for fingerprinting via backoff pattern (beta)

## Usage

```bash
usage: ikess [-h] [--fullalgs] [--fingerprint] [--enc ENC] [--hash HASH] [--auth AUTH] [--group GROUP] [--onlycustom] targets [targets ...]

ikess v1.1 - IKE Security Scanner (Sequential Mode)

Scans one or more targets (IP or CIDR) sequentially with ike-scan, detects IKEv1/IKEv2,
tests curated or expanded transform sets, optionally fingerprints backoff behavior, and
produces XML, JSON, and HTML reports with findings and proof sections.

Requirements:
  - The external binary 'ike-scan' must be installed and in PATH.
  - Root privileges are typically required to send raw IKE packets (use sudo).

How targets are interpreted:
  - Single IP: 192.0.2.10
  - CIDR: 192.0.2.0/24 (all usable hosts are scanned)

Scan flow per host:
  1) IKEv1 discovery
  2) IKEv2 discovery
  3) Aggressive Mode tests (only if IKEv1 observed)
  4) Main Mode transform tests (curated by default or expanded when requested)
  5) Optional backoff fingerprinting (--fingerprint)

Transform key format:
  ENC[/bits],HASH,AUTH,GROUP
  Example: '7/256,5,1,14' means AES-256, SHA256, PSK, MODP-2048.

positional arguments:
  targets              One or more IPv4 addresses or CIDR ranges to scan. Examples: 192.0.2.10 192.0.2.0/28
                       All usable hosts in a CIDR are enumerated.

options:
  -h, --help           show this help message and exit
  --fullalgs           Use the expanded transform sets. Increases coverage and scan time. The expanded sets include
                       additional DES/3DES, AES bit lengths, multiple DH groups, and RSA/HYBRID combinations. (default: False)
  --fingerprint        Enable backoff fingerprinting (ike-scan --showbackoff). If no fingerprint is obtained from a
                       generic probe, ikess retries using the first accepted transform to improve accuracy. (default: False)
  --enc ENC            Comma separated encryption list to try or restrict. Accepts numeric codes or aliases.
                       Examples: --enc AES256,3DES  or  --enc 7/256,5 (default: None)
  --hash HASH          Comma separated hash list. Accepts numeric codes or aliases.
                       Examples: --hash SHA1,SHA256  or  --hash 2,5 (default: None)
  --auth AUTH          Comma separated IKE authentication methods. Accepts numeric codes or aliases.
                       Examples: --auth PSK,RSA  or  --auth 1,3  or  --auth HYBRID (default: None)
  --group, --dh GROUP  Comma separated DH groups. Accepts numeric codes or aliases. '--dh' is an alias.
                       Examples: --group G14,G16  or  --dh MODP2048,MODP4096  or  --group 14,16 (default: None)
  --onlycustom         Scan only the transforms built from your custom --enc/--hash/--auth/--group lists. Without this
                       flag, custom items are merged into the curated or expanded set. (default: False)

Aliases you can use for --enc, --hash, --auth, --group:
  ENC:  DES=1, 3DES=5, AES=7/128, AES128=7/128, AES192=7/192, AES256=7/256
  HASH: MD5=1, SHA1=2, SHA-1=2, SHA 1=2, SHA256=5, SHA-256=5, SHA 256=5
  AUTH: PSK=1, RSA=3, RSA_SIG=3, RSA-SIG=3, RSA SIG=3, HYBRID=64221, HYBRID_RSA=64221
  DH:   G1=1,  G2=2,  G5=5,  G14=14, G15=15, G16=16
        MODP768=1, MODP1024=2, MODP1536=5, MODP2048=14, MODP3072=15, MODP4096=16

Notes:
  - By default ikess uses a curated set of common, modern, and legacy transforms.
  - --fullalgs switches to an expanded transform set that is larger and slower but thorough.
  - You can add custom lists via --enc/--hash/--auth/--group; these are merged with the curated
    or expanded set unless you also pass --onlycustom to scan only your provided items.
  - For Aggressive Mode, only PSK is tried unless you explicitly include other --auth values.

Exit codes:
  0 success, 1 dependency or runtime error, 124 external timeout.

Examples:
  sudo ./ikess.py 10.0.0.1
  sudo ./ikess.py 10.0.0.0/24 --fullalgs --fingerprint
  sudo ./ikess.py 10.0.0.1 --enc DES,3DES --onlycustom
  sudo ./ikess.py 10.0.0.1 --enc AES128,3DES,1,7/256 --hash SHA1,SHA256,1 --auth PSK,RSA --group G2,G14,16
  sudo ./ikess.py 203.0.113.5 --enc AES256 --hash SHA256 --auth PSK --group MODP2048 --onlycustom

```
