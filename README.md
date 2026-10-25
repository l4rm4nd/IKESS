# IKE Security Scanner (IKESS)
A Python3 Script for Auditing IKE VPN Servers

<img width="1632" height="1138" alt="image" src="https://github.com/user-attachments/assets/73939e6b-f885-4cc1-a3f5-8cd3005dd8f5" />

## Features

- Detects IKEv2 VPN servers
- Detects IKEv1 VPN servers + Aggressive Mode
- Detects supported transforms (ENC, HASH, AUTH, GROUP)
- Saves results as JSON, XML and HTML report
- Risk rates findings with summary and recommendations
- Support for fingerprinting via vendor ID (VID)
- Support for fingerprinting via backoff pattern (optional)
- Support for probing over NAT-T / UDP 4500 (optional)
- Detects NAT-T advertisement (RFC 3947 VID) on UDP 500 and auto-probes UDP 4500 to confirm
- Support for Aggressive Mode group VPN ID (`--id`) for gateways that only negotiate with a known group name
- Optional brute force of common group VPN IDs via wordlist (`--idfile`, curated list in `wordlists/group_ids.txt`)
- Automatically scans over NAT-T (UDP 4500) when UDP 500 is silent - NAT-T-only responders are detected and enumerated
- Robust against concurrent `ike-scan` usage: cross-process UDP port lock plus bind-error retries (no false negatives when someone probes port 500/4500 at the same time)

## Usage

> [!CAUTION]
> This script requires the binary `ike-scan` and must be run as root

```bash
usage: ikess [-h] [--fullalgs] [--fingerprint] [--enc ENC] [--hash HASH] [--auth AUTH] [--group GROUP] [--onlycustom] [--nat-t] [--id ID] [--idtype IDTYPE] targets [targets ...]

ikess - IKE Security Scanner (Sequential Mode)

Scans targets with ike-scan, detects IKEv1/IKEv2, tests transforms,
and generates XML/JSON/HTML reports.

Scan flow per host:
  1) IKEv1/IKEv2 discovery on UDP 500
  2) If UDP 500 is silent: NAT-T discovery on UDP 4500 (scan continues over 4500)
  3) If UDP 500 answered: probe whether the peer also answers on 4500 (info finding)
  4) Optional Aggressive Mode group VPN ID hunt (--idfile)
  5) Aggressive Mode tests (if IKEv1)
  6) Transform tests (Main Mode):
     - default: curated common+legacy combos
     - --fullalgs: brute-force all ENC/HASH/AUTH/DH combos
  7) Optional backoff fingerprinting (--fingerprint)

Transform format: ENC[/bits],HASH,AUTH,GROUP
Example: '7/256,4,1,14' = AES256 / SHA256 / PSK / MODP2048.

positional arguments:
  targets              One or more IPv4 addresses or CIDR ranges to scan. Examples: 192.0.2.10 192.0.2.0/28
                       All usable hosts in a CIDR are enumerated.

options:
  -h, --help           show this help message and exit
  --fullalgs           Try every ENC/HASH/AUTH/DH combination (full cartesian set).
                       You can still limit via --enc/--hash/--auth/--group. Very noisy. (default: False)
  --fingerprint        Enable backoff fingerprinting (ike-scan --showbackoff). If no fingerprint is obtained from a
                       generic probe, ikess retries using the first accepted transform to improve accuracy. (default: False)
  --enc ENC            Comma separated encryption list to try or restrict. Accepts numeric codes or aliases.
                       Examples: --enc AES256,3DES  or  --enc 7/256,5 (default: None)
  --hash HASH          Comma separated hash list. Accepts numeric codes or aliases.
                       Examples: --hash SHA1,SHA256  or  --hash 2,4 (default: None)
  --auth AUTH          Comma separated IKE authentication methods. Accepts numeric codes or aliases.
                       Examples: --auth PSK,RSA  or  --auth 1,3  or  --auth HYBRID (default: None)
  --group, --dh GROUP  Comma separated DH groups. Accepts numeric codes or aliases. '--dh' is an alias.
                       Examples: --group G14,G16  or  --dh MODP2048,MODP4096  or  --group 14,16 (default: None)
  --onlycustom         Scan only the transforms built from your custom --enc/--hash/--auth/--group lists. Without this
                       flag, custom items are merged into the curated or expanded set. (default: False)
  --nat-t, --natt      Probe over NAT-T (RFC 3947): UDP 4500 source+dest with non-ESP marker (ike-scan --nat-t).
                       Applies to every ike-scan call. Report files get a '_natt4500' suffix. ikess automatically
                       switches to UDP 4500 per host when UDP 500 is silent; this flag forces 4500 for the whole
                       scan. Note: many gateways only answer on 4500 after NAT detection on 500, so no response
                       here is not conclusive. (default: False)
  --id ID             Group VPN ID sent with every Aggressive Mode probe (ike-scan --id). Some gateways (Cisco ASA
                       tunnel-group, SonicWall, FortiGate dialup, WatchGuard, ...) only negotiate after seeing a known
                       group ID and otherwise answer NO-PROPOSAL-CHOSEN to every proposal. (default: None)
  --idtype IDTYPE     Identification type for --id (RFC 2407): 1=IPv4, 2=FQDN, 3=USER_FQDN, 11=KEY_ID. KEY_ID is the
                       usual type for group VPN names. (default: 11)
  --idfile IDFILE     Brute force group VPN IDs from a wordlist file (one candidate per line, '#' comments) with
                       Aggressive Mode probes; the matching ID is adopted for all further probes. Bundles a compact
                       PSK proposal set per DH group and runs on the host's scan transport (UDP 500, or UDP 4500
                       for NAT-T-only peers / --nat-t). A curated list ships in wordlists/group_ids.txt.
  --sport SPORT       UDP source port for every ike-scan call (ike-scan --sport). Default: 500 (4500 with --nat-t).
                       Use 0 for a random source port when scanning a local test server - its IKE daemon already
                       owns UDP 500/4500 and ike-scan cannot bind them at the same time. (default: None)

Aliases you can use for --enc, --hash, --auth, --group:
  ENC:  DES=1, 3DES=5, AES=7/128, AES128=7/128, AES192=7/192, AES256=7/256
  HASH: MD5=1, SHA1=2, SHA256=4, SHA384=5, SHA512=6
  AUTH: PSK=1, RSA=3, RSA_SIG=3, RSA-SIG=3, RSA SIG=3, HYBRID=64221, HYBRID_RSA=64221
  DH:   G1=1,  G2=2,  G5=5,  G14=14, G15=15, G16=16
        MODP768=1, MODP1024=2, MODP1536=5, MODP2048=14, MODP3072=15, MODP4096=16

Examples:
  sudo ./ikess.py 10.0.0.1
  sudo ./ikess.py 10.0.0.0/24 --fullalgs --fingerprint
  sudo ./ikess.py 10.0.0.1 --enc DES,3DES --onlycustom
  sudo ./ikess.py 10.0.0.1 --enc AES128,3DES,1,7/256 --hash SHA1,SHA256,1 --auth PSK,RSA --group G2,G14,16
  sudo ./ikess.py 203.0.113.5 --enc AES256 --hash SHA256 --auth PSK --group MODP2048 --onlycustom
  sudo ./ikess.py 203.0.113.5 --nat-t
  sudo ./ikess.py 203.0.113.5 --id mygroupvpn
  sudo ./ikess.py 203.0.113.5 --idfile wordlists/group_ids.txt
  sudo ./ikess.py 127.0.0.1 --sport 0
```

You can also run via Docker:

```bash
docker run --rm -v ./results:/app/results ghcr.io/l4rm4nd/ikess:latest <IP>
```

## Local testing (VPN server on the same machine)

`ike-scan` uses UDP source port 500 (4500 with `--nat-t`) - the same ports your local IKE daemon
listens on, so a local scan cannot bind them and every probe fails with `Address already in use`.
Use a random source port so both can run at the same time:

```bash
sudo ./ikess.py 127.0.0.1 --sport 0
```

Notes:

- Most IKE daemons answer IKEv2 IKE_SA_INIT from any source port, so IKEv2 discovery works locally.
- Some daemons (e.g. libreswan/pluto) stay silent for IKEv1 coming from source ports other than
  500, and site-to-site configs with fixed peer IPs match no policy for a localhost probe at all.
  For full IKEv1 enumeration of a local daemon, either add a test connection with `right=%any`, or
  run ikess from a separate network namespace/container so it owns its own UDP 500 and can use the
  default source port, e.g.:

  ```bash
  docker run --rm -v ./results:/app/results ghcr.io/l4rm4nd/ikess:latest <host-ip>
  ```

- Keep the default source port for remote gateways - some peers only answer clients from UDP 500.

## Why does the report show no accepted transforms?

If a host answers IKE but every offered proposal is rejected (`NO-PROPOSAL-CHOSEN`), ikess reports an
INFO finding ("Peer responded but rejected every offered proposal"). Common reasons and what to try:

- The gateway requires a **group VPN ID** before negotiating (Cisco ASA tunnel-group, SonicWall,
  FortiGate dialup, WatchGuard, ...): rerun with `--id <groupname>`, or try common names via
  `--idfile wordlists/group_ids.txt`. Without the correct group name the gateway refuses every
  proposal - unknown, organisation-specific names cannot be guessed.
- The accepted proposal is outside the tested set: rerun with `--fullalgs`, or narrow it with
  `--enc/--hash/--auth/--group` (e.g. vendor-specific combos such as AES192 or SHA-384).
- The peer only answers on UDP 4500 (only 4500 forwarded, NAT-T-only config): ikess detects
  this during discovery and scans over 4500 automatically. If UDP 500 answered but you
  suspect the 4500 listener runs a different policy, rerun with `--nat-t`.
- The gateway negotiates **IKEv2 only**: ike-scan cannot enumerate IKEv2 proposals (`--trans` is not
  supported with `--ikev2`), so IKEv2-only policies cannot be matched by any ike-scan based tool.
  ikess reports the IKEv2 capability from the discovery response instead.
