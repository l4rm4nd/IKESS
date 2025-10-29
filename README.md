# IKE Security Scanner (IKESS)
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
usage: ikess [-h] [-t THREADS] [--fullalgs] [--fingerprint] [--enc ENC] [--hash HASH] [--auth AUTH]
             [--group GROUP] [--onlycustom]
             targets [targets ...]

ikess v1.1 – IKE Security Scanner

positional arguments:
  targets               One or more target IPs/hostnames to probe (space-separated).

options:
  -h, --help            show this help message and exit
  -t, --threads THREADS
                        Number of concurrent worker threads (default: 1).
  --fullalgs            Use expanded curated transform sets (adds legacy DES/3DES and broader AES/DH variants).
                        If you also pass --enc/--hash/--auth/--group, those custom combos are MERGED in.
                        Use --onlycustom to skip curated sets entirely.
  --fingerprint         Run ike-scan --showbackoff to guess implementation. If the generic attempt is inconclusive
                        and we negotiated at least one transform, retry --showbackoff with the first accepted
                        transform to improve the fingerprint.
  --enc ENC             Comma-separated ENC list. Accepts names or tokens: AES,AES128,AES192,AES256,3DES,DES
                        or 1,5,7/128,7/192,7/256. Example: --enc AES128,3DES,1,7/256
  --hash HASH           Comma-separated HASH list. Accepts names or tokens: MD5,SHA1,SHA256 or 1,2,5.
                        Example: --hash SHA1,SHA256,1
  --auth AUTH           Comma-separated AUTH list. Accepts names or tokens: PSK,RSA,HYBRID or 1,3,64221.
                        Merged into Main & Aggressive cross-products. If omitted, Aggressive defaults to PSK only.
  --group, --dh GROUP   Comma-separated DH groups. Accepts names or tokens: G1,G2,G5,G14,G15,G16 or 1,2,5,14,15,16,
                        and MODP aliases like MODP1024, MODP2048. Example: --group G2,G14,16
  --onlycustom          Do NOT use curated transform sets. Scan ONLY the cross-product of your custom ENC/HASH/AUTH/GROUP.
                        If you omit --auth, Aggressive still defaults to PSK.

Examples:
  # Curated defaults only
  sudo python3 ikess.py 10.0.0.1

  # Expanded curated coverage (adds legacy/rare variants)
  sudo python3 ikess.py 10.0.0.1 --fullalgs

  # Try defaults PLUS a DES cross-product (merged with curated defaults)
  sudo python3 ikess.py 10.0.0.1 --enc DES

  # Only your custom cross-product (no curated defaults)
  sudo python3 ikess.py 10.0.0.1 --enc DES --onlycustom

  # Custom space using names or ike-scan tokens (mixed allowed)
  sudo python3 ikess.py 10.0.0.1 \
       --enc AES128,3DES,1,7/256 \
       --hash SHA1,SHA256,1 \
       --auth PSK,RSA,HYBRID \
       --group G2,G14,16

Notes:
  • Names are mapped to ike-scan tokens:
      ENC:  DES→1, 3DES→5, AES128→7/128, AES192→7/192, AES256→7/256, AES→7/128
      HASH: MD5→1, SHA1→2, SHA256→5
      AUTH: PSK→1, RSA (RSA_Sig)→3, HYBRID (Hybrid_RSA)→64221
      DH:   G1→1, G2→2, G5→5, G14→14, G15→15, G16→16, MODPxxxx→matching group
  • Aggressive mode focuses on PSK by default; include --auth if you want RSA/HYBRID
    proposals in the aggressive cross-product as well.
  • --fingerprint runs --showbackoff and, if needed, retries with a known accepted
    transform discovered during the scan.
```

## Screenshots

<img width="1571" height="979" alt="image" src="https://github.com/user-attachments/assets/9c11fd9e-6e7f-47fa-a469-46c2feb80fff" />
