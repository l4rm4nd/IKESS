# Local VPN test scenarios

These isolated Docker Compose projects provide deterministic VPN targets for IKESS. Run only one scenario at a time because every project publishes UDP ports 500 and 4500 on the host.

| Directory | IKE versions and behavior | Expected IKEv1 proposal |
| --- | --- | --- |
| `01-ikev1-aggressive` | IKEv1 Aggressive Mode; no gateway-specific or group ID required | AES-256/SHA-256/PSK/DH14 |
| `02-ikev1-ikev2-aes256` | IKEv1 Main Mode and IKEv2; IKEv1 is restricted to one AES proposal | AES-256/SHA-256/PSK/DH14 only |
| `03-ikev1-ikev2-default` | IKEv1 Main Mode and IKEv2 with the upstream IKE proposal set | Upstream AES proposal set |
| `04-ikev1-aggressive-group-vpn` | IKEv1 Aggressive Mode requiring group ID `vpn` (`KEY_ID`) | AES-256/SHA-256/PSK/DH14 |
| `05-ikev1-3des-only` | IKEv1 Main Mode restricted to a legacy cipher | 3DES/SHA-1/PSK/DH14 only |
| `06-ikev2-only` | Negative IKEv1 test and positive IKEv2 test | None |
| `07-ikev1-transform-matrix` | IKEv1 Main Mode with strong and deprecated proposals | AES-256/SHA-256/DH14, AES-128/SHA-1/DH5, 3DES/SHA-1/DH14 |

Entries 02 and 03 intentionally cover the two similar IKEv1+IKEv2 cases: entry 02 has a single explicit AES transform, while entry 03 retains the image's default proposal set. Aggressive Mode is disabled in both.

Single DES is not available because current Libreswan releases removed it. Scenario 05 uses 3DES, the oldest weak cipher still provided by the upstream image.

## Credentials

The Compose files contain test-only defaults. Override them in the shell before starting a scenario, or copy `.env.example` to the selected scenario as `.env`:

    cp test/.env.example test/02-ikev1-ikev2-aes256/.env

Never expose the default credentials to an untrusted network.

`VPN_PUBLIC_IP` defaults to `127.0.0.1` so local tests never depend on an external public-IP discovery service. Override it when the scanner runs from another host.

## Start and stop a scenario

From the repository root:

    docker compose -f test/02-ikev1-ikev2-aes256/docker-compose.yml up -d --build
    docker compose -f test/02-ikev1-ikev2-aes256/docker-compose.yml logs -f vpn
    docker compose -f test/02-ikev1-ikev2-aes256/docker-compose.yml down

Use `down -v` when the IKEv2 certificate volume should also be deleted and regenerated.

## Scan locally

Use `--sport 0` when IKESS and the VPN container run on the same host. Docker already owns host UDP port 500, so `ike-scan` must use an ephemeral source port.

General scan:

    python3 ikess.py 127.0.0.1 --sport 0

Aggressive Mode scenario 01:

        python3 ikess.py 127.0.0.1 --sport 0 \
            --enc AES256 --hash SHA256 --auth PSK --group G14 --onlycustom

Single AES transform in scenario 02:

    python3 ikess.py 127.0.0.1 --sport 0 \
      --enc AES256 --hash SHA256 --auth PSK --group G14 --onlycustom

Required group ID in scenario 04:

    python3 ikess.py 127.0.0.1 --sport 0 --id vpn --idtype 11 \
      --enc AES256 --hash SHA256 --auth PSK --group G14 --onlycustom

Group-ID wordlist hunt in scenario 04:

    python3 ikess.py 127.0.0.1 --sport 0 --idfile wordlists/group_ids.txt

3DES-only scenario 05:

    python3 ikess.py 127.0.0.1 --sport 0 \
      --enc 3DES --hash SHA1 --auth PSK --group G14 --onlycustom

## Implementation notes

The upstream image generates `/etc/ipsec.conf` during startup. Scenario Dockerfiles patch that generator rather than mounting a replacement configuration, preserving upstream networking, firewall, and credential setup. Scanner-focused IKEv1 profiles advertise standard PSK authentication instead of the upstream XAuth-PSK transform.

Mounting a volume at `/etc/ipsec.d` enables the image's automatic IKEv2 setup. Libreswan normally returns `NO_PROPOSAL_CHOSEN` even for an unconfigured IKE version, which still looks like protocol support to a scanner. The version-specific images therefore install payload-version firewall rules on UDP 500 and 4500 so disabled versions are strictly silent. L2TP is disabled throughout so scanner results are easier to interpret.

> Warning: IKEv1, Aggressive Mode, SHA-1, and 3DES are intentionally insecure test configurations. Use them only in an isolated local lab.
