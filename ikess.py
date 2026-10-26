#!/usr/bin/env python3
"""
ikess - IKE Security Scanner (Sequential Mode)
Author: LRVT[](https://github.com/l4rm4nd)
"""

import argparse
import html as html_lib
import json
import logging
import re
import socket
import random
import subprocess
import sys
import tempfile
import time
from datetime import datetime
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from itertools import product
import ipaddress
from pathlib import Path

try:
    import fcntl  # POSIX advisory file locks (used for the ike-scan UDP port lock)
except ImportError:  # non-POSIX platforms - bind-retry still applies
    fcntl = None

# ----------------------------- Logging ---------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ikess")

# --------------------------- Feature flags -----------------------------
FULLALGS: bool = False
FINGERPRINT: bool = False
CUSTOM_ENC: List[str] = []
CUSTOM_HASH: List[str] = []
CUSTOM_AUTH: List[str] = []
CUSTOM_GROUP: List[str] = []
ONLYCUSTOM: bool = False
NATT: bool = False
# Optional ike-scan --sport override (e.g. 0 = random source port for local testing)
IKE_SPORT: Optional[int] = None
# Aggressive Mode group VPN ID (ike-scan --id/--idtype). Some gateways
# (Cisco ASA tunnel-group, SonicWall, FortiGate dialup, WatchGuard, ...)
# only negotiate proposals after seeing a known group ID and otherwise
# answer NO-PROPOSAL-CHOSEN (or stay silent) for every proposal.
VPN_ID: Optional[str] = None
VPN_IDTYPE: int = 11  # RFC 2407 ID type: 11 = KEY_ID (group name)
# Aggressive Mode requires a non-empty initiator ID in the first exchange.
# Use a neutral FQDN when the caller did not provide a gateway-specific ID.
DEFAULT_AGGRESSIVE_ID = "ikess-probe.invalid"
DEFAULT_AGGRESSIVE_IDTYPE = 2  # ID_FQDN
# Optional wordlist for the Aggressive Mode group VPN ID hunt (--idfile)
IDFILE: Optional[str] = None
# Group VPN IDs discovered by the --idfile hunt (ip -> group name)
DISCOVERED_IDS: Dict[str, str] = {}
# Pause between group ID hunt probes (seconds) to stay gentle on the peer
HUNT_PROBE_DELAY: float = 0.05
# Extra flags prepended to every ike-scan invocation (e.g. --nat-t)
EXTRA_IKESCAN_ARGS: List[str] = []
# ike-scan binds a fixed UDP source port (500, or 4500 with --nat-t) and only one
# process may hold it at a time. Serialize our own calls with an advisory lock and
# retry when a non-cooperating process (e.g. a manual ike-scan) holds the port -
# otherwise ike-scan exits with empty output and probes look like false negatives.
IKE_PORT_BIND_MAX_RETRIES: int = 4
IKE_PORT_BIND_BASE_DELAY: float = 0.5
IKE_PORT_LOCK_MAX_WAIT: float = 300.0
IKE_PORT_BIND_ERR_RE = re.compile(r"(Could not bind network socket to local port|Address already in use)", re.I)

# --------------------------- Vulnerability text ------------------------
FLAWS = {
    "IKEV1": "Weak IKE version 1 supported - deprecated in favor of IKEv2",
    "DISC": "The IKE service is discoverable",
    "ENC_DES": "DES encryption detected - insecure and should be replaced with AES",
    "ENC_3DES": "3DES encryption detected - deprecated and should be replaced with AES",
    "ENC_AES_CBC": "AES-CBC encryption detected - legacy non-AEAD mode; prefer AES-GCM or ChaCha20-Poly1305",
    "HASH_MD5": "MD5 hash algorithm detected - insecure due to collision vulnerabilities",
    "HASH_SHA1": "SHA1 hash algorithm detected - deprecated due to collision vulnerabilities",
    "DHG_1": "DH Group 1 (MODP-768) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "DHG_2": "DH Group 2 (MODP-1024) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "DHG_5": "DH Group 5 (MODP-1536) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "AUTH_PSK": "Pre-shared key authentication - consider certificate-based authentication",
    "AGG_MODE": "Aggressive Mode supported - may reveal PSK hash for offline attacks",
    "FING_VID": "Fingerprinting possible via VID payload - informational leak",
    "FING_BACKOFF": "Fingerprinting possible via backoff pattern - informational leak",
    "IKEV2": "IKEv2 is supported - very good and recommended",
    "NATT_VID": "NAT-T advertised on UDP 500 (RFC 3947 VID) - peer switches to UDP 4500 after NAT detection; rerun with --nat-t to cover 4500",
    "NATT_4500": "IKE service also reachable on UDP 4500 (NAT-T) - additional exposed attack surface; rerun with --nat-t if the 4500 listener should be enumerated separately",
    "NATT_ONLY": "IKE service answers only on UDP 4500 (NAT-T) - UDP 500 is silent (typical when only 4500 is port-forwarded or the peer is configured for NAT-T only); scan continued over UDP 4500",
    "NO_PROPOSAL": "Peer responded but rejected every offered proposal - it may require a specific group VPN ID for Aggressive Mode (rerun with --id or --idfile), negotiate IKEv2-only proposals (not enumerable with ike-scan), use transforms outside the tested set (--fullalgs or custom --enc/--hash/--auth/--group), or expose a different policy on UDP 4500 (rerun with --nat-t)",
    "VPN_ID_FOUND": "Group VPN ID accepted in Aggressive Mode - peer requires this group name before negotiating proposals"
}

# ============================= MAIN MODE TRANSFORMS =============================
# Main Mode is used heavily for site-to-site and "permanent tunnel" style IPsec.
# It's what most orgs run between firewalls, branch routers, Azure VPN gateways, etc.
#
# Why we probe these:
# - If we get a match here, we learn exactly which crypto/auth/DH combo the peer accepts.
# - That tells us how modern (AES/SHA256/DH14+), lazy (AES/SHA1/DH2), or ancient (3DES/DES/MD5) the config is.
# - Weak combos here are still a legit finding even if we can't immediately brute credentials.
#
# Format of each transform string below:
#   "ENC[/bits],HASH,AUTH,GROUP"
#     ENC:   1=DES, 5=3DES, 7/128=AES128, 7/192=AES192, 7/256=AES256
#     HASH:  1=MD5, 2=SHA1, 4=SHA256, 5=SHA384, 6=SHA512
#     AUTH:  1=PSK, 3=RSA_SIG (cert-based), 64221=HYBRID_RSA
#     GROUP: 2=MODP1024, 5=MODP1536, 14=MODP2048, 15=MODP3072, 16=MODP4096, 19=ECP256 (elliptic curve)
#
# We group the transforms below from "modern-ish and common in 2025" down to "this belongs in a museum".
# ===============================================================================

MAIN_MODE_TRANSFORMS = [
    # ------------------------------------------------------------------
    # MODERN & COMMON PSK PROFILES (AES*, SHA1/SHA256, PSK, DH14/2048)
    # Typical for site-to-site tunnels and many "current but not fancy"
    # vendor templates. DH14 = MODP2048.
    # ------------------------------------------------------------------
    "7/128,4,1,14",   # AES128-SHA256-PSK-DH14 (MODP2048)
    "7/256,4,1,14",   # AES256-SHA256-PSK-DH14 (MODP2048)
    "7/128,2,1,14",   # AES128-SHA1-PSK-DH14 (MODP2048)
    "7/256,2,1,14",   # AES256-SHA1-PSK-DH14 (MODP2048)
    "7/192,2,1,14",   # AES192-SHA1-PSK-DH14 (MODP2048)
    "7/192,4,1,14",   # AES192-SHA256-PSK-DH14 (MODP2048)

    # ------------------------------------------------------------------
    # MODERN & COMMON RSA_SIG PROFILES (cert-based auth instead of PSK)
    # RSA_SIG is common for B2B tunnels and "we use certs" deployments.
    # ------------------------------------------------------------------
    "7/128,4,3,14",   # AES128-SHA256-RSA_SIG-DH14 (MODP2048)
    "7/256,4,3,14",   # AES256-SHA256-RSA_SIG-DH14 (MODP2048)
    "7/128,2,3,14",   # AES128-SHA1-RSA_SIG-DH14 (MODP2048)
    "7/256,2,3,14",   # AES256-SHA1-RSA_SIG-DH14 (MODP2048)

    # ------------------------------------------------------------------
    # RSA_SIG WITH WEAK DH (DH2/1024)
    # Seen in older "certificate-based" tunnels that never upgraded DH.
    # DH2 = MODP1024, considered weak today.
    # ------------------------------------------------------------------
    "7/128,2,3,2",    # AES128-SHA1-RSA_SIG-DH2 (MODP1024)
    "7/256,2,3,2",    # AES256-SHA1-RSA_SIG-DH2 (MODP1024)

    # ------------------------------------------------------------------
    # PSK WITH WEAK / LEGACY DH GROUPS (DH2/1024, DH5/1536)
    # Still extremely common in old branch tunnels and firewalls.
    # DH2 = MODP1024, DH5 = MODP1536.
    # SHA1 and SHA256 both appear in half-upgraded configs.
    # ------------------------------------------------------------------
    "7/128,2,1,2",    # AES128-SHA1-PSK-DH2  (MODP1024)
    "7/256,2,1,2",    # AES256-SHA1-PSK-DH2  (MODP1024)
    "7/128,4,1,2",    # AES128-SHA256-PSK-DH2 (MODP1024)
    "7/256,4,1,2",    # AES256-SHA256-PSK-DH2 (MODP1024)

    "7/128,4,1,5",    # AES128-SHA256-PSK-DH5 (MODP1536)
    "7/256,4,1,5",    # AES256-SHA256-PSK-DH5 (MODP1536)
    "7/128,2,1,5",    # AES128-SHA1-PSK-DH5   (MODP1536)
    "7/256,2,1,5",    # AES256-SHA1-PSK-DH5   (MODP1536)

    # ------------------------------------------------------------------
    # VERY HIGH DH GROUPS WITH PSK AND RSA_SIG
    # These are the "paranoid / we bumped DH to 4096" style configs.
    # DH16 = MODP4096.
    # ------------------------------------------------------------------
    "7/128,4,1,16",   # AES128-SHA256-PSK-DH16 (MODP4096)
    "7/256,4,1,16",   # AES256-SHA256-PSK-DH16 (MODP4096)
    "7/128,4,3,16",   # AES128-SHA256-RSA_SIG-DH16 (MODP4096)
    "7/256,4,3,16",   # AES256-SHA256-RSA_SIG-DH16 (MODP4096)

    # ------------------------------------------------------------------
    # ELLIPTIC CURVE DH GROUPS (ECP256 etc.)
    # Some vendors advertise IKEv2/ECP but will still answer in IKEv1.
    # Group 19 is typically ECP256.
    # ------------------------------------------------------------------
    "7/128,4,1,19",   # AES128-SHA256-PSK-ECP256 (DH19)
    "7/256,4,1,19",   # AES256-SHA256-PSK-ECP256 (DH19)

    # ------------------------------------------------------------------
    # WEAK HASH (MD5) WITH PSK
    # These are strong "red flag" combos. MD5 is collision-prone.
    # ------------------------------------------------------------------
    "7/128,1,1,14",   # AES128-MD5-PSK-DH14 (MODP2048)
    "7/256,1,1,14",   # AES256-MD5-PSK-DH14 (MODP2048)

    # ------------------------------------------------------------------
    # 3DES LEGACY
    # 3DES + SHA1 + PSK/RSA_SIG is still depressingly common on
    # older Cisco/SonicWall/WatchGuard tunnels. DH2 = MODP1024.
    # ------------------------------------------------------------------
    "5,2,1,14",       # 3DES-SHA1-PSK-DH14 (MODP2048)
    "5,2,1,2",        # 3DES-SHA1-PSK-DH2  (MODP1024)
    "5,2,3,14",       # 3DES-SHA1-RSA_SIG-DH14 (MODP2048)
    "5,2,3,2",        # 3DES-SHA1-RSA_SIG-DH2  (MODP1024)

    # ------------------------------------------------------------------
    # DES / MD5 / SHA1 ANCIENT GARBAGE
    # DES and MD5 are fully broken. If the peer accepts these,
    # it's an instant "critical/heritage VPN" finding.
    # DH2 = MODP1024, DH14 = MODP2048.
    # ------------------------------------------------------------------
    "1,2,1,14",       # DES-SHA1-PSK-DH14 (MODP2048)
    "1,1,1,14",       # DES-MD5-PSK-DH14 (MODP2048)
    "1,2,1,2",        # DES-SHA1-PSK-DH2  (MODP1024)
    "1,1,1,2",        # DES-MD5-PSK-DH2  (MODP1024)
]

# ============================= AGGRESSIVE MODE TRANSFORMS =============================
# Aggressive Mode is IKEv1-only and most interesting for PSK-based VPNs,
# because misconfigured gateways can leak an ID hash that can be cracked offline.
# We generally don't include RSA_SIG here by default, because the "classic"
# aggressive-mode exposure vector is PSK.
# =====================================================================================

AGGRESSIVE_MODE_TRANSFORMS = [
    # ------------------------------------------------------------------
    # MODERN(ish) PSK WITH DH14 (MODP2048)
    # This is what you'd hope to see in a semi-updated environment.
    # ------------------------------------------------------------------
    "7/128,4,1,14",   # AES128-SHA256-PSK-DH14 (MODP2048)
    "7/256,4,1,14",   # AES256-SHA256-PSK-DH14 (MODP2048)
    "7/128,2,1,14",   # AES128-SHA1-PSK-DH14  (MODP2048)
    "7/256,2,1,14",   # AES256-SHA1-PSK-DH14  (MODP2048)

    # ------------------------------------------------------------------
    # LEGACY PSK WITH SMALLER DH (DH2/1024, DH5/1536)
    # This is extremely common in old remote-access VPN configs.
    # DH2 = MODP1024, DH5 = MODP1536.
    # ------------------------------------------------------------------
    "7/128,2,1,2",    # AES128-SHA1-PSK-DH2  (MODP1024)
    "7/256,2,1,2",    # AES256-SHA1-PSK-DH2  (MODP1024)
    "7/128,4,1,5",    # AES128-SHA256-PSK-DH5 (MODP1536)
    "7/256,4,1,5",    # AES256-SHA256-PSK-DH5 (MODP1536)
    "7/128,2,1,5",    # AES128-SHA1-PSK-DH5   (MODP1536)

    # ------------------------------------------------------------------
    # VERY HIGH DH GROUPS WITH PSK (DH16/4096)
    # Some orgs crank DH size but still keep PSK.
    # DH16 = MODP4096.
    # ------------------------------------------------------------------
    "7/128,4,1,16",   # AES128-SHA256-PSK-DH16 (MODP4096)
    "7/256,4,1,16",   # AES256-SHA256-PSK-DH16 (MODP4096)

    # ------------------------------------------------------------------
    # 3DES / DES LEGACY PSK
    # These are the "this VPN is from 2004 and never died" configs.
    # SHA1 or even MD5, plus tiny DH groups. All of this is reportable.
    # ------------------------------------------------------------------
    "5,2,1,5",        # 3DES-SHA1-PSK-DH5   (MODP1536)
    "1,2,1,5",        # DES-SHA1-PSK-DH5    (MODP1536)
    "5,2,1,14",       # 3DES-SHA1-PSK-DH14  (MODP2048)
    "5,2,1,2",        # 3DES-SHA1-PSK-DH2   (MODP1024)
    "5,1,1,14",       # 3DES-MD5-PSK-DH14   (MODP2048)
    "5,1,1,2",        # 3DES-MD5-PSK-DH2    (MODP1024)

    # ------------------------------------------------------------------
    # DES / MD5 / SHA1 ANCIENT PSK
    # If a peer accepts any of these in Aggressive Mode, it's basically
    # instant critical: PSK, weak hash, weak cipher, weak DH, Aggressive.
    # ------------------------------------------------------------------
    "1,2,1,14",       # DES-SHA1-PSK-DH14   (MODP2048)
    "1,1,1,14",       # DES-MD5-PSK-DH14    (MODP2048)
    "1,2,1,2",        # DES-SHA1-PSK-DH2    (MODP1024)
    "1,1,1,2",        # DES-MD5-PSK-DH2     (MODP1024)
]

# Full cross-product spaces (used only with --fullalgs and custom args)
ENC_FULL   = ["1", "5", "7/128", "7/192", "7/256"]
HASH_FULL  = ["1", "2", "4", "5", "6"]
AUTH_FULL  = ["1", "3", "64221"]
GROUP_FULL = ["2", "5", "14", "15", "16", "19", "20", "21"]

def _build_transform_space(encs: List[str], hashes: List[str], auths: List[str], groups: List[str]) -> List[str]:
    return [f"{e},{h},{a},{g}" for e, h, a, g in product(encs, hashes, auths, groups)]

# ----------------------------- Helpers ----------------------------------

def _implementation_sources(data: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Return both implementation hints:
    - 'backoff': from --showbackoff (preferred if present & not N/A/unknown)
    - 'vid': first meaningful VID description (fallback)
    Also include a 'primary' key with the chosen display value.
    """
    backoff = (data.get("showbackoff") or "").strip()
    if backoff.lower() in {"", "n/a", "unknown"}:
        backoff = None

    vids = data.get("vid") or []
    vid_choice = None
    for v in vids:
        if not re.search(r"(draft|fragment|dead peer|xauth|rfc\s*3947|heartbeat)", v, re.I):
            vid_choice = v
            break
    if not vid_choice and vids:
        vid_choice = vids[0]

    primary = backoff or vid_choice or "N/A"
    return {"backoff": backoff, "vid": vid_choice, "primary": primary}

def _ike_source_port(cmd: List[str]) -> int:
    """Best-effort UDP source port ike-scan will bind for this invocation (0 = random/ephemeral)."""
    for i, arg in enumerate(cmd):
        if arg == "--sport" and i + 1 < len(cmd):
            try:
                return int(cmd[i + 1])
            except ValueError:
                return 0
        if arg.startswith("--sport="):
            try:
                return int(arg.split("=", 1)[1])
            except ValueError:
                return 0
    if "--nat-t" in cmd:
        return 4500
    return 500

def _acquire_ike_port_lock(port: int):
    """
    Advisory cross-process lock (flock) so concurrent ikess instances serialize their
    ike-scan calls instead of racing for the fixed UDP source port. Returns an open
    file handle that owns the lock, or None when locking is unavailable - the
    bind-retry in run_command still guards correctness in that case.
    """
    if fcntl is None or not port:
        return None
    lock_path = Path(tempfile.gettempdir()) / f"ikess_ikescan_udp{port}.lock"
    try:
        fh = open(lock_path, "w")
    except OSError as e:
        logger.debug(f"Cannot open ike-scan port lock {lock_path}: {e}")
        return None
    deadline = time.monotonic() + IKE_PORT_LOCK_MAX_WAIT
    announced = False
    while True:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except OSError:
            if time.monotonic() >= deadline:
                logger.warning(f"UDP {port} port lock stayed busy for {IKE_PORT_LOCK_MAX_WAIT:.0f}s - proceeding without lock")
                fh.close()
                return None
            if not announced:
                logger.info(f"UDP {port} in use by another ikess process - waiting for the port lock")
                announced = True
            time.sleep(0.25)

def _is_local_ike_target(cmd: List[str]) -> bool:
    """True when the ike-scan target is this machine (local test server scenario)."""
    if not cmd:
        return False
    try:
        target_ip = socket.gethostbyname(cmd[-1])
    except OSError:
        return False
    try:
        if ipaddress.ip_address(target_ip).is_loopback:
            return True
    except ValueError:
        return False
    try:
        local_addrs = set(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        return False
    return target_ip in local_addrs

def run_command(cmd: List[str], timeout: int = 30) -> Tuple[str, str, int]:
    if cmd and cmd[0] == "ike-scan" and EXTRA_IKESCAN_ARGS:
        cmd = [cmd[0]] + EXTRA_IKESCAN_ARGS + cmd[1:]
        # ike-scan: --sport/--dport only override the NAT-T defaults (4500/4500)
        # when given AFTER --nat-t - keep the order valid no matter who added what.
        if "--nat-t" in cmd:
            sport_args = [a for a in cmd if a.startswith("--sport=")]
            if sport_args and cmd.index("--nat-t") > min(cmd.index(a) for a in sport_args):
                cmd = [a for a in cmd if not a.startswith("--sport=")]
                nat_idx = cmd.index("--nat-t")
                cmd = cmd[:nat_idx + 1] + sport_args + cmd[nat_idx + 1:]
    is_ike = bool(cmd) and cmd[0] == "ike-scan"
    lock_fh = _acquire_ike_port_lock(_ike_source_port(cmd)) if is_ike else None
    try:
        attempts = IKE_PORT_BIND_MAX_RETRIES if is_ike else 1
        for attempt in range(1, attempts + 1):
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                out, err, rc = p.stdout.strip(), p.stderr.strip(), p.returncode
            except subprocess.TimeoutExpired:
                logger.warning(f"Command timed out: {' '.join(cmd)}")
                return ("", "Timeout expired", 124)
            except Exception as e:
                logger.error(f"Command failed: {' '.join(cmd)} - {str(e)}")
                return ("", str(e), 1)
            if is_ike and IKE_PORT_BIND_ERR_RE.search(err):
                if attempt < attempts:
                    delay = IKE_PORT_BIND_BASE_DELAY * (2 ** (attempt - 1)) + random.uniform(0.05, 0.25)
                    logger.warning(
                        f"ike-scan could not bind its UDP source port (in use by another process) - "
                        f"retry {attempt}/{attempts - 1} in {delay:.1f}s: {' '.join(cmd[:6])}"
                    )
                    time.sleep(delay)
                    continue
                hint = ""
                if _is_local_ike_target(cmd):
                    hint = " - target is local: your IKE daemon owns UDP 500/4500, rerun with --sport 0"
                logger.error(
                    f"ike-scan source port stayed busy after {attempts} attempts - this probe may be a "
                    f"false negative (peer appears silent){hint}: {' '.join(cmd[:6])}"
                )
            return (out, err, rc)
        return ("", "ike-scan source port unavailable", 1)  # defensive; loop always returns
    finally:
        if lock_fh is not None:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
            lock_fh.close()

def check_ike_dependency() -> bool:
    out, _, rc = run_command(["which", "ike-scan"], timeout=5)
    if rc == 0 and out:
        logger.info(f"ike-scan found: {out.splitlines()[0]}")
        return True
    logger.error("ike-scan not found. Please install ike-scan to continue.")
    return False

# ----------------------------- Aliases & Parsing -------------------------
ENC_ALIASES = {
    "DES": "1", "3DES": "5", "AES": "7/128",
    "AES128": "7/128", "AES-128": "7/128", "AES 128": "7/128",
    "AES192": "7/192", "AES-192": "7/192", "AES 192": "7/192",
    "AES256": "7/256", "AES-256": "7/256", "AES 256": "7/256",
}
HASH_ALIASES = {
    "MD5": "1",
    "SHA1": "2", "SHA-1": "2", "SHA 1": "2",
    "SHA256": "4", "SHA-256": "4", "SHA 256": "4",
    "SHA384": "5", "SHA-384": "5", "SHA 384": "5",
    "SHA512": "6", "SHA-512": "6", "SHA 512": "6",
}
AUTH_ALIASES = {"PSK": "1", "RSA": "3", "RSA_SIG": "3", "RSA-SIG": "3", "RSA SIG": "3", "HYBRID": "64221", "HYBRID_RSA": "64221"}
GROUP_ALIASES = {
    "G1": "1", "MODP768": "1", "MODP 768": "1", "MODP-768": "1",
    "G2": "2", "MODP1024": "2", "MODP 1024": "2", "MODP-1024": "2",
    "G5": "5", "MODP1536": "5", "MODP 1536": "5", "MODP-1536": "5",
    "G14": "14", "MODP2048": "14", "MODP 2048": "14", "MODP-2048": "14",
    "G15": "15", "MODP3072": "15", "MODP 3072": "15", "MODP-3072": "15",
    "G16": "16", "MODP4096": "16", "MODP 4096": "16", "MODP-4096": "16",
}

def _normalize_token(tok: str, aliases: Dict[str, str]) -> Optional[str]:
    if not tok:
        return None
    raw = tok.strip()
    if not raw:
        return None
    if raw.replace("/", "").isdigit():
        return raw
    key = raw.upper().replace("-", "").replace(" ", "")
    for k, v in aliases.items():
        if key == k.upper().replace("-", "").replace(" ", ""):
            return v
    return None

def _parse_list_arg(raw: Optional[str], aliases: Dict[str, str]) -> List[str]:
    if not raw:
        return []
    vals = []
    for part in raw.split(","):
        norm = _normalize_token(part.strip(), aliases)
        if norm:
            vals.append(norm)
    return list(dict.fromkeys(vals))

# -------------------------- Scan primitives -----------------------------
BODY_MARKERS_V1 = [r"\bNotify message\b", r"\bVID=", r"\bSA=\(", r"\bAggressive Mode Handshake returned\b", r"\bMain Mode Handshake returned\b", r"\bHandshake returned\b"]
BODY_MARKERS_V2 = [r"\bIKE_SA_INIT\b", r"\bNotify message\b", r"\bSA=\(", r"\bHandshake returned\b"]

def _has_positive_summary(text: str) -> bool:
    m_notify = re.search(r"(\d+)\s+returned\s+notify", text, re.I)
    m_hs = re.search(r"(\d+)\s+returned\s+handshake", text, re.I)
    return (int(m_notify.group(1)) if m_notify else 0) > 0 or (int(m_hs.group(1)) if m_hs else 0) > 0

def _has_body_markers(text: str, markers: List[str]) -> bool:
    return any(re.search(p, text, re.I) for p in markers)

def _strip_banner(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.startswith("Starting ike-scan") and not ln.startswith("Ending ike-scan"))

def _parse_vids(handshake: str) -> List[str]:
    vids = []
    for m in re.finditer(r"VID=([a-fA-F0-9]+)\s+\(([^)]+)\)", handshake):
        desc = m.group(2).strip()
        if any(s in desc for s in ["draft-ietf", "IKE Fragmentation", "Dead Peer Detection", "XAUTH", "RFC 3947", "heartbeat"]):
            continue
        vids.append(desc)
    return vids

def _parse_sa_block(handshake: str) -> List[str]:
    blocks: List[str] = []
    marker = "SA=("
    search_from = 0
    while (start := handshake.find(marker, search_from)) != -1:
        content_start = start + len(marker)
        depth = 1
        for pos in range(content_start, len(handshake)):
            char = handshake[pos]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    blocks.append(handshake[content_start:pos])
                    search_from = pos + 1
                    break
        else:
            break
    return blocks

def _parse_psk_crack_record(output: str) -> Optional[Dict[str, str]]:
    """Parse ike-scan --pskcrack output and return HASH_R plus the full record."""
    match = re.search(
        r"IKE PSK parameters[^\n]*:\s*\n\s*([0-9a-f]+(?::[0-9a-f]+){8})",
        output,
        re.IGNORECASE,
    )
    if not match:
        return None
    parameters = match.group(1).lower()
    hash_r = parameters.rsplit(":", 1)[1]
    hash_bytes = len(hash_r) // 2
    hash_name = {16: "MD5", 20: "SHA1", 32: "SHA2-256"}.get(hash_bytes, f"unknown ({hash_bytes} bytes)")
    return {
        "hash_r": hash_r,
        "hash_algorithm": hash_name,
        "psk_crack_supported": hash_bytes in {16, 20},
        "parameters": parameters,
    }

NATT_VID_RE = re.compile(r"VID=[a-fA-F0-9]+\s+\(([^)]*(?:RFC\s*3947|nat-t-ike)[^)]*)\)", re.I)

def _parse_natt_vids(handshake: str) -> List[str]:
    """NAT-T VIDs (RFC 3947 / draft-ietf-ipsec-nat-t-ike-*) advertised by the peer."""
    return list(dict.fromkeys(m.group(1).strip() for m in NATT_VID_RE.finditer(handshake)))

# --------------------------- Scanning steps ------------------------------
def check_ikev1(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    logger.info(f"Discovering IKEv1 services for {ip}")
    cmd = ["ike-scan", ip]
    out, _, _ = run_command(cmd, timeout=10)
    if not out:
        return
    positive = _has_positive_summary(out) or _has_body_markers(out, BODY_MARKERS_V1)
    if positive:
        vpns[ip]["v1"] = True
        vpns[ip]["ikev1_raw_handshake"] = out.strip()
        natt_vids = _parse_natt_vids(out)
        if natt_vids:
            vpns[ip]["natt_vid"] = natt_vids
        vids = _parse_vids(_strip_banner(out))
        for v in vids:
            vpns[ip].setdefault("vid", []).append(v)

def check_ikev2(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    logger.info(f"Checking IKEv2 support for {ip}")
    out, _, _ = run_command(["ike-scan", "--ikev2", ip], timeout=10)
    if not out:
        return
    body = _strip_banner(out)
    positive = _has_positive_summary(out) or _has_body_markers(body, BODY_MARKERS_V2)
    if positive:
        vpns[ip]["v2"] = True
        vpns[ip]["ikev2_raw_handshake"] = out.strip()
        if "IKEv2 SA_INIT Handshake returned" in body:
            vpns[ip]["ikev2_transforms"] = _parse_sa_block(body)

def check_ikev1_aggressive(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """Discover an Aggressive-Mode-only IKEv1 peer, optionally using --id."""
    if vpns[ip].get("v1"):
        return
    identity = f" with --id '{VPN_ID}'" if VPN_ID else ""
    logger.info(f"Main Mode was silent for {ip} - trying IKEv1 Aggressive Mode{identity}")
    _, transforms_aggr = _transform_sets()
    total = len(transforms_aggr)
    for i, transform in enumerate(transforms_aggr, 1):
        progress = (i / total) * 100
        print(f"\r[{'█' * int(progress / 100 * 30):30}] {progress:.1f}% - Aggressive Mode Discovery Transform: {transform}", end="", flush=True)
        out = _try_transform(ip, transform, aggressive=True)
        if not out:
            continue
        if _has_positive_summary(out) or _has_body_markers(out, BODY_MARKERS_V1):
            print()
            vpns[ip]["v1"] = True
            vpns[ip]["ikev1_raw_handshake"] = out.strip()
            vids = _parse_vids(out)
            for vid in vids:
                if vid not in vpns[ip].setdefault("vid", []):
                    vpns[ip]["vid"].append(vid)
            return
    print()

def probe_natt_port(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """
    When scanning UDP 500 (no --nat-t), check whether the peer also answers on UDP 4500.
    Gateways that advertise NAT-T VIDs on 500 typically move to 4500 after NAT detection.
    """
    if NATT:
        return  # every call already runs on 4500
    logger.info(f"Probing NAT-T (UDP 4500) for {ip}")
    probe: Dict[str, Any] = {"v1": False, "v2": False}
    # run_command only injects EXTRA_IKESCAN_ARGS when NATT is set, so pass --nat-t explicitly
    out, _, _ = run_command(["ike-scan", "--nat-t", ip], timeout=10)
    if out and (_has_positive_summary(out) or _has_body_markers(out, BODY_MARKERS_V1)):
        probe["v1"] = True
        probe["ikev1_raw"] = out.strip()
    if vpns[ip].get("v2"):
        out2, _, _ = run_command(["ike-scan", "--nat-t", "--ikev2", ip], timeout=10)
        if out2 and (_has_positive_summary(out2) or _has_body_markers(_strip_banner(out2), BODY_MARKERS_V2)):
            probe["v2"] = True
            probe["ikev2_raw"] = out2.strip()
            if not vpns[ip].get("ikev2_transforms") and "IKEv2 SA_INIT Handshake returned" in out2:
                vpns[ip]["ikev2_transforms"] = _parse_sa_block(out2)
    vpns[ip]["natt_4500"] = probe

def discover_over_natt(vpns: Dict[str, Dict[str, Any]], ip: str) -> bool:
    """
    UDP 500 was silent: check whether the peer is a NAT-T-only responder on UDP 4500
    (typical when only 4500 is port-forwarded, or the gateway is NAT-T only).
    Returns True when IKE was discovered on 4500; the caller then continues the scan
    for this host over NAT-T.

    This is a transport fallback only. When UDP 500 answers (even with
    NO-PROPOSAL-CHOSEN) the transport works and a 4500 rescan would just repeat
    the same policy rejection - that case is reported, not re-probed.
    """
    if NATT:
        return False  # every call already runs on 4500
    logger.info(f"No IKE response on UDP 500 for {ip} - probing NAT-T (UDP 4500)")
    probe: Dict[str, Any] = {"v1": False, "v2": False}
    out, _, _ = run_command(["ike-scan", "--nat-t", ip], timeout=10)
    if out and (_has_positive_summary(out) or _has_body_markers(out, BODY_MARKERS_V1)):
        probe["v1"] = True
        probe["ikev1_raw"] = out.strip()
        vpns[ip]["v1"] = True
        vpns[ip]["ikev1_raw_handshake"] = out.strip()
    out2, _, _ = run_command(["ike-scan", "--nat-t", "--ikev2", ip], timeout=10)
    if out2 and (_has_positive_summary(out2) or _has_body_markers(_strip_banner(out2), BODY_MARKERS_V2)):
        probe["v2"] = True
        probe["ikev2_raw"] = out2.strip()
        vpns[ip]["v2"] = True
        vpns[ip]["ikev2_raw_handshake"] = out2.strip()
        if "IKEv2 SA_INIT Handshake returned" in out2:
            vpns[ip]["ikev2_transforms"] = _parse_sa_block(out2)
    vpns[ip]["natt_4500"] = probe
    if probe["v1"] or probe["v2"]:
        logger.info(f"IKE discovered on UDP 4500 (NAT-T) for {ip}")
        return True
    return False

# ------------------- Aggressive Mode group VPN ID hunt -------------------
# Compact PSK proposal space for the --idfile hunt, grouped per DH group so
# the aggressive-mode KE payload (--dhgroup) always matches the SA proposals.
HUNT_TRANSFORMS = [
    # DH group 2 (MODP-1024)
    "7/256,2,1,2", "7/256,4,1,2", "7/128,2,1,2", "7/128,4,1,2", "7/192,2,1,2",
    "5,2,1,2", "5,1,1,2", "1,2,1,2", "1,1,1,2", "7/128,1,1,2",
    # DH group 14 (MODP-2048)
    "7/256,2,1,14", "7/256,4,1,14", "7/128,2,1,14", "7/128,4,1,14",
    "7/192,2,1,14", "5,2,1,14", "1,2,1,14",
    # DH group 5 (MODP-1536)
    "7/256,2,1,5", "7/128,2,1,5", "5,2,1,5", "7/128,4,1,5",
    # DH group 16 (MODP-4096)
    "7/256,2,1,16", "7/128,2,1,16", "7/256,4,1,16",
]

def _aggressive_hunt_bundles(max_per_packet: int = 16) -> List[Tuple[str, List[str]]]:
    """Chunk HUNT_TRANSFORMS into (dhgroup, transforms) bundles for one-packet probes."""
    by_dh: Dict[str, List[str]] = {}
    for t in HUNT_TRANSFORMS:
        by_dh.setdefault(t.rsplit(",", 1)[1], []).append(t)
    bundles: List[Tuple[str, List[str]]] = []
    for dh, items in by_dh.items():
        for i in range(0, len(items), max_per_packet):
            bundles.append((dh, items[i:i + max_per_packet]))
    return bundles

def _load_id_wordlist(path: str) -> List[str]:
    """Load group VPN ID candidates: one per line, '#' starts a comment."""
    names: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                names.append(ln)
    return list(dict.fromkeys(names))

def _hunt_group_ids_once(vpns: Dict[str, Dict[str, Any]], ip: str, names: List[str]) -> Optional[Dict[str, Any]]:
    """
    Try every candidate group VPN ID in Aggressive Mode (bundled PSK proposals per DH group).
    Returns evidence on a handshake hit; records notify anomalies in vpns[ip].
    """
    bundles = _aggressive_hunt_bundles()
    anomalies: Dict[str, str] = {}
    silent = 0
    total = len(names)
    for i, name in enumerate(names, 1):
        progress = (i / total) * 100
        print(f"\r[{'█' * int(progress / 100 * 30):30}] {progress:.1f}% - Aggressive Mode Group ID: {name.ljust(24)}", end="", flush=True)
        for dh, bundle in bundles:
            cmd = ["ike-scan", "--aggressive", "--id", name, "--idtype", str(VPN_IDTYPE)]
            for t in bundle:
                cmd += ["--trans", t]
            cmd += ["--dhgroup", dh, "--timeout=500", "--retry=1", ip]
            out, _, _ = run_command(cmd, timeout=10)
            body = _strip_banner(out)
            if "Handshake returned" in body:
                print()
                sa_blocks = _parse_sa_block(body)
                return {"id": name, "raw": out.strip(), "sa": "; ".join(sa_blocks) if sa_blocks else "n/a"}
            if not body:
                silent += 1
            else:
                upper = body.upper()
                if "NO-PROPOSAL" not in upper and "NO_PROPOSAL" not in upper:
                    anomalies.setdefault(name, body.strip().splitlines()[0][:160])
            time.sleep(HUNT_PROBE_DELAY)
    print()
    if anomalies:
        vpns[ip]["vpn_id_anomalies"] = anomalies
        for name, snip in list(anomalies.items())[:5]:
            logger.info(f"Group ID '{name}' produced a different notify: {snip}")
    if silent:
        vpns[ip]["vpn_id_silent_probes"] = silent
    return None

def hunt_group_id(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """
    Brute force group VPN IDs from --idfile in Aggressive Mode. Some gateways only
    negotiate after seeing a known group name and answer NO-PROPOSAL-CHOSEN otherwise.
    On a hit the ID is adopted (per host) for all further aggressive-mode probes.
    """
    try:
        names = _load_id_wordlist(IDFILE)
    except OSError as e:
        logger.error(f"Cannot read --idfile: {e}")
        return
    if not names:
        logger.warning(f"--idfile {IDFILE} contains no group VPN ID candidates")
        return
    logger.info(f"Brute-forcing {len(names)} group VPN IDs (Aggressive Mode, idtype {VPN_IDTYPE}) for {ip}")
    hit = _hunt_group_ids_once(vpns, ip, names)
    if hit:
        vpns[ip]["v1"] = True
        vpns[ip]["vpn_id_discovered"] = hit["id"]
        vpns[ip]["vpn_id_evidence"] = hit["raw"]
        vpns[ip]["vpn_id_sa"] = hit["sa"]
        DISCOVERED_IDS[ip] = hit["id"]
        logger.info(f"Group VPN ID found for {ip}: '{hit['id']}' (accepted SA: {hit['sa']})")
    else:
        logger.info(f"No group VPN ID from {IDFILE} was accepted by {ip}")

def fingerprint_backoff(vpns: Dict[str, Dict[str, Any]], ip: str, transform: Optional[str] = None, timeout: int = 300) -> None:
    logger.info(f"Fingerprinting {ip} via backoff analysis{' with transform ' + transform if transform else ''}")
    cmd = ["ike-scan", "--showbackoff"]
    if transform:
        cmd += ["--trans", transform.replace(" ", "")]
    cmd.append(ip)
    out, err, rc = run_command(cmd, timeout=timeout)
    guess = None
    pattern = None
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("Starting ike-scan") or ln.startswith("Ending ike-scan"):
            continue
        if "Implementation guess:" in ln:
            cand = ln.split("Implementation guess:", 1)[1].strip()
            if cand and cand.lower() != "unknown":
                guess = cand
        elif ln.startswith("Backoff pattern:"):
            raw = ln.split("Backoff pattern:", 1)[1].strip()
            pattern = [p.strip() for p in raw.split(",") if p.strip()]
    vpns.setdefault(ip, {})
    vpns[ip]["showbackoff"] = guess if guess else "N/A"
    if pattern:
        vpns[ip]["backoff_pattern"] = pattern
    if guess and guess != "N/A":
        logger.info(f"Backoff fingerprint for {ip}: {guess}")
    else:
        logger.info(f"No definitive backoff fingerprint for {ip}")

# DH groups ike-scan can express for the aggressive-mode KE payload size (--dhgroup, MODP only)
IKE_DHGROUP_SUPPORTED = {1, 2, 5, 14, 15, 16, 17, 18}

def _try_transform(ip: str, transform: str, aggressive: bool = False, capture_psk: bool = False) -> str:
    base = ["ike-scan"]
    if aggressive:
        base += ["--aggressive"]
        # Some gateways (Cisco ASA, SonicWall, FortiGate, WatchGuard, ...) only
        # negotiate after seeing a known group VPN ID; without it they reply
        # NO-PROPOSAL-CHOSEN (or stay silent) for every proposal.
        eff_id = VPN_ID or DISCOVERED_IDS.get(ip)
        if eff_id:
            base += ["--id", eff_id, "--idtype", str(VPN_IDTYPE)]
        else:
            base += ["--id", DEFAULT_AGGRESSIVE_ID, "--idtype", str(DEFAULT_AGGRESSIVE_IDTYPE)]
    base += ["--trans", transform]
    if aggressive:
        # ike-scan sizes the aggressive-mode KE payload from --dhgroup (default 2),
        # NOT from --trans. Keep them in sync so the peer does not reject on a
        # KE/group mismatch. ECP groups (19/20/21) cannot be expressed with
        # --dhgroup (ike-scan limitation, MODP only).
        parts = [p.strip() for p in transform.split(",")]
        if len(parts) == 4 and parts[3].isdigit() and int(parts[3]) in IKE_DHGROUP_SUPPORTED:
            base += ["--dhgroup", parts[3]]
        if capture_psk:
            # Emits HASH_R and the complete nine-field record required by psk-crack.
            base += ["--pskcrack"]
    base.append(ip)
    out, _, _ = run_command(base, timeout=10)
    return _strip_banner(out)

def _transform_sets() -> Tuple[List[str], List[str]]:
    """
    Decide which transform sets to try for Main Mode and Aggressive Mode.

    Behavior:
    - If --fullalgs is set:
        * Build full cartesian product from ENC_FULL, HASH_FULL, AUTH_FULL, GROUP_FULL
          for BOTH Main Mode and Aggressive Mode.
          (This is now truly exhaustive.)
    - Else (no --fullalgs):
        * Use curated baseline MAIN_MODE_TRANSFORMS / AGGRESSIVE_MODE_TRANSFORMS.
        * If custom alg lists were provided, merge them in (or replace if --onlycustom).
    """

    any_custom = bool(CUSTOM_ENC or CUSTOM_HASH or CUSTOM_AUTH or CUSTOM_GROUP)

    # 1. If FULLALGS: brute-force every combo from *_FULL
    if FULLALGS:
        # If the user ALSO provided custom lists and --onlycustom,
        # honor --onlycustom exactly.
        if ONLYCUSTOM and any_custom:
            encs = CUSTOM_ENC or ENC_FULL
            hashes = CUSTOM_HASH or HASH_FULL
            auths = CUSTOM_AUTH or AUTH_FULL
            groups = CUSTOM_GROUP or GROUP_FULL
        else:
            # FULL means: ignore curated lists and just take the global full sets,
            # unless user explicitly restricted some dimensions via --enc/--hash/...
            encs = CUSTOM_ENC or ENC_FULL
            hashes = CUSTOM_HASH or HASH_FULL
            auths = CUSTOM_AUTH or AUTH_FULL
            groups = CUSTOM_GROUP or GROUP_FULL

        # Build exhaustive combinations for Main Mode
        main_all = _build_transform_space(encs, hashes, auths, groups)

        # Build exhaustive combinations for Aggressive Mode
        # Historically you'd bias Aggressive to PSK only,
        # but "all possible transforms" means we include all auths here too.
        aggr_all = _build_transform_space(encs, hashes, auths, groups)

        # Deduplicate while preserving order
        main_all = list(dict.fromkeys(main_all))
        aggr_all = list(dict.fromkeys(aggr_all))

        return (main_all, aggr_all)

    # 2. If we're NOT in FULLALGS:
    #    use curated sets, then possibly merge/override with custom.
    if any_custom:
        # Build custom cartesian products (or restricted cartesian products)
        encs = CUSTOM_ENC or ENC_FULL
        hashes = CUSTOM_HASH or HASH_FULL
        auths = CUSTOM_AUTH or AUTH_FULL
        groups = CUSTOM_GROUP or GROUP_FULL

        custom_main = _build_transform_space(encs, hashes, auths, groups)

        # Aggressive mode normally PSK-focused unless caller asked for other auths.
        aggr_auths = CUSTOM_AUTH or ["1"]  # "1" = PSK
        custom_aggr = _build_transform_space(encs, hashes, aggr_auths, groups)

        if ONLYCUSTOM:
            # Only custom transforms
            return (
                list(dict.fromkeys(custom_main)),
                list(dict.fromkeys(custom_aggr)),
            )

        # Merge curated + custom
        base_main = list(MAIN_MODE_TRANSFORMS)
        base_aggr = list(AGGRESSIVE_MODE_TRANSFORMS)

        base_main = list(dict.fromkeys(base_main + custom_main))
        base_aggr = list(dict.fromkeys(base_aggr + custom_aggr))
        return (base_main, base_aggr)

    # 3. Default, no fullalgs, no custom:
    return (list(MAIN_MODE_TRANSFORMS), list(AGGRESSIVE_MODE_TRANSFORMS))

def test_transforms(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    if not vpns[ip].get("v1"):
        # ike-scan 1.9.x supports only its fixed default IKEv2 proposal;
        # --trans enumerates IKEv1 Main Mode proposals only.
        return
    logger.info(f"Testing encryption algorithms for {ip}")
    transforms_main, _ = _transform_sets()
    accepted_sa, accepted_keys = [], []
    total = len(transforms_main)
    for i, t in enumerate(transforms_main, 1):
        progress = (i / total) * 100
        print(f"\r[{'█' * int(progress/100*30):30}] {progress:.1f}% - Main Mode Transform: {t}", end="", flush=True)
        out = _try_transform(ip, t, aggressive=False)
        if "Handshake returned" in out:
            for sa in _parse_sa_block(out):
                accepted_sa.append(sa)
                accepted_keys.append(t)
            vids = _parse_vids(out)
            if vids:
                vpns[ip].setdefault("vid", [])
                for v in vids:
                    if v not in vpns[ip]["vid"]:
                        vpns[ip]["vid"].append(v)
    print()
    vpns[ip]["transforms"] = list(dict.fromkeys(accepted_sa))
    vpns[ip]["accepted_transform_keys_main"] = list(dict.fromkeys(accepted_keys))

def test_aggressive_mode(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    if not vpns[ip].get("v1"):
        vpns[ip]["aggressive"] = []
        vpns[ip]["accepted_transform_keys_aggr"] = []
        return
    logger.info(f"Testing Aggressive Mode for {ip}")
    _, transforms_aggr = _transform_sets()
    accepted_sa, accepted_keys, psk_records = [], [], []
    total = len(transforms_aggr)
    for i, t in enumerate(transforms_aggr, 1):
        progress = (i / total) * 100
        print(f"\r[{'█' * int(progress/100*30):30}] {progress:.1f}% - Aggressive Mode Transform: {t}", end="", flush=True)
        out = _try_transform(ip, t, aggressive=True, capture_psk=True)
        if "Handshake returned" in out:
            sa_blocks = _parse_sa_block(out)
            for sa in sa_blocks:
                accepted_sa.append(sa)
                accepted_keys.append(t)
            psk_record = _parse_psk_crack_record(out)
            if psk_record:
                psk_record["transform"] = "; ".join(sa_blocks) if sa_blocks else t
                psk_records.append(psk_record)
            vids = _parse_vids(out)
            if vids:
                vpns[ip].setdefault("vid", [])
                for v in vids:
                    if v not in vpns[ip]["vid"]:
                        vpns[ip]["vid"].append(v)
    print()
    vpns[ip]["aggressive"] = list(dict.fromkeys(accepted_sa))
    vpns[ip]["accepted_transform_keys_aggr"] = list(dict.fromkeys(accepted_keys))
    vpns[ip]["aggressive_psk"] = psk_records

def test_ikev2_features(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    if not vpns[ip].get("v2"):
        return
    out, _, _ = run_command(["ike-scan", "--ikev2", "--certreq", ip], timeout=5)
    if out:
        vpns[ip]["ikev2_certreq"] = True

# --------------------------- Analysis / Reports --------------------------
_TRANS_ENC = {"1": "DES", "5": "3DES", "7/128": "AES-128", "7/192": "AES-192", "7/256": "AES-256"}
_TRANS_HASH = {"1": "MD5", "2": "SHA1", "4": "SHA256", "5": "SHA384", "6": "SHA512"}
_TRANS_AUTH = {"1": "PSK", "3": "RSA_SIG", "64221": "HYBRID_RSA"}
_TRANS_DH   = {"1": "DH Group 1 (MODP-768)", "2": "DH Group 2 (MODP-1024)", "5": "DH Group 5 (MODP-1536)",
              "14": "DH Group 14 (MODP-2048)", "15": "DH Group 15 (MODP-3072)", "16": "DH Group 16 (MODP-4096)"}

def _decode_transform_key(key: str) -> List[str]:
    parts = [p.strip() for p in key.split(",")]
    if len(parts) != 4:
        return []
    enc, hsh, auth, dh = parts
    weak = []
    if enc in _TRANS_ENC and _TRANS_ENC[enc] in {"DES", "3DES"}:
        weak.append(_TRANS_ENC[enc])
    if hsh in _TRANS_HASH and _TRANS_HASH[hsh] in {"MD5", "SHA1"}:
        weak.append(_TRANS_HASH[hsh])
    if auth == "1":
        weak.append("PSK")
    if dh in {"1", "2", "5"}:
        weak.append(_TRANS_DH[dh])
    return weak

def analyze_security_flaws(vpns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    logger.info("Analyzing security flaws")
    results = {"services": {}, "summary": {}}

    for ip, data in vpns.items():
        impls = _implementation_sources(data)
        results["services"][ip] = {
            "flaws": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "good": 0},
            "accepted_transforms": {"main": [], "aggressive": [], "ikev2": []},
            "aggressive_psk": [],
            "weak_algorithms": [],
            "proof": {},  # <-- NEW: Proof section
            "meta": {
                "versions": [v for v, k in (("IKEv1", data.get("v1")), ("IKEv2", data.get("v2"))) if k],
                "implementation": impls["primary"],
                "implementation_backoff": impls["backoff"],
                "implementation_vid": impls["vid"],
            },
        }

        # === Add IKEv1 proof ===
        if data.get("ikev1_raw_handshake"):
            results["services"][ip]["proof"]["ikev1_discovery"] = data["ikev1_raw_handshake"]

        # === Add IKEv2 proof ===
        if data.get("ikev2_raw_handshake"):
            results["services"][ip]["proof"]["ikev2_discovery"] = data["ikev2_raw_handshake"]

        # === Add NAT-T (UDP 4500) proof ===
        natt_probe = data.get("natt_4500") or {}
        if natt_probe.get("ikev1_raw"):
            results["services"][ip]["proof"]["natt_4500_ikev1"] = natt_probe["ikev1_raw"]
        if natt_probe.get("ikev2_raw"):
            results["services"][ip]["proof"]["natt_4500_ikev2"] = natt_probe["ikev2_raw"]
        if data.get("vpn_id_evidence"):
            results["services"][ip]["proof"]["group_id_evidence"] = data["vpn_id_evidence"]
        results["services"][ip]["meta"]["natt"] = {
            "vid_advertised": data.get("natt_vid", []),
            "responds_on_4500": bool(natt_probe.get("v1") or natt_probe.get("v2")),
            "transforms_tested_on_4500": bool(data.get("natt_only")) or NATT,
        }
        results["services"][ip]["meta"]["vpn_id"] = data.get("vpn_id_discovered")

        added = set()

        def add_finding(desc: str, sev: str, payload: str = "") -> None:
            if (ip, desc) in added:
                return
            results["services"][ip]["flaws"].append({"description": desc, "severity": sev, "data": payload})
            results["services"][ip]["severity_counts"][sev] += 1
            added.add((ip, desc))

        if data.get("v1") or data.get("v2"):
            add_finding(FLAWS["DISC"], "info")
        if data.get("v1"):
            add_finding(FLAWS["IKEV1"], "high")
        if data.get("aggressive"):
            add_finding(FLAWS["AGG_MODE"], "critical")
        if data.get("v2"):
            add_finding(FLAWS["IKEV2"], "good")
        if data.get("natt_vid") and not NATT:
            add_finding(FLAWS["NATT_VID"], "info", "; ".join(data["natt_vid"]))
        if data.get("natt_only"):
            add_finding(FLAWS["NATT_ONLY"], "info")
        elif natt_probe.get("v1") or natt_probe.get("v2"):
            add_finding(FLAWS["NATT_4500"], "info")
        got_transforms = bool(
            data.get("accepted_transform_keys_main")
            or data.get("accepted_transform_keys_aggr")
            or data.get("transforms")
            or data.get("aggressive")
        )
        # The transform enumerator is IKEv1-only. An empty transform list for an
        # IKEv2-only peer is expected and does not mean its proposal was rejected.
        if data.get("v1") and not got_transforms:
            add_finding(FLAWS["NO_PROPOSAL"], "info")
        if data.get("vpn_id_discovered"):
            add_finding(f"{FLAWS['VPN_ID_FOUND']}: '{data['vpn_id_discovered']}'", "medium")

        all_keys = data.get("accepted_transform_keys_main", []) + data.get("accepted_transform_keys_aggr", [])
        decoded_weak = set()
        for key in all_keys:
            decoded_weak.update(_decode_transform_key(key))
        if any(re.search(r"\bEncr=AES_CBC\b", sa, re.I) for sa in data.get("ikev2_transforms", [])):
            decoded_weak.add("AES-CBC (non-AEAD)")

        if "DES" in decoded_weak:
            add_finding(FLAWS["ENC_DES"], "high")
        if "3DES" in decoded_weak:
            add_finding(FLAWS["ENC_3DES"], "medium")
        if "AES-CBC (non-AEAD)" in decoded_weak:
            add_finding(FLAWS["ENC_AES_CBC"], "medium")
        if "MD5" in decoded_weak:
            add_finding(FLAWS["HASH_MD5"], "high")
        if "SHA1" in decoded_weak:
            add_finding(FLAWS["HASH_SHA1"], "high")
        if "DH Group 1 (MODP-768)" in decoded_weak:
            add_finding(FLAWS["DHG_1"], "high")
        if "DH Group 2 (MODP-1024)" in decoded_weak:
            add_finding(FLAWS["DHG_2"], "high")
        if "DH Group 5 (MODP-1536)" in decoded_weak:
            add_finding(FLAWS["DHG_5"], "high")
        if "PSK" in decoded_weak:
            add_finding(FLAWS["AUTH_PSK"], "medium")

        for vid in data.get("vid", []):
            add_finding(f"{FLAWS['FING_VID']}: {vid}", "low")
        
        if impls["backoff"]:
            add_finding(f"{FLAWS['FING_BACKOFF']}: {impls['backoff']}", "low")

        results["services"][ip]["accepted_transforms"]["main"] = list(dict.fromkeys(data.get("transforms", [])))
        results["services"][ip]["accepted_transforms"]["aggressive"] = list(dict.fromkeys(data.get("aggressive", [])))
        results["services"][ip]["accepted_transforms"]["ikev2"] = list(dict.fromkeys(data.get("ikev2_transforms", [])))
        results["services"][ip]["aggressive_psk"] = data.get("aggressive_psk", [])
        results["services"][ip]["weak_algorithms"] = sorted(decoded_weak)

    summary = {"total_hosts": len(vpns), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "good":0}
    for svc in results["services"].values():
        for sev, c in svc["severity_counts"].items():
            summary[sev] += c
    results["summary"] = summary
    return results

# ------------------------------ HTML report -----------------------------
def _sev_badge(sev: str) -> str:
    sev = sev.lower()
    if sev == "critical": return '<span class="badge bg-critical">CRITICAL</span>'
    if sev == "high": return '<span class="badge bg-danger">HIGH</span>'
    if sev == "medium": return '<span class="badge bg-warning text-dark">MEDIUM</span>'
    if sev == "low": return '<span class="badge bg-info text-dark">LOW</span>'
    if sev == "info": return '<span class="badge bg-secondary text-dark">INFO</span>'
    if sev == "good": return '<span class="badge bg-success">GOOD</span>'

def _sev_pill(sev: str, count: int) -> str:
    sev = sev.lower()
    if sev == "critical": return f'<span class="badge rounded-pill text-bg-critical">CRITICAL {count}</span>'
    if sev == "high": return f'<span class="badge rounded-pill text-bg-danger">HIGH {count}</span>'
    if sev == "medium": return f'<span class="badge rounded-pill text-bg-warning text-dark">MEDIUM {count}</span>'
    if sev == "low": return f'<span class="badge rounded-pill text-bg-info text-dark">LOW {count}</span>'
    if sev == "info": return f'<span class="badge rounded-pill text-bg-secondary text-dark">INFO {count}</span>'
    if sev == "good": return f'<span class="badge rounded-pill text-bg-success">GOOD {count}</span>'

_WEAK_TRANSFORM_COMPONENT_RE = re.compile(
    r"\b(?:Enc|Encr)=(?:3DES|DES|AES_CBC)\b"
    r"|\b(?:Hash|Prf|Integ)=(?:MD5|SHA1|HMAC_MD5(?:_\d+)?|HMAC_SHA1(?:_\d+)?)\b"
    r"|\bAuth=PSK\b"
    r"|\b(?:Group|DH_Group)=(?:1|2|5)(?::[A-Za-z0-9_-]+)?\b",
    re.IGNORECASE,
)

def _format_transform_html(sa: str) -> str:
    """Escape an SA description and emphasize weak/deprecated components."""
    escaped = html_lib.escape(str(sa))
    return _WEAK_TRANSFORM_COMPONENT_RE.sub(
        lambda match: (
            "<span class='text-danger fw-bold' title='Weak or deprecated'>"
            f"{match.group(0)}</span>"
        ),
        escaped,
    )

def generate_html_report(results: Dict, filename: str):
    total = results["summary"]["total_hosts"]
    crit = results["summary"]["critical"]
    high = results["summary"]["high"]
    med = results["summary"]["medium"]
    low = results["summary"]["low"]
    info = results["summary"]["info"]
    good = results["summary"]["good"]

    confirmed_only = results.get("scan_info", {}).get("confirmed_only", False)

    scope_badge = '<span class="badge text-bg-primary">Scope: --onlycustom</span>' if confirmed_only \
                  else '<span class="badge text-bg-light">Scope: default</span>'
    if results.get("scan_info", {}).get("nat_t", False):
        scope_badge += ' <span class="badge text-bg-warning">Transport: NAT-T (UDP 4500)</span>'
    else:
        scope_badge += ' <span class="badge text-bg-light">Transport: UDP 500</span>'
    vpn_id = results.get("scan_info", {}).get("vpn_id")
    if vpn_id:
        scope_badge += f' <span class="badge text-bg-dark">Aggr. Group ID: {vpn_id}</span>'

    host_cards = []

    for idx, (ip, svc) in enumerate(results["services"].items()):
        versions = ", ".join(svc["meta"]["versions"]) if svc["meta"]["versions"] else "None"
        impl_backoff = svc["meta"].get("implementation_backoff")
        impl_vid = svc["meta"].get("implementation_vid")

        impl_parts = []
        if impl_backoff:
            impl_parts.append(f"{impl_backoff} <span class='badge text-bg-secondary ms-1'>backoff</span>")
        if impl_vid:
            impl_parts.append(f"{impl_vid} <span class='badge text-bg-secondary ms-1'>VID</span>")

        impl_display = " / ".join(impl_parts) if impl_parts else "N/A"

        main_rows = "".join(
            f"<li><code class='text-wrap'>{_format_transform_html(sa)}</code></li>"
            for sa in svc["accepted_transforms"]["main"]
        ) or "<li><span class='text-muted'>None</span></li>"
        aggr_rows = "".join(
            f"<li><code class='text-wrap'>{_format_transform_html(sa)}</code></li>"
            for sa in svc["accepted_transforms"]["aggressive"]
        ) or "<li><span class='text-muted'>None</span></li>"
        ikev2_rows = "".join(
            f"<li><code class='text-wrap'>{_format_transform_html(sa)}</code></li>"
            for sa in svc["accepted_transforms"].get("ikev2", [])
        ) or "<li><span class='text-muted'>No selected suite decoded</span></li>"
        psk_hash_row_parts = []
        for record_idx, record in enumerate(svc.get("aggressive_psk", [])):
            record_id = f"psk-{idx}-{record_idx}"
            hash_r = html_lib.escape(record["hash_r"])
            transform = html_lib.escape(record["transform"])
            parameters = html_lib.escape(record["parameters"])
            compatibility = (
                "Compatible with ike-scan psk-crack"
                if record.get("psk_crack_supported")
                else f"ike-scan psk-crack does not support {html_lib.escape(record.get('hash_algorithm', 'this hash'))}"
            )
            psk_hash_row_parts.append(
                "<li class='mb-3'>"
                f"<div><strong>HASH_R:</strong> <code class='text-danger text-break'>{hash_r}</code></div>"
                f"<div class='small text-muted text-break'>{transform}</div>"
                f"<div class='small text-muted'>{compatibility}</div>"
                "<details class='mt-2'><summary class='small'>Full psk-crack record</summary>"
                f"<pre id='{record_id}' class='json-pre mt-2 mb-2'><code>{parameters}</code></pre>"
                f"<button class='btn btn-outline-secondary btn-sm' type='button' onclick=\"copyTextFrom('{record_id}')\">Copy psk-crack record</button>"
                "</details></li>"
            )
        psk_hash_rows = "".join(psk_hash_row_parts) or "<li><span class='text-muted'>No PSK hash captured</span></li>"
        ikev2_transform_note = ""
        if "IKEv2" in svc["meta"]["versions"]:
            if svc["accepted_transforms"].get("ikev2"):
                ikev2_transform_note = (
                    "<div class='alert alert-secondary py-2 mb-3' role='note'>"
                    "<strong>IKEv2 result:</strong> the suite below was selected by the peer "
                    "from the discovery proposal. It is confirmed, but is not an exhaustive "
                    "enumeration of every suite the peer may accept."
                    "</div>"
                )
            else:
                ikev2_transform_note = (
                    "<div class='alert alert-secondary py-2 mb-3' role='note'>"
                    "<strong>IKEv2 result:</strong> the peer responded, but no selected suite "
                    "was decoded. Stock ike-scan 1.9.x cannot customize IKEv2 transforms."
                    "</div>"
                )

        weak_list = "".join(f"<li>{w}</li>" for w in svc["weak_algorithms"]) or "<li><span class='text-muted'>None detected</span></li>"

        findings_list = []
        order = ["critical", "high", "medium", "low", "info", "good"]
        for sev in order:
            for f in svc["flaws"]:
                if f["severity"] == sev:
                    findings_list.append(
                        f"<li class='mb-2'>{_sev_badge(sev)} "
                        f"{f['description']}</li>"
                    )
        findings_html = "".join(findings_list) or "<li class='text-muted'>No findings.</li>"

        host_json_obj = {
            "flaws": svc["flaws"],
            "severity_counts": svc["severity_counts"],
            "accepted_transforms": svc["accepted_transforms"],
            "aggressive_psk": svc.get("aggressive_psk", []),
            "weak_algorithms": svc["weak_algorithms"],
            "proof": svc.get("proof", {}),        # ADD THIS LINE
            "meta": svc["meta"],
        }

        host_json = json.dumps(host_json_obj, indent=2)

        host_cards.append(f"""
      <div class="accordion-item mb-2">
        <h2 class="accordion-header" id="heading-{ip.replace('.', '-')}-{idx}">
          <button class="accordion-button collapsed" type="button"
                  data-bs-toggle="collapse"
                  data-bs-target="#collapse-{ip.replace('.', '-')}-{idx}"
                  aria-expanded="false"
                  aria-controls="collapse-{ip.replace('.', '-')}-{idx}">
            <div class="d-flex w-100 justify-content-between align-items-center">
              <span class="me-3 fw-semibold">{ip}</span>
              <span class="text-muted">Supported: {versions} &nbsp;•&nbsp; Implementation: {impl_display}</span>
            </div>
          </button>
        </h2>
        <div id="collapse-{ip.replace('.', '-')}-{idx}" class="accordion-collapse collapse"
             aria-labelledby="heading-{ip.replace('.', '-')}-{idx}" data-bs-parent="#hostsAccordion">
          <div class="accordion-body">

            <div class="d-flex flex-wrap align-items-center mb-3">
              {_sev_pill('critical', svc['severity_counts']['critical'])}
              <span class="ms-2">{_sev_pill('high', svc['severity_counts']['high'])}</span>
              <span class="ms-2">{_sev_pill('medium', svc['severity_counts']['medium'])}</span>
              <span class="ms-2">{_sev_pill('low', svc['severity_counts']['low'])}</span>
              <span class="ms-2">{_sev_pill('info', svc['severity_counts']['info'])}</span>
              <span class="ms-2">{_sev_pill('good', svc['severity_counts']['good'])}</span>
            </div>

            <div class="row g-3">
              <div class="col-12 col-xl-6">
                <div class="card p-3 h-100">
                  <h5 class="mb-3">Accepted transforms</h5>
                                    {ikev2_transform_note}
                  <div class="table-responsive">
                    <table class="table table-sm table-striped align-middle">
                      <thead>
                                                <tr><th style="width:180px">Protocol / Mode</th><th>SA Transforms</th></tr>
                      </thead>
                      <tbody>
                        <tr>
                                                    <td class="fw-semibold">IKEv1 Main Mode</td>
                          <td><ul class="mb-0">{main_rows}</ul></td>
                        </tr>
                        <tr>
                                                    <td class="fw-semibold">IKEv1 Aggressive Mode</td>
                          <td><ul class="mb-0">{aggr_rows}</ul></td>
                        </tr>
                                                <tr>
                                                    <td class="fw-semibold">IKEv2 IKE_SA_INIT</td>
                                                    <td><ul class="mb-0">{ikev2_rows}</ul></td>
                                                </tr>
                      </tbody>
                    </table>
                  </div>
                                    <h6 class="mt-3 mb-2">Aggressive Mode PSK HASH_R</h6>
                                    <ul class="mb-0">{psk_hash_rows}</ul>
                                      <p class="small text-muted mt-2 mb-0">HASH_R alone is not valid psk-crack input. Its data file requires the complete nine-field record. Legacy psk-crack supports MD5 and SHA1, but not SHA2-256.</p>
                </div>
              </div>

              <div class="col-12 col-xl-6">
                <div class="card p-3 h-100">
                  <h5 class="mb-3">Weak / Deprecated algorithms</h5>
                  <ul class="mb-3">{weak_list}</ul>
                  <h5 class="mb-2">Findings</h5>
                  <ul class="mb-3">{findings_html}</ul>

                  <div class="d-flex gap-2">
                    <button class="btn btn-outline-secondary btn-sm" type="button" data-bs-toggle="collapse" data-bs-target="#json-{ip.replace('.', '-')}-{idx}">Show JSON</button>
                    <button class="btn btn-outline-secondary btn-sm" type="button" onclick="copyTextFrom('json-{ip.replace('.', '-')}-{idx}-pre')">Copy JSON</button>
                  </div>
                  <div class="collapse mt-2" id="json-{ip.replace('.', '-')}-{idx}">
                    <pre id="json-{ip.replace('.', '-')}-{idx}-pre" class="json-pre"><code>{host_json}</code></pre>
                  </div>

                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
        """)

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="color-scheme" content="light dark">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IKESS Report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  /* Darker red for CRITICAL badges (f-string safe with doubled braces) */
    :root {{
      --bs-critical: #8B0000;
      --bs-critical-rgb: 139, 0, 0;
    }}

    .badge.bg-critical,
    .badge.text-bg-critical {{
      background-color: var(--bs-critical) !important;
      border-color: var(--bs-critical) !important;
      color: #fff !important;
    }}
  body {{ background:#ffffff; color:#0c1116; }}
  .container-fluid {{ padding: 24px; }}
  .card {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; }}
  .json-pre {{ max-height: 420px; overflow:auto; }}
  code.text-wrap {{ white-space: normal; word-break: break-word; }}
  .accordion-button:not(.collapsed) {{ background:#f1f5f9; }}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bs-critical: #8B0000;
    --bs-critical-rgb: 139, 0, 0;
  }}
  .badge.bg-critical,
  .badge.text-bg-critical {{
    background-color: var(--bs-critical) !important;
    border-color: var(--bs-critical) !important;
  }}
  :root {{
    --surface-0: #0f172a;
    --surface-1: #111827;
    --surface-2: #0b1220;
    --border-1:  #334155;
    --text-1:    #f1f5f9;
    --text-2:    #cbd5e1;
  }}
  body {{ background: var(--surface-0); color: var(--text-1); }}
  .container-fluid {{ color: inherit; }}
  h1, h2, h3, h4, h5, h6 {{ color: var(--text-1); }}
  .text-muted {{ color: var(--text-2) !important; }}
  ul, li {{ color: var(--text-1); }}
  .card {{
    background: var(--surface-1);
    border-color: var(--border-1);
    box-shadow: 0 1px 0 rgba(0,0,0,.25);
  }}
  .accordion-item {{ background: transparent; border-color: var(--border-1); }}
  .accordion-button {{
    background: var(--surface-0);
    color: var(--text-1);
  }}
  .accordion-button:not(.collapsed) {{
    background: var(--surface-1);
    color: var(--text-1);
    border-bottom: 1px solid var(--border-1);
  }}
  .accordion-button:focus {{
    box-shadow: 0 0 0 .25rem rgba(99,102,241,.35);
  }}
  .table {{
    color: var(--text-1);
    --bs-table-bg: transparent;
    --bs-table-striped-bg: rgba(255,255,255,.04);
    --bs-table-striped-color: var(--text-1);
  }}
  .table thead th {{
    color: #f8fafc;
    background: var(--surface-2);
    border-bottom-color: var(--border-1);
  }}
  .table tbody td {{ border-color: var(--border-1); color: white; }}
  .badge.text-bg-secondary,
  .badge.text-bg-primary,
  .badge.text-bg-danger {{ color: #ffffff !important; }}
  .badge.text-bg-warning,
  .badge.text-bg-info {{ color: #0f172a !important; }}
  .json-pre {{
    background: var(--surface-2);
    border: 1px solid var(--border-1);
  }}
  pre, code {{ color: #f8fafc; }}
  .btn-outline-secondary {{
    color: var(--text-1);
    border-color: #475569;
  }}
  .btn-outline-secondary:hover {{
    background: #1f2937;
    border-color: #64748b;
    color: #ffffff;
  }}
  a {{ color: #93c5fd; }}
  a:hover, a:focus {{ color: #bfdbfe; }}
}}
</style>
</head>
<body>
  <div class="container-fluid">
    <div class="d-flex flex-wrap align-items-center justify-content-between mb-3">
      <h1 class="h3 mb-0">IKE Security Scanner Report</h1>
      <div class="d-flex gap-2 flex-wrap">
        <span class="badge text-bg-light">Total hosts: {total}</span>
        <span class="badge text-bg-critical">CRITICAL {crit}</span>
        <span class="badge text-bg-danger">HIGH {high}</span>
        <span class="badge text-bg-warning text-dark">MEDIUM {med}</span>
        <span class="badge text-bg-info text-dark">LOW {low}</span>
        <span class="badge text-bg-secondary text-dark">INFO {info}</span>
        <span class="badge text-bg-success">GOOD {good}</span>
        {scope_badge}
      </div>
    </div>

    <div class="accordion" id="hostsAccordion">
      {''.join(host_cards)}
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    function copyTextFrom(preId) {{
      const el = document.getElementById(preId);
      if (!el) return;
      const text = el.innerText || el.textContent || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
      }} else {{
        fallbackCopy(text);
      }}
    }}
    function fallbackCopy(text) {{
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try {{ document.execCommand('copy'); }} catch(e) {{}}
      document.body.removeChild(ta);
    }}
  </script>
</body>
</html>
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

# --------------------------------------------------------------
# 1. generate_xml_report  (unchanged – proof is already in JSON)
# --------------------------------------------------------------
def generate_xml_report(results: Dict[str, Any], filename: str) -> None:
    root = ET.Element("iker_scan")

    # ---- scan info ------------------------------------------------
    scan_info = results.get("scan_info", {})
    scan_info_el = ET.SubElement(root, "scan_info")
    for k, v in scan_info.items():
        child = ET.SubElement(scan_info_el, k)
        if isinstance(v, (list, tuple, set)):
            child.text = ", ".join(map(str, v))
        elif v is None:
            child.text = ""
        else:
            child.text = str(v)

    # ---- summary --------------------------------------------------
    summary = ET.SubElement(root, "summary")
    for k, v in results["summary"].items():
        ET.SubElement(summary, k).text = str(v)

    # ---- services -------------------------------------------------
    services = ET.SubElement(root, "services")
    for ip, svc in results["services"].items():
        s = ET.SubElement(services, "service", ip=str(ip))

        # meta
        meta = ET.SubElement(s, "meta")
        ET.SubElement(meta, "versions").text = ", ".join(svc["meta"].get("versions", []))
        ET.SubElement(meta, "implementation").text = str(svc["meta"].get("implementation") or "N/A")
        ET.SubElement(meta, "implementation_backoff").text = str(svc["meta"].get("implementation_backoff") or "")
        ET.SubElement(meta, "implementation_vid").text = str(svc["meta"].get("implementation_vid") or "")

        # accepted transforms
        acc = ET.SubElement(s, "accepted_transforms")
        main = ET.SubElement(acc, "main")
        for t in svc["accepted_transforms"].get("main", []):
            ET.SubElement(main, "sa").text = str(t)
        aggr = ET.SubElement(acc, "aggressive")
        for t in svc["accepted_transforms"].get("aggressive", []):
            ET.SubElement(aggr, "sa").text = str(t)
        ikev2 = ET.SubElement(acc, "ikev2")
        for t in svc["accepted_transforms"].get("ikev2", []):
            ET.SubElement(ikev2, "sa").text = str(t)

        # Aggressive Mode HASH_R and complete psk-crack records
        psk_records = ET.SubElement(s, "aggressive_psk")
        for record in svc.get("aggressive_psk", []):
            item = ET.SubElement(psk_records, "record")
            ET.SubElement(item, "transform").text = str(record.get("transform", ""))
            ET.SubElement(item, "hash_r").text = str(record.get("hash_r", ""))
            ET.SubElement(item, "hash_algorithm").text = str(record.get("hash_algorithm", ""))
            ET.SubElement(item, "psk_crack_supported").text = str(record.get("psk_crack_supported", False)).lower()
            ET.SubElement(item, "parameters").text = str(record.get("parameters", ""))

        # weak algorithms
        weak = ET.SubElement(s, "weak_algorithms")
        for w in svc.get("weak_algorithms", []):
            ET.SubElement(weak, "alg").text = str(w)

        # flaws
        flaws = ET.SubElement(s, "flaws")
        for fitem in svc.get("flaws", []):
            ET.SubElement(flaws, "flaw", severity=str(fitem["severity"])).text = str(fitem["description"])

        # ---- PROOF (raw ike-scan) ---------------------------------
        proof_el = ET.SubElement(s, "proof")
        if "ikev1_discovery" in svc.get("proof", {}):
            ET.SubElement(proof_el, "ikev1_raw").text = svc["proof"]["ikev1_discovery"]
        if "ikev2_discovery" in svc.get("proof", {}):
            ET.SubElement(proof_el, "ikev2_raw").text = svc["proof"]["ikev2_discovery"]
        if "natt_4500_ikev1" in svc.get("proof", {}):
            ET.SubElement(proof_el, "natt_4500_ikev1_raw").text = svc["proof"]["natt_4500_ikev1"]
        if "natt_4500_ikev2" in svc.get("proof", {}):
            ET.SubElement(proof_el, "natt_4500_ikev2_raw").text = svc["proof"]["natt_4500_ikev2"]
        if "group_id_evidence" in svc.get("proof", {}):
            ET.SubElement(proof_el, "group_id_evidence_raw").text = svc["proof"]["group_id_evidence"]

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ", level=0)
    tree.write(filename, encoding="utf-8", xml_declaration=True)

def print_console_report(results: Dict[str, Any]) -> None:
    s = results["summary"]
    line = "=" * 70
    logger.info("\n" + line + "\n                     SCAN RESULTS SUMMARY                     \n" + line)
    logger.info(f"Total hosts: {s['total_hosts']}")
    logger.info(f"Critical: [CRITICAL] {s['critical']}  High: [HIGH] {s['high']}  Medium: [MEDIUM] {s['medium']}  Low: [LOW] {s['low']}  Info: [INFO] {s['info']}  Good: [GOOD] {s['good']}")
    logger.info(line + "\n")

    for ip, svc in results["services"].items():
        versions = ", ".join(svc["meta"]["versions"]) if svc["meta"]["versions"] else "None"
        counts = svc["severity_counts"]
        logger.info(f"Host: {ip}")
        logger.info(f"  Supported versions: {versions}")

        # NEW: show both implementation hints if available
        impls = []
        backoff = svc["meta"].get("implementation_backoff")
        vid = svc["meta"].get("implementation_vid")
        if backoff:
            impls.append(f"{backoff} (backoff)")
        if vid:
            impls.append(f"{vid} (VID)")
        impl_line = " / ".join(impls) if impls else "N/A"
        logger.info(f"  Implementation: {impl_line}")

        logger.info(f"  Findings: {sum(counts.values())}  ([CRITICAL] {counts['critical']}, [HIGH] {counts['high']}, [MEDIUM] {counts['medium']}, [LOW] {counts['low']}, [INFO] {counts['info']})")
        for sev in ["critical", "high", "medium", "low", "info", "good"]:
            items = [f for f in svc["flaws"] if f["severity"] == sev]
            if items:
                logger.info(f"  [{sev.upper()}]")
                for it in items:
                    logger.info(f"    - {it['description']}")
        if svc["accepted_transforms"]["main"] or svc["accepted_transforms"]["aggressive"]:
            logger.info("  Accepted IKEv1 transforms:")
            if svc["accepted_transforms"]["main"]:
                for t in svc["accepted_transforms"]["main"]:
                    logger.info(f"    - IKEv1 Main Mode: {t}")
            if svc["accepted_transforms"]["aggressive"]:
                for t in svc["accepted_transforms"]["aggressive"]:
                    logger.info(f"    - IKEv1 Aggressive Mode: {t}")
        if svc.get("aggressive_psk"):
            logger.info("  Aggressive Mode PSK HASH_R values:")
            for record in svc["aggressive_psk"]:
                support = "psk-crack compatible" if record.get("psk_crack_supported") else "not supported by legacy psk-crack"
                logger.info(f"    - {record['hash_r']} [{record.get('hash_algorithm', 'unknown')}; {support}] ({record['transform']})")
        if svc["accepted_transforms"].get("ikev2"):
            logger.info("  Selected IKEv2 suite (confirmed, not exhaustive):")
            for t in svc["accepted_transforms"]["ikev2"]:
                logger.info(f"    - IKEv2 IKE_SA_INIT: {t}")
        elif "IKEv2" in svc["meta"]["versions"]:
            logger.info("  IKEv2 suite: peer responded, but no selected suite was decoded")
        logger.info("")

def generate_reports(vpns: Dict[str, Dict[str, Any]], start_time: str, end_time: str) -> None:
    logger.info("Generating reports...")
    results = analyze_security_flaws(vpns)
    results["scan_info"] = {
        "start_time": start_time,
        "end_time": end_time,
        "targets": list(vpns.keys()),
        "confirmed_only": ONLYCUSTOM,
        "nat_t": NATT,
        "udp_port": 4500 if NATT else 500,
        "udp_sport": IKE_SPORT if IKE_SPORT is not None else "",
        "vpn_id": VPN_ID or "",
        "vpn_idtype": VPN_IDTYPE,
        "idfile": IDFILE or "",
    }

    # ensure subfolder exists
    out_dir = Path("results")
    out_dir.mkdir(parents=True, exist_ok=True)

    # timestamp to avoid overwrites, e.g. 20251029-134512
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    # build timestamped paths
    suffix = "_natt4500" if NATT else ""
    xml_path = out_dir / f"{ts}_ikess_scan{suffix}.xml"
    json_path = out_dir / f"{ts}_ikess_scan{suffix}.json"
    html_path = out_dir / f"{ts}_ikess_scan{suffix}.html"
    psk_path = out_dir / f"{ts}_ikess_scan{suffix}.psk"

    generate_xml_report(results, str(xml_path))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    generate_html_report(results, str(html_path))
    print_console_report(results)

    psk_parameters = [
        record["parameters"]
        for svc in results["services"].values()
        for record in svc.get("aggressive_psk", [])
        if record.get("parameters")
    ]
    if psk_parameters:
        with open(psk_path, "w", encoding="ascii") as f:
            f.write("\n".join(psk_parameters) + "\n")

    logger.info("Detailed reports saved to:")
    logger.info(f"  XML: {xml_path}")
    logger.info(f"  JSON: {json_path}")
    logger.info(f"  HTML: {html_path}")
    if psk_parameters:
        logger.info(f"  PSK:  {psk_path} (complete nine-field records; psk-crack supports MD5/SHA1 only)")

# ------------------------------ Orchestration ---------------------------
def scan_target(ip: str) -> Dict[str, Any]:
    logger.info(f"Starting comprehensive scan of {ip}")

    vpn_data = {
        "v1": False, "v2": False,
        "vid": [],
        "transforms": [], "aggressive": [], "ikev2_transforms": [],
        "aggressive_psk": [],
        "accepted_transform_keys_main": [], "accepted_transform_keys_aggr": [],
        "showbackoff": "N/A",
    }

    vpn = {ip: vpn_data}

    check_ikev1(vpn, ip)
    check_ikev2(vpn, ip)
    if not vpn[ip].get("v1"):
        check_ikev1_aggressive(vpn, ip)
    if not vpn[ip].get("v1") and not vpn[ip].get("v2") and IDFILE and not VPN_ID:
        # An Aggressive-Mode-only gateway may stay silent until the correct
        # group KEY_ID is sent, so let the hunt double as IKEv1 discovery.
        hunt_group_id(vpn, ip)

    natt_only = False
    if not vpn[ip].get("v1") and not vpn[ip].get("v2"):
        # UDP 500 silent: maybe a NAT-T-only responder on 4500 (only 4500 forwarded,
        # or NAT-T-only config). Continue over NAT-T when 4500 answers.
        natt_only = discover_over_natt(vpn, ip)
        if not natt_only:
            logger.warning(f"No IKE services found on {ip}")
            return vpn
        vpn[ip]["natt_only"] = True
    else:
        # UDP 500 answered: the transport works. Only probe 4500 for the info
        # finding - a policy rejection on 500 (NO-PROPOSAL-CHOSEN, missing group
        # VPN ID, ...) would repeat identically on 4500, so the enumeration is
        # not duplicated over NAT-T.
        probe_natt_port(vpn, ip)

    if natt_only and not NATT:
        EXTRA_IKESCAN_ARGS.append("--nat-t")
    try:
        if IDFILE and not VPN_ID and not vpn[ip].get("vpn_id_discovered"):
            hunt_group_id(vpn, ip)
        test_aggressive_mode(vpn, ip)
        test_ikev2_features(vpn, ip)
        test_transforms(vpn, ip)
    finally:
        if natt_only and not NATT:
            EXTRA_IKESCAN_ARGS.remove("--nat-t")

    if FINGERPRINT:
        fingerprint_backoff(vpn, ip)
        if vpn.get(ip, {}).get("showbackoff") in (None, "N/A", "", "unknown"):
            tkey = None
            mains = vpn[ip].get("accepted_transform_keys_main") or []
            aggrs = vpn[ip].get("accepted_transform_keys_aggr") or []
            if mains:
                tkey = mains[0]
            elif aggrs:
                tkey = aggrs[0]
            if tkey:
                fingerprint_backoff(vpn, ip, transform=tkey)

    logger.info(f"Completed analysis of {ip}")
    return vpn

def main() -> int:
    global FULLALGS, FINGERPRINT, CUSTOM_ENC, CUSTOM_HASH, CUSTOM_AUTH, CUSTOM_GROUP, ONLYCUSTOM, NATT, VPN_ID, VPN_IDTYPE, IDFILE, IKE_SPORT

    class SmartFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
        pass

    parser = argparse.ArgumentParser(
        prog="ikess",
        description=(
            "ikess - IKE Security Scanner (Sequential Mode)\n\n"
            "Scans targets with ike-scan, detects IKEv1/IKEv2, tests transforms,\n"
            "and generates XML/JSON/HTML reports.\n\n"
            "Scan flow per host:\n"
            "  1) IKEv1/IKEv2 discovery on UDP 500\n"
            "  2) If UDP 500 is silent: NAT-T discovery on UDP 4500 (scan continues over 4500)\n"
            "  3) If UDP 500 answered: probe whether the peer also answers on 4500 (info finding)\n"
            "  4) Optional Aggressive Mode group VPN ID hunt (--idfile)\n"
            "  5) Aggressive Mode tests (if IKEv1)\n"
            "  6) Transform tests (Main Mode):\n"
            "     - default: curated common+legacy combos\n"
            "     - --fullalgs: brute-force all ENC/HASH/AUTH/DH combos\n"
            "  7) Optional backoff fingerprinting (--fingerprint)\n\n"
            "Transform format: ENC[/bits],HASH,AUTH,GROUP\n"
            "Example: '7/256,4,1,14' = AES256 / SHA256 / PSK / MODP2048.\n"
        ),
        formatter_class=SmartFormatter,
        epilog=(
            "Aliases you can use for --enc, --hash, --auth, --group:\n"
            "  ENC:  DES=1, 3DES=5, AES=7/128, AES128=7/128, AES192=7/192, AES256=7/256\n"
            "  HASH: MD5=1, SHA1=2, SHA256=4, SHA384=5, SHA512=6\n"
            "  AUTH: PSK=1, RSA=3, RSA_SIG=3, RSA-SIG=3, RSA SIG=3, HYBRID=64221, HYBRID_RSA=64221\n"
            "  DH:   G1=1,  G2=2,  G5=5,  G14=14, G15=15, G16=16\n"
            "        MODP768=1, MODP1024=2, MODP1536=5, MODP2048=14, MODP3072=15, MODP4096=16\n\n"
            "Examples:\n"
            "  sudo ./ikess.py 10.0.0.1\n"
            "  sudo ./ikess.py 10.0.0.0/24 --fullalgs --fingerprint\n"
            "  sudo ./ikess.py 10.0.0.1 --enc DES,3DES --onlycustom\n"
            "  sudo ./ikess.py 10.0.0.1 --enc AES128,3DES,1,7/256 --hash SHA1,SHA256,1 --auth PSK,RSA --group G2,G14,16\n"
            "  sudo ./ikess.py 203.0.113.5 --enc AES256 --hash SHA256 --auth PSK --group MODP2048 --onlycustom\n"
            "  sudo ./ikess.py 203.0.113.5 --nat-t\n"
            "  sudo ./ikess.py 203.0.113.5 --id mygroupvpn\n"
            "  sudo ./ikess.py 203.0.113.5 --idfile wordlists/group_ids.txt\n"
            "  sudo ./ikess.py 127.0.0.1 --sport 0\n"
        ),
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help=(
            "One or more IPv4 addresses or CIDR ranges to scan. Examples: 192.0.2.10 192.0.2.0/28\n"
            "All usable hosts in a CIDR are enumerated."
        ),
    )
    parser.add_argument(
        "--fullalgs",
        action="store_true",
        help=(
            "Try every ENC/HASH/AUTH/DH combination (full cartesian set).\n"
            "You can still limit via --enc/--hash/--auth/--group. Very noisy."
        ),
    )
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help=(
            "Enable backoff fingerprinting (ike-scan --showbackoff). If no fingerprint is obtained from a\n"
            "generic probe, ikess retries using the first accepted transform to improve accuracy."
        ),
    )
    parser.add_argument(
        "--enc",
        help=(
            "Comma separated encryption list to try or restrict. Accepts numeric codes or aliases.\n"
            "Examples: --enc AES256,3DES  or  --enc 7/256,5"
        ),
    )
    parser.add_argument(
        "--hash",
        help=(
            "Comma separated hash list. Accepts numeric codes or aliases.\n"
            "Examples: --hash SHA1,SHA256  or  --hash 2,4"
        ),
    )
    parser.add_argument(
        "--auth",
        help=(
            "Comma separated IKE authentication methods. Accepts numeric codes or aliases.\n"
            "Examples: --auth PSK,RSA  or  --auth 1,3  or  --auth HYBRID"
        ),
    )
    parser.add_argument(
        "--group", "--dh",
        dest="group",
        help=(
            "Comma separated DH groups. Accepts numeric codes or aliases. '--dh' is an alias.\n"
            "Examples: --group G14,G16  or  --dh MODP2048,MODP4096  or  --group 14,16"
        ),
    )
    parser.add_argument(
        "--onlycustom",
        action="store_true",
        help=(
            "Scan only the transforms built from your custom --enc/--hash/--auth/--group lists. Without this\n"
            "flag, custom items are merged into the curated or expanded set."
        ),
    )

    parser.add_argument(
        "--nat-t", "--natt",
        dest="nat_t",
        action="store_true",
        help=(
            "Probe over NAT-T (RFC 3947): UDP 4500 source+dest with non-ESP marker (ike-scan --nat-t).\n"
            "Applies to every ike-scan call. Report files get a '_natt4500' suffix. Note: many gateways\n"
            "only answer on 4500 after NAT detection on 500, so no response here is not conclusive."
        ),
    )

    parser.add_argument(
        "--id",
        dest="vpn_id",
        help=(
            "Group VPN ID sent with every Aggressive Mode probe (ike-scan --id).\n"
            "Some gateways (Cisco ASA tunnel-group, SonicWall, FortiGate dialup, WatchGuard, ...)\n"
            "only negotiate after seeing a known group ID and otherwise answer NO-PROPOSAL-CHOSEN\n"
            "to every proposal. Without --id, ike-scan sends no meaningful group name."
        ),
    )
    parser.add_argument(
        "--sport",
        dest="sport",
        type=int,
        default=None,
        help=(
            "UDP source port for every ike-scan call (ike-scan --sport). Default: 500 (4500 with --nat-t).\n"
            "Use 0 for a random source port when scanning a local test server - its IKE daemon already\n"
            "owns UDP 500/4500 and ike-scan cannot bind them at the same time. Note: some remote gateways\n"
            "only answer clients coming from source port 500."
        ),
    )
    parser.add_argument(
        "--idtype",
        dest="vpn_idtype",
        type=int,
        default=None,
        help=(
            "Identification type for --id (RFC 2407): 1=IPv4, 2=FQDN, 3=USER_FQDN, 11=KEY_ID.\n"
            "KEY_ID (11) is the usual type for group VPN names. (default: 11)"
        ),
    )
    parser.add_argument(
        "--idfile",
        dest="idfile",
        help=(
            "Brute force group VPN IDs from a wordlist file (one candidate per line, '#' comments)\n"
            "with Aggressive Mode probes; the matching ID is adopted for all further probes.\n"
            "Bundles a compact PSK proposal set per DH group and runs on the host's scan transport\n"
            "(UDP 500, or UDP 4500 for NAT-T-only peers / --nat-t). Curated list: wordlists/group_ids.txt"
        ),
    )

    args = parser.parse_args()

    CUSTOM_ENC   = _parse_list_arg(args.enc,   ENC_ALIASES)
    CUSTOM_HASH  = _parse_list_arg(args.hash,  HASH_ALIASES)
    CUSTOM_AUTH  = _parse_list_arg(args.auth,  AUTH_ALIASES)
    CUSTOM_GROUP = _parse_list_arg(args.group, GROUP_ALIASES)
    ONLYCUSTOM   = args.onlycustom
    FULLALGS     = args.fullalgs
    FINGERPRINT  = args.fingerprint
    NATT         = args.nat_t
    if NATT:
        EXTRA_IKESCAN_ARGS.append("--nat-t")
    IKE_SPORT    = args.sport
    if args.sport is not None:
        # ike-scan: --sport must come after --nat-t to also change the NAT-T source port
        EXTRA_IKESCAN_ARGS.append(f"--sport={args.sport}")
    VPN_ID       = args.vpn_id
    VPN_IDTYPE   = args.vpn_idtype if args.vpn_idtype is not None else 11
    if args.vpn_idtype is not None and not VPN_ID:
        logger.warning("--idtype given without --id - ignoring group VPN ID type")
    if args.idfile:
        if not Path(args.idfile).is_file():
            logger.error(f"--idfile not found: {args.idfile}")
            return 1
        IDFILE   = args.idfile
    if IDFILE and VPN_ID:
        logger.info(f"--id '{VPN_ID}' given together with --idfile - using --id and skipping the group ID hunt")

    if not check_ike_dependency():
        return 1

    logger.info("ikess – IKE Security Scanner by LRVT")
    start = datetime.now()
    logger.info(f"Scan started at {start:%Y-%m-%d %H:%M:%S}")
    logger.info(f"Targets: {', '.join(args.targets)}")
    logger.info(f"Transport: {'NAT-T (UDP 4500, ike-scan --nat-t)' if NATT else 'UDP 500'}")

    ips_to_scan: List[str] = []
    for t in args.targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            ips_to_scan.extend(str(ip) for ip in net.hosts())
        except ValueError:
            ips_to_scan.append(t)

    all_vpns: Dict[str, Dict[str, Any]] = {}

    for ip in ips_to_scan:
        result = scan_target(ip)
        all_vpns.update(result)

    end = datetime.now()
    logger.info(f"Scan completed at {end:%Y-%m-%d %H:%M:%S}")
    logger.info(f"Duration: {end - start}")

    if all_vpns:
        generate_reports(all_vpns, start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S"))
    else:
        logger.warning("No IKE services discovered – nothing to report.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
