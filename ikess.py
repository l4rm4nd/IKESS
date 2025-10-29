#!/usr/bin/env python3
"""
ikess v1.1 - IKE Security Scanner
Author: LRVT[](https://github.com/l4rm4nd)

Changes in v1.1:
- argparse: --fullalgs to broaden transform search sets
- argparse: --fingerprint (off by default) to run --showbackoff and retry with a known transform
- store accepted transform keys for main/aggressive to support transform-guided fingerprint retry
"""

import argparse
import json
import logging
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from itertools import product

# ----------------------------- Logging ---------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ikess")

# --------------------------- Feature flags (set by argparse) ------------

FULLALGS: bool = False
FINGERPRINT: bool = False
CUSTOM_ENC: List[str] = []
CUSTOM_HASH: List[str] = []
CUSTOM_AUTH: List[str] = []
CUSTOM_GROUP: List[str] = []
ONLYCUSTOM: bool = False

# --------------------------- Vulnerability text -------------------------

FLAWS = {
    "IKEV1": "Weak IKE version 1 supported - deprecated in favor of IKEv2",
    "DISC": "The IKE service is discoverable - switch to IKEv2 to prevent",
    "ENC_DES": "DES encryption detected - insecure and should be replaced with AES",
    "ENC_3DES": "3DES encryption detected - deprecated and should be replaced with AES",
    "HASH_MD5": "MD5 hash algorithm detected - insecure due to collision vulnerabilities",
    "HASH_SHA1": "SHA1 hash algorithm detected - deprecated due to collision vulnerabilities",
    "DHG_1": "DH Group 1 (MODP-768) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "DHG_2": "DH Group 2 (MODP-1024) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "DHG_5": "DH Group 5 (MODP-1536) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "AUTH_PSK": "Pre-shared key authentication - consider certificate-based authentication",
    "AGG_MODE": "Aggressive Mode supported - may reveal PSK hash for offline attacks",
    "FING_VID": "Fingerprinting possible via VID payload - informational leak",
    "FING_BACKOFF": "Fingerprinting possible via backoff pattern - informational leak",
}

# ------------------------ Transform candidate sets ----------------------
# Format for IKEv1 --trans inputs: "<enc>[/<bits>],<hash>,<auth>,<dhgroup>"
# Enc: 1=DES, 5=3DES, 7/128 or 7/256 for AES-128/AES-256
# Hash: 1=MD5, 2=SHA1, 5=SHA256 (ike-scan numeric mapping)
# Auth: 1=PSK, 3=RSA_Sig, 64221=Hybrid_RSA
# Group: 2=modp1024, 5=modp1536, 14=modp2048, 15=modp3072, 16=modp4096

MAIN_MODE_TRANSFORMS = [
    # Modern-ish common PSK
    "7/128,5,1,14",        # AES128-SHA256-PSK-G14  (popular)
    "7/256,5,1,14",        # AES256-SHA256-PSK-G14  (popular)
    "7/128,2,1,14",        # AES128-SHA1-PSK-G14    (legacy but still common)
    "7/256,2,1,14",        # AES256-SHA1-PSK-G14    (legacy but still common)

    # RSA Sig profiles often seen on gateways
    "7/128,5,3,14",        # AES128-SHA256-RSA_Sig-G14
    "7/256,5,3,14",        # AES256-SHA256-RSA_Sig-G14
    "7/128,2,3,14",        # AES128-SHA1-RSA_Sig-G14
    "7/256,2,3,14",        # AES256-SHA1-RSA_Sig-G14

    # A few alt DH groups for coverage without huge scan cost
    "7/128,2,1,2",         # AES128-SHA1-PSK-G2
    "7/256,2,1,2",         # AES256-SHA1-PSK-G2
    "7/128,5,1,5",         # AES128-SHA256-PSK-G5   ← **CRITICAL**
    "7/256,5,1,5",         # AES256-SHA256-PSK-G5
    "7/128,2,1,5",         # AES128-SHA1-PSK-G5
    "7/256,2,1,5",         # AES256-SHA1-PSK-G5
    "7/128,1,1,14",        # AES128-MD5-PSK-G14     ← MD5 flaw
    "7/256,1,1,14",        # AES256-MD5-PSK-G14
    "7/128,5,1,16",        # AES128-SHA256-PSK-G16
    "7/256,5,1,16",        # AES256-SHA256-PSK-G16
    "7/128,5,1,19",        # AES128-SHA256-PSK-ECP256 (IKEv2)
    "7/256,5,1,19",        # AES256-SHA256-PSK-ECP256  

    # 3DES legacy still around
    "5,2,1,14",            # 3DES-SHA1-PSK-G14
    "5,2,1,2",             # 3DES-SHA1-PSK-G2
    "5,2,3,14",            # 3DES-SHA1-RSA_Sig-G14
    "5,2,3,2",             # 3DES-SHA1-RSA_Sig-G2

    # Weak but widely seen historically. Keep minimal to stay quick.
    "1,2,1,14",            # DES-SHA1-PSK-G14      (deprecated)
    "1,1,1,14",            # DES-MD5-PSK-G14       (deprecated)
    "1,2,1,2",             # DES-SHA1-PSK-G2       (deprecated)
    "1,1,1,2",             # DES-MD5-PSK-G2        (deprecated)  
]

AGGRESSIVE_MODE_TRANSFORMS = [
    # Modern-ish
    "7/128,5,1,14",        # AES128-SHA256-PSK-G14
    "7/256,5,1,14",        # AES256-SHA256-PSK-G14
    "7/128,2,1,14",        # AES128-SHA1-PSK-G14
    "7/256,2,1,14",        # AES256-SHA1-PSK-G14

    # Alt DH to cover older setups
    "7/128,2,1,2",         # AES128-SHA1-PSK-G2
    "7/256,2,1,2",         # AES256-SHA1-PSK-G2
    "7/128,5,1,5",         # AES128-SHA256-PSK-G5
    "7/256,5,1,5",         # AES256-SHA256-PSK-G5
    "7/128,2,1,5",         # AES128-SHA1-PSK-G5
    "7/128,5,1,16",        # AES128-SHA256-PSK-G16
    "7/256,5,1,16",        # AES256-SHA256-PSK-G16
    "5,2,1,5",             # 3DES-SHA1-PSK-G5
    "1,2,1,5",             # DES-SHA1-PSK-G5

    # 3DES legacy
    "5,2,1,14",            # 3DES-SHA1-PSK-G14
    "5,2,1,2",             # 3DES-SHA1-PSK-G2
    "5,1,1,14",            # 3DES-MD5-PSK-G14     (very old)
    "5,1,1,2",             # 3DES-MD5-PSK-G2      (very old)

    # DES legacy quick hits
    "1,2,1,14",            # DES-SHA1-PSK-G14     (deprecated)
    "1,1,1,14",            # DES-MD5-PSK-G14      (deprecated)
    "1,2,1,2",             # DES-SHA1-PSK-G2      (deprecated)
    "1,1,1,2",             # DES-MD5-PSK-G2       (deprecated)
]


# ========================== FULL SETS (curated, expanded) ==========================
# These significantly widen coverage versus the defaults, adding:
# - DES/3DES across G2/G5/G14/G15/G16 (where sensible)
# - AES-128/192/256 across SHA1/SHA256, PSK/RSA_Sig/Hybrid_RSA, with multiple DH groups
# - A few AES+MD5 combos seen on very old gear (minimal, just enough for detection)
# - Aggressive mode focuses on PSK variants only (hash-leak targets), with broad DH coverage

MAIN_MODE_TRANSFORMS_FULL = list(dict.fromkeys(MAIN_MODE_TRANSFORMS + [
    # ===== DES (very legacy/weak) =====
    # PSK
    "1,2,1,2",             # DES-SHA1-PSK-G2
    "1,2,1,5",             # DES-SHA1-PSK-G5
    "1,2,1,14",            # DES-SHA1-PSK-G14
    "1,1,1,2",             # DES-MD5-PSK-G2
    "1,1,1,14",            # DES-MD5-PSK-G14
    # RSA_Sig / Hybrid
    "1,2,3,2",             # DES-SHA1-RSA_Sig-G2
    "1,2,3,14",            # DES-SHA1-RSA_Sig-G14
    "1,1,3,2",             # DES-MD5-RSA_Sig-G2
    "1,1,3,14",            # DES-MD5-RSA_Sig-G14
    "1,2,64221,2",         # DES-SHA1-Hybrid_RSA-G2
    "1,2,64221,14",        # DES-SHA1-Hybrid_RSA-G14
    "1,1,64221,2",         # DES-MD5-Hybrid_RSA-G2
    "1,1,64221,14",        # DES-MD5-Hybrid_RSA-G14

    # ===== 3DES (legacy but common) =====
    # PSK
    "5,2,1,2",             # 3DES-SHA1-PSK-G2
    "5,2,1,5",             # 3DES-SHA1-PSK-G5
    "5,2,1,14",            # 3DES-SHA1-PSK-G14
    "5,1,1,2",             # 3DES-MD5-PSK-G2
    "5,1,1,14",            # 3DES-MD5-PSK-G14
    # RSA_Sig / Hybrid
    "5,2,3,2",             # 3DES-SHA1-RSA_Sig-G2
    "5,2,3,14",            # 3DES-SHA1-RSA_Sig-G14
    "5,1,3,2",             # 3DES-MD5-RSA_Sig-G2
    "5,1,3,14",            # 3DES-MD5-RSA_Sig-G14
    "5,2,64221,2",         # 3DES-SHA1-Hybrid_RSA-G2
    "5,2,64221,14",        # 3DES-SHA1-Hybrid_RSA-G14
    "5,1,64221,2",         # 3DES-MD5-Hybrid_RSA-G2
    "5,1,64221,14",        # 3DES-MD5-Hybrid_RSA-G14

    # ===== AES-128 (SHA1/SHA256; PSK/RSA/Hybrid) across multiple DH groups =====
    # PSK
    "7/128,2,1,2",         # AES128-SHA1-PSK-G2
    "7/128,2,1,5",         # AES128-SHA1-PSK-G5
    "7/128,2,1,15",        # AES128-SHA1-PSK-G15
    "7/128,2,1,16",        # AES128-SHA1-PSK-G16
    "7/128,5,1,2",         # AES128-SHA256-PSK-G2
    "7/128,5,1,5",         # AES128-SHA256-PSK-G5
    "7/128,5,1,15",        # AES128-SHA256-PSK-G15
    "7/128,5,1,16",        # AES128-SHA256-PSK-G16
    # RSA_Sig
    "7/128,2,3,2",         # AES128-SHA1-RSA_Sig-G2
    "7/128,2,3,5",         # AES128-SHA1-RSA_Sig-G5
    "7/128,2,3,16",        # AES128-SHA1-RSA_Sig-G16
    "7/128,5,3,2",         # AES128-SHA256-RSA_Sig-G2
    "7/128,5,3,5",         # AES128-SHA256-RSA_Sig-G5
    "7/128,5,3,16",        # AES128-SHA256-RSA_Sig-G16
    # Hybrid
    "7/128,2,64221,14",    # AES128-SHA1-Hybrid_RSA-G14
    "7/128,5,64221,14",    # AES128-SHA256-Hybrid_RSA-G14
    "7/128,2,64221,2",     # AES128-SHA1-Hybrid_RSA-G2
    "7/128,5,64221,2",     # AES128-SHA256-Hybrid_RSA-G2

    # ===== AES-192 (less common but present) =====
    # PSK
    "7/192,2,1,14",        # AES192-SHA1-PSK-G14
    "7/192,5,1,14",        # AES192-SHA256-PSK-G14
    "7/192,2,1,2",         # AES192-SHA1-PSK-G2
    "7/192,5,1,2",         # AES192-SHA256-PSK-G2
    # RSA_Sig
    "7/192,2,3,14",        # AES192-SHA1-RSA_Sig-G14
    "7/192,5,3,14",        # AES192-SHA256-RSA_Sig-G14

    # ===== AES-256 (SHA1/SHA256; PSK/RSA/Hybrid) across multiple DH groups =====
    # PSK
    "7/256,2,1,2",         # AES256-SHA1-PSK-G2
    "7/256,2,1,5",         # AES256-SHA1-PSK-G5
    "7/256,2,1,15",        # AES256-SHA1-PSK-G15
    "7/256,2,1,16",        # AES256-SHA1-PSK-G16
    "7/256,5,1,2",         # AES256-SHA256-PSK-G2
    "7/256,5,1,5",         # AES256-SHA256-PSK-G5
    "7/256,5,1,15",        # AES256-SHA256-PSK-G15
    "7/256,5,1,16",        # AES256-SHA256-PSK-G16
    # RSA_Sig
    "7/256,2,3,2",         # AES256-SHA1-RSA_Sig-G2
    "7/256,2,3,5",         # AES256-SHA1-RSA_Sig-G5
    "7/256,2,3,16",        # AES256-SHA1-RSA_Sig-G16
    "7/256,5,3,2",         # AES256-SHA256-RSA_Sig-G2
    "7/256,5,3,5",         # AES256-SHA256-RSA_Sig-G5
    "7/256,5,3,16",        # AES256-SHA256-RSA_Sig-G16
    # Hybrid
    "7/256,2,64221,14",    # AES256-SHA1-Hybrid_RSA-G14
    "7/256,5,64221,14",    # AES256-SHA256-Hybrid_RSA-G14
    "7/256,2,64221,2",     # AES256-SHA1-Hybrid_RSA-G2
    "7/256,5,64221,2",     # AES256-SHA256-Hybrid_RSA-G2

    # ===== Very old AES+MD5 edge cases (minimal coverage) =====
    "7/128,1,1,14",        # AES128-MD5-PSK-G14
    "7/256,1,1,14",        # AES256-MD5-PSK-G14
    "7/128,1,3,14",        # AES128-MD5-RSA_Sig-G14
    "7/256,1,3,14",        # AES256-MD5-RSA_Sig-G14
]))

AGGRESSIVE_MODE_TRANSFORMS_FULL = list(dict.fromkeys(AGGRESSIVE_MODE_TRANSFORMS + [
    # ===== AES-128 PSK =====
    "7/128,2,1,2",         # AES128-SHA1-PSK-G2
    "7/128,2,1,5",         # AES128-SHA1-PSK-G5
    "7/128,2,1,15",        # AES128-SHA1-PSK-G15
    "7/128,2,1,16",        # AES128-SHA1-PSK-G16
    "7/128,5,1,2",         # AES128-SHA256-PSK-G2
    "7/128,5,1,5",         # AES128-SHA256-PSK-G5
    "7/128,5,1,15",        # AES128-SHA256-PSK-G15
    "7/128,5,1,16",        # AES128-SHA256-PSK-G16

    # ===== AES-256 PSK =====
    "7/256,2,1,2",         # AES256-SHA1-PSK-G2
    "7/256,2,1,5",         # AES256-SHA1-PSK-G5
    "7/256,2,1,15",        # AES256-SHA1-PSK-G15
    "7/256,2,1,16",        # AES256-SHA1-PSK-G16
    "7/256,5,1,2",         # AES256-SHA256-PSK-G2
    "7/256,5,1,5",         # AES256-SHA256-PSK-G5
    "7/256,5,1,15",        # AES256-SHA256-PSK-G15
    "7/256,5,1,16",        # AES256-SHA256-PSK-G16

    # ===== AES-192 PSK (rarer, but cheap to try) =====
    "7/192,2,1,14",        # AES192-SHA1-PSK-G14
    "7/192,2,1,2",         # AES192-SHA1-PSK-G2
    "7/192,5,1,14",        # AES192-SHA256-PSK-G14
    "7/192,5,1,2",         # AES192-SHA256-PSK-G2

    # ===== 3DES PSK =====
    "5,2,1,2",             # 3DES-SHA1-PSK-G2
    "5,2,1,5",             # 3DES-SHA1-PSK-G5
    "5,2,1,14",            # 3DES-SHA1-PSK-G14
    "5,1,1,2",             # 3DES-MD5-PSK-G2
    "5,1,1,14",            # 3DES-MD5-PSK-G14

    # ===== DES PSK (weak legacy) =====
    "1,2,1,2",             # DES-SHA1-PSK-G2
    "1,2,1,5",             # DES-SHA1-PSK-G5
    "1,2,1,14",            # DES-SHA1-PSK-G14
    "1,1,1,2",             # DES-MD5-PSK-G2
    "1,1,1,14",            # DES-MD5-PSK-G14
]))

# Candidate spaces used only when --fullalgs is on
ENC_FULL   = ["1", "5", "7/128", "7/192", "7/256"]   # 1=DES, 5=3DES, AES-128/192/256
HASH_FULL  = ["1", "2", "5"]                         # MD5, SHA1, SHA256
AUTH_FULL  = ["1", "3", "64221"]                     # PSK, RSA_Sig, Hybrid_RSA
GROUP_FULL = ["2", "5", "14", "15", "16"]

def _build_transform_space(encs: List[str], hashes: List[str], auths: List[str], groups: List[str]) -> List[str]:
    """Builds a list of transform strings from the Cartesian product of input lists."""
    return [f"{e},{h},{a},{g}" for e, h, a, g in product(encs, hashes, auths, groups)]

# ----------------------------- Helpers ----------------------------------

def run_command(cmd: List[str], timeout: int = 30) -> Tuple[str, str, int]:
    """Executes a shell command with timeout and captures output."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout.strip(), p.stderr.strip(), p.returncode)
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return ("", "Timeout expired", 124)
    except Exception as e:
        logger.error(f"Command failed: {' '.join(cmd)} - {str(e)}")
        return ("", str(e), 1)

def check_ike_dependency() -> bool:
    """Checks if ike-scan is installed and available in PATH."""
    out, _, rc = run_command(["which", "ike-scan"], timeout=5)
    if rc == 0 and out:
        logger.info(f"ike-scan found: {out.splitlines()[0]}")
        return True
    logger.error("ike-scan not found. Please install ike-scan to continue.")
    return False

# ----------------------------- Aliases & Parsing -------------------------
# Friendly aliases -> ike-scan numeric tokens
ENC_ALIASES = {
    "DES": "1",
    "3DES": "5",
    "AES": "7/128",   # fallback for plain 'AES'
    "AES128": "7/128", "AES-128": "7/128", "AES 128": "7/128",
    "AES192": "7/192", "AES-192": "7/192", "AES 192": "7/192",
    "AES256": "7/256", "AES-256": "7/256", "AES 256": "7/256",
}
HASH_ALIASES = {
    "MD5": "1",
    "SHA1": "2", "SHA-1": "2", "SHA 1": "2",
    "SHA256": "5", "SHA-256": "5", "SHA 256": "5",
}
AUTH_ALIASES = {
    "PSK": "1",
    "RSA": "3", "RSA_SIG": "3", "RSA-SIG": "3", "RSA SIG": "3",
    "HYBRID": "64221", "HYBRID_RSA": "64221", "HYBRID-RSA": "64221", "HYBRID RSA": "64221",
}
GROUP_ALIASES = {
    "G1": "1", "MODP768": "1", "MODP 768": "1", "MODP-768": "1",
    "G2": "2", "MODP1024": "2", "MODP 1024": "2", "MODP-1024": "2",
    "G5": "5", "MODP1536": "5", "MODP 1536": "5", "MODP-1536": "5",
    "G14": "14", "MODP2048": "14", "MODP 2048": "14", "MODP-2048": "14",
    "G15": "15", "MODP3072": "15", "MODP 3072": "15", "MODP-3072": "15",
    "G16": "16", "MODP4096": "16", "MODP 4096": "16", "MODP-4096": "16",
}

def _normalize_token(tok: str, aliases: Dict[str, str]) -> Optional[str]:
    """Normalizes a token using aliases or returns None if invalid."""
    if not tok:
        return None
    raw = tok.strip()
    if not raw:
        return None
    # direct numbers or AES notation like 7/256 are accepted
    if raw.replace("/", "").isdigit():
        return raw
    key = raw.upper().replace("-", "").replace(" ", "")
    # try direct alias first
    if key in {k.replace("-", "").replace(" ", "") for k in aliases}:
        # find the first matching alias key (to keep code simple)
        for k, v in aliases.items():
            if key == k.upper().replace("-", "").replace(" ", ""):
                return v
    return None

def _parse_list_arg(raw: Optional[str], aliases: Dict[str, str]) -> List[str]:
    """Parses a comma-separated string into normalized tokens, removing duplicates."""
    if not raw:
        return []
    vals = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        norm = _normalize_token(part, aliases)
        if norm:
            vals.append(norm)
    # de-dup while keeping order
    return list(dict.fromkeys(vals))

# -------------------------- Scan primitives -----------------------------

BODY_MARKERS_V1 = [
    r"\bNotify message\b",
    r"\bVID=",
    r"\bSA=\(",
    r"\bAggressive Mode Handshake returned\b",
    r"\bMain Mode Handshake returned\b",
    r"\bHandshake returned\b",
]

BODY_MARKERS_V2 = [
    r"\bIKE_SA_INIT\b",
    r"\bNotify message\b",
    r"\bSA=\(",
    r"\bHandshake returned\b",
]

def _has_positive_summary(text: str) -> bool:
    """Checks if the output indicates a positive response summary."""
    m_notify = re.search(r"(\d+)\s+returned\s+notify", text, re.I)
    m_hs = re.search(r"(\d+)\s+returned\s+handshake", text, re.I)
    n_notify = int(m_notify.group(1)) if m_notify else 0
    n_hs = int(m_hs.group(1)) if m_hs else 0
    return (n_notify > 0) or (n_hs > 0)

def _has_body_markers(text: str, markers: List[str]) -> bool:
    """Checks if the text contains any of the specified body markers."""
    return any(re.search(p, text, re.I) for p in markers)

def _strip_banner(text: str) -> str:
    """Strips ike-scan banner lines from the output."""
    return "\n".join(
        ln for ln in text.splitlines()
        if not ln.startswith("Starting ike-scan") and not ln.startswith("Ending ike-scan")
    )

def _parse_vids(handshake: str) -> List[str]:
    """Parses Vendor ID (VID) payloads from handshake output, filtering common ones."""
    vids = []
    for m in re.finditer(r"VID=([a-fA-F0-9]+)\s+\(([^)]+)\)", handshake):
        desc = m.group(2).strip()
        if any(s in desc for s in ["draft-ietf", "IKE Fragmentation", "Dead Peer Detection", "XAUTH", "RFC 3947", "heartbeat"]):
            continue
        vids.append(desc)
    return vids

def _parse_sa_block(handshake: str) -> List[str]:
    """Parses SA blocks from handshake output."""
    return re.findall(r"SA=\(([^)]+)\)", handshake)

def _collect_weaknesses_from_text(txt: str) -> List[str]:
    """Collects weak algorithm indicators from text."""
    wk = []
    if "Enc=DES" in txt:
        wk.append("DES")
    if "Enc=3DES" in txt:
        wk.append("3DES")
    if "Hash=MD5" in txt or "Integ=HMAC_MD5_96" in txt:
        wk.append("MD5")
    if "Hash=SHA1" in txt or "Integ=HMAC_SHA1_96" in txt:
        wk.append("SHA1")
    if "Group=1:modp768" in txt or "DH_Group=1:modp768" in txt:
        wk.append("DH Group 1 (MODP-768)")
    if "Group=2:modp1024" in txt or "DH_Group=2:modp1024" in txt:
        wk.append("DH Group 2 (MODP-1024)")
    if "Group=5:modp1536" in txt or "DH_Group=5:modp1536" in txt:
        wk.append("DH Group 5 (MODP-1536)")
    if "Auth=PSK" in txt:
        wk.append("PSK")
    return sorted(set(wk))

# --------------------------- Scanning steps ------------------------------

def check_ikev1(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """Checks for IKEv1 support and collects initial handshake data."""
    logger.info(f"Discovering IKEv1 services for {ip}")
    cmd = [
        "ike-scan",
        ip,
        "--vendor", "f4ed19e0c114eb516faaac0ee37daf2807b4381f",
        "--vendor", "1f07f70eaa6514d3b0fa96542a500300",
    ]
    out, _, _ = run_command(cmd, timeout=10)
    if not out:
        return
    positive = _has_positive_summary(out) or _has_body_markers(out, BODY_MARKERS_V1)
    if positive:
        vpns[ip]["v1"] = True
        vpns[ip]["handshake"] = out
        vids = _parse_vids(_strip_banner(out))
        for v in vids:
            vpns[ip].setdefault("vid", [])
            if v not in vpns[ip]["vid"]:
                vpns[ip]["vid"].append(v)

def check_ikev2(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """Checks for IKEv2 support."""
    logger.info(f"Checking IKEv2 support for {ip}")
    out, _, _ = run_command(["ike-scan", "--ikev2", ip], timeout=10)
    if not out:
        return
    body = _strip_banner(out)
    positive = _has_positive_summary(out) or _has_body_markers(body, BODY_MARKERS_V2)
    if positive:
        vpns[ip]["v2"] = True
        vpns[ip]["ikev2_handshake"] = out

def fingerprint_backoff(
    vpns: Dict[str, Dict[str, Any]],
    ip: str,
    transform: Optional[str] = None,
    ike_scan_bin: str = "ike-scan",
    timeout: int = 300,
) -> None:
    """Performs backoff fingerprinting to guess the IKE implementation."""
    logger.info(f"Fingerprinting {ip} via backoff analysis"
                f"{' with transform ' + transform if transform else ''}")
    cmd = [ike_scan_bin, "--showbackoff"]
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
        logger.info(f"Backoff fingerprint for {ip}: {guess}"
                    f"{' | pattern: ' + ', '.join(pattern) if pattern else ''}")
    else:
        logger.info(f"No definitive backoff fingerprint for {ip}"
                    f"{' | pattern: ' + ', '.join(pattern) if pattern else ''}")

def _try_transform(ip: str, transform: str, aggressive: bool = False) -> str:
    """Attempts a single transform proposal and returns the stripped output."""
    base = ["ike-scan"]
    if aggressive:
        base += ["--aggressive"]
    base += ["--trans", transform, ip]
    out, _, _ = run_command(base, timeout=10)
    return _strip_banner(out)

def _transform_sets() -> Tuple[List[str], List[str]]:
    """
    Returns (main, aggressive) transform lists, honoring:
    - --onlycustom : use ONLY the custom cross-product (if any lists provided)
    - custom lists (if provided) are merged with curated/default sets when --onlycustom is not set
    - --fullalgs : use the expanded curated FULL sets (unless --onlycustom is given)
    Aggressive mode logic: if no custom AUTH provided, default to PSK ('1') for aggr.
    """
    # Build custom cross-product if the user supplied any dimension
    custom_main: List[str] = []
    custom_aggr: List[str] = []

    any_custom = bool(CUSTOM_ENC or CUSTOM_HASH or CUSTOM_AUTH or CUSTOM_GROUP)
    if any_custom:
        encs   = CUSTOM_ENC   or ENC_FULL   # be generous if user passed partials
        hashes = CUSTOM_HASH  or HASH_FULL
        auths  = CUSTOM_AUTH  or AUTH_FULL
        groups = CUSTOM_GROUP or GROUP_FULL

        custom_main = _build_transform_space(encs, hashes, auths, groups)

        # Aggressive defaults to PSK if user didn't specify AUTH explicitly
        aggr_auths = CUSTOM_AUTH or ["1"]   # PSK only if no explicit custom auths
        custom_aggr = _build_transform_space(encs, hashes, aggr_auths, groups)

    # If ONLY custom requested and we have a custom space, return that
    if ONLYCUSTOM and any_custom:
        # Keep size sane by de-duping
        return (list(dict.fromkeys(custom_main)), list(dict.fromkeys(custom_aggr)))

    # Otherwise, start from curated defaults or FULL curated sets
    if FULLALGS:
        base_main = list(MAIN_MODE_TRANSFORMS_FULL)
        base_aggr = list(AGGRESSIVE_MODE_TRANSFORMS_FULL)
    else:
        base_main = list(MAIN_MODE_TRANSFORMS)
        base_aggr = list(AGGRESSIVE_MODE_TRANSFORMS)

    # If custom lists exist, merge them in
    if any_custom:
        base_main = list(dict.fromkeys(base_main + custom_main))
        base_aggr = list(dict.fromkeys(base_aggr + custom_aggr))

    return base_main, base_aggr

def test_transforms(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """Tests Main Mode transforms and collects accepted ones."""
    logger.info(f"Testing encryption algorithms for {ip}")
    transforms_main, _ = _transform_sets()
    accepted_sa: List[str] = []
    accepted_keys: List[str] = []

    for i, t in enumerate(transforms_main, 1):
        progress = (i / len(transforms_main)) * 100
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
    """Tests Aggressive Mode transforms if IKEv1 is supported."""
    if not vpns[ip].get("v1"):
        vpns[ip]["aggressive"] = []
        vpns[ip]["accepted_transform_keys_aggr"] = []
        return

    logger.info(f"Testing Aggressive Mode for {ip}")
    _, transforms_aggr = _transform_sets()
    accepted_sa: List[str] = []
    accepted_keys: List[str] = []

    for i, t in enumerate(transforms_aggr, 1):
        progress = (i / len(transforms_aggr)) * 100
        print(f"\r[{'█' * int(progress/100*30):30}] {progress:.1f}% - Aggressive Mode Transform: {t}", end="", flush=True)
        out = _try_transform(ip, t, aggressive=True)
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
    vpns[ip]["aggressive"] = list(dict.fromkeys(accepted_sa))
    vpns[ip]["accepted_transform_keys_aggr"] = list(dict.fromkeys(accepted_keys))

def test_ikev2_features(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
    """Tests additional IKEv2 features like CERTREQ support."""
    if not vpns[ip].get("v2"):
        return
    out, _, _ = run_command(["ike-scan", "--ikev2", "--certreq", ip], timeout=5)
    if out:
        vpns[ip]["ikev2_certreq"] = True

# --------------------------- Analysis / Reports --------------------------

def analyze_security_flaws(vpns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Analyzes collected data for security flaws and summarizes results."""
    logger.info("Analyzing security flaws")
    results = {"services": {}, "summary": {}}

    for ip, data in vpns.items():
        results["services"][ip] = {
            "flaws": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "accepted_transforms": {"main": [], "aggressive": []},
            "weak_algorithms": [],
            "meta": {
                "versions": [v for v, k in (("IKEv1", data.get("v1")), ("IKEv2", data.get("v2"))) if k],
                "implementation": data.get("showbackoff") or "N/A",
            },
        }
        added = set()

        def add_flaw(desc: str, sev: str, payload: str = "") -> None:
            if (ip, desc) in added:
                return
            results["services"][ip]["flaws"].append({"description": desc, "severity": sev, "data": payload})
            results["services"][ip]["severity_counts"][sev] += 1
            added.add((ip, desc))

        # Basic
        if data.get("v1") or data.get("v2"):
            add_flaw(FLAWS["DISC"], "info")
        if data.get("v1"):
            add_flaw(FLAWS["IKEV1"], "high")
        if data.get("aggressive"):
            add_flaw(FLAWS["AGG_MODE"], "critical")

        # --- Build discovery vs confirmed text blobs ---
        text_discovery = []
        if "handshake" in data:
            text_discovery.append(_strip_banner(data["handshake"]))
        if "ikev2_handshake" in data:
            text_discovery.append(_strip_banner(data["ikev2_handshake"]))
        text_discovery = " ".join(text_discovery)

        text_confirmed_parts = []
        for sa in data.get("transforms", []):
            text_confirmed_parts.append(f"SA=({sa})")
        for sa in data.get("aggressive", []):
            text_confirmed_parts.append(f"SA=({sa})")
        text_confirmed = " ".join(text_confirmed_parts)

        # If --onlycustom is set, treat the report as "confirmed-only".
        # Otherwise keep current behavior: discovery + confirmed.
        agg_sources = [text_confirmed] if ONLYCUSTOM else [text_discovery, text_confirmed]
        agg_text = " ".join(s for s in agg_sources if s)

        # Weak crypto
        if "Enc=DES" in agg_text:
            add_flaw(FLAWS["ENC_DES"], "high", agg_text)
        if "Enc=3DES" in agg_text:
            add_flaw(FLAWS["ENC_3DES"], "medium", agg_text)
        if "Hash=MD5" in agg_text or "Integ=HMAC_MD5_96" in agg_text:
            add_flaw(FLAWS["HASH_MD5"], "high", agg_text)
        if "Hash=SHA1" in agg_text or "Integ=HMAC_SHA1_96" in agg_text:
            add_flaw(FLAWS["HASH_SHA1"], "high", agg_text)
        if "Group=1:modp768" in agg_text or "DH_Group=1:modp768" in agg_text:
            add_flaw(FLAWS["DHG_1"], "high", agg_text)
        if "Group=2:modp1024" in agg_text or "DH_Group=2:modp1024" in agg_text:
            add_flaw(FLAWS["DHG_2"], "high", agg_text)
        if "Group=5:modp1536" in agg_text or "DH_Group=5:modp1536" in agg_text:
            add_flaw(FLAWS["DHG_5"], "high", agg_text)
        if "Auth=PSK" in agg_text:
            add_flaw(FLAWS["AUTH_PSK"], "medium", agg_text)

        # VIDs
        for vid in data.get("vid", []):
            add_flaw(f"{FLAWS['FING_VID']}: {vid}", "low", "")

        # Backoff guess (only if we actually set one)
        impl = data.get("showbackoff") or "N/A"
        if impl and impl != "N/A":
            add_flaw(f"{FLAWS['FING_BACKOFF']}: {impl}", "low", "")

        # Accepted transforms (strings for report)
        results["services"][ip]["accepted_transforms"]["main"] = list(dict.fromkeys(data.get("transforms", [])))
        results["services"][ip]["accepted_transforms"]["aggressive"] = list(dict.fromkeys(data.get("aggressive", [])))

        # Weak alg bullets
        results["services"][ip]["weak_algorithms"] = _collect_weaknesses_from_text(agg_text)

    # Summary
    summary = {"total_hosts": len(vpns), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for svc in results["services"].values():
        for sev, c in svc["severity_counts"].items():
            summary[sev] += c
    results["summary"] = summary
    return results

# ------------------------------ HTML report -----------------------------

def _sev_badge(sev: str) -> str:
    sev = sev.lower()
    if sev == "critical":
        return '<span class="badge bg-danger">CRITICAL</span>'
    if sev == "high":
        return '<span class="badge bg-danger">HIGH</span>'
    if sev == "medium":
        return '<span class="badge bg-warning text-dark">MEDIUM</span>'
    if sev == "low":
        return '<span class="badge bg-info text-dark">LOW</span>'
    if sev == "info":
        return '<span class="badge bg-secondary text-dark">INFO</span>'

def _sev_pill(sev: str, count: int) -> str:
    sev = sev.lower()
    if sev == "critical":
        return f'<span class="badge rounded-pill text-bg-danger">CRITICAL {count}</span>'
    if sev == "high":
        return f'<span class="badge rounded-pill text-bg-danger">HIGH {count}</span>'
    if sev == "medium":
        return f'<span class="badge rounded-pill text-bg-warning text-dark">MEDIUM {count}</span>'
    if sev == "low":
        return f'<span class="badge rounded-pill text-bg-info text-dark">LOW {count}</span>'
    if sev == "info":
        return f'<span class="badge rounded-pill text-bg-secondary text-dark">INFO {count}</span>'

def generate_html_report(results: Dict, filename: str):
    total = results["summary"]["total_hosts"]
    crit = results["summary"]["critical"]
    high = results["summary"]["high"]
    med = results["summary"]["medium"]
    low = results["summary"]["low"]
    info = results["summary"]["info"]
    confirmed_only = results.get("scan_info", {}).get("confirmed_only", False)

    scope_badge = '<span class="badge text-bg-primary">Scope: --onlycustom</span>' if confirmed_only \
                  else '<span class="badge text-bg-light">Scope: default</span>'

    host_cards = []

    for idx, (ip, svc) in enumerate(results["services"].items()):
        versions = ", ".join(svc["meta"]["versions"]) if svc["meta"]["versions"] else "None"
        impl = svc["meta"]["implementation"] or "N/A"

        main_rows = "".join(
            f"<li><code class='text-wrap'>{sa}</code></li>"
            for sa in svc["accepted_transforms"]["main"]
        ) or "<li><span class='text-muted'>None</span></li>"
        aggr_rows = "".join(
            f"<li><code class='text-wrap'>{sa}</code></li>"
            for sa in svc["accepted_transforms"]["aggressive"]
        ) or "<li><span class='text-muted'>None</span></li>"

        weak_list = "".join(f"<li>{w}</li>" for w in svc["weak_algorithms"]) or "<li><span class='text-muted'>None detected</span></li>"

        findings_list = []
        order = ["critical", "high", "medium", "low", "info"]
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
            "weak_algorithms": svc["weak_algorithms"],
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
              <span class="text-muted">Supported: {versions} &nbsp;•&nbsp; Implementation (backoff): {impl}</span>
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
            </div>

            <div class="row g-3">
              <div class="col-12 col-xl-6">
                <div class="card p-3 h-100">
                  <h5 class="mb-3">Accepted transforms</h5>
                  <div class="table-responsive">
                    <table class="table table-sm table-striped align-middle">
                      <thead>
                        <tr><th style="width:180px">Mode</th><th>SA Transforms</th></tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td class="fw-semibold">Main Mode</td>
                          <td><ul class="mb-0">{main_rows}</ul></td>
                        </tr>
                        <tr>
                          <td class="fw-semibold">Aggressive Mode</td>
                          <td><ul class="mb-0">{aggr_rows}</ul></td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
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
  body {{ background:#ffffff; color:#0c1116; }}
  .container-fluid {{ padding: 24px; }}
  .card {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; }}
  .json-pre {{ max-height: 420px; overflow:auto; }}
  code.text-wrap {{ white-space: normal; word-break: break-word; }}
  .accordion-button:not(.collapsed) {{ background:#f1f5f9; }}
@media (prefers-color-scheme: dark) {{
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
        <span class="badge text-bg-danger">CRITICAL {crit}</span>
        <span class="badge text-bg-danger">HIGH {high}</span>
        <span class="badge text-bg-warning text-dark">MEDIUM {med}</span>
        <span class="badge text-bg-info text-dark">LOW {low}</span>
        <span class="badge text-bg-secondary text-dark">INFO {info}</span>
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

def generate_xml_report(results: Dict[str, Any], filename: str) -> None:
    """Generates an XML report from analysis results."""
    root = ET.Element("iker_scan")

    # ---- scan_info as subelements (robust for non-strings) ----
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

    summary = ET.SubElement(root, "summary")
    for k, v in results["summary"].items():
        ET.SubElement(summary, k).text = str(v)

    services = ET.SubElement(root, "services")
    for ip, svc in results["services"].items():
        s = ET.SubElement(services, "service", ip=str(ip))
        meta = ET.SubElement(s, "meta")
        ET.SubElement(meta, "versions").text = ", ".join(svc["meta"].get("versions", []))
        ET.SubElement(meta, "implementation").text = str(svc["meta"].get("implementation") or "N/A")

        acc = ET.SubElement(s, "accepted_transforms")
        main = ET.SubElement(acc, "main")
        for t in svc["accepted_transforms"].get("main", []):
            ET.SubElement(main, "sa").text = str(t)
        aggr = ET.SubElement(acc, "aggressive")
        for t in svc["accepted_transforms"].get("aggressive", []):
            ET.SubElement(aggr, "sa").text = str(t)

        weak = ET.SubElement(s, "weak_algorithms")
        for w in svc.get("weak_algorithms", []):
            ET.SubElement(weak, "alg").text = str(w)

        flaws = ET.SubElement(s, "flaws")
        for fitem in svc.get("flaws", []):
            ET.SubElement(flaws, "flaw", severity=str(fitem["severity"])).text = str(fitem["description"])

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ", level=0)
    tree.write(filename, encoding="utf-8", xml_declaration=True)

def print_console_report(results: Dict[str, Any]) -> None:
    """Prints a console-friendly summary of the analysis results."""
    s = results["summary"]
    line = "=" * 70
    logger.info("\n" + line + "\n                     SCAN RESULTS SUMMARY                     \n" + line)
    logger.info(f"Total hosts: {s['total_hosts']}")
    logger.info(f"Critical: [CRITICAL] {s['critical']}  High: [HIGH] {s['high']}  Medium: [MEDIUM] {s['medium']}  Low: [LOW] {s['low']} Info: [INFO] {s['info']}")
    logger.info(line + "\n")

    for ip, svc in results["services"].items():
        versions = ", ".join(svc["meta"]["versions"]) if svc["meta"]["versions"] else "None"
        counts = svc["severity_counts"]
        logger.info(f"Host: {ip}")
        logger.info(f"  Supported versions: {versions}")
        logger.info(f"  Findings: {sum(counts.values())}  ([CRITICAL] {counts['critical']}, [HIGH] {counts['high']}, [MEDIUM] {counts['medium']}, [LOW] {counts['low']}), [INFO] {counts['info']})")
        for sev in ["critical", "high", "medium", "low", "info"]:
            items = [f for f in svc["flaws"] if f["severity"] == sev]
            if items:
                logger.info(f"  [{sev.upper()}]")
                for it in items:
                    logger.info(f"    - {it['description']}")
        if svc["accepted_transforms"]["main"] or svc["accepted_transforms"]["aggressive"]:
            logger.info("  Accepted transforms:")
            if svc["accepted_transforms"]["main"]:
                for t in svc["accepted_transforms"]["main"]:
                    logger.info(f"    - Main: {t}")
            if svc["accepted_transforms"]["aggressive"]:
                for t in svc["accepted_transforms"]["aggressive"]:
                    logger.info(f"    - Aggressive: {t}")
        logger.info("")

def generate_reports(vpns: Dict[str, Dict[str, Any]], start_time: str, end_time: str) -> None:
    """Generates XML, JSON, HTML reports and prints console summary."""
    logger.info("Generating reports...")
    results = analyze_security_flaws(vpns)
    results["scan_info"] = {
        "start_time": start_time,
        "end_time": end_time,
        "targets": list(vpns.keys()),
        "confirmed_only": ONLYCUSTOM,
    }

    xml_file = "ikess_output.xml"
    json_file = "ikess_output.json"
    html_file = "ikess_report.html"

    generate_xml_report(results, xml_file)
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    generate_html_report(results, html_file)
    print_console_report(results)

    logger.info("Detailed reports saved to:")
    logger.info(f"  XML: {xml_file}")
    logger.info(f"  JSON: {json_file}")
    logger.info(f"  HTML: {html_file}")

# ------------------------------ Orchestration ---------------------------

def scan_target(ip: str) -> Dict[str, Dict[str, Any]]:
    """Performs a full scan on a single target IP."""
    logger.info(f"Starting comprehensive scan of {ip}")
    vpn = {ip: {
        "v1": False, "v2": False,
        "vid": [],
        "transforms": [],                   # strings: SA blocks
        "aggressive": [],                   # strings: SA blocks
        "accepted_transform_keys_main": [], # keys that worked (for backoff retry)
        "accepted_transform_keys_aggr": [], # keys that worked (for backoff retry)
        "showbackoff": "N/A",
    }}

    # Version discovery
    check_ikev1(vpn, ip)
    check_ikev2(vpn, ip)

    if not vpn[ip].get("v1") and not vpn[ip].get("v2"):
        logger.warning(f"No IKE services found on {ip}")
        return vpn

    # Aggressive (IKEv1 only)
    test_aggressive_mode(vpn, ip)

    # IKEv2 extras
    test_ikev2_features(vpn, ip)

    # Main Mode transforms
    test_transforms(vpn, ip)

    # Optional: Backoff fingerprint (off by default)
    if FINGERPRINT:
        # first try generic
        fingerprint_backoff(vpn, ip)

        # If still N/A and we have accepted transform keys, retry with first key
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
    """Main entry point for the script."""
    global FULLALGS, FINGERPRINT, CUSTOM_ENC, CUSTOM_HASH, CUSTOM_AUTH, CUSTOM_GROUP, ONLYCUSTOM

    # -------- argparse (improved help & examples) --------
    parser = argparse.ArgumentParser(
        prog="ikess",
        description=(
            "ikess v1.1 – IKE Security Scanner\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Curated defaults only\n"
            "  sudo python3 ikess.py 10.0.0.1\n\n"
            "  # Expanded curated coverage (adds legacy/rare variants)\n"
            "  sudo python3 ikess.py 10.0.0.1 --fullalgs\n\n"
            "  # Try defaults PLUS a DES cross-product (merged with curated defaults)\n"
            "  sudo python3 ikess.py 10.0.0.1 --enc DES\n\n"
            "  # Only your custom cross-product (no curated defaults)\n"
            "  sudo python3 ikess.py 10.0.0.1 --enc DES --onlycustom\n\n"
            "  # Custom space using names or ike-scan tokens (mixed allowed)\n"
            "  sudo python3 ikess.py 10.0.0.1 \\\n"
            "       --enc AES128,3DES,1,7/256 \\\n"
            "       --hash SHA1,SHA256,1 \\\n"
            "       --auth PSK,RSA,HYBRID \\\n"
            "       --group G2,G14,16\n\n"
            "Notes:\n"
            "  • Names are mapped to ike-scan tokens:\n"
            "      ENC:  DES→1, 3DES→5, AES128→7/128, AES192→7/192, AES256→7/256, AES→7/128\n"
            "      HASH: MD5→1, SHA1→2, SHA256→5\n"
            "      AUTH: PSK→1, RSA (RSA_Sig)→3, HYBRID (Hybrid_RSA)→64221\n"
            "      DH:   G1→1, G2→2, G5→5, G14→14, G15→15, G16→16, MODPxxxx→matching group\n"
            "  • Aggressive mode focuses on PSK by default; include --auth if you want RSA/HYBRID\n"
            "    proposals in the aggressive cross-product as well.\n"
            "  • --fingerprint runs --showbackoff and, if needed, retries with a known accepted\n"
            "    transform discovered during the scan."
        ),
    )

    parser.add_argument(
        "targets", nargs="+",
        help="One or more target IPs/hostnames to probe (space-separated)."
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=1,
        help="Number of concurrent worker threads (default: 1)."
    )
    parser.add_argument(
        "--fullalgs", action="store_true",
        help=(
            "Use expanded curated transform sets (adds legacy DES/3DES and broader AES/DH variants).\n"
            "If you also pass --enc/--hash/--auth/--group, those custom combos are MERGED in.\n"
            "Use --onlycustom to skip curated sets entirely."
        ),
    )
    parser.add_argument(
        "--fingerprint", action="store_true",
        help=(
            "Run ike-scan --showbackoff to guess implementation. If the generic attempt is inconclusive\n"
            "and we negotiated at least one transform, retry --showbackoff with the first accepted\n"
            "transform to improve the fingerprint."
        ),
    )

    # Custom transform space (names or ike-scan tokens; merged unless --onlycustom)
    parser.add_argument(
        "--enc",
        help=(
            "Comma-separated ENC list. Accepts names or tokens: AES,AES128,AES192,AES256,3DES,DES\n"
            "or 1,5,7/128,7/192,7/256. Example: --enc AES128,3DES,1,7/256"
        ),
    )
    parser.add_argument(
        "--hash",
        help=(
            "Comma-separated HASH list. Accepts names or tokens: MD5,SHA1,SHA256 or 1,2,5.\n"
            "Example: --hash SHA1,SHA256,1"
        ),
    )
    parser.add_argument(
        "--auth",
        help=(
            "Comma-separated AUTH list. Accepts names or tokens: PSK,RSA,HYBRID or 1,3,64221.\n"
            "Merged into Main & Aggressive cross-products. If omitted, Aggressive defaults to PSK only."
        ),
    )
    parser.add_argument(
        "--group", "--dh", dest="group",
        help=(
            "Comma-separated DH groups. Accepts names or tokens: G1,G2,G5,G14,G15,G16 or 1,2,5,14,15,16,\n"
            "and MODP aliases like MODP1024, MODP2048. Example: --group G2,G14,16"
        ),
    )
    parser.add_argument(
        "--onlycustom", action="store_true",
        help=(
            "Do NOT use curated transform sets. Scan ONLY the cross-product of your custom ENC/HASH/AUTH/GROUP.\n"
            "If you omit --auth, Aggressive still defaults to PSK."
        ),
    )

    args = parser.parse_args()

    CUSTOM_ENC   = _parse_list_arg(args.enc,   ENC_ALIASES)
    CUSTOM_HASH  = _parse_list_arg(args.hash,  HASH_ALIASES)
    CUSTOM_AUTH  = _parse_list_arg(args.auth,  AUTH_ALIASES)
    CUSTOM_GROUP = _parse_list_arg(args.group, GROUP_ALIASES)
    ONLYCUSTOM   = bool(args.onlycustom)

    if CUSTOM_ENC or CUSTOM_HASH or CUSTOM_AUTH or CUSTOM_GROUP:
        logger.info("Custom transform space requested via CLI:")
        logger.info(f"  ENC={CUSTOM_ENC or '∅'}  HASH={CUSTOM_HASH or '∅'}  AUTH={CUSTOM_AUTH or '∅'}  GROUP={CUSTOM_GROUP or '∅'}")
        if ONLYCUSTOM:
            logger.info("Using ONLY custom cross-product (--onlycustom).")

    FULLALGS = bool(args.fullalgs)
    FINGERPRINT = bool(args.fingerprint)

    logger.info("ikess v1.1 - IKE Security Scanner")
    logger.info("Author: LRVT[](https://github.com/l4rm4nd)")
    logger.info("╰─⠠⠵ Original (iker.py) by Julio Gomez, enhanced by nullenc0de")

    if not check_ike_dependency():
        return 1

    if FULLALGS:
        logger.info("Using expanded transform candidate sets (--fullalgs)")

    if FINGERPRINT:
        logger.info("Backoff fingerprinting enabled (--fingerprint)")

    start = datetime.now()
    logger.info(f"Scan started at {start.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Targets: {', '.join(args.targets)} | Threads: {args.threads}")

    all_vpns: Dict[str, Dict[str, Any]] = {}
    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            fut_map = {ex.submit(scan_target, ip): ip for ip in args.targets}
            for fut in as_completed(fut_map):
                try:
                    all_vpns.update(fut.result())
                except Exception as e:
                    logger.error(f"Scan failed for {fut_map[fut]}: {e}")
    else:
        for ip in args.targets:
            all_vpns.update(scan_target(ip))

    end = datetime.now()
    logger.info(f"Scan completed at {end.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Total scan duration: {end - start}")

    if all_vpns:
        generate_reports(all_vpns, start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S"))
    else:
        logger.warning("No responsive IKE hosts found. No report generated.")
    logger.info("Scan finished.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
