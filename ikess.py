#!/usr/bin/env python3
"""
ikess v1.1 - IKE Security Scanner (Sequential Mode)
Author: LRVT[](https://github.com/l4rm4nd)

SAFE FOR IKE: No threading — avoids UDP 500 collision and backoff corruption.
"""

import argparse
import json
import logging
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from itertools import product
import ipaddress

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

# --------------------------- Vulnerability text ------------------------
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
    "IKEV2": "IKEv2 is supported - very good and recommended"
}

# ============================= MAIN MODE TRANSFORMS =============================
# Format: "ENC[/bits],HASH,AUTH,GROUP"
# ENC: 1=DES, 5=3DES, 7/128=AES128, 7/192=AES192, 7/256=AES256
# HASH: 1=MD5, 2=SHA1, 5=SHA256
# AUTH: 1=PSK, 3=RSA_SIG, 64221=HYBRID_RSA
# GROUP: 2=MODP1024, 5=MODP1536, 14=MODP2048, 15=MODP3072, 16=MODP4096

MAIN_MODE_TRANSFORMS = [
    # === Modern & Common PSK Profiles ===
    "7/128,5,1,14",   # AES128-SHA256-PSK-MODP2048
    "7/256,5,1,14",   # AES256-SHA256-PSK-MODP2048
    "7/128,2,1,14",   # AES128-SHA1-PSK-MODP2048
    "7/256,2,1,14",   # AES256-SHA1-PSK-MODP2048

    # === Modern & Common RSA_SIG Profiles ===
    "7/128,5,3,14",   # AES128-SHA256-RSA_SIG-MODP2048
    "7/256,5,3,14",   # AES256-SHA256-RSA_SIG-MODP2048
    "7/128,2,3,14",   # AES128-SHA1-RSA_SIG-MODP2048
    "7/256,2,3,14",   # AES256-SHA1-RSA_SIG-MODP2048

    # === Legacy but Common (Smaller DH Groups) ===
    "7/128,2,1,2",    # AES128-SHA1-PSK-MODP1024
    "7/256,2,1,2",    # AES256-SHA1-PSK-MODP1024
    "7/128,5,1,5",    # AES128-SHA256-PSK-MODP1536
    "7/256,5,1,5",    # AES256-SHA256-PSK-MODP1536
    "7/128,2,1,5",    # AES128-SHA1-PSK-MODP1536
    "7/256,2,1,5",    # AES256-SHA1-PSK-MODP1536

    # === Weak Crypto (MD5) ===
    "7/128,1,1,14",   # AES128-MD5-PSK-MODP2048
    "7/256,1,1,14",   # AES256-MD5-PSK-MODP2048

    # === Larger DH Groups ===
    "7/128,5,1,16",   # AES128-SHA256-PSK-MODP4096
    "7/256,5,1,16",   # AES256-SHA256-PSK-MODP4096

    # === IKEv2 ECP (Elliptic Curve) — may be accepted in IKEv1 by some vendors ===
    "7/128,5,1,19",   # AES128-SHA256-PSK-ECP256
    "7/256,5,1,19",   # AES256-SHA256-PSK-ECP256

    # === 3DES Legacy (Still Seen) ===
    "5,2,1,14",       # 3DES-SHA1-PSK-MODP2048
    "5,2,1,2",        # 3DES-SHA1-PSK-MODP1024
    "5,2,3,14",       # 3DES-SHA1-RSA_SIG-MODP2048
    "5,2,3,2",        # 3DES-SHA1-RSA_SIG-MODP1024

    # === DES (Deprecated, Insecure) ===
    "1,2,1,14",       # DES-SHA1-PSK-MODP2048
    "1,1,1,14",       # DES-MD5-PSK-MODP2048
    "1,2,1,2",        # DES-SHA1-PSK-MODP1024
    "1,1,1,2",        # DES-MD5-PSK-MODP1024
]

# ============================= AGGRESSIVE MODE TRANSFORMS =============================
# Aggressive Mode is IKEv1-only and typically PSK-focused
# We keep RSA/HYBRID out unless explicitly requested via --auth

AGGRESSIVE_MODE_TRANSFORMS = [
    # === Modern PSK ===
    "7/128,5,1,14",   # AES128-SHA256-PSK-MODP2048
    "7/256,5,1,14",   # AES256-SHA256-PSK-MODP2048
    "7/128,2,1,14",   # AES128-SHA1-PSK-MODP2048
    "7/256,2,1,14",   # AES256-SHA1-PSK-MODP2048

    # === Legacy DH Groups ===
    "7/128,2,1,2",    # AES128-SHA1-PSK-MODP1024
    "7/256,2,1,2",    # AES256-SHA1-PSK-MODP1024
    "7/128,5,1,5",    # AES128-SHA256-PSK-MODP1536
    "7/256,5,1,5",    # AES256-SHA256-PSK-MODP1536
    "7/128,2,1,5",    # AES128-SHA1-PSK-MODP1536
    "7/128,5,1,16",   # AES128-SHA256-PSK-MODP4096
    "7/256,5,1,16",   # AES256-SHA256-PSK-MODP4096

    # === 3DES Legacy ===
    "5,2,1,5",        # 3DES-SHA1-PSK-MODP1536
    "1,2,1,5",        # DES-SHA1-PSK-MODP1536
    "5,2,1,14",       # 3DES-SHA1-PSK-MODP2048
    "5,2,1,2",        # 3DES-SHA1-PSK-MODP1024
    "5,1,1,14",       # 3DES-MD5-PSK-MODP2048
    "5,1,1,2",        # 3DES-MD5-PSK-MODP1024

    # === DES (Deprecated) ===
    "1,2,1,14",       # DES-SHA1-PSK-MODP2048
    "1,1,1,14",       # DES-MD5-PSK-MODP2048
    "1,2,1,2",        # DES-SHA1-PSK-MODP1024
    "1,1,1,2",        # DES-MD5-PSK-MODP1024
]

# ============================= FULL EXPANDED SETS (when --fullalgs) =============================
MAIN_MODE_TRANSFORMS_FULL = list(dict.fromkeys(MAIN_MODE_TRANSFORMS + [
    # === DES (Legacy, Insecure) ===
    "1,2,1,2",        # DES-SHA1-PSK-MODP1024
    "1,2,1,5",        # DES-SHA1-PSK-MODP1536
    "1,2,1,14",       # DES-SHA1-PSK-MODP2048
    "1,1,1,2",        # DES-MD5-PSK-MODP1024
    "1,1,1,14",       # DES-MD5-PSK-MODP2048
    "1,2,3,2",        # DES-SHA1-RSA_SIG-MODP1024
    "1,2,3,14",       # DES-SHA1-RSA_SIG-MODP2048
    "1,1,3,2",        # DES-MD5-RSA_SIG-MODP1024
    "1,1,3,14",       # DES-MD5-RSA_SIG-MODP2048
    "1,2,64221,2",    # DES-SHA1-HYBRID_RSA-MODP1024
    "1,2,64221,14",   # DES-SHA1-HYBRID_RSA-MODP2048
    "1,1,64221,2",    # DES-MD5-HYBRID_RSA-MODP1024
    "1,1,64221,14",   # DES-MD5-HYBRID_RSA-MODP2048

    # === 3DES (Deprecated but Common) ===
    "5,2,1,2",        # 3DES-SHA1-PSK-MODP1024
    "5,2,1,5",        # 3DES-SHA1-PSK-MODP1536
    "5,2,1,14",       # 3DES-SHA1-PSK-MODP2048
    "5,1,1,2",        # 3DES-MD5-PSK-MODP1024
    "5,1,1,14",       # 3DES-MD5-PSK-MODP2048
    "5,2,3,2",        # 3DES-SHA1-RSA_SIG-MODP1024
    "5,2,3,14",       # 3DES-SHA1-RSA_SIG-MODP2048
    "5,1,3,2",        # 3DES-MD5-RSA_SIG-MODP1024
    "5,1,3,14",       # 3DES-MD5-RSA_SIG-MODP2048
    "5,2,64221,2",    # 3DES-SHA1-HYBRID_RSA-MODP1024
    "5,2,64221,14",   # 3DES-SHA1-HYBRID_RSA-MODP2048
    "5,1,64221,2",    # 3DES-MD5-HYBRID_RSA-MODP1024
    "5,1,64221,14",   # 3DES-MD5-HYBRID_RSA-MODP2048

    # === AES-128 across DH groups ===
    "7/128,2,1,2",    # AES128-SHA1-PSK-MODP1024
    "7/128,2,1,5",    # AES128-SHA1-PSK-MODP1536
    "7/128,2,1,15",   # AES128-SHA1-PSK-MODP3072
    "7/128,2,1,16",   # AES128-SHA1-PSK-MODP4096
    "7/128,5,1,2",    # AES128-SHA256-PSK-MODP1024
    "7/128,5,1,5",    # AES128-SHA256-PSK-MODP1536
    "7/128,5,1,15",   # AES128-SHA256-PSK-MODP3072
    "7/128,5,1,16",   # AES128-SHA256-PSK-MODP4096
    "7/128,2,3,2",    # AES128-SHA1-RSA_SIG-MODP1024
    "7/128,2,3,5",    # AES128-SHA1-RSA_SIG-MODP1536
    "7/128,2,3,16",   # AES128-SHA1-RSA_SIG-MODP4096
    "7/128,5,3,2",    # AES128-SHA256-RSA_SIG-MODP1024
    "7/128,5,3,5",    # AES128-SHA256-RSA_SIG-MODP1536
    "7/128,5,3,16",   # AES128-SHA256-RSA_SIG-MODP4096
    "7/128,2,64221,14", # AES128-SHA1-HYBRID_RSA-MODP2048
    "7/128,5,64221,14", # AES128-SHA256-HYBRID_RSA-MODP2048
    "7/128,2,64221,2",  # AES128-SHA1-HYBRID_RSA-MODP1024
    "7/128,5,64221,2",  # AES128-SHA256-HYBRID_RSA-MODP1024

    # === AES-192 ===
    "7/192,2,1,14",   # AES192-SHA1-PSK-MODP2048
    "7/192,5,1,14",   # AES192-SHA256-PSK-MODP2048
    "7/192,2,1,2",    # AES192-SHA1-PSK-MODP1024
    "7/192,5,1,2",    # AES192-SHA256-PSK-MODP1024
    "7/192,2,3,14",   # AES192-SHA1-RSA_SIG-MODP2048
    "7/192,5,3,14",   # AES192-SHA256-RSA_SIG-MODP2048

    # === AES-256 ===
    "7/256,2,1,2",    # AES256-SHA1-PSK-MODP1024
    "7/256,2,1,5",    # AES256-SHA1-PSK-MODP1536
    "7/256,2,1,15",   # AES256-SHA1-PSK-MODP3072
    "7/256,2,1,16",   # AES256-SHA1-PSK-MODP4096
    "7/256,5,1,2",    # AES256-SHA256-PSK-MODP1024
    "7/256,5,1,5",    # AES256-SHA256-PSK-MODP1536
    "7/256,5,1,15",   # AES256-SHA256-PSK-MODP3072
    "7/256,5,1,16",   # AES256-SHA256-PSK-MODP4096
    "7/256,2,3,2",    # AES256-SHA1-RSA_SIG-MODP1024
    "7/256,2,3,5",    # AES256-SHA1-RSA_SIG-MODP1536
    "7/256,2,3,16",   # AES256-SHA1-RSA_SIG-MODP4096
    "7/256,5,3,2",    # AES256-SHA256-RSA_SIG-MODP1024
    "7/256,5,3,5",    # AES256-SHA256-RSA_SIG-MODP1536
    "7/256,5,3,16",   # AES256-SHA256-RSA_SIG-MODP4096
    "7/256,2,64221,14", # AES256-SHA1-HYBRID_RSA-MODP2048
    "7/256,5,64221,14", # AES256-SHA256-HYBRID_RSA-MODP2048
    "7/256,2,64221,2",  # AES256-SHA1-HYBRID_RSA-MODP1024
    "7/256,5,64221,2",  # AES256-SHA256-HYBRID_RSA-MODP1024

    # === AES + MD5 (Edge Cases) ===
    "7/128,1,1,14",   # AES128-MD5-PSK-MODP2048
    "7/256,1,1,14",   # AES256-MD5-PSK-MODP2048
    "7/128,1,3,14",   # AES128-MD5-RSA_SIG-MODP2048
    "7/256,1,3,14",   # AES256-MD5-RSA_SIG-MODP2048
    
    # === AES + ECP
    "7/128,5,1,19",   # AES128-SHA256-PSK-ECP256
    "7/256,5,1,19",   # AES256-SHA256-PSK-ECP256
    "7/128,5,3,19",   # AES128-SHA256-RSA_SIG-ECP256
    "7/256,5,3,19",   # AES256-SHA256-RSA_SIG-ECP256
]))

AGGRESSIVE_MODE_TRANSFORMS_FULL = list(dict.fromkeys(AGGRESSIVE_MODE_TRANSFORMS + [
    "7/128,2,1,2",    # AES128-SHA1-PSK-MODP1024
    "7/128,2,1,5",    # AES128-SHA1-PSK-MODP1536
    "7/128,2,1,15",   # AES128-SHA1-PSK-MODP3072
    "7/128,2,1,16",   # AES128-SHA1-PSK-MODP4096
    "7/128,5,1,2",    # AES128-SHA256-PSK-MODP1024
    "7/128,5,1,5",    # AES128-SHA256-PSK-MODP1536
    "7/128,5,1,15",   # AES128-SHA256-PSK-MODP3072
    "7/128,5,1,16",   # AES128-SHA256-PSK-MODP4096
    "7/256,2,1,2",    # AES256-SHA1-PSK-MODP1024
    "7/256,2,1,5",    # AES256-SHA1-PSK-MODP1536
    "7/256,2,1,15",   # AES256-SHA1-PSK-MODP3072
    "7/256,2,1,16",   # AES256-SHA1-PSK-MODP4096
    "7/256,5,1,2",    # AES256-SHA256-PSK-MODP1024
    "7/256,5,1,5",    # AES256-SHA256-PSK-MODP1536
    "7/256,5,1,15",   # AES256-SHA256-PSK-MODP3072
    "7/256,5,1,16",   # AES256-SHA256-PSK-MODP4096
    "7/192,2,1,14",   # AES192-SHA1-PSK-MODP2048
    "7/192,2,1,2",    # AES192-SHA1-PSK-MODP1024
    "7/192,5,1,14",   # AES192-SHA256-PSK-MODP2048
    "7/192,5,1,2",    # AES192-SHA256-PSK-MODP1024
    "5,2,1,2",        # 3DES-SHA1-PSK-MODP1024
    "5,2,1,5",        # 3DES-SHA1-PSK-MODP1536
    "5,2,1,14",       # 3DES-SHA1-PSK-MODP2048
    "5,1,1,2",        # 3DES-MD5-PSK-MODP1024
    "5,1,1,14",       # 3DES-MD5-PSK-MODP2048
    "1,2,1,2",        # DES-SHA1-PSK-MODP1024
    "1,2,1,5",        # DES-SHA1-PSK-MODP1536
    "1,2,1,14",       # DES-SHA1-PSK-MODP2048
    "1,1,1,2",        # DES-MD5-PSK-MODP1024
    "1,1,1,14",       # DES-MD5-PSK-MODP2048
]))

# Full cross-product spaces (used only with --fullalgs and custom args)
ENC_FULL   = ["1", "5", "7/128", "7/192", "7/256"]
HASH_FULL  = ["1", "2", "4", "5", "6"]
AUTH_FULL  = ["1", "3", "64221"]
GROUP_FULL = ["2", "5", "14", "15", "16", "19", "20", "21"]

def _build_transform_space(encs: List[str], hashes: List[str], auths: List[str], groups: List[str]) -> List[str]:
    return [f"{e},{h},{a},{g}" for e, h, a, g in product(encs, hashes, auths, groups)]

# ----------------------------- Helpers ----------------------------------
def run_command(cmd: List[str], timeout: int = 30) -> Tuple[str, str, int]:
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
HASH_ALIASES = {"MD5": "1", "SHA1": "2", "SHA-1": "2", "SHA 1": "2", "SHA256": "5", "SHA-256": "5", "SHA 256": "5"}
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
    return re.findall(r"SA=\(([^)]+)\)", handshake)

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

def _try_transform(ip: str, transform: str, aggressive: bool = False) -> str:
    base = ["ike-scan"]
    if aggressive:
        base += ["--aggressive"]
    base += ["--trans", transform, ip]
    out, _, _ = run_command(base, timeout=10)
    return _strip_banner(out)

def _transform_sets() -> Tuple[List[str], List[str]]:
    custom_main, custom_aggr = [], []
    any_custom = bool(CUSTOM_ENC or CUSTOM_HASH or CUSTOM_AUTH or CUSTOM_GROUP)
    if any_custom:
        encs = CUSTOM_ENC or ENC_FULL
        hashes = CUSTOM_HASH or HASH_FULL
        auths = CUSTOM_AUTH or AUTH_FULL
        groups = CUSTOM_GROUP or GROUP_FULL
        custom_main = _build_transform_space(encs, hashes, auths, groups)
        aggr_auths = CUSTOM_AUTH or ["1"]
        custom_aggr = _build_transform_space(encs, hashes, aggr_auths, groups)
    if ONLYCUSTOM and any_custom:
        return (list(dict.fromkeys(custom_main)), list(dict.fromkeys(custom_aggr)))
    base_main = list(MAIN_MODE_TRANSFORMS_FULL if FULLALGS else MAIN_MODE_TRANSFORMS)
    base_aggr = list(AGGRESSIVE_MODE_TRANSFORMS_FULL if FULLALGS else AGGRESSIVE_MODE_TRANSFORMS)
    if any_custom:
        base_main = list(dict.fromkeys(base_main + custom_main))
        base_aggr = list(dict.fromkeys(base_aggr + custom_aggr))
    return base_main, base_aggr

def test_transforms(vpns: Dict[str, Dict[str, Any]], ip: str) -> None:
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
    accepted_sa, accepted_keys = [], []
    total = len(transforms_aggr)
    for i, t in enumerate(transforms_aggr, 1):
        progress = (i / total) * 100
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
    if not vpns[ip].get("v2"):
        return
    out, _, _ = run_command(["ike-scan", "--ikev2", "--certreq", ip], timeout=5)
    if out:
        vpns[ip]["ikev2_certreq"] = True

# --------------------------- Analysis / Reports --------------------------
_TRANS_ENC = {"1": "DES", "5": "3DES", "7/128": "AES-128", "7/192": "AES-192", "7/256": "AES-256"}
_TRANS_HASH = {"1": "MD5", "2": "SHA1", "5": "SHA256"}
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
    if dh in _TRANS_DH and any(x in _TRANS_DH[dh] for x in {"1", "2", "5"}):
        weak.append(_TRANS_DH[dh])
    return weak

def analyze_security_flaws(vpns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    logger.info("Analyzing security flaws")
    results = {"services": {}, "summary": {}}

    for ip, data in vpns.items():
        results["services"][ip] = {
            "flaws": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "good": 0},
            "accepted_transforms": {"main": [], "aggressive": []},
            "weak_algorithms": [],
            "proof": {},  # <-- NEW: Proof section
            "meta": {
                "versions": [v for v, k in (("IKEv1", data.get("v1")), ("IKEv2", data.get("v2"))) if k],
                "implementation": data.get("showbackoff") or "N/A",
            },
        }

        # === Add IKEv1 proof ===
        if data.get("ikev1_raw_handshake"):
            results["services"][ip]["proof"]["ikev1_discovery"] = data["ikev1_raw_handshake"]

        # === Add IKEv2 proof ===
        if data.get("ikev2_raw_handshake"):
            results["services"][ip]["proof"]["ikev2_discovery"] = data["ikev2_raw_handshake"]

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

        all_keys = data.get("accepted_transform_keys_main", []) + data.get("accepted_transform_keys_aggr", [])
        decoded_weak = set()
        for key in all_keys:
            decoded_weak.update(_decode_transform_key(key))

        if "DES" in decoded_weak:
            add_finding(FLAWS["ENC_DES"], "high")
        if "3DES" in decoded_weak:
            add_finding(FLAWS["ENC_3DES"], "medium")
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
        impl = data.get("showbackoff") or "N/A"
        if impl and impl != "N/A":
            add_finding(f"{FLAWS['FING_BACKOFF']}: {impl}", "low")

        results["services"][ip]["accepted_transforms"]["main"] = list(dict.fromkeys(data.get("transforms", [])))
        results["services"][ip]["accepted_transforms"]["aggressive"] = list(dict.fromkeys(data.get("aggressive", [])))
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
    if sev == "critical": return '<span class="badge bg-danger">CRITICAL</span>'
    if sev == "high": return '<span class="badge bg-danger">HIGH</span>'
    if sev == "medium": return '<span class="badge bg-warning text-dark">MEDIUM</span>'
    if sev == "low": return '<span class="badge bg-info text-dark">LOW</span>'
    if sev == "info": return '<span class="badge bg-secondary text-dark">INFO</span>'
    if sev == "good": return '<span class="badge bg-success">GOOD</span>'

def _sev_pill(sev: str, count: int) -> str:
    sev = sev.lower()
    if sev == "critical": return f'<span class="badge rounded-pill text-bg-danger">CRITICAL {count}</span>'
    if sev == "high": return f'<span class="badge rounded-pill text-bg-danger">HIGH {count}</span>'
    if sev == "medium": return f'<span class="badge rounded-pill text-bg-warning text-dark">MEDIUM {count}</span>'
    if sev == "low": return f'<span class="badge rounded-pill text-bg-info text-dark">LOW {count}</span>'
    if sev == "info": return f'<span class="badge rounded-pill text-bg-secondary text-dark">INFO {count}</span>'
    if sev == "good": return f'<span class="badge rounded-pill text-bg-success">GOOD {count}</span>'

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
              <span class="ms-2">{_sev_pill('good', svc['severity_counts']['good'])}</span>
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

        # accepted transforms
        acc = ET.SubElement(s, "accepted_transforms")
        main = ET.SubElement(acc, "main")
        for t in svc["accepted_transforms"].get("main", []):
            ET.SubElement(main, "sa").text = str(t)
        aggr = ET.SubElement(acc, "aggressive")
        for t in svc["accepted_transforms"].get("aggressive", []):
            ET.SubElement(aggr, "sa").text = str(t)

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
        logger.info(f"  Findings: {sum(counts.values())}  ([CRITICAL] {counts['critical']}, [HIGH] {counts['high']}, [MEDIUM] {counts['medium']}, [LOW] {counts['low']}, [INFO] {counts['info']})")
        for sev in ["critical", "high", "medium", "low", "info", "good"]:
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
def scan_target(ip: str) -> Dict[str, Any]:
    logger.info(f"Starting comprehensive scan of {ip}")

    vpn_data = {
        "v1": False, "v2": False,
        "vid": [],
        "transforms": [], "aggressive": [],
        "accepted_transform_keys_main": [], "accepted_transform_keys_aggr": [],
        "showbackoff": "N/A",
    }

    vpn = {ip: vpn_data}

    check_ikev1(vpn, ip)
    check_ikev2(vpn, ip)

    if not vpn[ip].get("v1") and not vpn[ip].get("v2"):
        logger.warning(f"No IKE services found on {ip}")
        return vpn

    test_aggressive_mode(vpn, ip)
    test_ikev2_features(vpn, ip)
    test_transforms(vpn, ip)

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
    global FULLALGS, FINGERPRINT, CUSTOM_ENC, CUSTOM_HASH, CUSTOM_AUTH, CUSTOM_GROUP, ONLYCUSTOM

    class SmartFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
        pass

    parser = argparse.ArgumentParser(
        prog="ikess",
        description=(
            "ikess v1.1 - IKE Security Scanner (Sequential Mode)\n\n"
            "Scans one or more targets (IP or CIDR) sequentially with ike-scan, detects IKEv1/IKEv2,\n"
            "tests curated or expanded transform sets, optionally fingerprints backoff behavior, and\n"
            "produces XML, JSON, and HTML reports with findings and proof sections.\n\n"
            "Requirements:\n"
            "  - The external binary 'ike-scan' must be installed and in PATH.\n"
            "  - Root privileges are typically required to send raw IKE packets (use sudo).\n\n"
            "How targets are interpreted:\n"
            "  - Single IP: 192.0.2.10\n"
            "  - CIDR: 192.0.2.0/24 (all usable hosts are scanned)\n\n"
            "Scan flow per host:\n"
            "  1) IKEv1 discovery\n"
            "  2) IKEv2 discovery\n"
            "  3) Aggressive Mode tests (only if IKEv1 observed)\n"
            "  4) Main Mode transform tests (curated by default or expanded when requested)\n"
            "  5) Optional backoff fingerprinting (--fingerprint)\n\n"
            "Transform key format:\n"
            "  ENC[/bits],HASH,AUTH,GROUP\n"
            "  Example: '7/256,5,1,14' means AES-256, SHA256, PSK, MODP-2048.\n"
        ),
        formatter_class=SmartFormatter,
        epilog=(
            "Aliases you can use for --enc, --hash, --auth, --group:\n"
            "  ENC:  DES=1, 3DES=5, AES=7/128, AES128=7/128, AES192=7/192, AES256=7/256\n"
            "  HASH: MD5=1, SHA1=2, SHA-1=2, SHA 1=2, SHA256=5, SHA-256=5, SHA 256=5\n"
            "  AUTH: PSK=1, RSA=3, RSA_SIG=3, RSA-SIG=3, RSA SIG=3, HYBRID=64221, HYBRID_RSA=64221\n"
            "  DH:   G1=1,  G2=2,  G5=5,  G14=14, G15=15, G16=16\n"
            "        MODP768=1, MODP1024=2, MODP1536=5, MODP2048=14, MODP3072=15, MODP4096=16\n\n"
            "Notes:\n"
            "  - By default ikess uses a curated set of common, modern, and legacy transforms.\n"
            "  - --fullalgs switches to an expanded transform set that is larger and slower but thorough.\n"
            "  - You can add custom lists via --enc/--hash/--auth/--group; these are merged with the curated\n"
            "    or expanded set unless you also pass --onlycustom to scan only your provided items.\n"
            "  - For Aggressive Mode, only PSK is tried unless you explicitly include other --auth values.\n\n"
            "Exit codes:\n"
            "  0 success, 1 dependency or runtime error, 124 external timeout.\n\n"
            "Examples:\n"
            "  sudo ./ikess.py 10.0.0.1\n"
            "  sudo ./ikess.py 10.0.0.0/24 --fullalgs --fingerprint\n"
            "  sudo ./ikess.py 10.0.0.1 --enc DES,3DES --onlycustom\n"
            "  sudo ./ikess.py 10.0.0.1 --enc AES128,3DES,1,7/256 --hash SHA1,SHA256,1 --auth PSK,RSA --group G2,G14,16\n"
            "  sudo ./ikess.py 203.0.113.5 --enc AES256 --hash SHA256 --auth PSK --group MODP2048 --onlycustom\n"
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
            "Use the expanded transform sets. Increases coverage and scan time. The expanded sets include\n"
            "additional DES/3DES, AES bit lengths, multiple DH groups, and RSA/HYBRID combinations."
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
            "Examples: --hash SHA1,SHA256  or  --hash 2,5"
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

    args = parser.parse_args()

    CUSTOM_ENC   = _parse_list_arg(args.enc,   ENC_ALIASES)
    CUSTOM_HASH  = _parse_list_arg(args.hash,  HASH_ALIASES)
    CUSTOM_AUTH  = _parse_list_arg(args.auth,  AUTH_ALIASES)
    CUSTOM_GROUP = _parse_list_arg(args.group, GROUP_ALIASES)
    ONLYCUSTOM   = args.onlycustom
    FULLALGS     = args.fullalgs
    FINGERPRINT  = args.fingerprint

    if not check_ike_dependency():
        return 1

    logger.info("ikess v1.1 – IKE Security Scanner (Sequential Mode)")
    start = datetime.now()
    logger.info(f"Scan started at {start:%Y-%m-%d %H:%M:%S}")
    logger.info(f"Targets: {', '.join(args.targets)}")

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
