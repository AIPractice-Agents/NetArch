"""
Device classification: vendor, model, role, tier.
Pure rules / regex, no external packages.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Tier ordering (higher = more important in tree layout)
# ---------------------------------------------------------------------------
TIER_ORDER = {
    "Perimeter": 7,
    "Gateway": 6,
    "WAN": 6,
    "Core": 5,
    "Distribution": 4,
    "Network": 4,
    "Edge": 3,
    "Access": 3,
    "Wireless": 2,
    "Endpoint": 1,
    "Unknown": 0,
}

# ---------------------------------------------------------------------------
# sysObjectID enterprise prefix -> vendor
# ---------------------------------------------------------------------------
_OID_VENDOR: List[Tuple[str, str]] = [
    ("1.3.6.1.4.1.9.",      "Cisco"),
    ("1.3.6.1.4.1.2636.",   "Juniper"),
    ("1.3.6.1.4.1.12356.",  "Fortinet"),
    ("1.3.6.1.4.1.25461.",  "Palo Alto"),
    ("1.3.6.1.4.1.30065.",  "Arista"),
    ("1.3.6.1.4.1.2620.",   "Check Point"),
    ("1.3.6.1.4.1.11.",     "HPE"),
    ("1.3.6.1.4.1.14823.",  "Aruba"),
    ("1.3.6.1.4.1.14988.",  "MikroTik"),
    ("1.3.6.1.4.1.4526.",   "Netgear"),
    ("1.3.6.1.4.1.1916.",   "Extreme"),
    ("1.3.6.1.4.1.6486.",   "Alcatel-Lucent"),
    ("1.3.6.1.4.1.890.",    "Zyxel"),
    ("1.3.6.1.4.1.8072.",   "Net-SNMP"),
    ("1.3.6.1.4.1.311.",    "Microsoft"),
    ("1.3.6.1.4.1.232.",    "HPE"),
    ("1.3.6.1.4.1.6876.",   "VMware"),
]

# Brand regex -> vendor
_BRAND_VENDOR: List[Tuple[str, str]] = [
    (r'\bcisco\b',           "Cisco"),
    (r'\bjuniper\b|\bjunos\b', "Juniper"),
    (r'\bfortinet\b|\bfortigate\b|\bfortios\b', "Fortinet"),
    (r'\bpalo\s*alto\b|\bpan-os\b|\bpanos\b', "Palo Alto"),
    (r'\barista\b|\beos\b',  "Arista"),
    (r'\bcheck\s*point\b',   "Check Point"),
    (r'\bhpe\b|\bhewlett.packard\b|\bprocurve\b', "HPE"),
    (r'\baruba\b',           "Aruba"),
    (r'\bmikrotik\b|\brouteros\b', "MikroTik"),
    (r'\bnetgear\b',         "Netgear"),
    (r'\bextreme\b',         "Extreme"),
    (r'\bubiquiti\b|\bunifi\b|\bedgeos\b', "Ubiquiti"),
    (r'\bhuawei\b|\bvrp\b',  "Huawei"),
    (r'\bsynology\b|\bdiskstation\b', "Synology"),
    (r'\bqnap\b',            "QNAP"),
    (r'\bhikvision\b',       "Hikvision"),
    (r'\bdahua\b',           "Dahua"),
    (r'\bepson\b',           "Epson"),
    (r'\bcanon\b',           "Canon"),
    (r'\bbrother\b',         "Brother"),
    (r'\bpfsense\b',         "pfSense"),
    (r'\bopnsense\b',        "OPNsense"),
    (r'\bsophos\b',          "Sophos"),
    (r'\bsonicwall\b',       "SonicWall"),
    (r'\bvmware\b',          "VMware"),
    (r'\blinux\b',           "Linux"),
    (r'\bwindows\b',         "Microsoft"),
]

# ---------------------------------------------------------------------------
# Role/tier classification rules (applied in order, first match wins)
# ---------------------------------------------------------------------------
# Each entry: (pattern, role, tier)
_ROLE_RULES: List[Tuple[str, str, str]] = [
    # Juniper
    (r'\bex4400\b',                        "L3 Switch",    "Core"),
    (r'\bex4100\b',                        "Switch",       "Access"),
    (r'\bex4000\b',                        "Switch",       "Edge"),
    (r'\bex[0-9]',                         "Switch",       "Distribution"),
    (r'\bsrx\b',                           "Firewall",     "Perimeter"),
    (r'\bmx\b|\bex9[0-9]',                 "Router",       "WAN"),
    # Cisco
    (r'\bc9300\b|\bcat9k_iosxe\b',         "L3 Switch",    "Distribution"),
    (r'\bc9200\b|\bcat9k_lite\b',          "Switch",       "Access"),
    (r'\bap45\b|\bmist\b',                 "Wireless AP",  "Wireless"),
    (r'\bcatalyst\s*9[0-9]{3}\b',          "Switch",       "Distribution"),
    (r'\bcatalyst\b',                      "Switch",       "Distribution"),
    (r'\bnexus\b',                         "Switch",       "Core"),
    (r'\basa\b',                           "Firewall",     "Perimeter"),
    (r'\bfirepower\b',                     "Firewall",     "Perimeter"),
    (r'\bisr\b|\basr\b|\bcsr1000\b|\bc8[0-9]{3}', "Router", "WAN"),
    (r'\binternet\s+router\b',             "Router",       "WAN"),
    # Fortinet
    (r'\bfortigate\b|\bfortios\b',         "Firewall",     "Perimeter"),
    # Palo Alto
    (r'\bpan-os\b|\bpanos\b',              "Firewall",     "Perimeter"),
    # pfSense / OPNsense / Sophos
    (r'\bpfsense\b|\bopnsense\b|\bsophos\b', "Firewall",   "Perimeter"),
    # Generic router indicators
    (r'\brouter\b|\bmikrotik\b',           "Router",       "Network"),
    # Wireless
    (r'\baccess\s*point\b|\bwireless\s*ap\b|\bwap\b|\barubaos\b', "Wireless AP", "Wireless"),
    # Cameras / NVR / DVR
    (r'\bnvr\b|\bdvr\b|\bip\s*camera\b|\bcamera\b|\bhikvision\b|\bdahua\b', "IP Camera / NVR", "Endpoint"),
    # Printers
    (r'\bprinter\b|\blaserjet\b|\bepson\b|\bcanon\b|\bbrother\b|\bofficejet\b', "Printer", "Endpoint"),
    # NAS / Storage
    (r'\bsynology\b|\bqnap\b|\bdiskstation\b|\bnas\b', "NAS / Storage", "Endpoint"),
    # IP Phones
    (r'\bip\s*phone\b|\bvoip\b|\bsip\b|\bcisco\s*phone\b', "IP Phone", "Endpoint"),
    # Generic switch
    (r'\bswitch\b',                        "Switch",       "Access"),
]

# Port-based fallback role
_PORT_ROLE: List[Tuple[List[int], str, str]] = [
    ([554],                           "IP Camera / NVR",  "Endpoint"),
    ([9100],                          "Printer",          "Endpoint"),
    ([1433, 3306, 5432],              "Database Server",  "Endpoint"),
    ([80, 443, 8080, 8443],           "Web Server",       "Endpoint"),
    ([3389, 445],                     "Workstation",      "Endpoint"),
]


def vendor_from_oid(sys_object_id: str) -> str:
    """Return vendor name from sysObjectID, or empty string."""
    for prefix, vendor in _OID_VENDOR:
        if sys_object_id.startswith(prefix):
            return vendor
    return ""


def vendor_from_text(text: str) -> str:
    """Return vendor name from text using brand regexes."""
    tl = text.lower()
    for pattern, vendor in _BRAND_VENDOR:
        if re.search(pattern, tl):
            return vendor
    return ""


def _combine_text(*sources: str) -> str:
    return " ".join(s for s in sources if s).lower()


def classify_device(
    sys_descr: str = "",
    sys_object_id: str = "",
    sys_name: str = "",
    sys_services: Optional[int] = None,
    entity_model: str = "",
    http_title: str = "",
    http_server: str = "",
    http_hints: Optional[List[str]] = None,
    mac_vendor: str = "",
    open_ports: Optional[List[int]] = None,
    is_gateway: bool = False,
    existing_role: str = "",
    existing_tier: str = "",
) -> Dict:
    """
    Returns dict: vendor, model, role, tier, evidence (list of strings).
    """
    evidence: List[str] = []
    open_ports = open_ports or []
    http_hints = http_hints or []

    # ------- Vendor -------
    vendor = ""
    if sys_object_id:
        vendor = vendor_from_oid(sys_object_id)
        if vendor:
            evidence.append(f"vendor={vendor} from sysObjectID {sys_object_id}")

    if not vendor:
        combo = _combine_text(sys_descr, entity_model, http_title, http_server,
                              " ".join(http_hints))
        vendor = vendor_from_text(combo)
        if vendor:
            evidence.append(f"vendor={vendor} from text match")

    if not vendor and mac_vendor and mac_vendor != "Private MAC":
        vendor = mac_vendor
        evidence.append(f"vendor={vendor} from MAC OUI")

    if not vendor:
        combo = _combine_text(*[b for b in [sys_descr, entity_model]])
        vendor = vendor_from_text(combo)
        if vendor:
            evidence.append(f"vendor={vendor} from banner/OS text")

    # ------- Model -------
    model = ""
    if entity_model:
        model = entity_model
        evidence.append(f"model={model} from ENTITY-MIB")
    if not model and sys_descr:
        # Extract first meaningful token that looks like a model number
        m = re.search(r'(?:Version\s+[\d\.]+\s*,\s*)?([A-Za-z0-9][-A-Za-z0-9/\.]+)',
                      sys_descr)
        if m:
            candidate = m.group(1).strip()
            if len(candidate) >= 3 and not candidate.lower().startswith("cisco ios"):
                model = candidate
                evidence.append(f"model={model} from sysDescr")

    # ------- Role / Tier -------
    role = ""
    tier = ""
    combo = _combine_text(sys_descr, entity_model, http_title, http_server,
                          " ".join(http_hints), model)

    for pattern, r, t in _ROLE_RULES:
        if re.search(pattern, combo):
            role = r
            tier = t
            evidence.append(f"role={role}, tier={tier} from pattern '{pattern}'")
            break

    # sysServices fallback
    if not role and sys_services is not None:
        bits = int(sys_services)
        if bits & (1 << 6):
            role, tier = "L3 Switch", "Core"
            evidence.append(f"role={role} from sysServices bit 6")
        elif bits & (1 << 4):
            role, tier = "Router", "Network"
            evidence.append(f"role={role} from sysServices bit 4")
        elif bits & (1 << 2):
            role, tier = "Switch", "Access"
            evidence.append(f"role={role} from sysServices bit 2")

    # Port fallback
    if not role and open_ports:
        for ports, r, t in _PORT_ROLE:
            if any(p in open_ports for p in ports):
                role = r
                tier = t
                evidence.append(f"role={role} from open port(s) {[p for p in ports if p in open_ports]}")
                break

    if not role:
        role = "Host"
        tier = "Endpoint"
        evidence.append("role=Host (default fallback)")

    # Gateway override
    if is_gateway:
        if role not in ("Router", "Firewall", "L3 Switch"):
            role = "Router"
            evidence.append("role=Router (is_gateway override)")
        if tier not in ("Perimeter", "Core"):
            tier = "Gateway"
            evidence.append("tier=Gateway (is_gateway override)")
        # Use web title as model for routers/cameras/printers
        if http_title and not model:
            model = http_title[:80]
            evidence.append(f"model from web title (gateway)")

    # Readable default model from title for cameras/printers
    if http_title and role in ("IP Camera / NVR", "Printer") and not model:
        model = http_title[:80]
        evidence.append(f"model from web title for {role}")

    return {
        "vendor": vendor or "-",
        "model": model or "-",
        "role": role,
        "tier": tier,
        "evidence": evidence,
    }


def default_device_name(role: str, ip: str) -> str:
    """Generate a readable default name from role and IP."""
    last = ip.split(".")[-1] if ip else "0"
    mapping = {
        "Router": f"router-{last}",
        "L3 Switch": f"l3switch-{last}",
        "Switch": f"switch-{last}",
        "Firewall": f"firewall-{last}",
        "Wireless AP": f"ap-{last}",
        "IP Camera / NVR": f"camera-nvr-{last}",
        "Printer": f"printer-{last}",
        "NAS / Storage": f"nas-{last}",
        "IP Phone": f"phone-{last}",
        "Database Server": f"db-{last}",
        "Web Server": f"web-{last}",
        "Workstation": f"pc-{last}",
    }
    return mapping.get(role, f"host-{last}")


def confidence_score(device: Dict) -> int:
    """
    Compute confidence score 0-100 for a device dict.
    device must have keys: snmp, http, mac_vendor, open_ports, via,
    seen_in_neighbour, evidence.
    """
    score = 0
    snmp = device.get("snmp", {})
    via = device.get("via", [])
    evidence = device.get("evidence", [])

    # Neighbour-only base
    if "LLDP" in via or "CDP" in via:
        if not device.get("ip") or device.get("ip", "").startswith("nbr:"):
            score = 40

    # ARP-only base
    if via == ["ARP"] and score == 0:
        score = 20

    if snmp.get("sysDescr") or snmp.get("sysObjectID") or snmp.get("sysName"):
        score += 40
    if snmp.get("entity_model"):
        score += 10
    if any("from sysObjectID" in e for e in evidence):
        score += 15
    if device.get("http", {}).get("title") or any("from text match" in e for e in evidence):
        score += 15
    if device.get("mac_vendor") and device.get("mac_vendor") != "Private MAC":
        score += 5
    if device.get("open_ports"):
        score += 5
    if device.get("seen_in_neighbour"):
        score += 10
    if device.get("rdns"):
        score += 5

    return min(100, score)
