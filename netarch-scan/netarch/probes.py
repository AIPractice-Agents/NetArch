"""
Network probes: TCP connect, HTTP fingerprint, ICMP ping, ARP cache,
gateway detection, connected-network enumeration, OUI lookup.
Standard library only.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import threading
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# OUI lookup (optional oui.csv)
# ---------------------------------------------------------------------------

_oui_lock = threading.Lock()
_oui_table: Optional[Dict[str, str]] = None  # prefix -> vendor name


def _load_oui(path: Optional[str] = None) -> Dict[str, str]:
    global _oui_table
    with _oui_lock:
        if _oui_table is not None:
            return _oui_table
        table: Dict[str, str] = {}
        candidates = [path] if path else []
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates += [
            os.path.join(here, "oui.csv"),
            os.path.join(here, "netarch", "oui.csv"),
        ]
        for cand in candidates:
            if cand and os.path.isfile(cand):
                try:
                    with open(cand, newline="", encoding="utf-8", errors="replace") as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if len(row) >= 2:
                                prefix = row[0].strip().upper().replace(":", "").replace("-", "")[:6]
                                vendor = row[1].strip()
                                if len(prefix) == 6 and vendor:
                                    table[prefix] = vendor
                    break
                except Exception:
                    pass
        _oui_table = table
        return _oui_table


def mac_vendor(mac: str, oui_path: Optional[str] = None) -> str:
    """Return vendor name for a MAC address, or empty string."""
    if not mac:
        return ""
    cleaned = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) < 6:
        return ""
    # Locally administered bit (bit 1 of first byte)
    try:
        first_byte = int(cleaned[:2], 16)
        if first_byte & 0x02:
            return "Private MAC"
    except ValueError:
        return ""
    prefix = cleaned[:6]
    table = _load_oui(oui_path)
    return table.get(prefix, "")


# ---------------------------------------------------------------------------
# TCP port probe
# ---------------------------------------------------------------------------

COMMON_PORTS = [22, 23, 53, 80, 443, 445, 554, 830, 1433, 3306, 3389, 5432, 8080, 8443, 9100]


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
    """
    Try to TCP-connect.  Returns (open, banner).
    Banner is the first 256 bytes received, stripped.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        try:
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        except Exception:
            banner = ""
        sock.close()
        return True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""


def probe_ports(host: str, ports: List[int], timeout: float = 1.0
                ) -> Tuple[List[int], Dict[int, str]]:
    """
    Probe a list of ports concurrently (via threads).
    Returns (open_ports, {port: banner}).
    """
    import concurrent.futures
    open_ports: List[int] = []
    banners: Dict[int, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), 32)) as ex:
        futures = {ex.submit(tcp_connect, host, p, timeout): p for p in ports}
        for fut, port in futures.items():
            ok, banner = fut.result()
            if ok:
                open_ports.append(port)
                if banner:
                    banners[port] = banner
    return sorted(open_ports), banners


# ---------------------------------------------------------------------------
# HTTP fingerprint
# ---------------------------------------------------------------------------

class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


BRAND_HINTS = [
    "cisco", "juniper", "aruba", "fortigate", "palo alto", "pfsense",
    "opnsense", "sophos", "mikrotik", "ubiquiti", "huawei", "router",
    "firewall", "switch", "access point", "nvr", "dvr", "hikvision",
    "dahua", "camera", "printer", "laserjet", "epson", "canon", "brother",
    "synology", "qnap",
]


def _extract_brands(text: str) -> List[str]:
    tl = text.lower()
    return [h for h in BRAND_HINTS if h in tl]


def _follow_redirect(url: str, location: str) -> str:
    """Build absolute URL from a Location header or relative path."""
    if location.startswith("http"):
        return location
    from urllib.parse import urlparse, urljoin
    return urljoin(url, location)


def http_fingerprint(host: str, port: int, timeout: float = 3.0) -> Dict:
    """
    Fetch the root page of an HTTP/HTTPS service and extract fingerprint info.
    Returns dict with keys: title, server, hints, url, error.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    result = {"title": "", "server": "", "hints": [], "url": url, "error": ""}

    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    headers = {"User-Agent": "NetArchScan"}

    def _fetch(fetch_url: str) -> Optional[bytes]:
        try:
            req = urllib.request.Request(fetch_url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            result["server"] = resp.headers.get("Server", "")
            result["url"] = fetch_url
            body = resp.read(32768)
            # check for redirect in response header (already followed by urlopen)
            return body
        except urllib.error.HTTPError as e:
            result["error"] = f"HTTP {e.code}"
            try:
                return e.read(8192)
            except Exception:
                return None
        except urllib.error.URLError as e:
            result["error"] = str(e.reason)
            return None
        except Exception as e:
            result["error"] = str(e)
            return None

    body = _fetch(url)
    if body is None:
        return result

    text = body.decode("utf-8", errors="replace")

    # meta refresh redirect
    meta_match = re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
                           text, re.IGNORECASE)
    if meta_match:
        redirect_url = _follow_redirect(url, meta_match.group(1))
        body2 = _fetch(redirect_url)
        if body2:
            text = body2.decode("utf-8", errors="replace")

    # JS location.replace / location.href single-redirect
    js_match = re.search(r'location(?:\.replace)?\s*\(\s*["\']([^"\']+)["\']', text)
    if js_match:
        redirect_url = _follow_redirect(url, js_match.group(1))
        body2 = _fetch(redirect_url)
        if body2:
            text = body2.decode("utf-8", errors="replace")

    parser = _TitleParser()
    try:
        parser.feed(text)
    except Exception:
        pass
    result["title"] = parser.title.strip()
    result["hints"] = _extract_brands(text + " " + result["title"] + " " + result["server"])
    return result


# ---------------------------------------------------------------------------
# ICMP ping (cross-platform)
# ---------------------------------------------------------------------------

def ping(host: str, timeout: float = 1.5) -> bool:
    """
    Return True if the host responds to ping.
    Uses the system ping binary and checks for 'ttl=' in output.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
        )
        output = result.stdout.decode("utf-8", errors="replace").lower()
        return "ttl=" in output
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ARP cache
# ---------------------------------------------------------------------------

def read_arp_cache() -> Dict[str, str]:
    """
    Return {ip: mac} from the system ARP cache.
    Works on Linux (/proc/net/arp) and Windows/macOS (arp -a).
    """
    result: Dict[str, str] = {}
    system = platform.system().lower()

    if system == "linux":
        try:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "0x2":  # complete entry
                        ip = parts[0]
                        mac = parts[3].lower()
                        if mac != "00:00:00:00:00:00":
                            result[ip] = mac
        except Exception:
            pass
        if result:
            return result

    # Fallback: arp -a
    try:
        cmd = ["arp", "-a"] if system != "linux" else ["arp", "-an"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      timeout=5).decode("utf-8", errors="replace")
        for line in out.splitlines():
            # Match IP and MAC in various formats
            ip_match = re.search(r'\(?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\)?', line)
            mac_match = re.search(r'([0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}'
                                   r'[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2})',
                                   line)
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1).replace("-", ":").lower()
                if mac != "00:00:00:00:00:00":
                    result[ip] = mac
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Gateway detection
# ---------------------------------------------------------------------------

def get_default_gateway() -> Optional[str]:
    """Return the default IPv4 gateway IP, or None."""
    system = platform.system().lower()

    if system == "linux":
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "00000000":  # default route
                        gw_hex = parts[2]
                        gw = socket.inet_ntoa(struct.pack("<I", int(gw_hex, 16)))
                        if gw != "0.0.0.0":
                            return gw
        except Exception:
            pass

    if system == "windows":
        try:
            out = subprocess.check_output(["route", "print", "-4"],
                                          stderr=subprocess.DEVNULL,
                                          timeout=5).decode("utf-8", errors="replace")
            for line in out.splitlines():
                # 0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>
                m = re.match(
                    r'\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)',
                    line
                )
                if m:
                    gw = m.group(1)
                    if gw not in ("0.0.0.0", ""):
                        return gw
        except Exception:
            pass

    # macOS / BSD fallback
    try:
        out = subprocess.check_output(["netstat", "-rn"],
                                      stderr=subprocess.DEVNULL,
                                      timeout=5).decode("utf-8", errors="replace")
        for line in out.splitlines():
            m = re.match(r'(?:0\.0\.0\.0|default)\s+([\d\.]+)', line)
            if m:
                gw = m.group(1)
                if gw not in ("0.0.0.0", ""):
                    return gw
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Connected networks / local interfaces
# ---------------------------------------------------------------------------

def get_local_interfaces() -> List[Dict]:
    """
    Return a list of dicts with keys: ip, netmask, network (CIDR), interface.
    Uses socket + getaddrinfo / ifconfig / ipconfig.
    """
    interfaces: List[Dict] = []

    # Try using netifaces-style via /proc/net/if_inet6 and /proc/net/fib_trie (Linux)
    # or ipconfig (Windows)
    system = platform.system().lower()

    if system == "linux":
        try:
            # Use `ip addr` if available
            out = subprocess.check_output(["ip", "addr"], stderr=subprocess.DEVNULL,
                                          timeout=5).decode("utf-8", errors="replace")
            iface = None
            for line in out.splitlines():
                m_iface = re.match(r'\d+:\s+(\S+):', line)
                if m_iface:
                    iface = m_iface.group(1)
                m_inet = re.match(r'\s+inet\s+([\d\.]+)/([\d]+)', line)
                if m_inet and iface:
                    ip = m_inet.group(1)
                    prefix = int(m_inet.group(2))
                    net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                    interfaces.append({
                        "ip": ip,
                        "netmask": str(net.netmask),
                        "network": str(net),
                        "interface": iface,
                    })
        except Exception:
            pass

    if system == "windows" or not interfaces:
        try:
            cmd = "ipconfig" if system == "windows" else "ifconfig"
            out = subprocess.check_output([cmd], stderr=subprocess.DEVNULL,
                                          timeout=5).decode("utf-8", errors="replace")
            ip = mask = iface_name = None
            for line in out.splitlines():
                m_iface = re.match(r'^(\S.*):$', line)
                if m_iface:
                    iface_name = m_iface.group(1)
                m_ip = re.search(r'IPv4[^:]*:\s*([\d\.]+)', line) or \
                       re.search(r'inet\s+([\d\.]+)', line)
                if m_ip:
                    ip = m_ip.group(1)
                m_mask = re.search(r'Subnet Mask[^:]*:\s*([\d\.]+)', line) or \
                         re.search(r'netmask\s+([\d\.]+)', line)
                if m_mask:
                    mask = m_mask.group(1)
                if ip and mask:
                    try:
                        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        if not net.is_loopback:
                            interfaces.append({
                                "ip": ip,
                                "netmask": mask,
                                "network": str(net),
                                "interface": iface_name or "unknown",
                            })
                    except Exception:
                        pass
                    ip = mask = None
        except Exception:
            pass

    return interfaces


# ---------------------------------------------------------------------------
# Self-identification
# ---------------------------------------------------------------------------

def get_local_ips() -> Set[str]:
    """Return all local IPv4 addresses."""
    ips: Set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            if info[0] == socket.AF_INET:
                ips.add(info[4][0])
    except Exception:
        pass
    for iface in get_local_interfaces():
        ips.add(iface["ip"])
    return ips


def get_local_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    """Return the reverse-DNS name for an IP, or empty string."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------------
# IP/CIDR/range target parsing
# ---------------------------------------------------------------------------

class TargetError(ValueError):
    pass


def parse_targets(raw: str, max_hosts: int = 4096) -> List[str]:
    """
    Parse a target specification and return a list of unique IP strings.
    Supports: single IP, CIDR, range (10.1.1.10-60 or 10.1.1.10-10.1.1.60),
    hostname, comma/space-separated list, @filename.
    Raises TargetError if the resulting list is larger than max_hosts.
    """
    targets: List[str] = []

    # Expand @file
    parts = re.split(r'[,\s]+', raw.strip())
    expanded: List[str] = []
    for part in parts:
        if not part:
            continue
        if part.startswith("@"):
            filepath = part[1:]
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            expanded.append(line)
            except OSError as e:
                raise TargetError(f"Cannot read file {filepath}: {e}")
        else:
            expanded.append(part)

    seen: Set[str] = set()

    def add(ip: str):
        if ip not in seen:
            seen.add(ip)
            targets.append(ip)
        if len(targets) > max_hosts:
            raise TargetError(f"Target list exceeds max_hosts={max_hosts}")

    for item in expanded:
        # CIDR
        if "/" in item:
            try:
                net = ipaddress.IPv4Network(item, strict=False)
                for host in net.hosts():
                    add(str(host))
            except ValueError:
                raise TargetError(f"Invalid CIDR: {item}")
        # Range: 10.1.1.10-60 or 10.1.1.10-10.1.1.60
        elif "-" in item:
            parts2 = item.split("-", 1)
            start_ip = parts2[0]
            end_part = parts2[1]
            try:
                start = int(ipaddress.IPv4Address(start_ip))
            except ValueError:
                raise TargetError(f"Invalid range start: {start_ip}")
            # end is a full IP or just the last octet
            if "." in end_part:
                try:
                    end = int(ipaddress.IPv4Address(end_part))
                except ValueError:
                    raise TargetError(f"Invalid range end: {end_part}")
            else:
                try:
                    last_octet = int(end_part)
                    prefix = ".".join(start_ip.split(".")[:3])
                    end = int(ipaddress.IPv4Address(f"{prefix}.{last_octet}"))
                except (ValueError, IndexError):
                    raise TargetError(f"Invalid range: {item}")
            if start > end:
                raise TargetError(f"Range start > end: {item}")
            for n in range(start, end + 1):
                add(str(ipaddress.IPv4Address(n)))
        # Single IP or hostname
        else:
            try:
                ipaddress.IPv4Address(item)
                add(item)
            except ValueError:
                # Resolve hostname
                try:
                    ip = socket.gethostbyname(item)
                    add(ip)
                except socket.gaierror:
                    raise TargetError(f"Cannot resolve hostname: {item}")

    return targets


def is_loopback_target(targets: List[str]) -> bool:
    """Return True if every target is a loopback (127.x.x.x) address."""
    if not targets:
        return False
    for t in targets:
        try:
            if not ipaddress.IPv4Address(t).is_loopback:
                return False
        except ValueError:
            return False
    return True


def auto_port_offset(targets: List[str]) -> int:
    """Return 20000 if all targets are loopback, else 0."""
    return 20000 if is_loopback_target(targets) else 0
