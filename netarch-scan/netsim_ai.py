#!/usr/bin/env python3
"""
NetSim AI - engine: virtual network lab + live/lab scanner + auto architecture diagram
=====================================================================================
Pure Python 3.8+ standard library. Used by app.py (Flask UI) and also runnable as a CLI.

Discovery methods
  * SNMP  : sysDescr / sysObjectID / ENTITY-MIB model  -> vendor, model, role
  * LLDP / CDP neighbour tables (via SNMP)             -> real links + port names
  * TCP port scan + banners + HTTP page title/server   -> role hints (router UI, NVR, printer ...)
  * ICMP ping + ARP table + MAC vendor (OUI)           -> devices that expose nothing (phones, IoT)
  * Default gateway                                    -> home/ISP Wi-Fi routers & ONTs (e.g. Syrotech)
                                                          with no SNMP/LLDP: hosts drawn behind the
                                                          gateway as INFERRED links (dashed)

CLI
  python netsim_ai.py demo                                   virtual campus lab + scan + report
  python netsim_ai.py scan 192.168.1.0/24                    LIVE scan of home/office LAN (gateway auto-detected)
  python netsim_ai.py scan 10.10.1.0/24 --community <ro>     LIVE scan with SNMP
  python netsim_ai.py scan 10.10.0.1 --crawl 3               start at core switch, follow LLDP/CDP
  python netsim_ai.py scan 127.20.20.0/24 --gateway 127.20.20.1   lab scan with a gateway

Optional: put IEEE 'oui.csv' (https://standards-oui.ieee.org/oui/oui.csv) next to this file
to show MAC vendor names.

Lab uses port offset 20000 (SNMP 161 -> 20161, SSH 22 -> 20022 ...) so no admin rights are
needed. Windows/Linux work as-is. macOS: add loopback aliases first, e.g.
  for i in 1 10 11 12 13 14 21 22 31 32 33 34 41 42; do sudo ifconfig lo0 alias 127.20.20.$i; done
"""
import argparse, bisect, csv, datetime, html, ipaddress, json, os, platform, random, re, socket, ssl
import subprocess, sys, threading, time, webbrowser
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

LAB_OFFSET = 20000
LAB_SUBNET = "127.20.20.0/24"
HERE = os.path.dirname(os.path.abspath(__file__))

# =====================================================================================
# 1. Minimal SNMPv2c (BER) encoder / decoder
# =====================================================================================
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def tlv(t, v):
    return bytes([t]) + _len(len(v)) + v

def ber_int(i, t=0x02):
    return tlv(t, i.to_bytes((i.bit_length() + 8) // 8 or 1, "big", signed=True))

def ber_oid(oid):
    a = [int(x) for x in oid.strip(".").split(".")]
    out = bytearray([40 * a[0] + a[1]])
    for n in a[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))

def parse(buf, i=0):
    t, l = buf[i], buf[i + 1]
    i += 2
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(buf[i:i + n], "big")
        i += n
    return t, buf[i:i + l], i + l

def items(v):
    out, i = [], 0
    while i < len(v):
        t, val, i = parse(v, i)
        out.append((t, val))
    return out

def dec_oid(v):
    a, n = [v[0] // 40, v[0] % 40], 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            a.append(n)
            n = 0
    return ".".join(map(str, a))

def dec_val(t, v):
    if t == 0x04:
        if all(32 <= c < 127 or c in (9, 10, 13) for c in v):
            return v.decode("ascii")
        return "0x" + v.hex()
    if t == 0x40 and len(v) == 4:
        return ".".join(map(str, v))
    if t == 0x06:
        return dec_oid(v)
    if t in (0x02, 0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(v, "big", signed=(t == 0x02))
    return None

def oid_t(s):
    return tuple(int(x) for x in s.strip(".").split("."))

NO_SUCH, END_MIB = b"\x80\x00", b"\x82\x00"

SYS_DESCR, SYS_OID, SYS_UPTIME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0"
SYS_CONTACT, SYS_NAME, SYS_LOC, SYS_SVC = ("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.5.0",
                                           "1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.7.0")
ENT_MODEL, ENT_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.13", "1.3.6.1.2.1.47.1.1.1.1.11"
LLDP_LOC_PORT  = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PDESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_PORT  = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PDESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_NAME  = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_DESC  = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_REM_MAN   = "1.0.8802.1.1.2.1.4.2.1.3"
CDP_CACHE      = "1.3.6.1.4.1.9.9.23.1.2.1.1"
IF_NAME        = "1.3.6.1.2.1.31.1.1.1.1"

# =====================================================================================
# 2. Sample virtual inventory (Juniper + Cisco campus)
# =====================================================================================
JUNOS_SSH, CISCO_SSH = "SSH-2.0-OpenSSH_8.6", "SSH-2.0-Cisco-1.25"
DEVICES = [
    dict(name="core-ex4400", ip=10, ports={22: JUNOS_SSH, 443: "HTTP"},
         snmp=dict(descr="Juniper Networks, Inc. ex4400-24x Ethernet Switch, kernel JUNOS 23.4R1.9",
                   oid="1.3.6.1.4.1.2636.1.1.1.4.144", svc=6, model="EX4400-24X", loc="DC Rack-A"),
         lldp=[("xe-0/0/0", "dist-c9300", "Te1/1/1"), ("xe-0/0/1", "edge-ex4000", "ge-0/0/0"),
               ("xe-0/0/2", "db-01", "eth0")]),
    dict(name="dist-c9300", ip=11, ports={22: CISCO_SSH, 443: "HTTP"},
         snmp=dict(descr="Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4",
                   oid="1.3.6.1.4.1.9.1.2494", svc=6, model="C9300-48P", loc="Floor-1 IDF"),
         lldp=[("Te1/1/1", "core-ex4400", "xe-0/0/0"), ("Gi1/0/1", "acc-c9200", "Gi1/1/1"),
               ("Gi1/0/2", "acc-ex4100", "ge-0/2/0"), ("Gi1/0/3", "web-01", "eth0")]),
    dict(name="acc-c9200", ip=12, ports={22: CISCO_SSH, 443: "HTTP"},
         snmp=dict(descr="Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4",
                   oid="1.3.6.1.4.1.9.1.2667", svc=2, model="C9200-24P", loc="Floor-1 Users"),
         lldp=[("Gi1/1/1", "dist-c9300", "Gi1/0/1"), ("Gi1/0/1", "pc-01", "eth0"), ("Gi1/0/2", "pc-02", "eth0")]),
    dict(name="acc-ex4100", ip=13, ports={22: JUNOS_SSH, 443: "HTTP"},
         snmp=dict(descr="Juniper Networks, Inc. ex4100-48mp Ethernet Switch, kernel JUNOS 23.4R1.9",
                   oid="1.3.6.1.4.1.2636.1.1.1.4.165", svc=2, model="EX4100-48MP", loc="Floor-2 PoE"),
         lldp=[("ge-0/2/0", "dist-c9300", "Gi1/0/2"), ("mge-0/0/0", "ap45-01", "eth0"),
               ("mge-0/0/1", "ap45-02", "eth0"), ("ge-0/0/10", "pc-03", "eth0")]),
    dict(name="edge-ex4000", ip=14, ports={22: JUNOS_SSH, 23: "login: "},
         snmp=dict(descr="Juniper Networks, Inc. ex4000-8p Ethernet Switch, kernel JUNOS 24.4R1.5",
                   oid="1.3.6.1.4.1.2636.1.1.1.4.170", svc=2, model="EX4000-8P", loc="Meeting Room"),
         lldp=[("ge-0/0/0", "core-ex4400", "xe-0/0/1"), ("ge-0/0/1", "mtg-room-pc", "eth0")]),
    dict(name="ap45-01", ip=21, ports={}, snmp=None, lldp=[], lldp_desc="Juniper Mist AP45 Wi-Fi 6E Access Point"),
    dict(name="ap45-02", ip=22, ports={}, snmp=None, lldp=[], lldp_desc="Juniper Mist AP45 Wi-Fi 6E Access Point"),
    dict(name="pc-01", ip=31, ports={445: "", 3389: ""}, snmp=None, lldp=[], lldp_desc="Windows 11 Enterprise"),
    dict(name="pc-02", ip=32, ports={445: ""}, snmp=None, lldp=[], lldp_desc="Windows 11 Enterprise"),
    dict(name="pc-03", ip=33, ports={445: ""}, snmp=None, lldp=[], lldp_desc="Windows 11 Enterprise"),
    dict(name="mtg-room-pc", ip=34, ports={3389: ""}, snmp=None, lldp=[], lldp_desc="Windows 11 IoT (Teams Room)"),
    dict(name="web-01", ip=41, ports={22: "SSH-2.0-OpenSSH_9.6p1 Ubuntu", 80: "HTTP", 443: "HTTP"},
         snmp=None, lldp=[], lldp_desc="Ubuntu 24.04 LTS nginx"),
    dict(name="db-01", ip=42, ports={22: "SSH-2.0-OpenSSH_9.6p1 Ubuntu", 3306: ""},
         snmp=None, lldp=[], lldp_desc="Ubuntu 24.04 LTS MariaDB"),
]

def lab_ip(d, base=LAB_SUBNET):
    if d.get("addr"):
        return d["addr"]
    return str(ipaddress.ip_network(base).network_address + d["ip"])

# =====================================================================================
# 3. LAB: SNMP agent + TCP services per virtual device (stoppable)
# =====================================================================================
class SnmpAgent(threading.Thread):
    def __init__(self, ip, port, mib, community="public"):
        super().__init__(daemon=True)
        self.addr, self.community, self.running = (ip, port), community, True
        self.mib = {oid_t(k): v for k, v in mib.items()}
        self.keys = sorted(self.mib)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sock.settimeout(0.5)

    def nxt(self, o):
        i = bisect.bisect_right(self.keys, oid_t(o))
        if i < len(self.keys):
            k = self.keys[i]
            return ".".join(map(str, k)), self.mib[k]
        return o, END_MIB

    def handle(self, data):
        _, msg, _ = parse(data)
        (_, ver), (_, comm), (pdu_t, pdu) = items(msg)
        if comm.decode(errors="ignore") != self.community:
            return None
        (_, rid), (_, a), (_, b), (_, vbl) = items(pdu)
        a, b = int.from_bytes(a, "big", signed=True), int.from_bytes(b, "big", signed=True)
        oids = [dec_oid(items(vb)[0][1]) for _, vb in items(vbl)]
        if pdu_t == 0xA0:
            res = [(o, self.mib.get(oid_t(o), NO_SUCH)) for o in oids]
        elif pdu_t == 0xA1:
            res = [self.nxt(o) for o in oids]
        elif pdu_t == 0xA5:
            res = [self.nxt(o) for o in oids[:a]]
            for o in oids[a:]:
                cur = o
                for _ in range(min(max(b, 1), 40)):
                    cur, v = self.nxt(cur)
                    res.append((cur, v))
                    if v == END_MIB:
                        break
        else:
            return None
        vbs = b"".join(tlv(0x30, ber_oid(o) + v) for o, v in res)
        body = tlv(0xA2, ber_int(int.from_bytes(rid, "big", signed=True)) + ber_int(0) + ber_int(0) + tlv(0x30, vbs))
        return tlv(0x30, ber_int(int.from_bytes(ver, "big")) + tlv(0x04, comm) + body)

    def run(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                out = self.handle(data)
                if out:
                    self.sock.sendto(out, peer)
            except Exception:
                continue
        self.sock.close()

    def stop(self):
        self.running = False

class TcpService(threading.Thread):
    """banner: 'HTTP' or 'HTTP:<page title>' -> web page, any other text -> sent on connect."""
    def __init__(self, ip, port, banner):
        super().__init__(daemon=True)
        self.banner, self.running = banner, True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(16)
        self.sock.settimeout(0.5)

    def run(self):
        while self.running:
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                c.settimeout(0.5)
                if self.banner.startswith("HTTP"):
                    try:
                        c.recv(2048)
                    except Exception:
                        pass
                    title = html.escape(self.banner[5:] if self.banner.startswith("HTTP:") else "Welcome")
                    body = f"<html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>".encode()
                    c.sendall(b"HTTP/1.1 200 OK\r\nServer: lab-httpd\r\nContent-Type: text/html\r\n"
                              b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                elif self.banner:
                    c.sendall((self.banner + "\r\n").encode())
            except Exception:
                pass
            finally:
                c.close()
        self.sock.close()

    def stop(self):
        self.running = False

def build_mib(d, ip_of, desc_of):
    s = d["snmp"]
    mib = {SYS_DESCR: tlv(0x04, s["descr"].encode()), SYS_OID: ber_oid(s["oid"]),
           SYS_UPTIME: ber_int(random.randint(10**7, 10**9), 0x43), SYS_CONTACT: tlv(0x04, b"netops@demo.local"),
           SYS_NAME: tlv(0x04, d["name"].encode()), SYS_LOC: tlv(0x04, (s.get("loc") or "").encode()),
           SYS_SVC: ber_int(int(s.get("svc") or 0)), ENT_MODEL + ".1": tlv(0x04, (s.get("model") or "").encode()),
           ENT_SERIAL + ".1": tlv(0x04, ("SN" + str(abs(hash(d["name"])))[:9]).encode())}
    for n, (lport, rname, rport) in enumerate(d["lldp"], 1):
        mib[f"{LLDP_LOC_PORT}.{n}"] = tlv(0x04, lport.encode())
        mib[f"{LLDP_REM_PORT}.0.{n}.1"] = tlv(0x04, rport.encode())
        mib[f"{LLDP_REM_NAME}.0.{n}.1"] = tlv(0x04, rname.encode())
        mib[f"{LLDP_REM_DESC}.0.{n}.1"] = tlv(0x04, desc_of.get(rname, "").encode())
        if rname in ip_of:
            mib[f"{LLDP_REM_MAN}.0.{n}.1.1.4.{ip_of[rname]}"] = ber_int(2)
    return mib

def start_lab(offset=LAB_OFFSET, community="public", devices=None, quiet=False):
    """Start virtual devices. Returns running threads. Raises RuntimeError on bind failure."""
    devices = DEVICES if devices is None else devices
    ip_of = {d["name"]: lab_ip(d) for d in devices}
    desc_of = {d["name"]: (d["snmp"]["descr"] if d["snmp"] else d.get("lldp_desc", "")) for d in devices}
    threads = []
    if not quiet:
        print(f"[LAB] Starting {len(devices)} virtual devices (port offset {offset})")
    for d in devices:
        ip = ip_of[d["name"]]
        try:
            if d["snmp"]:
                threads.append(SnmpAgent(ip, 161 + offset, build_mib(d, ip_of, desc_of), community))
            for p, banner in d["ports"].items():
                threads.append(TcpService(ip, int(p) + offset, banner))
        except OSError as e:
            stop_lab(threads)
            raise RuntimeError(f"Cannot bind {ip} for {d['name']}: {e}. "
                               "(Port in use? macOS needs loopback aliases - see README)")
        if not quiet:
            kind = d["snmp"]["model"] if d["snmp"] else d.get("lldp_desc", "")
            print(f"   {d['name']:<13} {ip:<15} {kind}")
    for t in threads:
        t.start()
    if not quiet:
        print("[LAB] Ready.\n")
    return threads

def stop_lab(threads):
    for t in threads:
        t.stop()
    for t in threads:
        if t.is_alive():
            t.join(timeout=2)
        else:
            try:
                t.sock.close()
            except Exception:
                pass

# =====================================================================================
# 4. SCANNER
# =====================================================================================
SCAN_PORTS = {22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 554: "RTSP",
              830: "NETCONF", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
              8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9100: "Printer"}
WEB_PORTS = (80, 8080, 443, 8443)
CFG = {"snmp_timeout": 0.7, "tcp_timeout": 0.4, "ping": False, "dns": False}

def snmp_req(ip, port, oids, community, pdu=0xA0, timeout=None, retries=1):
    timeout = timeout or CFG["snmp_timeout"]
    vbs = b"".join(tlv(0x30, ber_oid(o) + b"\x05\x00") for o in oids)
    pkt = tlv(0x30, ber_int(1) + tlv(0x04, community.encode()) +
              tlv(pdu, ber_int(random.randint(1, 2**30)) + ber_int(0) + ber_int(0) + tlv(0x30, vbs)))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        for _ in range(retries + 1):
            try:
                s.sendto(pkt, (ip, port))
                data, _ = s.recvfrom(65535)
                break
            except socket.timeout:
                continue
        else:
            return None
        _, msg, _ = parse(data)
        _, _, _, (_, vbl) = items(items(msg)[2][1])
        return [(dec_oid(o), dec_val(t, v)) for (_, o), (t, v) in (items(vb) for _, vb in items(vbl))]
    except (OSError, ValueError, IndexError):
        return None
    finally:
        s.close()

def snmp_walk(ip, port, base, community, limit=500):
    out, cur = [], base
    for _ in range(limit):
        r = snmp_req(ip, port, [cur], community, pdu=0xA1)
        if not r:
            break
        o, v = r[0]
        if v is None or not o.startswith(base + "."):
            break
        out.append((o[len(base) + 1:], v))
        cur = o
    return out

def tcp_probe(ip, port, timeout=None):
    timeout = timeout or CFG["tcp_timeout"]
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(0.4)
            try:
                return True, s.recv(80).decode("utf-8", "replace").strip()
            except Exception:
                return True, ""
    except OSError:
        return False, ""

# ---------------- HTTP fingerprint (router / ONT / NVR / printer web UIs) ----------------
HINT_RE = re.compile(r"(syrotech|sy-[a-z]+-[\w-]+|gpon|epon|xpon|\bont\b|\bonu\b|router|wireless|wi-?fi|"
                     r"tp-?link|d-?link|netgear|tenda|mercusys|huawei|zte|netlink|digisol|mikrotik|ubiquiti|"
                     r"nvr|dvr|hikvision|dahua|cp plus|camera|printer|laserjet|epson|canon|brother|"
                     r"synology|qnap|nas\b|fortigate|pfsense|opnsense|sophos)", re.I)

def _http_get(ip, port, path, tls, timeout):
    req = (f"GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 NetSimAI\r\n"
           f"Accept: text/html\r\nConnection: close\r\n\r\n").encode()
    raw = socket.create_connection((ip, port), timeout=timeout)
    s = raw
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            s = ctx.wrap_socket(raw)
        s.settimeout(timeout)
        s.sendall(req)
        data = b""
        while len(data) < 32768:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "replace")
    finally:
        s.close()

def http_fingerprint(ip, port, tls=False):
    timeout = max(CFG["tcp_timeout"], 1.5)
    for use_tls in ([True, False] if tls else [False]):
        path = "/"
        try:
            for _ in range(2):                                      # follow one redirect
                text = _http_get(ip, port, path, use_tls, timeout)
                head, _, body = text.partition("\r\n\r\n")
                status = re.match(r"HTTP/\S+\s+(\d+)", head)
                loc = re.search(r"^location:\s*(\S+)", head, re.I | re.M)
                meta = re.search(r"http-equiv=[\"']?refresh[^>]*url=([^\"'>\s]+)", body, re.I)
                js = re.search(r"location(?:\.href)?\s*=\s*[\"']([^\"']+)", body)
                nxt = (loc.group(1) if loc and status and status.group(1).startswith("3")
                       else meta.group(1) if meta else js.group(1) if js and len(body) < 2000 else None)
                if nxt and _ == 0:
                    u = urlparse(nxt)
                    if not u.netloc or u.hostname == ip:
                        path = (u.path or "/") if u.path.startswith("/") else "/" + u.path
                        continue
                break
        except (OSError, ssl.SSLError, ValueError):
            continue
        server = re.search(r"^server:\s*(.+)$", head, re.I | re.M)
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        hints = []
        for m in HINT_RE.findall(head + " " + body[:20000]):
            m = m.lower()
            if m not in hints:
                hints.append(m)
        return dict(port=port, server=server.group(1).strip()[:60] if server else "",
                    title=re.sub(r"\s+", " ", html.unescape(title.group(1))).strip()[:80] if title else "",
                    hints=hints[:8])
    return None

def ping(ip, timeout=1):
    osn = platform.system().lower()
    if osn == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif osn == "darwin":
        cmd = ["ping", "-c", "1", "-t", str(max(1, int(timeout))), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        return r.returncode == 0 and "ttl=" in r.stdout.lower()
    except Exception:
        return False

# ---------------- local host helpers: gateway, ARP, MAC vendor ----------------
def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""

def default_gateways():
    gws = []
    if os.path.exists("/proc/net/route"):
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if len(f) > 3 and f[1] == "00000000" and int(f[3], 16) & 2:
                gws.append(socket.inet_ntoa(int(f[2], 16).to_bytes(4, "little")))
    elif platform.system().lower() == "windows":
        gws = re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", _run(["route", "print", "-4"]), re.M)
    else:
        gws = re.findall(r"^default\s+(\d+\.\d+\.\d+\.\d+)", _run(["netstat", "-rn", "-f", "inet"]), re.M)
    return list(dict.fromkeys(gws))

def connected_networks():
    """Directly connected IPv4 networks of this PC (Linux /proc, Windows 'route print', macOS fallback)."""
    nets = []
    if os.path.exists("/proc/net/route"):
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if len(f) > 7 and f[2] == "00000000" and f[1] != "00000000":
                dst = socket.inet_ntoa(int(f[1], 16).to_bytes(4, "little"))
                mask = socket.inet_ntoa(int(f[7], 16).to_bytes(4, "little"))
                try:
                    nets.append(ipaddress.ip_network(f"{dst}/{mask}", strict=False))
                except ValueError:
                    pass
    elif platform.system().lower() == "windows":
        for dst, mask in re.findall(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+On-link",
                                    _run(["route", "print", "-4"]), re.M):
            try:
                n = ipaddress.ip_network(f"{dst}/{mask}", strict=False)
                if 8 <= n.prefixlen < 32 and not n.is_loopback and not n.is_multicast:
                    nets.append(n)
            except ValueError:
                pass
    return nets

def lan_for(gw, target=""):
    """Network the gateway serves: a CIDR in the target that contains it, else a connected network, else /24."""
    ip = ipaddress.ip_address(gw)
    for item in re.split(r"[,\s]+", target or ""):
        if "/" in item:
            try:
                n = ipaddress.ip_network(item, strict=False)
                if ip in n:
                    return n
            except ValueError:
                pass
    for n in sorted(connected_networks(), key=lambda n: -n.prefixlen):
        if ip in n:
            return n
    return ipaddress.ip_network(f"{gw}/24", strict=False)

def arp_table():
    """ip -> mac (lower, colon separated) from the OS neighbour cache."""
    out = {}
    if os.path.exists("/proc/net/arp"):
        for line in open("/proc/net/arp").read().splitlines()[1:]:
            f = line.split()
            if len(f) >= 4 and f[2] != "0x0":
                out[f[0]] = f[3].lower()
    else:
        text = _run(["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-an"])
        for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[-:][0-9a-fA-F]{1,2}){5})", text):
            out[ip] = ":".join(x.zfill(2) for x in re.split(r"[-:]", mac.lower()))
    return {ip: m for ip, m in out.items()
            if m not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and not m.startswith("01:00:5e")}

_OUI = None

def load_oui():
    global _OUI
    if _OUI is None:
        _OUI = {}
        p = os.path.join(HERE, "oui.csv")
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
                        _OUI[row[1].upper()] = row[2].strip()
    return _OUI

def mac_vendor(mac):
    if not mac:
        return ""
    if int(mac[1], 16) & 2:
        return "Private MAC"
    return load_oui().get(mac.replace(":", "")[:6].upper(), "")

def local_ips(sample_hosts=()):
    ips = set()
    try:
        ips |= set(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    for h in list(sample_hosts)[:1]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((h, 9))
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return ips

def _txt(v):
    return v if isinstance(v, str) and v and not v.startswith("0x") else ""

def norm(n):
    return re.split(r"[.(]", str(n).strip().lower())[0]

def show_ip(ip):
    return "-" if str(ip).startswith("nbr:") else ip

def read_neighbours(ip, port, community):
    """LLDP-MIB (all vendors) + CISCO-CDP-MIB."""
    nbrs, seen = [], set()
    W = lambda o: dict(snmp_walk(ip, port, o, community))
    rn = W(LLDP_REM_NAME)
    if rn:
        lid, ldesc = W(LLDP_LOC_PORT), W(LLDP_LOC_PDESC)
        rid, rdescp, rsys = W(LLDP_REM_PORT), W(LLDP_REM_PDESC), W(LLDP_REM_DESC)
        man = {}
        for k, _ in snmp_walk(ip, port, LLDP_REM_MAN, community):
            p = k.split(".")
            if len(p) >= 9 and p[3] == "1" and p[4] == "4":
                man[".".join(p[:3])] = ".".join(p[5:9])
        for key, name in rn.items():
            lp = key.split(".")[1]
            n = dict(proto="LLDP", rname=_txt(name) or f"lldp-nbr-{lp}",
                     lport=_txt(lid.get(lp)) or _txt(ldesc.get(lp)) or f"port{lp}",
                     rport=_txt(rid.get(key)) or _txt(rdescp.get(key)),
                     rdesc=_txt(rsys.get(key)), rip=man.get(key))
            seen.add((norm(n["rname"]), n["lport"]))
            nbrs.append(n)
    did = W(CDP_CACHE + ".6")
    if did:
        addr, rport, plat = W(CDP_CACHE + ".4"), W(CDP_CACHE + ".7"), W(CDP_CACHE + ".8")
        for key, name in did.items():
            ifx = key.split(".")[0]
            r = snmp_req(ip, port, [f"{IF_NAME}.{ifx}"], community)
            lport = _txt(r[0][1]) if r else ""
            a = addr.get(key, "")
            rip = (".".join(str(b) for b in bytes.fromhex(a[2:]))
                   if isinstance(a, str) and a.startswith("0x") and len(a) == 10 else None)
            n = dict(proto="CDP", rname=_txt(name) or f"cdp-nbr-{key}", lport=lport or f"ifIndex{ifx}",
                     rport=_txt(rport.get(key)), rdesc=_txt(plat.get(key)), rip=rip)
            if (norm(n["rname"]), n["lport"]) not in seen:
                nbrs.append(n)
    return nbrs

def new_dev(ip, via=None):
    return {"ip": ip, "ports": [], "banners": {}, "snmp": None, "lldp": [], "via": list(via or [])}

def probe(ip, offset, community):
    dev = new_dev(ip)
    sp = 161 + offset
    r = snmp_req(ip, sp, [SYS_DESCR, SYS_OID, SYS_NAME, SYS_SVC, SYS_LOC], community)
    if r and r[0][1]:
        dev["snmp"] = dict(zip(["descr", "oid", "name", "svc", "loc"], [v for _, v in r]))
        dev["via"].append("SNMP")
        models = [v for _, v in snmp_walk(ip, sp, ENT_MODEL, community, 20) if _txt(v)]
        dev["snmp"]["model"] = models[0] if models else ""
        dev["lldp"] = read_neighbours(ip, sp, community)
    for p in SCAN_PORTS:
        ok, banner = tcp_probe(ip, p + offset)
        if ok:
            dev["ports"].append(p)
            if banner:
                dev["banners"][p] = banner
    if dev["ports"]:
        dev["via"].append("Ports")
    for p in WEB_PORTS:
        if p in dev["ports"]:
            fp = http_fingerprint(ip, p + offset, tls=p in (443, 8443))
            if fp and (fp["title"] or fp["server"] or fp["hints"]):
                fp["port"] = p
                dev["http"] = fp
                dev["via"].append("HTTP")
                break
    if CFG["ping"] and ping(ip):
        dev["via"].append("ICMP")
    if not dev["via"]:
        return None
    if CFG["dns"]:
        try:
            dev["dns"] = socket.gethostbyaddr(ip)[0].split(".")[0]
        except Exception:
            pass
    return dev

class TargetError(ValueError):
    pass

def parse_targets(spec, max_hosts=4096):
    """'10.1.1.5' | '10.1.1.0/24' | '10.1.1.10-50' | '10.1.1.10-10.1.2.20' | 'host' | '@file' | comma/space list"""
    out = []
    for item in [x for x in re.split(r"[,\s]+", spec.strip()) if x and not x.startswith("#")]:
        if item.startswith("@"):
            try:
                out += parse_targets(open(item[1:]).read(), max_hosts)
            except OSError as e:
                raise TargetError(f"Cannot read {item[1:]}: {e}")
        elif "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise TargetError(f"Invalid network '{item}'")
            if net.num_addresses > max_hosts + 2:
                raise TargetError(f"{item} has {net.num_addresses} addresses (> max {max_hosts}).")
            out += [str(h) for h in net.hosts()] or [str(net.network_address)]
        elif re.match(r"^\d+\.\d+\.\d+\.\d+-[\d.]+$", item):
            a, b = item.split("-", 1)
            try:
                start = ipaddress.ip_address(a)
                end = ipaddress.ip_address(b if "." in b else a.rsplit(".", 1)[0] + "." + b)
            except ValueError:
                raise TargetError(f"Invalid range '{item}'")
            if int(end) < int(start) or int(end) - int(start) >= max_hosts:
                raise TargetError(f"Invalid or too large range: {item}")
            out += [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        else:
            try:
                out.append(str(ipaddress.ip_address(item)))
            except ValueError:
                try:
                    out.append(socket.gethostbyname(item))
                except OSError:
                    raise TargetError(f"Cannot resolve '{item}'")
    out = list(dict.fromkeys(out))
    if not out:
        raise TargetError("No targets given.")
    if len(out) > max_hosts:
        raise TargetError(f"{len(out)} targets exceed max {max_hosts}.")
    return out

# =====================================================================================
# 5. CLASSIFICATION
# =====================================================================================
VENDOR_OID = {"1.3.6.1.4.1.9.": "Cisco", "1.3.6.1.4.1.2636.": "Juniper", "1.3.6.1.4.1.12356.": "Fortinet",
              "1.3.6.1.4.1.25461.": "Palo Alto", "1.3.6.1.4.1.30065.": "Arista", "1.3.6.1.4.1.2620.": "Check Point",
              "1.3.6.1.4.1.11.": "HPE", "1.3.6.1.4.1.14823.": "Aruba", "1.3.6.1.4.1.14988.": "MikroTik"}
MODEL_RULES = [  # regex, vendor, model, role, tier
    (r"syrotech|\bsy-g?e?o?pon", "Syrotech", None, "Wi-Fi Router", "Gateway"),
    (r"ex4400", "Juniper", "EX4400-24X", "L3 Switch", "Core"),
    (r"ex4100", "Juniper", "EX4100-48MP", "Switch", "Access"),
    (r"ex4000", "Juniper", "EX4000-8P", "Switch", "Edge"),
    (r"c9300|cat9k_iosxe", "Cisco", "Catalyst 9300", "L3 Switch", "Distribution"),
    (r"c9200|cat9k_lite", "Cisco", "Catalyst 9200", "Switch", "Access"),
    (r"ap45|mist", "Juniper Mist", "AP45", "Wireless AP", "Wireless"),
    (r"adaptive security|\basa\b|fortigate|pan-os|\bsrx|firewall|firepower|pfsense|opnsense|sophos",
     None, None, "Firewall", "Perimeter"),
    (r"\bisr|\basr|\bmx\d|csr1000|c8[0-9]{3}|internet router", None, None, "Router", "WAN"),
    (r"gpon|epon|xpon|\bont\b|\bonu\b|tp-?link|d-?link|netgear|tenda|mercusys|digisol|wireless router|wi-?fi router",
     None, None, "Wi-Fi Router", "Gateway"),
    (r"\brouter\b|mikrotik", None, None, "Router", "WAN"),
    (r"air-c?ap|access point|\bap\d", None, None, "Wireless AP", "Wireless"),
    (r"\bnvr\b|\bdvr\b|hikvision|dahua|cp plus|ip camera|\bcctv", None, None, "IP Camera / NVR", "Endpoint"),
    (r"printer|laserjet|officejet|epson|canon|brother", None, None, "Printer", "Endpoint"),
    (r"synology|qnap|diskstation|\bnas\b", None, None, "NAS / Storage", "Endpoint"),
    (r"\bphone|\bcp-\d", None, None, "IP Phone", "Endpoint"),
    (r"nexus|catalyst|ethernet switch|\bqfx|\bex\d{4}|switch", None, None, "Switch", "Network"),
]
ROUTERISH = ("Router", "Wi-Fi Router", "Firewall", "L3 Switch")
BRANDS = [(r"syrotech", "Syrotech"), (r"tp-?link", "TP-Link"), (r"d-?link", "D-Link"), (r"netgear", "Netgear"),
          (r"tenda", "Tenda"), (r"mercusys", "Mercusys"), (r"huawei", "Huawei"), (r"\bzte\b", "ZTE"),
          (r"netlink", "Netlink"), (r"digisol", "Digisol"), (r"mikrotik", "MikroTik"), (r"ubiquiti", "Ubiquiti"),
          (r"hikvision", "Hikvision"), (r"dahua", "Dahua"), (r"cp plus", "CP Plus"),
          (r"\bhp\b|laserjet|officejet", "HP"), (r"epson", "Epson"), (r"canon", "Canon"), (r"brother", "Brother"),
          (r"synology", "Synology"), (r"qnap", "QNAP")]

def classify(d):
    s = d.get("snmp") or {}
    h = d.get("http") or {}
    text = " ".join([str(s.get("descr", "")), str(s.get("model", "")), d.get("lldp_desc", ""),
                     h.get("title", ""), h.get("server", ""), " ".join(h.get("hints", [])),
                     d.get("mac_vendor", "")]).lower()
    vendor = next((v for k, v in VENDOR_OID.items() if str(s.get("oid", "")).startswith(k)), None)
    model, role, tier = s.get("model") or None, None, "Endpoint"
    for pat, v, m, r, t in MODEL_RULES:
        if re.search(pat, text):
            vendor, model, role, tier = vendor or v, model or m, r, t
            break
    if not model:
        m = re.search(r"\b(sy-[a-z]+-[\w-]+)", text)
        model = m.group(1).upper() if m else None
    if not role and s:
        svc = int(s.get("svc") or 0)
        role = "L3 Switch" if svc & 6 == 6 else "Router" if svc & 4 else "Switch" if svc & 2 else "Network Device"
        tier = "Network"
    if not role:
        p = set(d["ports"])
        role = ("IP Camera / NVR" if 554 in p else "Printer" if 9100 in p
                else "Database Server" if p & {3306, 1433, 5432} else "Web Server" if p & {80, 443, 8080, 8443}
                else "Workstation" if p & {3389, 445} or "windows" in text else "Host")
        m = re.search(r"(windows[\w ]*|ubuntu [\d.]+|red hat[\w ]*)", d.get("lldp_desc", ""), re.I)
        model = model or (m.group(1).strip() if m else "")
    if d.get("is_gateway"):
        if role not in ROUTERISH:
            role = "Wi-Fi Router" if re.search(r"wi-?fi|wireless|wlan|\bont\b|\bonu\b|pon", text) else "Router"
        tier = "Gateway"
    if not model and h.get("title") and role in ROUTERISH + ("IP Camera / NVR", "Printer"):
        model = h["title"][:30]
    if not vendor:
        vendor = next((v for pat, v in BRANDS if re.search(pat, text)), None)
    if not vendor:
        b = " ".join(d.get("banners", {}).values()).lower()
        mv = d.get("mac_vendor", "")
        vendor = ("Cisco" if "cisco" in b else "Microsoft" if "windows" in text
                  else "Linux" if "ubuntu" in text + b or "linux" in text
                  else mv if mv and mv != "Private MAC" else "-")
    if d.get("mac_vendor") == "Private MAC" and role == "Host":
        model = "Randomized MAC (phone/laptop)"
    d.update(vendor=vendor, model=model or "-", role=role, tier=tier)
    return d

# =====================================================================================
# 6. TOPOLOGY + LAYOUT
# =====================================================================================
def build_topology(devs):
    by_ip = {d["ip"]: d for d in devs}
    for d in devs:
        if d["snmp"] and _txt(d["snmp"].get("name")):
            d["name"] = d["snmp"]["name"]
    by_name = {norm(d["name"]): d for d in devs if "name" in d}
    for d in list(devs):
        for n in d["lldp"]:
            t = (by_ip.get(n["rip"]) if n["rip"] else None) or by_name.get(norm(n["rname"]))
            if not t:
                key = n["rip"] or f"nbr:{norm(n['rname'])}"
                t = new_dev(key)
                devs.append(t)
                by_ip[key] = t
            t.setdefault("name", n["rname"])
            by_name.setdefault(norm(t["name"]), t)
            if n["rdesc"]:
                t.setdefault("lldp_desc", n["rdesc"])
            if n["proto"] not in t["via"]:
                t["via"].append(n["proto"])
            n["rid"] = t["ip"]
    for d in devs:
        d.setdefault("name", d.get("dns") or d["ip"])
        classify(d)
        if d["name"] == d["ip"] and not d["ip"].startswith("nbr:"):        # readable default name
            short = {"Wi-Fi Router": "wifi-router", "IP Camera / NVR": "camera-nvr", "Workstation": "pc",
                     "Database Server": "db", "Web Server": "web"}.get(d["role"], re.sub(r"\W+", "-", d["role"].lower()))
            d["name"] = f"{short}-{d['ip'].rsplit('.', 1)[1]}"
    edges = {}
    for d in devs:
        for n in d["lldp"]:
            if n["rid"] == d["ip"]:
                continue
            e = edges.setdefault(tuple(sorted([d["ip"], n["rid"]])), {})
            e.setdefault(d["ip"], n["lport"])
            e.setdefault(n["rid"], n["rport"])
    # ---- Gateway inference: attach every island (incl. single hosts) on the gateway's LAN to it ----
    gw = next((d for d in devs if d.get("is_gateway")), None)
    if gw:
        lan = gw.get("lan") or ipaddress.ip_network(gw["ip"] + "/24", strict=False)
        adj = {d["ip"]: set() for d in devs}
        for a, b in edges:
            adj[a].add(b)
            adj[b].add(a)
        seen = set()
        for d in devs:
            if d["ip"] in seen:
                continue
            comp, stack = [], [d["ip"]]
            while stack:
                x = stack.pop()
                if x in seen:
                    continue
                seen.add(x)
                comp.append(x)
                stack.extend(adj[x] - seen)
            if gw["ip"] in comp:
                continue
            in_lan = [x for x in comp if not x.startswith("nbr:") and ipaddress.ip_address(x) in lan]
            if not in_lan:
                continue
            head = min(comp, key=lambda x: (TIER_ORDER.get(by_ip[x]["tier"], 9), x))
            edges[tuple(sorted([gw["ip"], head]))] = {gw["ip"]: "LAN/Wi-Fi", head: "", "_inferred": True}
    return devs, edges

TIER_ORDER = {"Perimeter": 0, "Gateway": 1, "WAN": 1, "Core": 2, "Distribution": 3, "Network": 3, "Edge": 4,
              "Access": 4, "Wireless": 5, "Endpoint": 6}

def layout(devs, edges):
    by_ip = {d["ip"]: d for d in devs}
    adj = {d["ip"]: set() for d in devs}
    for a, b in edges:
        adj[a].add(b)
        adj[b].add(a)
    W, H, GAP, LVL = 176, 66, 18, 150
    pos, width, children, seen = {}, {}, {}, set()

    def w(ip):
        width[ip] = max(W, sum(w(c) for c in children[ip]) + GAP * (len(children[ip]) - 1)) if children[ip] else W
        return width[ip]

    def place(ip, x0, lvl):
        pos[ip] = (x0 + width[ip] / 2, 40 + lvl * LVL)
        x = x0
        for c in children[ip]:
            place(c, x, lvl + 1)
            x += width[c] + GAP

    x0, orphans, roots = 30, [], []
    rank = lambda ip: (0 if by_ip[ip].get("is_gateway") else 1, TIER_ORDER.get(by_ip[ip]["tier"], 9),
                       -len(adj[ip]), str(by_ip[ip]["name"]))
    for ip in sorted(adj, key=rank):
        if ip in seen:
            continue
        if not adj[ip]:
            orphans.append(ip)
            seen.add(ip)
            continue
        roots.append(ip)
        children[ip], order = [], [ip]
        seen.add(ip)
        for cur in order:
            for nb in sorted(adj[cur], key=lambda x: (TIER_ORDER.get(by_ip[x]["tier"], 9), str(by_ip[x]["name"]))):
                if nb not in seen:
                    seen.add(nb)
                    children[cur].append(nb)
                    children[nb] = []
                    order.append(nb)
        # very wide star (home router with many hosts): wrap leaf children into rows
        w(ip)
        place(ip, x0, 0)
        x0 += width[ip] + GAP * 3
    total = x0
    depth = max([p[1] for p in pos.values()] or [40 - LVL])
    per_row = max(4, int(max(total, 900) // (W + GAP)))
    for i, ip in enumerate(orphans):
        pos[ip] = (30 + W / 2 + (i % per_row) * (W + GAP), depth + LVL + 30 + (i // per_row) * (H + 30))
        children[ip] = []
    total = max(total, min(len(orphans), per_row) * (W + GAP) + 60)
    tree = {(p, c) for p, cs in children.items() for c in cs}
    root = roots[0] if roots else (orphans[0] if orphans else None)
    return pos, tree, total + 60, max([p[1] for p in pos.values()] or [0]) + H + 60, root, children, orphans

# =====================================================================================
# 7. INSIGHTS
# =====================================================================================
RISKS = {23: "Telnet enabled (clear-text management)", 3389: "RDP reachable", 445: "SMB reachable"}

def insights(devs, edges, children, root):
    by_ip = {d["ip"]: d for d in devs}
    out, vend, roles = [], {}, {}
    real = sum(1 for e in edges.values() if not e.get("_inferred"))
    inferred = len(edges) - real
    for d in devs:
        roles[d["role"]] = roles.get(d["role"], 0) + 1
        if d["tier"] != "Endpoint":
            vend[d["vendor"]] = vend.get(d["vendor"], 0) + 1
    out.append(f"Discovered <b>{len(devs)}</b> devices, <b>{real}</b> LLDP/CDP links"
               + (f" and <b>{inferred}</b> inferred gateway links" if inferred else "") + ".")
    out.append("Roles: " + ", ".join(f"{v} {k}" for k, v in sorted(roles.items(), key=lambda x: -x[1])) + ".")
    vend.pop("-", None)
    if vend:
        out.append("Network vendors: " + ", ".join(f"{k} ({v})" for k, v in vend.items()) + ".")
    if len({v for v in vend if v != "-"}) > 1:
        out.append("ℹ Multi-vendor estate - keep config standards, NTP/SNMP/AAA baselines consistent across vendors.")
    gw = next((d for d in devs if d.get("is_gateway")), None)
    spof = [by_ip[i]["name"] for i, c in children.items() if c and by_ip[i]["tier"] != "Endpoint"]
    if real == 0 and inferred:
        out.append(f"ℹ No SNMP/LLDP on gateway <b>{gw['name']}</b> (normal for home/ISP Wi-Fi routers and fibre ONTs "
                   "such as Syrotech) - links are <b>inferred</b> (dashed): every host is drawn behind the gateway; "
                   "wired vs Wi-Fi and switch ports cannot be distinguished.")
    elif real == 0:
        if gw and len(devs) == 1:
            out.append(f"ℹ Only the gateway was scanned - scan the whole LAN (e.g. "
                       f"{ipaddress.ip_network(gw['ip'] + '/24', strict=False)}) to see the devices behind it.")
        else:
            out.append("ℹ No LLDP/CDP neighbours read - enable SNMP read-only + LLDP/CDP on network devices, "
                       "scan from a core switch IP with crawl, or include the default gateway so hosts can be "
                       "linked to it.")
    elif len(edges) == len(devs) - 1 and spof:
        out.append(f"⚠ No redundant links (tree topology). Single points of failure: <b>{', '.join(spof)}</b>.")
    nbr_only = [d["name"] for d in devs if d["via"] and set(d["via"]) <= {"LLDP", "CDP"}]
    if nbr_only:
        out.append(f"✔ {len(nbr_only)} device(s) found only via LLDP/CDP neighbour tables: {', '.join(nbr_only)}.")
    arp_only = [d["name"] for d in devs if d["via"] == ["ARP"]]
    if arp_only:
        out.append(f"✔ {len(arp_only)} device(s) answered nothing but were found in the ARP table "
                   f"(phones, IoT, firewalled PCs): {', '.join(arp_only[:8])}{' …' if len(arp_only) > 8 else ''}.")
    priv = sum(1 for d in devs if d.get("mac_vendor") == "Private MAC")
    if priv:
        out.append(f"ℹ {priv} device(s) use randomized (private) MAC addresses - typical of phones/laptops on Wi-Fi.")
    no_snmp = [d["name"] for d in devs if d["tier"] not in ("Endpoint", "Wireless", "Gateway") and not d["snmp"]]
    if no_snmp:
        out.append(f"ℹ Network devices without SNMP access (model may be partial): {', '.join(no_snmp)}.")
    for d in devs:
        if d["role"] == "Wireless AP":
            up = next((by_ip[p]["name"] for p, cs in children.items() if d["ip"] in cs), "?")
            out.append(f"📶 {d['name']} ({d['model']}) powered/uplinked via <b>{up}</b> - verify PoE budget.")
            break
    for d in devs:
        if d["role"] in ("Wi-Fi Router", "Router") and d["tier"] == "Gateway":
            web = [p for p in d["ports"] if p in WEB_PORTS]
            if web and not set(web) & {443, 8443}:
                out.append(f"⚠ <b>{d['name']}</b>: admin page only on plain HTTP - change the default admin "
                           "password and avoid logging in over guest Wi-Fi.")
            elif web:
                out.append(f"ℹ <b>{d['name']}</b>: admin web UI reachable from the LAN - make sure the default "
                           "admin password has been changed.")
        if 554 in d["ports"]:
            out.append(f"⚠ <b>{d['name']}</b>: RTSP video stream (554) open - do not port-forward it to the internet.")
        for p in d["ports"]:
            if p == 23 or (p in RISKS and d["tier"] != "Endpoint") or (p == 3389 and d["tier"] == "Endpoint"):
                out.append(f"⚠ <b>{d['name']}</b> ({show_ip(d['ip'])}): {RISKS[p]}.")
    return out

# =====================================================================================
# 8. OUTPUT
# =====================================================================================
STYLE = {"Firewall": ("#c0392b", "🛡"), "Wi-Fi Router": ("#a04000", "📡"), "Router": ("#8e44ad", "🔀"),
         "L3 Switch": ("#1f4e79", "🧭"), "Switch": ("#2e86c1", "🔁"), "Network Device": ("#5d6d7e", "📦"),
         "Wireless AP": ("#d68910", "📶"), "Web Server": ("#1e8449", "🌐"), "Database Server": ("#117a65", "🗄"),
         "IP Camera / NVR": ("#6e2c00", "📹"), "Printer": ("#5b2c6f", "🖨"), "NAS / Storage": ("#1a5276", "💾"), "Workstation": ("#7f8c8d", "💻"),
         "IP Phone": ("#6c3483", "☎"), "Host": ("#95a5a6", "▪")}

def subtitle(d):
    v, m = str(d.get("vendor", "-")), str(d.get("model", "-"))
    v = "" if v == "-" else v
    m = "" if m == "-" else m
    if v and m.lower().startswith(v.lower()):
        v = ""
    return (f"{v} {m}".strip()) or d.get("role", "")

def svg_diagram(devs, edges, pos, tree, W_, H_):
    by_ip = {d["ip"]: d for d in devs}
    W, H = 176, 66
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W_}" height="{H_}" font-family="Segoe UI,Arial">']
    for (a, b), ports in edges.items():
        inf = ports.get("_inferred")
        if (a, b) in tree or (b, a) in tree:
            p, c = (a, b) if (a, b) in tree else (b, a)
            (x1, y1), (x2, y2) = pos[p], pos[c]
            y1, ym = y1 + H, (y1 + H + y2) / 2
            dash = ' stroke-dasharray="5,4"' if inf else ""
            s.append(f'<path d="M{x1},{y1} V{ym} H{x2} V{y2}" fill="none" stroke="{"#a9b4bf" if inf else "#7b8a97"}" '
                     f'stroke-width="2"{dash}><title>{"Inferred: same LAN as gateway" if inf else "LLDP/CDP link"}</title></path>')
            lbl = "inferred" if inf else f"{ports.get(p, '')} ↔ {ports.get(c, '')}"
            s.append(f'<text x="{x2 + 4}" y="{y2 - 8}" font-size="9" fill="#777">{html.escape(lbl)}</text>')
        else:
            (x1, y1), (x2, y2) = pos[a], pos[b]
            s.append(f'<line x1="{x1}" y1="{y1 + H/2}" x2="{x2}" y2="{y2 + H/2}" stroke="#c0392b" '
                     f'stroke-dasharray="6,4" stroke-width="2"><title>Redundant link</title></line>')
    for ip, (x, y) in pos.items():
        d = by_ip[ip]
        col, ic = STYLE.get(d["role"], ("#95a5a6", "▪"))
        risk = 23 in d["ports"]
        hh = d.get("http") or {}
        tip = (f"{d['name']}\n{show_ip(ip)}\n{d['vendor']} {d['model']}\nRole: {d['role']} ({d['tier']})\n"
               + (f"MAC: {d['mac']} {d.get('mac_vendor', '')}\n" if d.get("mac") else "")
               + (f"Web: {hh.get('title') or hh.get('server')}\n" if hh else "")
               + f"Identified via: {'+'.join(d['via'])}\n"
               + f"Ports: {', '.join(f'{p}/{SCAN_PORTS.get(p, p)}' for p in d['ports']) or '-'}")
        s.append(f'<g><title>{html.escape(tip)}</title>'
                 f'<rect x="{x - W/2}" y="{y}" width="{W}" height="{H}" rx="9" fill="{col}" '
                 f'stroke="{"#ff2d2d" if risk else "#ffffff"}" stroke-width="{4 if risk else 1.5}"/>'
                 f'<text x="{x - W/2 + 10}" y="{y + 22}" font-size="15">{ic}</text>'
                 f'<text x="{x - W/2 + 32}" y="{y + 21}" font-size="13" font-weight="bold" fill="#fff">{html.escape(str(d["name"])[:20])}</text>'
                 f'<text x="{x - W/2 + 32}" y="{y + 38}" font-size="10.5" fill="#eef">{html.escape(subtitle(d)[:25])}</text>'
                 f'<text x="{x - W/2 + 32}" y="{y + 54}" font-size="10" fill="#dde">{show_ip(ip)} · {d["tier"]}</text></g>')
    s.append("</svg>")
    return "".join(s)

def render_svg(devs, edges):
    pos, tree, W_, H_, *_ = layout(devs, edges)
    return svg_diagram(devs, edges, pos, tree, W_, H_)

def write_outputs(devs, edges, target, outdir, mode):
    os.makedirs(outdir, exist_ok=True)
    pos, tree, W_, H_, root, children, orphans = layout(devs, edges)
    ins = insights(devs, edges, children, root)
    svg = svg_diagram(devs, edges, pos, tree, W_, H_)
    legend = "".join(f'<span class="lg"><i style="background:{c}"></i>{ic} {r}</span>' for r, (c, ic) in STYLE.items()
                     if any(d["role"] == r for d in devs))
    if any(e.get("_inferred") for e in edges.values()):
        legend += '<span class="lg">┄ inferred link (no LLDP/CDP)</span>'
    rows = "".join(f"<tr><td>{html.escape(str(d['name']))}</td><td>{show_ip(d['ip'])}</td>"
                   f"<td>{html.escape(d.get('mac', ''))}</td><td>{html.escape(str(d['vendor']))}</td>"
                   f"<td>{html.escape(str(d['model']))}</td><td>{d['role']}</td><td>{d['tier']}</td>"
                   f"<td>{'+'.join(d['via'])}</td><td>{', '.join(SCAN_PORTS.get(p, str(p)) for p in d['ports']) or '-'}</td></tr>"
                   for d in sorted(devs, key=lambda d: (TIER_ORDER.get(d['tier'], 9), str(d['name']))))
    real = sum(1 for e in edges.values() if not e.get("_inferred"))
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>NetSim AI - {html.escape(target)}</title><style>
body{{font-family:Segoe UI,Arial;margin:0;background:#eef2f6;color:#222}}
header{{background:linear-gradient(90deg,#0b2545,#13315c,#1d4e89);color:#fff;padding:14px 26px}}
header h1{{margin:0;font-size:22px}} header p{{margin:4px 0 0;opacity:.85;font-size:13px}}
.card{{background:#fff;border-radius:10px;box-shadow:0 2px 8px #0002;margin:14px 18px;padding:14px 18px}}
.card h2{{margin:0 0 10px;font-size:16px;color:#13315c}} .dia{{overflow:auto}}
.kpi{{display:flex;gap:14px;margin:14px 18px}} .kpi div{{flex:1;background:#fff;border-radius:10px;padding:12px 16px;box-shadow:0 2px 8px #0002}}
.kpi b{{font-size:26px;color:#1d4e89;display:block}} li{{margin:6px 0;font-size:14px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th{{background:#13315c;color:#fff;text-align:left;padding:7px}}
td{{padding:6px 7px;border-bottom:1px solid #e3e8ee}} tr:hover td{{background:#f4f8fc}}
.lg{{display:inline-block;margin:0 14px 6px 0;font-size:13px}} .lg i{{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:5px;vertical-align:-1px}}
</style></head><body>
<header><h1>🛰 NetSim AI — Auto-Discovered Network Architecture</h1>
<p>Target: {html.escape(target)} &nbsp;|&nbsp; Mode: {mode} &nbsp;|&nbsp; Generated: {datetime.datetime.now():%Y-%m-%d %H:%M}</p></header>
<div class="kpi"><div><b>{len(devs)}</b>Devices</div><div><b>{real}</b>Links (LLDP/CDP)</div>
<div><b>{len(edges) - real}</b>Inferred links</div>
<div><b>{sum(d['tier'] != 'Endpoint' for d in devs)}</b>Network devices</div>
<div><b>{len({d['vendor'] for d in devs if d['tier'] != 'Endpoint'})}</b>Vendors</div></div>
<div class="card"><h2>Architecture Diagram <span style="font-weight:normal;font-size:12px;color:#777">(hover a device for details)</span></h2>
<div>{legend}</div><div class="dia">{svg}</div></div>
<div class="card"><h2>🤖 Insights</h2><ul>{''.join(f'<li>{i}</li>' for i in ins)}</ul></div>
<div class="card"><h2>Inventory</h2><table><tr><th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Model</th><th>Role</th>
<th>Tier</th><th>Identified via</th><th>Open ports</th></tr>{rows}</table></div></body></html>"""
    html_path = os.path.join(outdir, "netsim_report.html")
    open(html_path, "w", encoding="utf-8").write(page)
    nid = {d["ip"]: "n_" + re.sub(r"\W", "_", str(d["name"])) for d in devs}
    mm = ["graph TD"] + [f'  {nid[d["ip"]]}["{d["name"]}<br/>{subtitle(d)}<br/>{show_ip(d["ip"])}"]' for d in devs]
    for (a, b), p in edges.items():
        mm.append(f"  {nid[a]} -.- {nid[b]}" if p.get("_inferred")
                  else f'  {nid[a]} ---|"{p.get(a, "")} - {p.get(b, "")}"| {nid[b]}')
    open(os.path.join(outdir, "netsim_topology.mmd"), "w", encoding="utf-8").write("\n".join(mm))
    with open(os.path.join(outdir, "netsim_inventory.csv"), "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["Name", "IP", "MAC", "MACVendor", "Vendor", "Model", "Role", "Tier", "IdentifiedVia",
                     "OpenPorts", "WebTitle", "Location"])
        for d in devs:
            wr.writerow([d["name"], show_ip(d["ip"]), d.get("mac", ""), d.get("mac_vendor", ""), d["vendor"],
                         d["model"], d["role"], d["tier"], "+".join(d["via"]), " ".join(map(str, d["ports"])),
                         (d.get("http") or {}).get("title", ""), (d.get("snmp") or {}).get("loc", "")])
    json.dump({"target": target, "mode": mode, "insights": [re.sub(r"<[^>]+>", "", i) for i in ins],
               "devices": devs, "links": [{"a": a, "b": b, "inferred": bool(p.get("_inferred")),
                                           "ports": {k: v for k, v in p.items() if k != "_inferred"}}
                                          for (a, b), p in edges.items()]},
              open(os.path.join(outdir, "netsim_scan.json"), "w", encoding="utf-8"), indent=2, default=str)
    return html_path, ins

# =====================================================================================
# 9. SCAN RUNNER + CLI
# =====================================================================================
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

def is_live(hosts):
    return not all(ipaddress.ip_address(h).is_loopback for h in hosts)

def run_scan(target, offset, community, outdir, mode, live=False, crawl=0, scope=None, max_hosts=4096,
             threads=128, progress=None, gateway=None):
    """gateway: None/'' -> auto-detect on live scans, 'none' -> disabled, or an IP."""
    hosts = parse_targets(target, max_hosts)
    CFG.update(snmp_timeout=1.5 if live else 0.7, tcp_timeout=0.8 if live else 0.4, ping=live, dns=live)
    print(f"[SCAN] {target} - {len(hosts)} address(es) | SNMP community '{community}' | "
          f"port offset {offset} | {'ICMP+SNMP+TCP+HTTP+ARP' if live else 'SNMP+TCP+HTTP'}")
    t0, done, lock = time.time(), [0], threading.Lock()

    def job(ip):
        r = probe(ip, offset, community)
        with lock:
            done[0] += 1
            if progress:
                progress(done[0], len(hosts))
            if r:
                print(f"   + {ip:<16} {'+'.join(r['via'])}")
        return r

    with ThreadPoolExecutor(min(threads, max(1, len(hosts)))) as ex:
        found = [d for d in ex.map(job, hosts) if d]
    probed = set(hosts)
    allowed = [ipaddress.ip_network(s, strict=False) for s in scope] if scope else PRIVATE
    for hop in range(1, crawl + 1):
        nxt = {n["rip"] for d in found for n in d["lldp"] if n["rip"]} - probed
        nxt = [ip for ip in nxt if any(ipaddress.ip_address(ip) in net for net in allowed)][:max_hosts]
        if not nxt:
            break
        print(f"[CRAWL] hop {hop}: probing {len(nxt)} neighbour IP(s) learned via LLDP/CDP")
        probed |= set(nxt)
        with ThreadPoolExecutor(min(threads, len(nxt))) as ex:
            found += [d for d in ex.map(lambda ip: probe(ip, offset, community), nxt) if d]

    # ---- ARP: catch silent devices (phones, IoT) + MAC / vendor ----
    if live:
        arp = arp_table()
        have = {d["ip"] for d in found}
        silent = [ip for ip in hosts if ip in arp and ip not in have]
        for ip in silent:
            found.append(new_dev(ip, ["ARP"]))
            print(f"   + {ip:<16} ARP")
        for d in found:
            if d["ip"] in arp:
                d["mac"] = arp[d["ip"]]
                d["mac_vendor"] = mac_vendor(d["mac"])
        me = local_ips(hosts)
        for d in found:
            if d["ip"] in me:
                d["is_self"], d["name"] = True, f"{socket.gethostname()[:14]} (this PC)"
        if arp:
            print(f"[ARP] {len(arp)} entries in local ARP cache, {len(silent)} silent device(s) added"
                  + ("" if load_oui() else " (add oui.csv for MAC vendor names)"))

    # ---- Gateway ----
    g = (gateway or "").strip().lower()
    gws = [] if g == "none" else [gateway.strip()] if g and g != "auto" else (default_gateways() if live or g == "auto" else [])
    for gip in gws:
        if gip in hosts:
            d = next((x for x in found if x["ip"] == gip), None)
            if not d:
                d = new_dev(gip, ["Route"])
                found.append(d)
            d["is_gateway"], d["lan"] = True, lan_for(gip, target)
            print(f"[GW] Gateway {gip} (LAN {d['lan']}) is in scan range - used as LAN root")
            break
    else:
        if gws:
            print(f"[GW] Gateway {', '.join(gws)} not in scan targets - include it to link hosts to it")

    print(f"[SCAN] {len(found)} device(s), {sum(1 for d in found if d['snmp'])} via SNMP "
          f"({time.time() - t0:.1f}s). Building topology...")
    if not found:
        print("[SCAN] Nothing responded. Check reachability, firewall rules, SNMP community / ACLs.")
        return None
    devs, edges = build_topology(found)
    print(f"\n{'NAME':<20}{'IP':<16}{'VENDOR':<14}{'MODEL':<22}{'ROLE':<17}{'VIA'}")
    for d in sorted(devs, key=lambda d: (TIER_ORDER.get(d["tier"], 9), str(d["name"]))):
        print(f"{str(d['name'])[:19]:<20}{show_ip(d['ip']):<16}{str(d['vendor'])[:13]:<14}"
              f"{str(d['model'])[:21]:<22}{d['role']:<17}{'+'.join(d['via'])}")
    path, ins = write_outputs(devs, edges, target, outdir, mode)
    print("\n[INSIGHTS]")
    for i in ins:
        print("  -", re.sub(r"<[^>]+>", "", i))
    print(f"\n[DONE] Report: {os.path.abspath(path)}")
    return path

# =====================================================================================
# PUBLIC API – diagram generation from netarch application device/link dicts
# =====================================================================================

def render_diagram(devices: dict, links: dict, is_draft: bool = False):
    """
    Generate an SVG diagram and a Mermaid topology string from the netarch
    application's device/link data format (as stored in ScanContext).

    Parameters
    ----------
    devices : dict
        Mapping of device_id -> device dict.
        Recognised keys: ip, name, role, tier, vendor, model, via,
        open_ports, mac, mac_vendor, http, snmp, review_status, confidence.
    links : dict
        Mapping of link_id -> link dict.
        Recognised keys: a, b, a_port, b_port, source, review_status.
    is_draft : bool
        When True, adds a "DRAFT – pending review" watermark to the SVG.

    Returns
    -------
    (svg_str, mermaid_str) : tuple[str, str]
    """
    # --- Convert app device format -> netsim internal list ---
    devs = []
    for dev_id, dev in devices.items():
        d = {
            "ip":        dev.get("ip", dev_id),
            "name":      dev.get("name", dev_id),
            "role":      dev.get("role", "Host"),
            "tier":      dev.get("tier", "Endpoint"),
            "vendor":    dev.get("vendor") or "-",
            "model":     dev.get("model") or "-",
            "via":       list(dev.get("via") or []),
            "ports":     [int(p) for p in (dev.get("open_ports") or [])
                          if str(p).strip().lstrip("-").isdigit()],
            "mac":       dev.get("mac") or "",
            "mac_vendor": dev.get("mac_vendor") or "",
            "http":      dev.get("http") or {},
            "snmp":      dev.get("snmp") or {},
            "lldp":      [],
            "is_gateway": dev.get("tier") == "Gateway",
        }
        devs.append(d)

    # --- Convert app link format -> netsim edges dict ---
    edges = {}
    for lk, link in links.items():
        a, b = link["a"], link["b"]
        edge_key = tuple(sorted([a, b]))
        edges[edge_key] = {
            a: link.get("a_port", ""),
            b: link.get("b_port", ""),
            "_inferred": link.get("source") == "inferred",
        }

    if not devs:
        empty_svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80">'
                     '<text x="10" y="40" font-size="18" fill="#666">'
                     'No devices to display.</text></svg>')
        return empty_svg, "graph TD\n"

    # --- Build SVG via netsim layout engine ---
    pos, tree, W_, H_, *_ = layout(devs, edges)
    svg = svg_diagram(devs, edges, pos, tree, W_, H_)

    if is_draft:
        watermark = (
            f'<text x="{W_ // 2}" y="{H_ - 10}" text-anchor="middle" '
            f'font-size="14" fill="#ff000055" font-weight="bold">'
            f'DRAFT \u2013 pending review</text>'
        )
        svg = svg.replace("</svg>", watermark + "</svg>")

    # --- Build Mermaid ---
    nid = {d["ip"]: "n_" + re.sub(r"\W", "_", str(d["name"])) for d in devs}
    mm_lines = ["graph TD"]
    for d in devs:
        vendor_model = f"{d['vendor']} {d['model']}".strip().strip("-")
        label = f"{d['name']}<br/>{vendor_model}<br/>{show_ip(d['ip'])}"
        mm_lines.append(f'  {nid[d["ip"]]}["{label.strip()}"]')
    for (a, b), p in edges.items():
        if a in nid and b in nid:
            if p.get("_inferred"):
                mm_lines.append(f"  {nid[a]} -.- {nid[b]}")
            else:
                port_label = f"{p.get(a, '')} - {p.get(b, '')}".strip(" -")
                mm_lines.append(
                    f'  {nid[a]} ---|"{port_label}"| {nid[b]}' if port_label
                    else f"  {nid[a]} --- {nid[b]}"
                )
    mermaid = "\n".join(mm_lines)

    return svg, mermaid


def main():
    ap = argparse.ArgumentParser(description="NetSim AI - virtual lab, live/lab scan, auto architecture diagram")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("demo", "lab", "scan"):
        p = sub.add_parser(c)
        p.add_argument("--community", default="public")
        p.add_argument("--port-offset", type=int, default=None)
        if c == "scan":
            p.add_argument("target", nargs="?", help="IP | CIDR | range | hostname | comma list | @file")
            p.add_argument("--crawl", type=int, default=0)
            p.add_argument("--scope", nargs="*")
            p.add_argument("--max-hosts", type=int, default=4096)
            p.add_argument("--gateway", default="", help="gateway IP, 'auto' or 'none' (default auto on live scans)")
        if c != "lab":
            p.add_argument("--out", default="netsim_output")
            p.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    try:
        if a.cmd == "lab":
            start_lab(a.port_offset if a.port_offset is not None else LAB_OFFSET, a.community)
            print(f"Running. Scan from another terminal: python netsim_ai.py scan {LAB_SUBNET}  (Ctrl+C to stop)")
            while True:
                time.sleep(1)
        if a.cmd == "demo":
            off = a.port_offset if a.port_offset is not None else LAB_OFFSET
            th = start_lab(off, a.community)
            time.sleep(0.5)
            path = run_scan(LAB_SUBNET, off, a.community, a.out, "DEMO (virtual lab)")
            stop_lab(th)
        else:
            target = a.target or LAB_SUBNET
            live = is_live(parse_targets(target, a.max_hosts))
            off = a.port_offset if a.port_offset is not None else (0 if live else LAB_OFFSET)
            if live:
                print("[LIVE] Scanning real devices - make sure you have approval for these targets.")
            path = run_scan(target, off, a.community, a.out, "LIVE SCAN" if live else "LAB SCAN", live=live,
                            crawl=a.crawl, scope=a.scope, max_hosts=a.max_hosts, gateway=a.gateway)
        if path and not a.no_browser:
            webbrowser.open("file://" + os.path.abspath(path))
    except (TargetError, RuntimeError) as e:
        sys.exit(f"[ERR] {e}")
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
