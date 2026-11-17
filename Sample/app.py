#!/usr/bin/env python3
"""
NetSim AI - Flask web app
  Tab 1  Lab Devices : add / modify / clone / delete virtual devices and links, start / stop the lab,
                       load sample campus or sample home Wi-Fi, live design preview
  Tab 2  Scan        : scan the virtual lab or LIVE IPs / subnets / ranges, gateway inference for home
                       routers (e.g. Syrotech), live log, report + downloads

Run:   pip install flask
       python app.py                 -> http://127.0.0.1:5000
       python app.py --host 0.0.0.0 --port 8080
"""
import argparse, io, ipaddress, json, os, re, shutil, sys, threading, time, uuid, datetime
from flask import Flask, jsonify, request, render_template, send_from_directory, abort

import netsim_ai as ns

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE, "lab_devices.json")
SCAN_DIR = os.path.join(BASE, "scans")
os.makedirs(SCAN_DIR, exist_ok=True)

app = Flask(__name__)

# =====================================================================================
# Device templates (pre-fill the add/edit form)
#   desc = LLDP description AND the web page title for HTTP ports (used for fingerprinting)
# =====================================================================================
TEMPLATES = {
    "juniper-ex4400": dict(label="Juniper EX4400-24X (Core L3 switch)", snmp=True, svc=6, model="EX4400-24X",
        descr="Juniper Networks, Inc. ex4400-24x Ethernet Switch, kernel JUNOS 23.4R1.9",
        oid="1.3.6.1.4.1.2636.1.1.1.4.144", ports=[22, 443]),
    "juniper-ex4100": dict(label="Juniper EX4100-48MP (Access PoE switch)", snmp=True, svc=2, model="EX4100-48MP",
        descr="Juniper Networks, Inc. ex4100-48mp Ethernet Switch, kernel JUNOS 23.4R1.9",
        oid="1.3.6.1.4.1.2636.1.1.1.4.165", ports=[22, 443]),
    "juniper-ex4000": dict(label="Juniper EX4000-8P (Edge switch)", snmp=True, svc=2, model="EX4000-8P",
        descr="Juniper Networks, Inc. ex4000-8p Ethernet Switch, kernel JUNOS 24.4R1.5",
        oid="1.3.6.1.4.1.2636.1.1.1.4.170", ports=[22]),
    "cisco-c9300": dict(label="Cisco Catalyst C9300 (Distribution L3 switch)", snmp=True, svc=6, model="C9300-48P",
        descr="Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4",
        oid="1.3.6.1.4.1.9.1.2494", ports=[22, 443]),
    "cisco-c9200": dict(label="Cisco Catalyst C9200 (Access switch)", snmp=True, svc=2, model="C9200-24P",
        descr="Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4",
        oid="1.3.6.1.4.1.9.1.2667", ports=[22, 443]),
    "cisco-isr4331": dict(label="Cisco ISR4331 (WAN router)", snmp=True, svc=78, model="ISR4331/K9",
        descr="Cisco IOS XE Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4",
        oid="1.3.6.1.4.1.9.1.1861", ports=[22]),
    "cisco-asa": dict(label="Cisco ASA 5516-X (Firewall)", snmp=True, svc=76, model="ASA5516",
        descr="Cisco Adaptive Security Appliance Version 9.18(4)", oid="1.3.6.1.4.1.9.1.2114", ports=[22, 443]),
    "fortigate": dict(label="Fortinet FortiGate-100F (Firewall)", snmp=True, svc=78, model="FG100F",
        descr="FortiGate-100F v7.2.8,build1639,240313 (GA.M)", oid="1.3.6.1.4.1.12356.101.1.1004", ports=[22, 443]),
    "juniper-srx": dict(label="Juniper SRX345 (Firewall)", snmp=True, svc=76, model="SRX345",
        descr="Juniper Networks, Inc. srx345 internet router, kernel JUNOS 23.4R1.9",
        oid="1.3.6.1.4.1.2636.1.1.1.2.135", ports=[22, 443]),
    "syrotech-ont": dict(label="Syrotech GPON ONT Wi-Fi router (no SNMP/LLDP – home/ISP)", snmp=False,
        desc="Syrotech SY-GPON-2010-WADONT", ports=[80, 53]),
    "mist-ap45": dict(label="Juniper Mist AP45 (Wi-Fi AP, cloud-managed, LLDP only)", snmp=False,
        desc="Juniper Mist AP45 Wi-Fi 6E Access Point", ports=[]),
    "windows-pc": dict(label="Windows 11 PC", snmp=False, desc="Windows 11 Enterprise", ports=[445, 3389]),
    "cctv-nvr": dict(label="CCTV NVR / IP camera", snmp=False, desc="Network Video Recorder (NVR) Login", ports=[80, 554]),
    "printer": dict(label="Network printer", snmp=False, desc="HP LaserJet MFP", ports=[80, 9100]),
    "linux-web": dict(label="Linux web server (nginx)", snmp=False, desc="Ubuntu 24.04 LTS nginx", ports=[22, 80, 443]),
    "linux-db": dict(label="Linux DB server (MariaDB)", snmp=False, desc="Ubuntu 24.04 LTS MariaDB", ports=[22, 3306]),
    "custom": dict(label="Custom device", snmp=True, svc=2, model="", descr="", oid="1.3.6.1.4.1.8072.3.2.10", ports=[22]),
}
for t in TEMPLATES.values():
    for k, v in (("descr", ""), ("oid", ""), ("svc", 0), ("model", ""), ("desc", "")):
        t.setdefault(k, v)

# =====================================================================================
# Persistence + samples
# =====================================================================================
STATE_LOCK = threading.RLock()

def _dev(name, ip, tmpl, location="", **over):
    t = TEMPLATES[tmpl]
    d = dict(id=uuid.uuid4().hex[:8], name=name, ip=ip, template=tmpl, snmp=t["snmp"], descr=t["descr"],
             oid=t["oid"], svc=t["svc"], model=t["model"], location=location, desc=t["desc"], ports=list(t["ports"]))
    d.update(over)
    return d

def sample_campus():
    devices, name_id = [], {}
    tmpl_by_model = {t["model"]: k for k, t in TEMPLATES.items() if t["model"]}
    for d in ns.DEVICES:
        s = d["snmp"]
        tmpl = tmpl_by_model.get(s["model"]) if s else (
            "mist-ap45" if "AP45" in d.get("lldp_desc", "") else "windows-pc" if "Windows" in d.get("lldp_desc", "")
            else "linux-db" if 3306 in d["ports"] else "linux-web")
        nd = dict(id=uuid.uuid4().hex[:8], name=d["name"], ip=ns.lab_ip(d), template=tmpl or "custom",
                  snmp=bool(s), descr=s["descr"] if s else "", oid=s["oid"] if s else "",
                  svc=s["svc"] if s else 0, model=s["model"] if s else "", location=s["loc"] if s else "",
                  desc=d.get("lldp_desc", ""), ports=sorted(d["ports"]))
        name_id[d["name"]] = nd["id"]
        devices.append(nd)
    links, seen = [], set()
    for d in ns.DEVICES:
        for lp, rn, rp in d["lldp"]:
            key = frozenset([(d["name"], lp), (rn, rp)])
            if key not in seen:
                seen.add(key)
                links.append(dict(id=uuid.uuid4().hex[:8], a=name_id[d["name"]], a_port=lp, b=name_id[rn], b_port=rp))
    return {"devices": devices, "links": links, "community": "public", "sample": "campus"}

def sample_home():
    """Home / small office behind an ISP fibre Wi-Fi router: no SNMP, no LLDP anywhere."""
    devices = [
        _dev("syrotech-ont", "127.20.20.1", "syrotech-ont", "Hall"),
        _dev("laptop-01", "127.20.20.20", "windows-pc", desc="Windows 11 Home"),
        _dev("laptop-02", "127.20.20.21", "windows-pc", desc="Windows 11 Home", ports=[445]),
        _dev("cctv-nvr", "127.20.20.30", "cctv-nvr"),
        _dev("printer", "127.20.20.40", "printer"),
        _dev("nas-01", "127.20.20.50", "linux-web", desc="Synology DiskStation", ports=[80, 443, 445]),
    ]
    return {"devices": devices, "links": [], "community": "public", "sample": "home", "gateway": "127.20.20.1"}

def load_state():
    if os.path.exists(DATA_FILE):
        try:
            return json.load(open(DATA_FILE, encoding="utf-8"))
        except Exception:
            pass
    st = sample_campus()
    save_state(st)
    return st

def save_state(st):
    tmp = DATA_FILE + ".tmp"
    json.dump(st, open(tmp, "w", encoding="utf-8"), indent=2)
    os.replace(tmp, DATA_FILE)

STATE = load_state()

# =====================================================================================
# Lab manager
# =====================================================================================
class Lab:
    def __init__(self):
        self.threads, self.running, self.started, self.error = [], False, None, ""

    def to_engine(self):
        devs, by_id = [], {d["id"]: d for d in STATE["devices"]}
        for d in STATE["devices"]:
            lldp = []
            for l in STATE["links"]:
                if l["a"] == d["id"] and l["b"] in by_id:
                    lldp.append((l["a_port"], by_id[l["b"]]["name"], l["b_port"]))
                elif l["b"] == d["id"] and l["a"] in by_id:
                    lldp.append((l["b_port"], by_id[l["a"]]["name"], l["a_port"]))
            text = (d["descr"] + " " + d["desc"]).lower()
            ssh = (ns.CISCO_SSH if "cisco" in text else "SSH-2.0-OpenSSH_9.6p1 Ubuntu" if "ubuntu" in text
                   else ns.JUNOS_SSH if "juniper" in text else "SSH-2.0-dropbear_2022.83")
            title = d["desc"] or d["model"] or d["name"]
            ports = {p: (ssh if p == 22 else f"HTTP:{title}" if p in (80, 443, 8080, 8443)
                         else "login: " if p == 23 else "") for p in d["ports"]}
            devs.append(dict(name=d["name"], addr=d["ip"], ports=ports, lldp=lldp, lldp_desc=d["desc"],
                             snmp=dict(descr=d["descr"], oid=d["oid"], svc=int(d["svc"] or 0), model=d["model"],
                                       loc=d["location"]) if d["snmp"] else None))
        return devs

    def start(self):
        with STATE_LOCK:
            self.stop()
            try:
                self.threads = ns.start_lab(ns.LAB_OFFSET, STATE.get("community", "public"), self.to_engine(), quiet=True)
                self.running, self.started, self.error = True, time.time(), ""
            except RuntimeError as e:
                self.threads, self.running, self.error = [], False, str(e)
                raise

    def stop(self):
        if self.threads:
            ns.stop_lab(self.threads)
        self.threads, self.running, self.started = [], False, None

    def apply(self):
        if self.running:
            self.start()
            return True
        return False

    def status(self):
        return dict(running=self.running, services=len(self.threads), devices=len(STATE["devices"]),
                    links=len(STATE["links"]), subnet=ns.LAB_SUBNET, offset=ns.LAB_OFFSET,
                    uptime=int(time.time() - self.started) if self.started else 0, error=self.error,
                    community=STATE.get("community", "public"), sample=STATE.get("sample", ""),
                    gateway=STATE.get("gateway", ""))

LAB = Lab()

# =====================================================================================
# Validation
# =====================================================================================
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
OID_RE = re.compile(r"^1\.3\.6\.1(\.\d+)+$")

def validate_device(data, existing_id=None):
    errs = {}
    d = dict(
        name=str(data.get("name", "")).strip(), ip=str(data.get("ip", "")).strip(),
        template=str(data.get("template", "custom")), snmp=bool(data.get("snmp")),
        descr=str(data.get("descr", "")).strip(), oid=str(data.get("oid", "")).strip().strip("."),
        svc=data.get("svc", 0), model=str(data.get("model", "")).strip(),
        location=str(data.get("location", "")).strip(), desc=str(data.get("desc", "")).strip(), ports=[])
    if not NAME_RE.match(d["name"]):
        errs["name"] = "Use letters, digits, . _ - (max 40)."
    elif any(x["name"].lower() == d["name"].lower() and x["id"] != existing_id for x in STATE["devices"]):
        errs["name"] = "Name already exists."
    net = ipaddress.ip_network(ns.LAB_SUBNET)
    try:
        ip = ipaddress.ip_address(d["ip"])
        if ip not in net:
            errs["ip"] = f"Must be inside lab subnet {ns.LAB_SUBNET}."
        elif ip in (net.network_address, net.broadcast_address):
            errs["ip"] = "Network/broadcast address not allowed."
        elif any(x["ip"] == str(ip) and x["id"] != existing_id for x in STATE["devices"]):
            errs["ip"] = "IP already used."
        d["ip"] = str(ip)
    except ValueError:
        errs["ip"] = "Invalid IPv4 address."
    raw = data.get("ports", [])
    if isinstance(raw, str):
        raw = [x for x in re.split(r"[,\s]+", raw) if x]
    try:
        ports = sorted({int(p) for p in raw})
        if any(p < 1 or p > 65535 - ns.LAB_OFFSET for p in ports):
            raise ValueError
        d["ports"] = ports
    except (ValueError, TypeError):
        errs["ports"] = f"Comma list of ports 1-{65535 - ns.LAB_OFFSET}."
    if d["snmp"]:
        if not d["descr"]:
            errs["descr"] = "sysDescr is required for SNMP devices."
        if not OID_RE.match(d["oid"]):
            errs["oid"] = "OID like 1.3.6.1.4.1.9.1.2494"
        try:
            d["svc"] = int(d["svc"])
            if not 0 <= d["svc"] <= 127:
                raise ValueError
        except (ValueError, TypeError):
            errs["svc"] = "0-127 (2=L2 switch, 6=L3 switch, 78=router)."
    else:
        d["svc"] = 0
        if not d["ports"] and not d["desc"]:
            errs["desc"] = "Add a description (LLDP / web title) or at least one port."
    return d, errs

# =====================================================================================
# Design preview
# =====================================================================================
def design_svg():
    by_id = {d["id"]: d for d in STATE["devices"]}
    devs = []
    for d in STATE["devices"]:
        devs.append(dict(ip=d["ip"], name=d["name"], ports=d["ports"], banners={}, lldp=[], via=["Design"],
                         lldp_desc=d["desc"], http={"title": d["desc"], "server": "", "hints": []} if d["desc"] else None,
                         is_gateway=d["ip"] == STATE.get("gateway"),
                         snmp=dict(descr=d["descr"], oid=d["oid"], svc=d["svc"], model=d["model"],
                                   loc=d["location"]) if d["snmp"] else None))
    if not devs:
        return '<p class="muted">No devices yet - add one.</p>', {}
    for d in devs:
        ns.classify(d)
    edges = {}
    for l in STATE["links"]:
        if l["a"] in by_id and l["b"] in by_id:
            a, b = by_id[l["a"]]["ip"], by_id[l["b"]]["ip"]
            e = edges.setdefault(tuple(sorted([a, b])), {})
            e.setdefault(a, l["a_port"])
            e.setdefault(b, l["b_port"])
    gw = next((d for d in devs if d.get("is_gateway")), None)
    if gw:                                                    # same inference as the scanner
        linked = {x for e in edges for x in e}
        for d in devs:
            if d is not gw and d["ip"] not in linked:
                edges[tuple(sorted([gw["ip"], d["ip"]]))] = {gw["ip"]: "LAN/Wi-Fi", d["ip"]: "", "_inferred": True}
    roles = {d["ip"]: dict(role=d["role"], tier=d["tier"], vendor=d["vendor"]) for d in devs}
    return ns.render_svg(devs, edges), roles

# =====================================================================================
# Scan jobs
# =====================================================================================
class ThreadStdout(io.TextIOBase):
    """Route print() from scan threads into the job log; everything else to real stdout."""
    def __init__(self, real):
        self.real, self.local = real, threading.local()

    def write(self, s):
        buf = getattr(self.local, "buf", None)
        if buf is not None:
            buf.append(s)
        else:
            self.real.write(s)
        return len(s)

    def flush(self):
        self.real.flush()

ROUTER = ThreadStdout(sys.stdout)
sys.stdout = ROUTER
JOBS, SCAN_LOCK = {}, threading.Lock()

def load_history():
    for jid in os.listdir(SCAN_DIR):
        meta = os.path.join(SCAN_DIR, jid, "meta.json")
        if os.path.exists(meta):
            try:
                j = json.load(open(meta, encoding="utf-8"))
                j["log"] = []
                JOBS[jid] = j
            except Exception:
                pass

load_history()

def job_public(j, with_log=True):
    keys = ["id", "target", "mode", "status", "error", "created", "finished", "progress", "total", "summary",
            "community", "crawl", "gateway"]
    out = {k: j.get(k) for k in keys}
    if with_log:
        out["log"] = "".join(j.get("log", []))
    out["has_report"] = os.path.exists(os.path.join(SCAN_DIR, j["id"], "netsim_report.html"))
    return out

def run_job(j):
    ROUTER.local.buf = j["log"]
    try:
        with SCAN_LOCK:
            j["status"] = "running"
            if j["live"]:
                print("[LIVE] Scanning real devices - approval confirmed by user.")
            elif not LAB.running:
                print("[WARN] Virtual lab is stopped - start it on the Lab Devices tab for results.")

            def prog(done, total):
                j["progress"], j["total"] = done, total

            path = ns.run_scan(j["target"], j["offset"], j["community"], os.path.join(SCAN_DIR, j["id"]), j["mode"],
                               live=j["live"], crawl=j["crawl"], scope=j["scope"] or None, max_hosts=j["max_hosts"],
                               progress=prog, gateway=j["gateway"])
            if path:
                res = json.load(open(os.path.join(SCAN_DIR, j["id"], "netsim_scan.json"), encoding="utf-8"))
                devs = res["devices"]
                j["summary"] = dict(devices=len(devs), links=sum(1 for l in res["links"] if not l["inferred"]),
                                    inferred=sum(1 for l in res["links"] if l["inferred"]),
                                    snmp=sum(1 for d in devs if d.get("snmp")),
                                    network=sum(1 for d in devs if d.get("tier") != "Endpoint"),
                                    vendors=sorted({d["vendor"] for d in devs
                                                    if d.get("tier") != "Endpoint" and d["vendor"] != "-"}),
                                    insights=res["insights"])
                j["status"] = "done"
            else:
                j["status"], j["error"] = "empty", "No hosts responded."
    except Exception as e:
        j["status"], j["error"] = "error", f"{type(e).__name__}: {e}"
        print(f"[ERR] {e}")
    finally:
        ROUTER.local.buf = None
        j["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
        os.makedirs(os.path.join(SCAN_DIR, j["id"]), exist_ok=True)
        json.dump({k: v for k, v in j.items() if k != "log"},
                  open(os.path.join(SCAN_DIR, j["id"], "meta.json"), "w", encoding="utf-8"), indent=2)
        open(os.path.join(SCAN_DIR, j["id"], "scan.log"), "w", encoding="utf-8").write("".join(j["log"]))

# =====================================================================================
# Routes
# =====================================================================================
@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/templates")
def api_templates():
    return jsonify(TEMPLATES)

@app.get("/api/lab")
def api_lab():
    return jsonify(LAB.status())

@app.post("/api/lab/<action>")
def api_lab_action(action):
    try:
        if action in ("start", "restart"):
            LAB.start()
        elif action == "stop":
            LAB.stop()
        elif action == "reset":
            sample = request.args.get("sample", "campus")
            was = LAB.running
            LAB.stop()
            with STATE_LOCK:
                STATE.clear()
                STATE.update(sample_home() if sample == "home" else sample_campus())
                save_state(STATE)
            if was:
                LAB.start()
        elif action == "community":
            c = str((request.json or {}).get("community", "")).strip()
            if not c or len(c) > 64:
                return jsonify(error="Community must be 1-64 chars."), 400
            STATE["community"] = c
            save_state(STATE)
            LAB.apply()
        elif action == "gateway":
            g = str((request.json or {}).get("gateway", "")).strip()
            if g and g not in {d["ip"] for d in STATE["devices"]}:
                return jsonify(error="Gateway must be the IP of a lab device (or empty)."), 400
            STATE["gateway"] = g
            save_state(STATE)
        else:
            abort(404)
    except RuntimeError as e:
        return jsonify(error=str(e), lab=LAB.status()), 500
    return jsonify(LAB.status())

@app.get("/api/devices")
def api_devices():
    svg, roles = design_svg()
    return jsonify(devices=STATE["devices"], links=STATE["links"], design=svg, roles=roles, lab=LAB.status())

def _apply_msg():
    try:
        return "Lab restarted with changes." if LAB.apply() else ""
    except RuntimeError as e:
        return f"Saved, but lab failed to restart: {e}"

@app.post("/api/devices")
def api_device_add():
    with STATE_LOCK:
        d, errs = validate_device(request.json or {})
        if errs:
            return jsonify(errors=errs), 400
        d["id"] = uuid.uuid4().hex[:8]
        STATE["devices"].append(d)
        save_state(STATE)
    return jsonify(device=d, message=_apply_msg()), 201

@app.put("/api/devices/<did>")
def api_device_update(did):
    with STATE_LOCK:
        cur = next((x for x in STATE["devices"] if x["id"] == did), None)
        if not cur:
            return jsonify(error="Device not found."), 404
        d, errs = validate_device(request.json or {}, existing_id=did)
        if errs:
            return jsonify(errors=errs), 400
        d["id"] = did
        if STATE.get("gateway") == cur["ip"]:
            STATE["gateway"] = d["ip"]
        STATE["devices"][STATE["devices"].index(cur)] = d
        save_state(STATE)
    return jsonify(device=d, message=_apply_msg())

@app.delete("/api/devices/<did>")
def api_device_delete(did):
    with STATE_LOCK:
        cur = next((x for x in STATE["devices"] if x["id"] == did), None)
        if not cur:
            return jsonify(error="Device not found."), 404
        STATE["devices"].remove(cur)
        if STATE.get("gateway") == cur["ip"]:
            STATE["gateway"] = ""
        removed = [l for l in STATE["links"] if did in (l["a"], l["b"])]
        STATE["links"] = [l for l in STATE["links"] if did not in (l["a"], l["b"])]
        save_state(STATE)
    return jsonify(removed_links=len(removed), message=_apply_msg())

@app.post("/api/links")
def api_link_add():
    data = request.json or {}
    with STATE_LOCK:
        ids = {d["id"]: d for d in STATE["devices"]}
        a, b = data.get("a"), data.get("b")
        ap_, bp = str(data.get("a_port", "")).strip(), str(data.get("b_port", "")).strip()
        errs = {}
        if a not in ids:
            errs["a"] = "Select device A."
        if b not in ids:
            errs["b"] = "Select device B."
        if a == b and a:
            errs["b"] = "A and B must be different."
        if not re.match(r"^[\w/.:-]{1,32}$", ap_):
            errs["a_port"] = "Port name e.g. Gi1/0/1, xe-0/0/0, eth0."
        if not re.match(r"^[\w/.:-]{1,32}$", bp):
            errs["b_port"] = "Port name e.g. Gi1/0/1, xe-0/0/0, eth0."
        for l in STATE["links"]:
            if {(l["a"], l["a_port"]), (l["b"], l["b_port"])} & {(a, ap_), (b, bp)}:
                errs["a_port"] = "One of these ports is already linked."
        if errs:
            return jsonify(errors=errs), 400
        l = dict(id=uuid.uuid4().hex[:8], a=a, a_port=ap_, b=b, b_port=bp)
        STATE["links"].append(l)
        save_state(STATE)
        warn = ("Neither device has SNMP - this link will not be discoverable by the scanner."
                if not ids[a]["snmp"] and not ids[b]["snmp"] else "")
    return jsonify(link=l, warning=warn, message=_apply_msg()), 201

@app.delete("/api/links/<lid>")
def api_link_delete(lid):
    with STATE_LOCK:
        before = len(STATE["links"])
        STATE["links"] = [l for l in STATE["links"] if l["id"] != lid]
        if len(STATE["links"]) == before:
            return jsonify(error="Link not found."), 404
        save_state(STATE)
    return jsonify(message=_apply_msg())

@app.get("/api/export")
def api_export():
    return app.response_class(json.dumps(STATE, indent=2), mimetype="application/json",
                              headers={"Content-Disposition": "attachment; filename=lab_devices.json"})

@app.post("/api/import")
def api_import():
    data = request.json or {}
    if not isinstance(data.get("devices"), list) or not isinstance(data.get("links"), list):
        return jsonify(error="JSON must contain 'devices' and 'links' lists."), 400
    with STATE_LOCK:
        backup = json.loads(json.dumps(STATE))
        STATE["devices"], STATE["links"] = [], []
        for raw in data["devices"]:
            d, errs = validate_device(raw)
            if errs:
                STATE.clear()
                STATE.update(backup)
                return jsonify(error=f"Device '{raw.get('name')}': {errs}"), 400
            d["id"] = raw.get("id") or uuid.uuid4().hex[:8]
            STATE["devices"].append(d)
        ids = {d["id"] for d in STATE["devices"]}
        STATE["links"] = [l for l in data["links"] if l.get("a") in ids and l.get("b") in ids]
        STATE["community"] = data.get("community", STATE.get("community", "public"))
        STATE["gateway"] = data.get("gateway", "")
        STATE["sample"] = data.get("sample", "")
        save_state(STATE)
    return jsonify(message=_apply_msg() or "Imported.")

@app.post("/api/scan")
def api_scan():
    data = request.json or {}
    target = str(data.get("target", "")).strip()
    community = str(data.get("community") or "public").strip()
    gateway = str(data.get("gateway") or "").strip()
    try:
        crawl = max(0, min(5, int(data.get("crawl") or 0)))
        max_hosts = max(1, min(4096, int(data.get("max_hosts") or 1024)))
        hosts = ns.parse_targets(target, max_hosts)
        scope = [str(ipaddress.ip_network(s.strip(), strict=False))
                 for s in re.split(r"[,\s]+", str(data.get("scope") or "")) if s.strip()]
        if gateway.lower() not in ("", "auto", "none"):
            gateway = str(ipaddress.ip_address(gateway))
    except ns.TargetError as e:
        return jsonify(error=str(e)), 400
    except ValueError as e:
        return jsonify(error=f"Invalid input: {e}"), 400
    live = ns.is_live(hosts)
    if live and not data.get("approved"):
        return jsonify(error="Live scan: tick the approval checkbox to confirm you are authorised to scan."), 400
    if SCAN_LOCK.locked():
        return jsonify(error="A scan is already running - wait for it to finish."), 409
    off = data.get("offset")
    offset = int(off) if str(off or "").strip() != "" else (0 if live else ns.LAB_OFFSET)
    jid = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    j = dict(id=jid, target=target, community=community, crawl=crawl, scope=scope, max_hosts=max_hosts,
             offset=offset, live=live, gateway=gateway, mode="LIVE SCAN" if live else "LAB SCAN", status="queued",
             error="", created=datetime.datetime.now().isoformat(timespec="seconds"), finished=None,
             progress=0, total=len(hosts), summary=None, log=[])
    JOBS[jid] = j
    threading.Thread(target=run_job, args=(j,), daemon=True).start()
    return jsonify(job_public(j)), 202

@app.get("/api/scans")
def api_scans():
    jobs = sorted(JOBS.values(), key=lambda j: j["created"], reverse=True)
    return jsonify([job_public(j, with_log=False) for j in jobs])

@app.get("/api/scans/<jid>")
def api_scan_get(jid):
    j = JOBS.get(jid)
    if not j:
        abort(404)
    out = job_public(j)
    if not out["log"]:
        p = os.path.join(SCAN_DIR, jid, "scan.log")
        if os.path.exists(p):
            out["log"] = open(p, encoding="utf-8").read()
    return jsonify(out)

@app.delete("/api/scans/<jid>")
def api_scan_delete(jid):
    j = JOBS.get(jid)
    if not j or j["status"] in ("queued", "running"):
        return jsonify(error="Not found or still running."), 400
    shutil.rmtree(os.path.join(SCAN_DIR, jid), ignore_errors=True)
    JOBS.pop(jid, None)
    return jsonify(ok=True)

@app.get("/scans/<jid>/<path:fname>")
def scan_file(jid, fname):
    if jid not in JOBS or fname not in ("netsim_report.html", "netsim_inventory.csv", "netsim_topology.mmd",
                                       "netsim_scan.json", "scan.log"):
        abort(404)
    return send_from_directory(os.path.join(SCAN_DIR, jid), fname, as_attachment=request.args.get("dl") == "1")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="NetSim AI web app")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--start-lab", action="store_true", help="start the virtual lab on launch")
    a = ap.parse_args()
    if a.start_lab:
        try:
            LAB.start()
        except RuntimeError as e:
            print(f"[LAB] {e}")
    print(f"NetSim AI UI -> http://{a.host}:{a.port}")
    app.run(host=a.host, port=a.port, debug=False, threaded=True)
