"""
Agent 1 – Discovery Agent
Find which targets are alive: SNMP quick-GET, TCP port probes, ICMP ping,
ARP cache, gateway detection.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Set

from netarch.agents.base import BaseAgent
from netarch.context import ScanContext
from netarch.probes import (
    COMMON_PORTS,
    get_default_gateway,
    get_local_hostname,
    get_local_interfaces,
    get_local_ips,
    parse_targets,
    ping,
    read_arp_cache,
    tcp_connect,
    TargetError,
)
from netarch.snmp import snmp_get, SNMPError, OID_sysDescr


class DiscoveryAgent(BaseAgent):
    name = "discovery"
    title = "Discovery"
    description = "Find which targets are alive via SNMP, TCP, ICMP and ARP."

    # Default ports to probe
    PROBE_PORTS = COMMON_PORTS

    def run(
        self,
        ctx: ScanContext,
        log: Callable[[str], None],
        progress: Callable[[int, int], None],
    ) -> Dict[str, Any]:
        t0 = time.time()
        settings = ctx.settings
        offset = settings.get("offset", 0)
        community = settings.get("community", "public")
        live_mode = settings.get("live", False)
        max_hosts = settings.get("max_hosts", 4096)
        gw_option = settings.get("gateway", "auto")

        # ------------------------------------------------------------------
        # 1. Parse targets
        # ------------------------------------------------------------------
        raw_target = settings.get("target", "")
        try:
            targets = parse_targets(raw_target, max_hosts=max_hosts)
        except TargetError as e:
            ctx.set_status("error", str(e))
            raise

        ctx.settings["hosts"] = targets
        self._log(log, f"Parsed {len(targets)} target(s) from: {raw_target!r}")

        # ------------------------------------------------------------------
        # 2. Live mode: read ARP cache and add IPs only in ARP
        # ------------------------------------------------------------------
        arp_cache: Dict[str, str] = {}  # ip -> mac
        if live_mode:
            arp_cache = read_arp_cache()
            arp_only = set(arp_cache.keys()) - set(targets)
            # Only add ARP entries within the target subnets or on the same /24
            target_nets = []
            for t in targets:
                try:
                    target_nets.append(ipaddress.IPv4Network(t + "/24", strict=False))
                except Exception:
                    pass
            for ip in list(arp_only):
                try:
                    addr = ipaddress.IPv4Address(ip)
                    if any(addr in net for net in target_nets):
                        targets.append(ip)
                        self._log(log, f"  + {ip} via ARP")
                except Exception:
                    pass

        # Deduplicate
        seen: Set[str] = set()
        unique_targets: List[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)
        targets = unique_targets

        # ------------------------------------------------------------------
        # 3. Identify local IPs
        # ------------------------------------------------------------------
        local_ips = get_local_ips()
        local_hostname = get_local_hostname()

        # ------------------------------------------------------------------
        # 4. Probe each host in parallel
        # ------------------------------------------------------------------
        total = len(targets)
        completed = 0
        results: Dict[str, Dict] = {}

        def probe_host(ip: str) -> Optional[Dict]:
            dev: Dict = {
                "ip": ip,
                "mac": arp_cache.get(ip, ""),
                "open_ports": [],
                "banners": {},
                "via": [],
                "snmp": {},
                "is_local": ip in local_ips,
            }

            # Quick SNMP GET sysDescr
            snmp_port = 161 + offset
            try:
                res = snmp_get(ip, [OID_sysDescr], community=community,
                               port=snmp_port, timeout=1.5, retries=0)
                if res:
                    dev["snmp"] = {"sysDescr": res.get(OID_sysDescr, "")}
                    dev["via"].append("SNMP")
            except SNMPError:
                pass

            # TCP port probe
            port_results: Dict[int, bool] = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex2:
                port_futures = {
                    ex2.submit(tcp_connect, ip, p + offset, 1.0): p
                    for p in self.PROBE_PORTS
                }
                for fut, p in port_futures.items():
                    ok, banner = fut.result()
                    if ok:
                        actual_port = p + offset
                        dev["open_ports"].append(actual_port)
                        if banner:
                            dev["banners"][actual_port] = banner
                        if "Ports" not in dev["via"]:
                            dev["via"].append("Ports")

            # Ping (live mode only)
            if live_mode and not dev["via"]:
                if ping(ip, timeout=1.5):
                    dev["via"].append("ICMP")

            # Mark ARP source
            if ip in arp_cache and "ARP" not in dev["via"]:
                dev["via"].append("ARP")

            if dev["via"] or ip in arp_cache:
                return dev
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            future_map = {ex.submit(probe_host, ip): ip for ip in targets}
            for fut in concurrent.futures.as_completed(future_map):
                ip = future_map[fut]
                completed += 1
                progress(completed, total)
                try:
                    dev = fut.result()
                except Exception as e:
                    self._log(log, f"  ! Error probing {ip}: {e}")
                    dev = None
                if dev:
                    if dev.get("is_local"):
                        dev["name"] = f"{local_hostname} (this PC)"
                    via_str = "+".join(dev.get("via", []))
                    self._log(log, f"  + {ip} via {via_str}")
                    results[ip] = dev

        # ------------------------------------------------------------------
        # 5. Gateway detection
        # ------------------------------------------------------------------
        gateway_ip: Optional[str] = None
        if gw_option == "none":
            gateway_ip = None
        elif gw_option == "auto":
            if live_mode:
                gateway_ip = get_default_gateway()
                if gateway_ip:
                    self._log(log, f"  Gateway detected: {gateway_ip}")
        elif gw_option:
            gateway_ip = gw_option

        # Determine gateway LAN
        gateway_lan: Optional[str] = None
        if gateway_ip:
            # Find target CIDR containing the gateway
            raw_target_stripped = raw_target.strip()
            if "/" in raw_target_stripped:
                try:
                    net = ipaddress.IPv4Network(raw_target_stripped, strict=False)
                    if ipaddress.IPv4Address(gateway_ip) in net:
                        gateway_lan = str(net)
                except Exception:
                    pass
            if not gateway_lan:
                # connected network
                for iface in get_local_interfaces():
                    try:
                        net = ipaddress.IPv4Network(iface["network"], strict=False)
                        if ipaddress.IPv4Address(gateway_ip) in net:
                            gateway_lan = str(net)
                            break
                    except Exception:
                        pass
            if not gateway_lan:
                gateway_lan = str(ipaddress.IPv4Network(
                    f"{gateway_ip}/24", strict=False))

        # Mark gateway device
        if gateway_ip and gateway_ip in results:
            results[gateway_ip]["is_gateway"] = True
            results[gateway_ip]["lan"] = gateway_lan
            if gateway_ip not in results[gateway_ip].get("via", []):
                pass  # already there
        elif gateway_ip and gateway_ip not in results:
            # Gateway not reachable but option specified
            self._log(log, f"  ! Gateway {gateway_ip} not in live devices")

        # ------------------------------------------------------------------
        # 6. Persist to context
        # ------------------------------------------------------------------
        # Remove devices that existed from a prior run (idempotent rerun)
        with ctx._lock:
            keys_to_remove = [k for k in ctx.devices if not k.startswith("nbr:")]
            for k in keys_to_remove:
                del ctx.devices[k]

        for ip, dev in results.items():
            dev.setdefault("name", "")
            dev.setdefault("mac_vendor", "")
            dev.setdefault("ports", dev.get("open_ports", []))
            dev.setdefault("http", {})
            dev.setdefault("lldp", {})
            dev.setdefault("vendor", "")
            dev.setdefault("model", "")
            dev.setdefault("role", "")
            dev.setdefault("tier", "")
            dev.setdefault("is_gateway", False)
            dev.setdefault("lan", "")
            dev.setdefault("confidence", 0)
            dev.setdefault("issues", [])
            dev.setdefault("evidence", [])
            dev.setdefault("review_status", "pending")
            dev.setdefault("human_edits", {})
            ctx.add_device(ip, dev, actor="agent:discovery")

        # Summary
        by_method: Dict[str, int] = {}
        for dev in results.values():
            for m in dev.get("via", []):
                by_method[m] = by_method.get(m, 0) + 1

        duration = round(time.time() - t0, 1)
        summary = (
            f"Probed {total} hosts in {duration}s; "
            f"found {len(results)} live. "
            f"Methods: {by_method}. "
            f"Gateway: {gateway_ip or 'none'}."
        )
        self._log(log, summary)

        counts = {
            "probed": total,
            "live": len(results),
            "by_method": by_method,
            "gateway": gateway_ip,
        }
        return {"summary": summary, "counts": counts}
