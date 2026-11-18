"""
Agent 3 – Link Agent
Walk LLDP-MIB and CISCO-CDP-MIB, build device links, infer gateway links,
optionally crawl neighbour management IPs.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from netarch.agents.base import BaseAgent
from netarch.classify import classify_device, confidence_score, default_device_name, TIER_ORDER
from netarch.context import ScanContext
from netarch.probes import COMMON_PORTS, tcp_connect
from netarch.snmp import (
    SNMPError,
    OID_lldpRemSysName, OID_lldpRemSysDesc, OID_lldpRemPortId,
    OID_lldpRemPortDesc, OID_lldpRemManAddr, OID_lldpLocPortDesc,
    OID_cdpCacheDeviceId, OID_cdpCacheAddress, OID_cdpCachePort,
    OID_cdpCachePlatform, OID_ifName,
    OID_sysDescr, OID_sysObjectID, OID_sysName, OID_sysServices,
    decode_hex_ip, parse_lldp_rem_man_addr,
    snmp_get, snmp_walk, snmp_walk_dict,
)

_RFC1918 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
]


def _in_scope(ip: str, scope: List[str]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if not scope:
        return any(addr in net for net in _RFC1918)
    for s in scope:
        try:
            if addr in ipaddress.IPv4Network(s, strict=False):
                return True
        except Exception:
            pass
    return False


def _normalise_name(name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', name.lower())


class LinksAgent(BaseAgent):
    name = "links"
    title = "Links"
    description = "Discover device links via LLDP/CDP and gateway inference."

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
        crawl_hops = settings.get("crawl", 0)
        scope = settings.get("scope", [])
        snmp_port = 161 + offset

        # Clear previous links from agent (idempotent)
        with ctx._lock:
            keys_to_remove = [k for k, lnk in ctx.links.items()
                               if lnk.get("source") in ("LLDP", "CDP", "inferred")]
            for k in keys_to_remove:
                del ctx.links[k]

        devices = ctx.all_devices()
        lldp_count = cdp_count = inferred_count = crawl_added = 0
        devices_with_tables = 0

        # Build lookup tables
        ip_to_key: Dict[str, str] = {d.get("ip", k): k for k, d in devices.items()}
        name_to_key: Dict[str, str] = {
            _normalise_name(d.get("name", "") or d.get("snmp", {}).get("sysName", "")): k
            for k, d in devices.items()
            if d.get("name") or d.get("snmp", {}).get("sysName")
        }

        # Queue for crawl
        crawled: Set[str] = set(ip_to_key.keys())
        crawl_queue: List[Tuple[str, int]] = []  # (ip, hop)

        def find_device_key(mgmt_ip: str = "", name: str = "") -> Optional[str]:
            if mgmt_ip and mgmt_ip in ip_to_key:
                return ip_to_key[mgmt_ip]
            if name:
                nn = _normalise_name(name)
                if nn in name_to_key:
                    return name_to_key[nn]
            return None

        def ensure_neighbour(mgmt_ip: str, name: str, desc: str,
                              via: str) -> str:
            """Return key of existing or new neighbour-only device."""
            key = find_device_key(mgmt_ip, name)
            if key:
                # Mark as seen in neighbour
                ctx.update_device(key, {"seen_in_neighbour": True}, actor="agent:links")
                return key
            # Create neighbour-only device
            if mgmt_ip:
                key = mgmt_ip
            else:
                key = f"nbr:{_normalise_name(name) or desc[:20]}"
            classification = classify_device(sys_descr=desc)
            nbr_dev = {
                "ip": mgmt_ip or "",
                "name": name or key,
                "mac": "",
                "mac_vendor": "",
                "open_ports": [],
                "banners": {},
                "via": [via],
                "snmp": {"sysDescr": desc} if desc else {},
                "http": {},
                "lldp": {},
                "vendor": classification["vendor"],
                "model": classification["model"],
                "role": classification["role"],
                "tier": classification["tier"],
                "is_gateway": False,
                "lan": "",
                "confidence": 40,
                "issues": [],
                "evidence": classification["evidence"],
                "review_status": "pending",
                "human_edits": {},
                "seen_in_neighbour": True,
            }
            ctx.add_device(key, nbr_dev, actor="agent:links")
            ip_to_key[mgmt_ip] = key
            nn = _normalise_name(name)
            if nn:
                name_to_key[nn] = key
            if mgmt_ip and _in_scope(mgmt_ip, scope) and mgmt_ip not in crawled:
                crawl_queue.append((mgmt_ip, 1))
            return key

        def add_link(a_key: str, b_key: str, a_port: str, b_port: str,
                     source: str, seen_from: str):
            lk = ctx.link_key(a_key, b_key)
            existing = ctx.links.get(lk)
            if existing:
                # Update seen_from and ports
                sf = existing.get("seen_from", [])
                if seen_from not in sf:
                    sf.append(seen_from)
                if a_key == existing["a"]:
                    if a_port and not existing.get("a_port"):
                        existing["a_port"] = a_port
                    if b_port and not existing.get("b_port"):
                        existing["b_port"] = b_port
                else:
                    if b_port and not existing.get("a_port"):
                        existing["a_port"] = b_port
                    if a_port and not existing.get("b_port"):
                        existing["b_port"] = a_port
                existing["seen_from"] = sf
                ctx.links[lk] = existing
            else:
                pair = sorted([a_key, b_key])
                ctx.add_link(lk, {
                    "a": pair[0], "b": pair[1],
                    "a_port": a_port if a_key == pair[0] else b_port,
                    "b_port": b_port if b_key == pair[1] else a_port,
                    "source": source,
                    "seen_from": [seen_from],
                    "confidence": 70,
                    "issues": [],
                    "review_status": "pending",
                    "human_edits": {},
                }, actor="agent:links")

        # ----------------------------------------------------------------
        # Walk LLDP and CDP for every device
        # ----------------------------------------------------------------
        all_keys = list(ctx.devices.keys())
        total = len(all_keys)
        completed = 0

        for key in all_keys:
            completed += 1
            progress(completed, total)
            dev = ctx.get_device(key)
            if not dev:
                continue
            ip = dev.get("ip", "")
            if not ip or key.startswith("nbr:"):
                continue

            has_table = False

            # --- LLDP ---
            # Walk lldpRemSysName to discover entries
            try:
                rem_names = snmp_walk_dict(ip, OID_lldpRemSysName,
                                           community=community, port=snmp_port,
                                           timeout=2.0, max_entries=200)
                rem_descs = snmp_walk_dict(ip, OID_lldpRemSysDesc,
                                           community=community, port=snmp_port,
                                           timeout=2.0, max_entries=200)
                rem_port_ids = snmp_walk_dict(ip, OID_lldpRemPortId,
                                              community=community, port=snmp_port,
                                              timeout=2.0, max_entries=200)
                rem_port_descs = snmp_walk_dict(ip, OID_lldpRemPortDesc,
                                                community=community, port=snmp_port,
                                                timeout=2.0, max_entries=200)
                # Management addresses
                man_addrs = snmp_walk_dict(ip, OID_lldpRemManAddr,
                                           community=community, port=snmp_port,
                                           timeout=2.0, max_entries=500)

                if rem_names:
                    has_table = True
                    # Build a map of <timeMark>.<portNum>.<idx> -> mgmt_ip
                    mgmt_map: Dict[str, str] = {}
                    base_len = len(OID_lldpRemManAddr) + 1
                    for man_oid in man_addrs:
                        suffix = man_oid[base_len:]
                        parsed_ip = parse_lldp_rem_man_addr(suffix)
                        # key suffix format: <tm>.<port>.<idx>
                        parts = suffix.split(".")
                        if len(parts) >= 3:
                            entry_key = ".".join(parts[:3])
                            if parsed_ip:
                                mgmt_map[entry_key] = parsed_ip

                    # local port descriptions
                    loc_port_descs = snmp_walk_dict(ip, OID_lldpLocPortDesc,
                                                    community=community, port=snmp_port,
                                                    timeout=2.0, max_entries=100)

                    seen_neighbours: Set[str] = set()
                    for oid, rem_name in rem_names.items():
                        base_len2 = len(OID_lldpRemSysName) + 1
                        suffix = oid[base_len2:]
                        parts = suffix.split(".")
                        if len(parts) < 3:
                            continue
                        tm, port_num, idx = parts[0], parts[1], parts[2]
                        entry_key = f"{tm}.{port_num}.{idx}"

                        mgmt_ip = mgmt_map.get(entry_key, "")
                        # Dedup
                        dedup_key = mgmt_ip or _normalise_name(str(rem_name))
                        if dedup_key in seen_neighbours:
                            continue
                        seen_neighbours.add(dedup_key)

                        rem_desc = rem_descs.get(
                            OID_lldpRemSysDesc + "." + suffix, "")
                        rem_port = rem_port_descs.get(
                            OID_lldpRemPortDesc + "." + suffix, "") or \
                                   rem_port_ids.get(
                            OID_lldpRemPortId + "." + suffix, "")
                        # Local port: match port_num
                        loc_port = ""
                        for lp_oid, lp_val in loc_port_descs.items():
                            if lp_oid.endswith(f".{port_num}"):
                                loc_port = str(lp_val)
                                break

                        nbr_key = ensure_neighbour(mgmt_ip, str(rem_name),
                                                   str(rem_desc), "LLDP")
                        add_link(key, nbr_key, loc_port, str(rem_port),
                                 "LLDP", key)
                        lldp_count += 1

                        if crawl_hops > 0 and mgmt_ip and \
                                _in_scope(mgmt_ip, scope) and \
                                mgmt_ip not in crawled:
                            crawl_queue.append((mgmt_ip, 1))
            except Exception as e:
                self._log(log, f"  LLDP walk error for {ip}: {e}")

            # --- CDP ---
            try:
                cdp_device_ids = snmp_walk_dict(ip, OID_cdpCacheDeviceId,
                                                community=community, port=snmp_port,
                                                timeout=2.0, max_entries=200)
                if cdp_device_ids:
                    has_table = True
                    cdp_addrs = snmp_walk_dict(ip, OID_cdpCacheAddress,
                                               community=community, port=snmp_port,
                                               timeout=2.0, max_entries=200)
                    cdp_ports = snmp_walk_dict(ip, OID_cdpCachePort,
                                               community=community, port=snmp_port,
                                               timeout=2.0, max_entries=200)
                    cdp_platforms = snmp_walk_dict(ip, OID_cdpCachePlatform,
                                                   community=community, port=snmp_port,
                                                   timeout=2.0, max_entries=200)
                    ifnames = snmp_walk_dict(ip, OID_ifName,
                                            community=community, port=snmp_port,
                                            timeout=2.0, max_entries=200)

                    base_len = len(OID_cdpCacheDeviceId) + 1
                    seen_cdp: Set[str] = set()
                    for oid, dev_id in cdp_device_ids.items():
                        suffix = oid[base_len:]
                        # suffix = <ifIndex>.<deviceIndex>
                        parts = suffix.split(".")
                        if len(parts) < 2:
                            continue
                        if_index = parts[0]
                        raw_addr = cdp_addrs.get(OID_cdpCacheAddress + "." + suffix)
                        mgmt_ip = decode_hex_ip(str(raw_addr)) if raw_addr else ""
                        rem_port = str(cdp_ports.get(OID_cdpCachePort + "." + suffix, ""))
                        platform = str(cdp_platforms.get(OID_cdpCachePlatform + "." + suffix, ""))
                        loc_port = str(ifnames.get(OID_ifName + "." + if_index, ""))

                        dedup_key = mgmt_ip or _normalise_name(str(dev_id))
                        if dedup_key in seen_cdp:
                            continue
                        seen_cdp.add(dedup_key)

                        nbr_key = ensure_neighbour(mgmt_ip, str(dev_id),
                                                   platform, "CDP")
                        add_link(key, nbr_key, loc_port, rem_port, "CDP", key)
                        cdp_count += 1

                        if crawl_hops > 0 and mgmt_ip and \
                                _in_scope(mgmt_ip, scope) and \
                                mgmt_ip not in crawled:
                            crawl_queue.append((mgmt_ip, 1))
            except Exception as e:
                self._log(log, f"  CDP walk error for {ip}: {e}")

            if has_table:
                devices_with_tables += 1

        # ----------------------------------------------------------------
        # Crawl
        # ----------------------------------------------------------------
        crawl_idx = 0
        while crawl_idx < len(crawl_queue) and crawl_hops > 0:
            crawl_ip, hop = crawl_queue[crawl_idx]
            crawl_idx += 1
            if hop > crawl_hops:
                continue
            if crawl_ip in crawled:
                continue
            crawled.add(crawl_ip)

            self._log(log, f"  Crawl hop {hop}: probing {crawl_ip}")

            # Quick discovery probe
            from netarch.snmp import OID_sysDescr
            snmp_data = {}
            try:
                res = snmp_get(crawl_ip, [OID_sysDescr, OID_sysObjectID, OID_sysName,
                                          OID_sysServices],
                               community=community, port=snmp_port, timeout=2.0)
                if res:
                    snmp_data = {
                        "sysDescr":    res.get(OID_sysDescr, ""),
                        "sysObjectID": res.get(OID_sysObjectID, ""),
                        "sysName":     res.get(OID_sysName, ""),
                        "sysServices": res.get(OID_sysServices),
                    }
            except Exception:
                pass

            open_ports = []
            for p in [22, 23, 80, 443]:
                ok, _ = tcp_connect(crawl_ip, p + offset, timeout=1.0)
                if ok:
                    open_ports.append(p + offset)

            existing_key = ip_to_key.get(crawl_ip)
            if not existing_key:
                classification = classify_device(
                    sys_descr=snmp_data.get("sysDescr", ""),
                    sys_object_id=snmp_data.get("sysObjectID", ""),
                    sys_name=snmp_data.get("sysName", ""),
                    sys_services=snmp_data.get("sysServices"),
                    open_ports=open_ports,
                )
                new_dev = {
                    "ip": crawl_ip,
                    "name": snmp_data.get("sysName", "") or default_device_name(
                        classification["role"], crawl_ip),
                    "mac": "",
                    "mac_vendor": "",
                    "open_ports": open_ports,
                    "banners": {},
                    "via": ["crawl"],
                    "snmp": snmp_data,
                    "http": {},
                    "lldp": {},
                    "vendor": classification["vendor"],
                    "model": classification["model"],
                    "role": classification["role"],
                    "tier": classification["tier"],
                    "is_gateway": False,
                    "lan": "",
                    "confidence": 40,
                    "issues": [],
                    "evidence": classification["evidence"],
                    "review_status": "pending",
                    "human_edits": {},
                    "seen_in_neighbour": True,
                }
                ctx.add_device(crawl_ip, new_dev, actor="agent:links")
                ip_to_key[crawl_ip] = crawl_ip
                crawl_added += 1
                self._log(log, f"  Crawl added {crawl_ip}")
            else:
                if snmp_data:
                    ctx.update_device(existing_key, {"snmp": snmp_data},
                                      actor="agent:links")

            # Queue LLDP neighbours from crawled device for next hop
            if hop < crawl_hops:
                try:
                    rem_names = snmp_walk_dict(crawl_ip, OID_lldpRemSysName,
                                               community=community, port=snmp_port,
                                               timeout=2.0, max_entries=200)
                    man_addrs = snmp_walk_dict(crawl_ip, OID_lldpRemManAddr,
                                               community=community, port=snmp_port,
                                               timeout=2.0, max_entries=500)
                    mgmt_map2: Dict[str, str] = {}
                    base_len3 = len(OID_lldpRemManAddr) + 1
                    for man_oid in man_addrs:
                        suffix = man_oid[base_len3:]
                        parsed_ip = parse_lldp_rem_man_addr(suffix)
                        parts = suffix.split(".")
                        if len(parts) >= 3 and parsed_ip:
                            mgmt_map2[".".join(parts[:3])] = parsed_ip

                    base_len4 = len(OID_lldpRemSysName) + 1
                    for oid in rem_names:
                        suffix = oid[base_len4:]
                        parts = suffix.split(".")
                        if len(parts) >= 3:
                            mgmt_ip2 = mgmt_map2.get(".".join(parts[:3]), "")
                            if mgmt_ip2 and _in_scope(mgmt_ip2, scope) \
                                    and mgmt_ip2 not in crawled:
                                crawl_queue.append((mgmt_ip2, hop + 1))
                except Exception:
                    pass

        # ----------------------------------------------------------------
        # Gateway inference
        # ----------------------------------------------------------------
        gw_key = None
        gw_lan = None
        for k, d in ctx.all_devices().items():
            if d.get("is_gateway"):
                gw_key = k
                gw_lan = d.get("lan", "")
                break

        if gw_key and gw_lan:
            # Find all devices on the gateway's LAN
            try:
                gw_net = ipaddress.IPv4Network(gw_lan, strict=False)
            except Exception:
                gw_net = None

            if gw_net:
                # Build connected groups (devices linked directly to each other)
                # For every device on the gateway's LAN that has NO link to gw_key,
                # add an inferred link to the highest-tier device in its group.
                all_devs = ctx.all_devices()
                all_links_snap = ctx.all_links()

                def linked_to_gw(key: str) -> bool:
                    lk1 = ctx.link_key(key, gw_key)
                    return lk1 in all_links_snap

                on_lan: List[str] = []
                for k, d in all_devs.items():
                    ip_d = d.get("ip", "")
                    if k == gw_key:
                        continue
                    try:
                        if ip_d and ipaddress.IPv4Address(ip_d) in gw_net:
                            on_lan.append(k)
                    except Exception:
                        pass

                # Simple grouping: BFS over existing links
                unvisited = set(on_lan)
                adj: Dict[str, Set[str]] = {k: set() for k in on_lan}
                for lk, link in all_links_snap.items():
                    la, lb = link["a"], link["b"]
                    if la in adj and lb in adj:
                        adj[la].add(lb)
                        adj[lb].add(la)

                while unvisited:
                    seed = next(iter(unvisited))
                    group: Set[str] = set()
                    queue2 = [seed]
                    while queue2:
                        node = queue2.pop()
                        if node in group:
                            continue
                        group.add(node)
                        queue2.extend(adj.get(node, set()) - group)
                    unvisited -= group
                    # Does this group already connect to gw?
                    if any(linked_to_gw(k) for k in group):
                        continue
                    # Find highest-tier device in group
                    best = max(group, key=lambda k: TIER_ORDER.get(
                        all_devs.get(k, {}).get("tier", "Unknown"), 0))
                    lk = ctx.link_key(gw_key, best)
                    ctx.add_link(lk, {
                        "a": sorted([gw_key, best])[0],
                        "b": sorted([gw_key, best])[1],
                        "a_port": "", "b_port": "",
                        "source": "inferred",
                        "seen_from": [],
                        "confidence": 40,
                        "issues": [{"severity": "info", "msg":
                                    "assumed from gateway, not measured"}],
                        "review_status": "pending",
                        "human_edits": {},
                    }, actor="agent:links")
                    inferred_count += 1
                    self._log(log, f"  inferred link: {gw_key} <-> {best}")

        duration = round(time.time() - t0, 1)
        summary = (
            f"Processed {total} devices in {duration}s; "
            f"LLDP links: {lldp_count}, CDP: {cdp_count}, "
            f"inferred: {inferred_count}, crawl added: {crawl_added}."
        )
        self._log(log, summary)
        counts = {
            "devices_with_tables": devices_with_tables,
            "lldp_links": lldp_count,
            "cdp_links": cdp_count,
            "inferred_links": inferred_count,
            "crawl_added": crawl_added,
        }
        return {"summary": summary, "counts": counts}
