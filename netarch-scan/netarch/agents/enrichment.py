"""
Agent 2 – Enrichment Agent
Collect SNMP identity, HTTP fingerprint, reverse DNS, MAC vendor,
classify each device, apply overrides.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional

from netarch.agents.base import BaseAgent
from netarch.classify import classify_device, confidence_score, default_device_name
from netarch.context import ScanContext
from netarch.probes import http_fingerprint, mac_vendor, reverse_dns
from netarch.snmp import (
    SNMPError,
    OID_sysDescr, OID_sysObjectID, OID_sysName, OID_sysServices, OID_sysLocation,
    OID_entPhysical_model_prefix,
    snmp_get, snmp_walk,
)

_SYSTEM_OIDS = [OID_sysDescr, OID_sysObjectID, OID_sysName, OID_sysServices, OID_sysLocation]


def _load_overrides(path: str = "overrides.json") -> List[Dict]:
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _match_override(device: Dict, override: Dict) -> bool:
    """Match by MAC first, then by IP+sysName."""
    if override.get("mac") and device.get("mac"):
        if override["mac"].lower() == device["mac"].lower():
            return True
    if override.get("ip") and device.get("ip"):
        if override["ip"] == device["ip"]:
            if not override.get("sysname"):
                return True
            snmp_name = device.get("snmp", {}).get("sysName", "")
            if override["sysname"].lower() == snmp_name.lower():
                return True
    return False


class EnrichmentAgent(BaseAgent):
    name = "enrichment"
    title = "Enrichment"
    description = "Collect SNMP data, HTTP fingerprint, classify and override devices."

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
        snmp_port = 161 + offset

        overrides = _load_overrides()
        self._log(log, f"Loaded {len(overrides)} override(s) from overrides.json")

        devices = ctx.all_devices()
        # Only enrich live devices (non-neighbour-only that passed discovery)
        live_keys = [k for k, d in devices.items()
                     if not k.startswith("nbr:") and d.get("via")]

        total = len(live_keys)
        completed = 0
        snmp_count = http_count = override_count = 0
        vendors_found: set = set()

        for key in live_keys:
            completed += 1
            progress(completed, total)
            dev = ctx.get_device(key)
            if not dev:
                continue
            ip = dev.get("ip", key)
            updates: Dict = {}

            # ----------------------------------------------------------------
            # SNMP enrichment
            # ----------------------------------------------------------------
            existing_snmp = dev.get("snmp", {})
            if not existing_snmp.get("sysDescr"):
                try:
                    res = snmp_get(ip, _SYSTEM_OIDS, community=community,
                                   port=snmp_port, timeout=2.0, retries=1)
                    if res:
                        existing_snmp.update({
                            "sysDescr":    res.get(OID_sysDescr, ""),
                            "sysObjectID": res.get(OID_sysObjectID, ""),
                            "sysName":     res.get(OID_sysName, ""),
                            "sysServices": res.get(OID_sysServices),
                            "sysLocation": res.get(OID_sysLocation, ""),
                        })
                        snmp_count += 1
                except SNMPError:
                    pass

            # ENTITY-MIB first non-empty model
            entity_model = existing_snmp.get("entity_model", "")
            if not entity_model:
                try:
                    for oid, val in snmp_walk(ip, OID_entPhysical_model_prefix,
                                              community=community, port=snmp_port,
                                              timeout=2.0, max_entries=10):
                        if isinstance(val, str) and val.strip():
                            entity_model = val.strip()
                            break
                except Exception:
                    pass
                if entity_model:
                    existing_snmp["entity_model"] = entity_model

            updates["snmp"] = existing_snmp

            # ----------------------------------------------------------------
            # HTTP fingerprint on first open web port
            # ----------------------------------------------------------------
            existing_http = dev.get("http", {})
            if not existing_http.get("title"):
                web_ports = [p for p in dev.get("open_ports", [])
                             if (p - offset) in (80, 443, 8080, 8443)]
                if web_ports:
                    # Try the offset-adjusted port
                    for wp in web_ports:
                        # For http_fingerprint we need the actual port
                        hfp = http_fingerprint(ip, wp, timeout=3.0)
                        if hfp.get("title") or hfp.get("hints"):
                            existing_http = hfp
                            http_count += 1
                            break
            updates["http"] = existing_http

            # ----------------------------------------------------------------
            # Reverse DNS (live mode)
            # ----------------------------------------------------------------
            if live_mode and not dev.get("rdns"):
                rdns = reverse_dns(ip, timeout=2.0)
                if rdns:
                    updates["rdns"] = rdns

            # ----------------------------------------------------------------
            # MAC vendor
            # ----------------------------------------------------------------
            if dev.get("mac") and not dev.get("mac_vendor"):
                mv = mac_vendor(dev["mac"])
                if mv:
                    updates["mac_vendor"] = mv

            # ----------------------------------------------------------------
            # Classification
            # ----------------------------------------------------------------
            snmp_data = updates["snmp"]
            http_data = updates.get("http", {})
            classification = classify_device(
                sys_descr=snmp_data.get("sysDescr", ""),
                sys_object_id=snmp_data.get("sysObjectID", ""),
                sys_name=snmp_data.get("sysName", ""),
                sys_services=snmp_data.get("sysServices"),
                entity_model=snmp_data.get("entity_model", ""),
                http_title=http_data.get("title", ""),
                http_server=http_data.get("server", ""),
                http_hints=http_data.get("hints", []),
                mac_vendor=updates.get("mac_vendor", dev.get("mac_vendor", "")),
                open_ports=dev.get("open_ports", []),
                is_gateway=dev.get("is_gateway", False),
                existing_role=dev.get("role", ""),
                existing_tier=dev.get("tier", ""),
            )
            updates["vendor"] = classification["vendor"]
            updates["model"] = classification["model"]
            updates["role"] = classification["role"]
            updates["tier"] = classification["tier"]
            updates["evidence"] = dev.get("evidence", []) + classification["evidence"]

            if classification["vendor"] and classification["vendor"] != "-":
                vendors_found.add(classification["vendor"])

            # Device name
            name = dev.get("name", "")
            if not name:
                sysname = snmp_data.get("sysName", "")
                if sysname:
                    name = sysname
                elif dev.get("rdns"):
                    name = updates.get("rdns", "")
                else:
                    name = default_device_name(classification["role"], ip)
            updates["name"] = name

            # ----------------------------------------------------------------
            # Apply overrides
            # ----------------------------------------------------------------
            merged_dev = {**dev, **updates}
            for ov in overrides:
                if _match_override(merged_dev, ov):
                    for field in ("name", "vendor", "model", "role", "tier",
                                  "is_gateway", "notes"):
                        if ov.get(field):
                            updates[field] = ov[field]
                    updates.setdefault("evidence", []).append(
                        f"override from human review on {ov.get('date', '?')}"
                    )
                    override_count += 1
                    self._log(log, f"  override applied to {ip} from overrides.json")
                    break

            # ----------------------------------------------------------------
            # Confidence
            # ----------------------------------------------------------------
            merged_dev2 = {**dev, **updates}
            merged_dev2["seen_in_neighbour"] = dev.get("seen_in_neighbour", False)
            updates["confidence"] = confidence_score(merged_dev2)

            ctx.update_device(key, updates, actor="agent:enrichment")
            self._log(log, f"  enriched {ip} -> {updates.get('vendor','-')} "
                           f"{updates.get('model','-')} [{updates.get('role','-')}] "
                           f"conf={updates.get('confidence',0)}")

        duration = round(time.time() - t0, 1)
        summary = (
            f"Enriched {total} devices in {duration}s; "
            f"SNMP {snmp_count}, HTTP {http_count}, "
            f"vendors: {sorted(vendors_found)}, overrides: {override_count}."
        )
        self._log(log, summary)
        counts = {
            "enriched": total, "snmp": snmp_count, "http": http_count,
            "vendors": len(vendors_found), "overrides": override_count,
        }
        return {"summary": summary, "counts": counts}
