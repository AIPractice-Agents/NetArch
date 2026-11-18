"""
Agent 4 – Verification Agent
Score confidence, run checks, flag issues, re-probe weak devices,
optionally request AI explanations.
"""
from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, List, Optional

from netarch.agents.base import BaseAgent
from netarch.classify import confidence_score
from netarch.context import ScanContext
from netarch.probes import COMMON_PORTS, tcp_connect
from netarch.snmp import (
    SNMPError,
    OID_sysDescr, OID_sysObjectID, OID_sysName, OID_sysServices,
    snmp_get,
)


def _make_issue(severity: str, msg: str) -> Dict:
    return {"severity": severity, "msg": msg}


class VerificationAgent(BaseAgent):
    name = "verification"
    title = "Verification"
    description = "Score, verify, flag issues and mark review candidates."

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
        snmp_port = 161 + offset
        llm_enabled = settings.get("llm", False)
        llm_url = os.environ.get("NETARCH_LLM_URL", "")
        llm_model = os.environ.get("NETARCH_LLM_MODEL", "gpt-4o-mini")

        devices = ctx.all_devices()
        total = len(devices)
        completed = 0

        # --- MAC -> keys and sysName -> keys for duplicate checks
        mac_to_keys: Dict[str, List[str]] = {}
        name_to_keys: Dict[str, List[str]] = {}
        gw_keys: List[str] = []
        for k, d in devices.items():
            mac = d.get("mac", "")
            if mac and mac != "00:00:00:00:00:00":
                mac_to_keys.setdefault(mac, []).append(k)
            sn = d.get("snmp", {}).get("sysName", "")
            if sn:
                name_to_keys.setdefault(sn, []).append(k)
            if d.get("is_gateway"):
                gw_keys.append(k)

        issue_counts = {"critical": 0, "warning": 0, "info": 0}
        needs_review = 0
        auto_approve = 0

        for key in list(devices.keys()):
            completed += 1
            progress(completed, total)
            dev = ctx.get_device(key)
            if not dev:
                continue

            issues: List[Dict] = []
            evidence = dev.get("evidence", [])

            # ----- Re-compute confidence -----
            dev["seen_in_neighbour"] = dev.get("seen_in_neighbour", False)
            conf = confidence_score(dev)

            # ARP-only base
            via = dev.get("via", [])
            if via == ["ARP"]:
                conf = max(conf, 20)

            # Neighbour-only base
            if key.startswith("nbr:") or (dev.get("seen_in_neighbour") and not dev.get("snmp", {}).get("sysDescr")):
                conf = max(conf, 40)

            # --- Re-probe weak devices ---
            if conf < 50 and dev.get("ip") and not key.startswith("nbr:"):
                self._log(log, f"  Re-probing {dev['ip']} (conf={conf})")
                try:
                    res = snmp_get(dev["ip"], [OID_sysDescr, OID_sysObjectID,
                                               OID_sysName, OID_sysServices],
                                   community=community, port=snmp_port,
                                   timeout=4.0, retries=2)
                    if res:
                        old_snmp = dev.get("snmp", {})
                        updated_snmp = {**old_snmp,
                                        "sysDescr":    res.get(OID_sysDescr, old_snmp.get("sysDescr", "")),
                                        "sysObjectID": res.get(OID_sysObjectID, old_snmp.get("sysObjectID", "")),
                                        "sysName":     res.get(OID_sysName, old_snmp.get("sysName", "")),
                                        "sysServices": res.get(OID_sysServices, old_snmp.get("sysServices"))}
                        dev["snmp"] = updated_snmp
                        evidence.append("re-verified with extended probe")
                        ctx.update_device(key, {"snmp": updated_snmp, "evidence": evidence},
                                          actor="agent:verification")
                        conf = confidence_score(dev)
                        ctx.add_audit("agent:verification", "re-probe", key,
                                      None, {"snmp": updated_snmp})
                except Exception:
                    pass

                # Re-probe ports with double timeout
                open_ports = []
                for p in COMMON_PORTS:
                    ok, banner = tcp_connect(dev["ip"], p + offset, timeout=2.0)
                    if ok:
                        open_ports.append(p + offset)
                if open_ports != dev.get("open_ports", []):
                    dev["open_ports"] = open_ports
                    ctx.update_device(key, {"open_ports": open_ports}, actor="agent:verification")

            # ----- Checks -----
            # Conflicting vendor
            vendor = dev.get("vendor", "")
            oid_vendor = ""
            from netarch.classify import vendor_from_oid, vendor_from_text
            if dev.get("snmp", {}).get("sysObjectID"):
                oid_vendor = vendor_from_oid(dev["snmp"]["sysObjectID"])
            http_vendor = vendor_from_text(dev.get("http", {}).get("title", "") +
                                           " " + dev.get("http", {}).get("server", ""))
            if oid_vendor and http_vendor and oid_vendor != http_vendor:
                issues.append(_make_issue("warning",
                    f"Vendor conflict: sysObjectID={oid_vendor}, HTTP={http_vendor}"))

            # Weak classification (port fallback only)
            ev_text = " ".join(evidence)
            if "open port" in ev_text and "sysDescr" not in ev_text and \
               "sysObjectID" not in ev_text and "ENTITY" not in ev_text and \
               "web title" not in ev_text:
                issues.append(_make_issue("info", "Weak classification – decided by port fallback only"))

            # Unknown name or model
            if not dev.get("name") or dev.get("name", "").startswith("host-"):
                issues.append(_make_issue("info", "Name unknown (default name assigned)"))
            if not dev.get("model") or dev.get("model") == "-":
                issues.append(_make_issue("info", "Model unknown"))

            # Duplicate MAC
            mac = dev.get("mac", "")
            if mac and len(mac_to_keys.get(mac, [])) > 1:
                issues.append(_make_issue("warning",
                    f"Same MAC {mac} on multiple IPs: {mac_to_keys[mac]}"))

            # Duplicate sysName
            sn = dev.get("snmp", {}).get("sysName", "")
            if sn and len(name_to_keys.get(sn, [])) > 1:
                issues.append(_make_issue("warning",
                    f"Same sysName '{sn}' on multiple IPs: {name_to_keys[sn]}"))

            # Neighbour-only mgmt IP not answering
            if key.startswith("nbr:") or (dev.get("seen_in_neighbour") and
                                           not dev.get("snmp", {}).get("sysDescr")):
                if dev.get("ip"):
                    ok, _ = tcp_connect(dev["ip"], 161 + offset, timeout=1.5)
                    if not ok:
                        issues.append(_make_issue("info",
                            "Neighbour-only device – management IP not responding"))

            # Security findings
            open_ports = dev.get("open_ports", [])
            if (23 + offset) in open_ports:
                issues.append(_make_issue("critical", "Telnet (port 23) is open"))
            if (3389 + offset) in open_ports and dev.get("role") in (
                    "Router", "Switch", "L3 Switch", "Firewall", "Wireless AP"):
                issues.append(_make_issue("warning", "RDP open on a network device"))
            if (445 + offset) in open_ports and dev.get("role") in (
                    "Router", "Switch", "L3 Switch", "Firewall", "Wireless AP"):
                issues.append(_make_issue("warning", "SMB open on a network device"))
            if (554 + offset) in open_ports:
                issues.append(_make_issue("info", "RTSP (554) – likely camera/NVR"))
            if (80 + offset) in open_ports and dev.get("role") in (
                    "Router", "Switch", "L3 Switch", "Firewall", "Wireless AP"):
                issues.append(_make_issue("warning",
                    "Admin web UI accessible over plain HTTP (not HTTPS)"))

            # Tally
            for iss in issues:
                issue_counts[iss["severity"]] = issue_counts.get(iss["severity"], 0) + 1

            # Update device
            ctx.update_device(key, {
                "confidence": conf,
                "issues": issues,
                "review_status": "pending",
                "evidence": evidence,
            }, actor="agent:verification")

            # Auto-approve candidate
            has_warn_crit = any(i["severity"] in ("warning", "critical") for i in issues)
            if conf >= 80 and not has_warn_crit:
                ctx.update_device(key, {"_auto_approve": True}, actor="agent:verification")
                auto_approve += 1
            else:
                needs_review += 1

        # ----- Link checks -----
        all_links = ctx.all_links()
        all_devs = ctx.all_devices()

        for lk, link in all_links.items():
            issues_l: List[Dict] = []
            sf = link.get("seen_from", [])
            conf_l = link.get("confidence", 70)
            a_key, b_key = link["a"], link["b"]

            if link.get("source") == "inferred":
                conf_l = 40
                issues_l.append(_make_issue("info",
                    "assumed from gateway, not measured"))
            elif len(sf) == 2:
                conf_l = 100
            elif len(sf) == 1:
                conf_l = 70
                issues_l.append(_make_issue("info",
                    "Link reported by one end only"))

            # Port name mismatch
            a_dev = all_devs.get(a_key, {})
            b_dev = all_devs.get(b_key, {})
            if not a_dev or not b_dev:
                issues_l.append(_make_issue("warning",
                    "Link refers to a device that is no longer in the scan"))

            ctx.update_link(lk, {
                "confidence": conf_l,
                "issues": issues_l,
                "review_status": "pending",
            }, actor="agent:verification")

        # ----- Multiple gateways -----
        if len(gw_keys) > 1:
            for k in gw_keys:
                existing = ctx.get_device(k) or {}
                iss = existing.get("issues", [])
                iss.append(_make_issue("warning",
                    f"Multiple gateways detected: {gw_keys}"))
                ctx.update_device(k, {"issues": iss}, actor="agent:verification")

        # ----- Optional AI explanations -----
        if llm_enabled and llm_url:
            self._run_llm_explanations(ctx, llm_url, llm_model, log)

        duration = round(time.time() - t0, 1)
        avg_conf = 0
        all_devs2 = ctx.all_devices()
        if all_devs2:
            avg_conf = round(
                sum(d.get("confidence", 0) for d in all_devs2.values()) / len(all_devs2))
        summary = (
            f"Verified {total} devices in {duration}s. "
            f"Avg confidence: {avg_conf}. "
            f"Issues: {issue_counts}. "
            f"Needs review: {needs_review}, auto-approve: {auto_approve}."
        )
        self._log(log, summary)
        counts = {
            "verified": total, "avg_confidence": avg_conf,
            "issues": issue_counts, "needs_review": needs_review,
            "auto_approve": auto_approve,
        }
        return {"summary": summary, "counts": counts}

    def _run_llm_explanations(self, ctx: ScanContext, url: str, model: str,
                               log: Callable) -> None:
        """Call an OpenAI-compatible endpoint for flagged devices."""
        import json
        import urllib.error
        import urllib.request
        devices = ctx.all_devices()
        for key, dev in devices.items():
            issues = dev.get("issues", [])
            if not issues:
                continue
            payload = {
                "model": model,
                "messages": [{
                    "role": "user",
                    "content": (
                        f"Device: {dev.get('name')} ({dev.get('ip')})\n"
                        f"Vendor: {dev.get('vendor')}, Model: {dev.get('model')}\n"
                        f"Role: {dev.get('role')}, Tier: {dev.get('tier')}\n"
                        f"Issues: {[i['msg'] for i in issues]}\n\n"
                        "In one paragraph, explain these issues in plain English "
                        "and suggest what a network engineer should check."
                    )
                }],
                "max_tokens": 200,
            }
            try:
                data = json.dumps(payload).encode()
                req = urllib.request.Request(
                    f"{url.rstrip('/')}/chat/completions",
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                resp = urllib.request.urlopen(req, timeout=10)
                result = json.loads(resp.read())
                explanation = (result.get("choices", [{}])[0]
                               .get("message", {}).get("content", ""))
                if explanation:
                    ctx.update_device(key, {"ai_explanation": explanation},
                                      actor="agent:verification")
            except Exception as e:
                self._log(log, f"  LLM call failed for {key}: {e}")
