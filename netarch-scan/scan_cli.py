#!/usr/bin/env python3
"""
scan_cli.py – NetArch Scan command-line interface.

Usage:
  python scan_cli.py <target> [options]

Review modes:
  interactive (default) – interactive prompt after verification
  auto                  – approve safe candidates, exit code 2 if anything pending
  skip                  – approve everything (lab demos only)
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import webbrowser

# Allow running from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netarch.context import ScanContext
from netarch.orchestrator import Orchestrator
from netarch.probes import auto_port_offset, parse_targets, TargetError, is_loopback_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_device_table(devices: dict):
    header = f"{'#':>3}  {'Name':<24} {'IP':<16} {'Vendor':<12} {'Role':<18} {'Conf':>5}  {'Status':<10}  Issues"
    print(header)
    print("-" * 100)
    for idx, (key, d) in enumerate(sorted(devices.items()), 1):
        issues = [i["msg"][:40] for i in d.get("issues", [])]
        issues_str = " | ".join(issues)
        print(f"{idx:>3}  {str(d.get('name','')):<24} {str(d.get('ip','')):<16} "
              f"{str(d.get('vendor','')):<12} {str(d.get('role','')):<18} "
              f"{d.get('confidence',0):>5}  {d.get('review_status',''):<10}  {issues_str}")


def _print_link_table(links: dict, devices: dict):
    header = f"{'#':>3}  {'A':<20}  {'B':<20}  {'Source':<10}  {'Conf':>5}  {'Status':<10}  Issues"
    print(header)
    print("-" * 100)
    for idx, (lk, link) in enumerate(sorted(links.items()), 1):
        a_dev = devices.get(link["a"], {})
        b_dev = devices.get(link["b"], {})
        a_name = f"{a_dev.get('name', link['a'])[:18]}"
        b_name = f"{b_dev.get('name', link['b'])[:18]}"
        issues = " | ".join(i["msg"][:30] for i in link.get("issues", []))
        print(f"{idx:>3}  {a_name:<20}  {b_name:<20}  {link.get('source',''):<10}  "
              f"{link.get('confidence',0):>5}  {link.get('review_status',''):<10}  {issues}")


def _key_at(mapping: dict, n: int) -> str:
    keys = sorted(mapping.keys())
    return keys[n - 1] if 1 <= n <= len(keys) else ""


def _interactive_review(orch: Orchestrator, job_id: str):
    """Interactive CLI review loop."""
    ctx = orch.get_job(job_id)
    print("\n" + "=" * 60)
    print("REVIEW MODE – type 'help' for commands")
    print("=" * 60)

    while True:
        ctx = orch.get_job(job_id)
        devices = ctx.all_devices()
        links = ctx.all_links()
        pending_d = sum(1 for d in devices.values() if d.get("review_status") == "pending")
        pending_l = sum(1 for ln in links.values() if ln.get("review_status") == "pending")
        print(f"\n  Pending: {pending_d} devices, {pending_l} links\n")

        try:
            cmd = input("review> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return

        if not cmd:
            continue
        parts = cmd.split()
        verb = parts[0].lower()

        if verb == "help":
            print("""
  devices                  – list all devices
  links                    – list all links
  a <n>                    – approve device #n
  r <n>                    – reject device #n
  al <n>                   – approve link #n
  rl <n>                   – reject link #n
  e <n> key=val ...        – edit device (name, vendor, model, role, tier, notes)
  link <a_key> <b_key>     – add manual link
  approve-safe             – approve all auto-approve candidates
  approve-all              – approve everything
  reject-arp               – reject all ARP-only devices
  finalize [reviewer]      – finalize (approve remaining optional)
  discard                  – discard the scan
  rerun <agent>            – rerun from agent (discovery|enrichment|links|verification)
  quit / exit              – exit without finalizing
""")
        elif verb == "devices":
            _print_device_table(devices)
        elif verb == "links":
            _print_link_table(links, devices)
        elif verb == "a" and len(parts) >= 2:
            key = _key_at(devices, int(parts[1]))
            if key:
                _apply_device_action(orch, job_id, key, "approve", {})
                print(f"  Approved {key}")
        elif verb == "r" and len(parts) >= 2:
            key = _key_at(devices, int(parts[1]))
            if key:
                _apply_device_action(orch, job_id, key, "reject", {})
                print(f"  Rejected {key}")
        elif verb == "al" and len(parts) >= 2:
            key = _key_at(links, int(parts[1]))
            if key:
                _apply_link_action(orch, job_id, key, "approve", {})
                print(f"  Approved link {key}")
        elif verb == "rl" and len(parts) >= 2:
            key = _key_at(links, int(parts[1]))
            if key:
                _apply_link_action(orch, job_id, key, "reject", {})
                print(f"  Rejected link {key}")
        elif verb == "e" and len(parts) >= 3:
            key = _key_at(devices, int(parts[1]))
            if key:
                fields: dict = {}
                for tok in parts[2:]:
                    if "=" in tok:
                        k2, v2 = tok.split("=", 1)
                        fields[k2] = v2
                _apply_device_action(orch, job_id, key, "edit", fields)
                print(f"  Edited {key}: {fields}")
        elif verb == "link" and len(parts) >= 3:
            _add_manual_link(orch, job_id, parts[1], parts[2])
            print(f"  Added manual link {parts[1]} <-> {parts[2]}")
        elif verb == "approve-safe":
            _bulk_action(orch, job_id, "approve_safe")
            print("  Approved all auto-approve candidates.")
        elif verb == "approve-all":
            _bulk_action(orch, job_id, "approve_all")
            print("  Approved all items.")
        elif verb == "reject-arp":
            _bulk_action(orch, job_id, "reject_arp_only")
            print("  Rejected all ARP-only devices.")
        elif verb == "finalize":
            reviewer = parts[1] if len(parts) >= 2 else "cli-user"
            approve_rest = False
            if len(parts) >= 3 and parts[2] == "approve-pending":
                approve_rest = True
            result = orch.finalize(job_id, reviewer, approve_rest, remember=False)
            if result.get("ok"):
                print(f"  Finalized! Report v{result.get('version')} written.")
                return
            else:
                print(f"  Cannot finalize: {result.get('blocking', result.get('error'))}")
        elif verb == "discard":
            orch.discard(job_id)
            print("  Scan discarded.")
            return
        elif verb == "rerun" and len(parts) >= 2:
            agent = parts[1]
            print(f"  Rerunning from {agent}...")
            try:
                orch.rerun_from(job_id, agent)
                # Wait for it to reach awaiting_review again
                _wait_for_review(orch, job_id)
            except Exception as e:
                print(f"  Error: {e}")
        elif verb in ("quit", "exit"):
            print("  Exiting without finalizing.")
            return
        else:
            print(f"  Unknown command: {cmd}. Type 'help'.")


def _apply_device_action(orch: Orchestrator, job_id: str, key: str,
                          action: str, fields: dict):
    ctx = orch.get_job(job_id)
    dev = ctx.get_device(key)
    if not dev:
        return
    old = {k: dev.get(k) for k in fields}
    updates = {}
    if action == "approve":
        updates["review_status"] = "approved"
    elif action == "reject":
        updates["review_status"] = "rejected"
    elif action == "edit":
        updates["review_status"] = "edited"
        for k2, v2 in fields.items():
            updates[k2] = v2
        human_edits = dev.get("human_edits", {})
        human_edits.update(fields)
        updates["human_edits"] = human_edits
    ctx.update_device(key, updates, actor="human:cli")
    ctx.save(orch.scans_dir)


def _apply_link_action(orch: Orchestrator, job_id: str, key: str,
                        action: str, fields: dict):
    ctx = orch.get_job(job_id)
    updates = {}
    if action == "approve":
        updates["review_status"] = "approved"
    elif action == "reject":
        updates["review_status"] = "rejected"
    elif action == "edit":
        updates["review_status"] = "edited"
        updates.update(fields)
    ctx.update_link(key, updates, actor="human:cli")
    ctx.save(orch.scans_dir)


def _add_manual_link(orch: Orchestrator, job_id: str, a_key: str, b_key: str):
    ctx = orch.get_job(job_id)
    lk = ctx.link_key(a_key, b_key)
    pair = sorted([a_key, b_key])
    ctx.add_link(lk, {
        "a": pair[0], "b": pair[1],
        "a_port": "", "b_port": "",
        "source": "manual",
        "seen_from": ["human"],
        "confidence": 100,
        "issues": [],
        "review_status": "approved",
        "human_edits": {},
    }, actor="human:cli")
    ctx.save(orch.scans_dir)


def _bulk_action(orch: Orchestrator, job_id: str, action: str):
    ctx = orch.get_job(job_id)
    if action == "approve_safe":
        for key, dev in ctx.devices.items():
            if dev.get("_auto_approve") and dev.get("review_status") == "pending":
                ctx.update_device(key, {"review_status": "approved"}, actor="human:cli")
        for lk, lnk in ctx.links.items():
            if lnk.get("confidence", 0) >= 80 and lnk.get("review_status") == "pending":
                ctx.update_link(lk, {"review_status": "approved"}, actor="human:cli")
    elif action == "approve_all":
        for key in ctx.devices:
            if ctx.devices[key].get("review_status") == "pending":
                ctx.update_device(key, {"review_status": "approved"}, actor="human:cli")
        for lk in ctx.links:
            if ctx.links[lk].get("review_status") == "pending":
                ctx.update_link(lk, {"review_status": "approved"}, actor="human:cli")
    elif action == "reject_arp_only":
        for key, dev in ctx.devices.items():
            if dev.get("via") == ["ARP"]:
                ctx.update_device(key, {"review_status": "rejected"}, actor="human:cli")
    ctx.save(orch.scans_dir)


def _wait_for_pipeline(orch: Orchestrator, job_id: str, timeout: float = 600.0):
    """Wait for the pipeline to reach awaiting_review or terminal state."""
    t0 = time.time()
    last_status = ""
    while time.time() - t0 < timeout:
        ctx = orch.get_job(job_id)
        status = ctx.status
        if status != last_status:
            print(f"  [{status}] ...", flush=True)
            last_status = status
        if status in ("awaiting_review", "done", "error", "empty", "discarded"):
            return
        time.sleep(0.8)
    print("  Timeout waiting for pipeline.")


def _wait_for_review(orch: Orchestrator, job_id: str, timeout: float = 300.0):
    """Wait until a rerun reaches awaiting_review."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        ctx = orch.get_job(job_id)
        if ctx.status == "awaiting_review":
            return
        if ctx.status in ("error", "empty", "discarded"):
            return
        time.sleep(0.8)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="scan_cli.py",
        description="NetArch Scan – 5-agent network discovery CLI"
    )
    parser.add_argument("target", help="IP, CIDR, range, hostname, comma list, or @file")
    parser.add_argument("--community", default="public", help="SNMPv2c community string")
    parser.add_argument("--crawl", type=int, default=0, metavar="N",
                        help="LLDP/CDP crawl hops (0-5)")
    parser.add_argument("--scope", default="", help="Comma-separated CIDR list for crawl scope")
    parser.add_argument("--gateway", default="auto", help="Gateway IP, 'auto', or 'none'")
    parser.add_argument("--max-hosts", type=int, default=4096)
    parser.add_argument("--port-offset", type=int, default=None,
                        help="Port offset (blank = auto-detect)")
    parser.add_argument("--out", default="netarch_output", help="Output directory (unused; scans/ used)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser")
    parser.add_argument("--review", choices=["interactive", "auto", "skip"],
                        default="interactive")
    parser.add_argument("--live", action="store_true", default=False,
                        help="Enable live mode (ping + ARP). "
                             "Only use on networks you are authorized to scan.")
    args = parser.parse_args()

    # Resolve port offset
    try:
        targets_preview = parse_targets(args.target, max_hosts=1)
    except Exception:
        targets_preview = []
    if args.port_offset is not None:
        offset = args.port_offset
    else:
        offset = auto_port_offset(targets_preview) if targets_preview else 0

    # Live scan approval reminder
    if args.live:
        print("\n[LIVE] ⚠️  You are about to scan a live network.")
        print("       Only scan networks you are authorized to scan.")
        confirm = input("       Type 'I have approval to scan' to continue: ").strip()
        if confirm != "I have approval to scan":
            print("Scan cancelled.")
            sys.exit(1)

    scope_list = [s.strip() for s in args.scope.split(",") if s.strip()] if args.scope else []

    settings = {
        "target": args.target,
        "community": args.community,
        "crawl": args.crawl,
        "scope": scope_list,
        "gateway": args.gateway,
        "max_hosts": args.max_hosts,
        "offset": offset,
        "live": args.live,
        "approval": "",
    }

    print(f"\nNetArch Scan – starting")
    print(f"  Target:      {args.target}")
    print(f"  Community:   {args.community}")
    print(f"  Port offset: {offset} {'(auto-detected lab)' if offset == 20000 else ''}")
    print(f"  Crawl:       {args.crawl} hops")
    print(f"  Review:      {args.review}")
    print()

    orch = Orchestrator(scans_dir="scans")
    ctx = orch.create_job(settings)
    job_id = ctx.job_id
    print(f"  Job ID: {job_id}")

    # Start pipeline
    orch.start_job(job_id)
    _wait_for_pipeline(orch, job_id)

    ctx = orch.get_job(job_id)
    if ctx.status == "error":
        print(f"\nPipeline error: {ctx.error_msg}")
        sys.exit(1)
    if ctx.status == "empty":
        print("\nNo live devices found.")
        sys.exit(0)

    devices = ctx.all_devices()
    print(f"\nVerification complete: {len(devices)} devices found.")
    _print_device_table(devices)

    # Review
    if args.review == "skip":
        print("\n[WARNING] --review skip: approving all items (lab demo only)")
        _bulk_action(orch, job_id, "approve_all")
        result = orch.finalize(job_id, "cli-skip", True, remember=False)
        if result.get("ok"):
            report_path = os.path.join("scans", job_id, "netarch_report.html")
            print(f"\nReport written to {report_path}")
            if not args.no_browser:
                webbrowser.open(f"file://{os.path.abspath(report_path)}")
        sys.exit(0)

    elif args.review == "auto":
        _bulk_action(orch, job_id, "approve_safe")
        ctx = orch.get_job(job_id)
        devices = ctx.all_devices()
        pending = [k for k, d in devices.items() if d.get("review_status") == "pending"]
        from netarch.report import generate_reports
        ctx.report_version = 1
        generate_reports(ctx, "scans", is_draft=True)
        report_path = os.path.join("scans", job_id, "netarch_report.html")
        print(f"\nDRAFT report written to {report_path}")
        if not args.no_browser:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
        if pending:
            print(f"\n[auto] {len(pending)} items still pending review.")
            sys.exit(2)
        sys.exit(0)

    else:  # interactive
        _interactive_review(orch, job_id)
        ctx = orch.get_job(job_id)
        if ctx.status == "done":
            report_path = os.path.join("scans", job_id, "netarch_report.html")
            print(f"\nReport written to {report_path}")
            if not args.no_browser:
                webbrowser.open(f"file://{os.path.abspath(report_path)}")
        sys.exit(0)


if __name__ == "__main__":
    main()
