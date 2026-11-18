#!/usr/bin/env python3
"""
app.py – NetArch Scan Flask web application, port 5002.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import sys
import traceback
import urllib.error
import urllib.request

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from netarch.context import ScanContext
from netarch.orchestrator import Orchestrator
from netarch.probes import auto_port_offset, parse_targets, TargetError, is_loopback_target
from netarch.report import generate_reports, get_draft_svg

SCANS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans")

app = Flask(__name__, template_folder="templates")
orch = Orchestrator(scans_dir=SCANS_DIR)

_WHITELISTED_FILES = {
    "netarch_report.html", "netarch_inventory.csv", "netarch_links.csv",
    "netarch_topology.mmd", "netarch_scan.json", "netarch_audit.csv",
    "scan.log",
}


# ---------------------------------------------------------------------------
# Helper: check if job is in a running state
# ---------------------------------------------------------------------------

def _is_running(ctx: ScanContext) -> bool:
    return ctx.status in ("discovery", "enrichment", "links", "verification")


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Static file serving for scan outputs
# ---------------------------------------------------------------------------

@app.route("/scans/<job_id>/<filename>")
def serve_scan_file(job_id, filename):
    # Whitelist check
    base = filename
    # strip version suffix like _v2
    import re
    base_stripped = re.sub(r'_v\d+', '', base)
    if not any(base_stripped == wf or base == wf for wf in _WHITELISTED_FILES):
        abort(403)
    path = os.path.join(SCANS_DIR, job_id, filename)
    if not os.path.isfile(path):
        abort(404)
    as_attachment = request.args.get("dl") == "1"
    return send_file(path, as_attachment=as_attachment)


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api/scans", methods=["GET"])
def api_list_scans():
    return jsonify(orch.list_jobs())


@app.route("/api/scans/<job_id>", methods=["GET"])
def api_get_scan(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    data = {
        "job_id": ctx.job_id,
        "status": ctx.status,
        "error_msg": ctx.error_msg,
        "created": ctx.created,
        "updated": ctx.updated,
        "settings": ctx.settings,
        "agent_runs": ctx.agent_runs,
        "device_count": len(ctx.devices),
        "link_count": len(ctx.links),
        "log": orch.get_log(job_id)[-300:],
        "report_version": ctx.report_version,
    }
    return jsonify(data)


@app.route("/api/scans/<job_id>", methods=["DELETE"])
def api_delete_scan(job_id):
    ok = orch.delete_job(job_id)
    if not ok:
        return jsonify({"error": "Cannot delete (running or not found)"}), 409
    return jsonify({"ok": True})


@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    body = request.get_json(force=True)
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    community = body.get("community", "public")
    crawl     = int(body.get("crawl", 0))
    gateway   = body.get("gateway", "auto")
    max_hosts = int(body.get("max_hosts", 4096))
    scope_raw = body.get("scope", "")
    scope     = [s.strip() for s in scope_raw.split(",") if s.strip()] if scope_raw else []
    llm       = bool(body.get("llm", False))
    live      = bool(body.get("live", False))
    approval  = (body.get("approval") or "").strip()

    # Live scan approval gate
    if live and approval != "I have approval to scan":
        return jsonify({"error": "Live scan requires approval confirmation"}), 400

    # Determine offset
    offset_raw = body.get("offset", None)
    if offset_raw is not None and str(offset_raw).strip() != "":
        offset = int(offset_raw)
    else:
        try:
            preview = parse_targets(target, max_hosts=max_hosts)
        except Exception:
            preview = []
        offset = auto_port_offset(preview) if preview else 0

    # Busy check
    running_jobs = [j for j in orch.list_jobs()
                    if j["status"] in ("discovery", "enrichment", "links", "verification")]
    if running_jobs:
        return jsonify({"error": f"Another job is already running: {running_jobs[0]['job_id']}",
                        "running_job": running_jobs[0]["job_id"]}), 409

    settings = {
        "target":    target,
        "community": community,
        "crawl":     crawl,
        "scope":     scope,
        "gateway":   gateway,
        "max_hosts": max_hosts,
        "offset":    offset,
        "live":      live,
        "llm":       llm,
        "approval":  approval,
    }
    ctx = orch.create_job(settings)
    orch.start_job(ctx.job_id)
    return jsonify({"job_id": ctx.job_id}), 201


@app.route("/api/scans/<job_id>/review", methods=["GET"])
def api_review(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    devices = ctx.all_devices()
    links   = ctx.all_links()
    # Build issue summary
    crit = sum(1 for d in devices.values()
               for i in d.get("issues", []) if i["severity"] == "critical")
    warn = sum(1 for d in devices.values()
               for i in d.get("issues", []) if i["severity"] == "warning")
    info = sum(1 for d in devices.values()
               for i in d.get("issues", []) if i["severity"] == "info")
    pending  = sum(1 for d in devices.values() if d.get("review_status") == "pending")
    approved = sum(1 for d in devices.values() if d.get("review_status") == "approved")
    edited   = sum(1 for d in devices.values() if d.get("review_status") == "edited")
    rejected = sum(1 for d in devices.values() if d.get("review_status") == "rejected")

    draft_svg = get_draft_svg(ctx)

    return jsonify({
        "devices": devices,
        "links": links,
        "issues": {"critical": crit, "warning": warn, "info": info},
        "summary": {"pending": pending, "approved": approved,
                    "edited": edited, "rejected": rejected},
        "draft_svg": draft_svg,
    })


@app.route("/api/scans/<job_id>/devices/<path:key>", methods=["PUT"])
def api_device_action(job_id, key):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    if ctx.status != "awaiting_review":
        return jsonify({"error": "Job is not awaiting review"}), 409

    body   = request.get_json(force=True)
    action = body.get("action", "")
    reviewer = body.get("reviewer", "unknown")

    dev = ctx.get_device(key)
    if not dev:
        abort(404)

    updates = {}
    if action == "approve":
        updates["review_status"] = "approved"
    elif action == "reject":
        updates["review_status"] = "rejected"
    elif action == "edit":
        updates["review_status"] = "edited"
        editable = ["name", "vendor", "model", "role", "tier",
                    "is_gateway", "notes", "mac"]
        human_edits = dev.get("human_edits", {})
        for field in editable:
            if field in body:
                updates[field] = body[field]
                human_edits[field] = body[field]
        updates["human_edits"] = human_edits
    else:
        return jsonify({"error": "Invalid action"}), 400

    ctx.update_device(key, updates, actor=f"human:{reviewer}")
    ctx.save(SCANS_DIR)
    return jsonify({"ok": True})


@app.route("/api/scans/<job_id>/links/<path:key>", methods=["PUT"])
def api_link_action(job_id, key):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    if ctx.status != "awaiting_review":
        return jsonify({"error": "Job is not awaiting review"}), 409

    body   = request.get_json(force=True)
    action = body.get("action", "")
    reviewer = body.get("reviewer", "unknown")

    updates = {}
    if action == "approve":
        updates["review_status"] = "approved"
    elif action == "reject":
        updates["review_status"] = "rejected"
    elif action == "edit":
        updates["review_status"] = "edited"
        for f in ("a_port", "b_port"):
            if f in body:
                updates[f] = body[f]
    else:
        return jsonify({"error": "Invalid action"}), 400

    ctx.update_link(key, updates, actor=f"human:{reviewer}")
    ctx.save(SCANS_DIR)
    return jsonify({"ok": True})


@app.route("/api/scans/<job_id>/links", methods=["POST"])
def api_add_link(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    if ctx.status != "awaiting_review":
        return jsonify({"error": "Job is not awaiting review"}), 409

    body    = request.get_json(force=True)
    a_key   = body.get("a", "")
    b_key   = body.get("b", "")
    a_port  = body.get("a_port", "")
    b_port  = body.get("b_port", "")
    reviewer = body.get("reviewer", "unknown")

    if not a_key or not b_key:
        return jsonify({"error": "a and b required"}), 400

    lk   = ctx.link_key(a_key, b_key)
    pair = sorted([a_key, b_key])
    ctx.add_link(lk, {
        "a": pair[0], "b": pair[1],
        "a_port": a_port, "b_port": b_port,
        "source": "manual",
        "seen_from": [f"human:{reviewer}"],
        "confidence": 100,
        "issues": [],
        "review_status": "approved",
        "human_edits": {},
    }, actor=f"human:{reviewer}")
    ctx.save(SCANS_DIR)
    return jsonify({"ok": True, "link_key": lk})


@app.route("/api/scans/<job_id>/bulk", methods=["POST"])
def api_bulk(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    if ctx.status != "awaiting_review":
        return jsonify({"error": "Job is not awaiting review"}), 409

    body    = request.get_json(force=True)
    action  = body.get("action", "")
    reviewer = body.get("reviewer", "unknown")

    if action == "approve_safe":
        for key, dev in ctx.devices.items():
            if dev.get("_auto_approve") and dev.get("review_status") == "pending":
                ctx.update_device(key, {"review_status": "approved"},
                                  actor=f"human:{reviewer}")
        for lk, lnk in ctx.links.items():
            if lnk.get("confidence", 0) >= 80 and lnk.get("review_status") == "pending":
                ctx.update_link(lk, {"review_status": "approved"},
                                actor=f"human:{reviewer}")
    elif action == "approve_all":
        for key in ctx.devices:
            if ctx.devices[key].get("review_status") == "pending":
                ctx.update_device(key, {"review_status": "approved"},
                                  actor=f"human:{reviewer}")
        for lk in ctx.links:
            if ctx.links[lk].get("review_status") == "pending":
                ctx.update_link(lk, {"review_status": "approved"},
                                actor=f"human:{reviewer}")
    elif action == "reject_arp_only":
        for key, dev in ctx.devices.items():
            if dev.get("via") == ["ARP"]:
                ctx.update_device(key, {"review_status": "rejected"},
                                  actor=f"human:{reviewer}")
    else:
        return jsonify({"error": "Unknown bulk action"}), 400

    ctx.save(SCANS_DIR)
    return jsonify({"ok": True})


@app.route("/api/scans/<job_id>/rerun/<agent_name>", methods=["POST"])
def api_rerun(job_id, agent_name):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    if _is_running(ctx):
        return jsonify({"error": "Job is already running"}), 409
    valid_agents = ["discovery", "enrichment", "links", "verification"]
    if agent_name not in valid_agents:
        return jsonify({"error": f"Invalid agent. Choose from {valid_agents}"}), 400

    # Accept additional settings for this rerun (e.g. new crawl value)
    body = request.get_json(force=True, silent=True) or {}
    for key in ("crawl", "scope", "community", "gateway", "offset"):
        if key in body:
            ctx.settings[key] = body[key]

    try:
        orch.rerun_from(job_id, agent_name)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409

    return jsonify({"ok": True})


@app.route("/api/scans/<job_id>/finalize", methods=["POST"])
def api_finalize(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    if ctx.status != "awaiting_review":
        return jsonify({"error": "Job is not awaiting review"}), 409

    body = request.get_json(force=True)
    reviewer        = body.get("reviewer", "anonymous")
    approve_pending = bool(body.get("approve_pending", False))
    remember        = bool(body.get("remember", False))

    result = orch.finalize(job_id, reviewer, approve_pending, remember)
    return jsonify(result)


@app.route("/api/scans/<job_id>/discard", methods=["POST"])
def api_discard(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    orch.discard(job_id)
    return jsonify({"ok": True})


@app.route("/api/scans/<job_id>/reopen", methods=["POST"])
def api_reopen(job_id):
    ctx = orch.get_job(job_id)
    if not ctx:
        abort(404)
    try:
        orch.reopen(job_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/lab-info", methods=["GET"])
def api_lab_info():
    """Server-side proxy to fetch NetArch Lab /api/info."""
    lab_url = request.args.get("url", "http://127.0.0.1:5001").rstrip("/")
    if not lab_url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL scheme"}), 400
    try:
        req = urllib.request.Request(
            f"{lab_url}/api/info",
            headers={"User-Agent": "NetArchScan"},
        )
        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        return jsonify(data)
    except urllib.error.URLError as e:
        return jsonify({"error": f"Lab not reachable: {e.reason}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 503


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetArch Scan web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5002)
    args = parser.parse_args()
    print(f"NetArch Scan starting on http://{args.host}:{args.port}")
    print("NOTE: There is no login system. Reviewer names are not authenticated.")
    print("      Scanning requires authorisation. Never scan networks without permission.")
    app.run(host=args.host, port=args.port, debug=False)
