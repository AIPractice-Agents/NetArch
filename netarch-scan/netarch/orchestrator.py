"""
Orchestrator: runs the 5-agent pipeline in a background thread,
manages job lifecycle, pause/resume, rerun-from-agent.
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import time
import traceback
from typing import Any, Callable, Dict, List, Optional

from netarch.agents.discovery import DiscoveryAgent
from netarch.agents.enrichment import EnrichmentAgent
from netarch.agents.links import LinksAgent
from netarch.agents.verification import VerificationAgent
from netarch.agents.review import ReviewAgent
from netarch.context import ScanContext

_AGENT_ORDER = ["discovery", "enrichment", "links", "verification"]
_ALL_AGENTS = _AGENT_ORDER + ["review"]
_AGENT_CLASSES = {
    "discovery":    DiscoveryAgent,
    "enrichment":   EnrichmentAgent,
    "links":        LinksAgent,
    "verification": VerificationAgent,
    "review":       ReviewAgent,
}

# Global: at most one job may be in an agent-running state at a time.
_running_lock = threading.Lock()
_running_job_id: Optional[str] = None


class _JobLogger:
    """
    Captures print() calls on a per-job basis using thread-local stdout routing.
    Also accepts explicit log(msg) calls.
    """
    def __init__(self, ctx: ScanContext, scans_dir: str):
        self.ctx = ctx
        self.scans_dir = scans_dir
        self._lines: List[str] = []
        self._flock = threading.Lock()
        self._log_path = os.path.join(scans_dir, ctx.job_id, "scan.log")
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)

    def log(self, agent_name: str, msg: str):
        line = msg if msg.startswith("[") else f"[{agent_name}] {msg}"
        with self._flock:
            self._lines.append(line)
            self.ctx.log_agent(agent_name, line)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def all_lines(self) -> List[str]:
        with self._flock:
            return list(self._lines)


class Orchestrator:
    def __init__(self, scans_dir: str = "scans"):
        self.scans_dir = scans_dir
        os.makedirs(scans_dir, exist_ok=True)
        self._jobs: Dict[str, ScanContext] = {}
        self._loggers: Dict[str, _JobLogger] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._load_persisted_jobs()

    # ------------------------------------------------------------------
    # Job management
    # ------------------------------------------------------------------

    def _load_persisted_jobs(self):
        """Reload jobs from disk on startup."""
        if not os.path.isdir(self.scans_dir):
            return
        for job_id in os.listdir(self.scans_dir):
            ctx_path = os.path.join(self.scans_dir, job_id, "context.json")
            if os.path.isfile(ctx_path):
                try:
                    ctx = ScanContext.load(job_id, self.scans_dir)
                    # Jobs that were running when app stopped are marked error
                    if ctx.status in ("discovery", "enrichment", "links",
                                      "verification", "queued", "finalizing"):
                        ctx.set_status("error",
                                       "interrupted: app restarted")
                        ctx.save(self.scans_dir)
                    self._jobs[job_id] = ctx
                    self._loggers[job_id] = _JobLogger(ctx, self.scans_dir)
                except Exception:
                    pass

    def create_job(self, settings: Dict) -> ScanContext:
        ctx = ScanContext()
        ctx.settings.update(settings)
        ctx.set_status("queued")
        self._jobs[ctx.job_id] = ctx
        self._loggers[ctx.job_id] = _JobLogger(ctx, self.scans_dir)
        ctx.save(self.scans_dir)
        return ctx

    def get_job(self, job_id: str) -> Optional[ScanContext]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[Dict]:
        result = []
        for jid, ctx in self._jobs.items():
            result.append({
                "job_id": jid,
                "status": ctx.status,
                "target": ctx.settings.get("target", ""),
                "created": ctx.created,
                "updated": ctx.updated,
                "device_count": len(ctx.devices),
                "live": ctx.settings.get("live", False),
                "error_msg": ctx.error_msg,
            })
        result.sort(key=lambda x: x["created"], reverse=True)
        return result

    def delete_job(self, job_id: str) -> bool:
        ctx = self._jobs.get(job_id)
        if not ctx:
            return False
        if ctx.status in ("discovery", "enrichment", "links", "verification"):
            return False  # running
        import shutil
        job_dir = os.path.join(self.scans_dir, job_id)
        if os.path.isdir(job_dir):
            shutil.rmtree(job_dir, ignore_errors=True)
        del self._jobs[job_id]
        self._loggers.pop(job_id, None)
        return True

    def get_log(self, job_id: str) -> List[str]:
        logger = self._loggers.get(job_id)
        if logger:
            return logger.all_lines()
        # Read from file
        log_path = os.path.join(self.scans_dir, job_id, "scan.log")
        if os.path.isfile(log_path):
            with open(log_path, encoding="utf-8") as f:
                return f.read().splitlines()
        return []

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def start_job(self, job_id: str):
        """Start or resume the pipeline in a background thread."""
        global _running_job_id
        ctx = self._jobs.get(job_id)
        if not ctx:
            raise KeyError(f"Unknown job: {job_id}")
        with _running_lock:
            if _running_job_id and _running_job_id != job_id:
                other = self._jobs.get(_running_job_id)
                if other and other.status in _AGENT_ORDER:
                    raise RuntimeError(f"Another job is already running: {_running_job_id}")
            _running_job_id = job_id

        t = threading.Thread(target=self._run_pipeline,
                             args=(job_id,), daemon=True)
        self._threads[job_id] = t
        t.start()

    def rerun_from(self, job_id: str, agent_name: str):
        """Rerun from agent_name onwards, then return to awaiting_review."""
        global _running_job_id
        ctx = self._jobs.get(job_id)
        if not ctx:
            raise KeyError(f"Unknown job: {job_id}")
        with _running_lock:
            if _running_job_id and _running_job_id != job_id:
                other = self._jobs.get(_running_job_id)
                if other and other.status in _AGENT_ORDER:
                    raise RuntimeError(f"Another job is already running: {_running_job_id}")
            _running_job_id = job_id

        t = threading.Thread(target=self._run_pipeline,
                             args=(job_id, agent_name), daemon=True)
        self._threads[job_id] = t
        t.start()

    def _run_pipeline(self, job_id: str, start_from: str = "discovery"):
        global _running_job_id
        ctx = self._jobs[job_id]
        logger = self._loggers[job_id]

        try:
            # Determine which agents to run
            if start_from in _AGENT_ORDER:
                start_idx = _AGENT_ORDER.index(start_from)
            else:
                start_idx = 0

            agents_to_run = _AGENT_ORDER[start_idx:]

            for agent_name in agents_to_run:
                AgentClass = _AGENT_CLASSES[agent_name]
                agent = AgentClass()
                ctx.set_status(agent_name)
                ctx.set_agent_status(agent_name, "running")
                ctx.save(self.scans_dir)

                def _log(msg: str, _an=agent_name):
                    logger.log(_an, msg)

                def _progress(cur: int, tot: int):
                    pass  # could update progress field

                try:
                    result = agent.run(ctx, _log, _progress)
                    ctx.set_agent_status(agent_name, "done",
                                         summary=result.get("summary", ""),
                                         counts=result.get("counts"))
                except Exception as e:
                    tb = traceback.format_exc()
                    logger.log(agent_name, f"ERROR: {e}\n{tb}")
                    ctx.set_agent_status(agent_name, "error", summary=str(e))
                    ctx.set_status("error", str(e))
                    ctx.save(self.scans_dir)
                    return

                ctx.save(self.scans_dir)

                # If Discovery found nothing, stop
                if agent_name == "discovery" and not ctx.devices:
                    ctx.set_status("empty")
                    ctx.save(self.scans_dir)
                    logger.log("discovery", "No live devices found. Stopping.")
                    return

            # Run the review agent (transition to awaiting_review)
            review_agent = ReviewAgent()
            ctx.set_agent_status("review", "running")
            ctx.save(self.scans_dir)

            def _log_rev(msg: str):
                logger.log("review", msg)

            result = review_agent.run(ctx, _log_rev, lambda c, t: None)
            ctx.set_agent_status("review", "done",
                                  summary=result.get("summary", ""),
                                  counts=result.get("counts"))
            ctx.set_status("awaiting_review")
            ctx.save(self.scans_dir)

        finally:
            with _running_lock:
                if _running_job_id == job_id:
                    _running_job_id = None

    # ------------------------------------------------------------------
    # Finalize / Discard / Reopen
    # ------------------------------------------------------------------

    def finalize(self, job_id: str, reviewer: str, approve_pending: bool,
                 remember: bool) -> Dict[str, Any]:
        """Finalize the job: write reports, update status."""
        from netarch.report import generate_reports

        ctx = self._jobs.get(job_id)
        if not ctx:
            raise KeyError(f"Unknown job: {job_id}")
        if ctx.status != "awaiting_review":
            raise ValueError(f"Job {job_id} is not awaiting review (status={ctx.status})")

        # Check blocking items
        blocking = []
        for key, dev in ctx.devices.items():
            issues = dev.get("issues", [])
            crit = any(i["severity"] == "critical" for i in issues)
            if crit and dev.get("review_status") == "pending":
                blocking.append(f"Device {dev.get('name', key)} has critical issues and is pending")

        if blocking and not approve_pending:
            return {"ok": False, "blocking": blocking}

        ctx.set_status("finalizing")
        ctx.save(self.scans_dir)
        ctx.settings["approval"] = reviewer

        # Approve remaining pending if requested
        if approve_pending:
            for key in list(ctx.devices.keys()):
                dev = ctx.get_device(key)
                if dev and dev.get("review_status") == "pending":
                    ctx.update_device(key, {"review_status": "approved"},
                                      actor=f"human:{reviewer}")
            for lk in list(ctx.links.keys()):
                lnk = ctx.links.get(lk)
                if lnk and lnk.get("review_status") == "pending":
                    ctx.update_link(lk, {"review_status": "approved"},
                                    actor=f"human:{reviewer}")

        ctx.add_audit(f"human:{reviewer}", "finalize", job_id)

        # Remember overrides
        if remember:
            self._write_overrides(ctx, reviewer)

        # Generate reports
        ctx.report_version += 1
        try:
            generate_reports(ctx, self.scans_dir)
        except Exception as e:
            traceback.print_exc()
            ctx.set_status("error", f"Report generation failed: {e}")
            ctx.save(self.scans_dir)
            return {"ok": False, "error": str(e)}

        ctx.set_status("done")
        ctx.save(self.scans_dir)
        return {"ok": True, "version": ctx.report_version}

    def discard(self, job_id: str):
        ctx = self._jobs.get(job_id)
        if not ctx:
            raise KeyError(job_id)
        ctx.set_status("discarded")
        ctx.save(self.scans_dir)

    def reopen(self, job_id: str):
        ctx = self._jobs.get(job_id)
        if not ctx:
            raise KeyError(job_id)
        if ctx.status != "done":
            raise ValueError("Can only reopen a done job")
        ctx.set_status("awaiting_review")
        ctx.save(self.scans_dir)

    @staticmethod
    def _write_overrides(ctx: ScanContext, reviewer: str):
        import datetime
        overrides_path = "overrides.json"
        try:
            if os.path.isfile(overrides_path):
                with open(overrides_path, encoding="utf-8") as f:
                    overrides = json.load(f)
            else:
                overrides = []
        except Exception:
            overrides = []

        date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        for key, dev in ctx.devices.items():
            if dev.get("review_status") not in ("edited", "approved"):
                continue
            edits = dev.get("human_edits", {})
            if not edits and dev.get("review_status") != "edited":
                continue
            entry = {
                "mac":     dev.get("mac", ""),
                "ip":      dev.get("ip", ""),
                "sysname": dev.get("snmp", {}).get("sysName", ""),
                "date":    date_str,
                "reviewer": reviewer,
            }
            for field in ("name", "vendor", "model", "role", "tier",
                           "is_gateway", "notes"):
                if edits.get(field) is not None:
                    entry[field] = edits[field]
                elif dev.get(field):
                    pass  # only write explicit edits
            if any(k in entry for k in ("name", "vendor", "model", "role",
                                         "tier", "is_gateway", "notes")):
                # Update existing or append
                found = False
                for i, ov in enumerate(overrides):
                    if (ov.get("mac") and ov["mac"] == entry["mac"]) or \
                       (ov.get("ip") == entry["ip"] and
                            ov.get("sysname") == entry["sysname"]):
                        overrides[i].update(entry)
                        found = True
                        break
                if not found:
                    overrides.append(entry)

        with open(overrides_path, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2)
