"""
ScanContext: the shared blackboard all agents read and write.
Thread-safe via an RLock.
"""
from __future__ import annotations

import copy
import datetime
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class ScanContext:
    """
    One per scan job.  Persisted as scans/<job-id>/context.json.
    """

    def __init__(self, job_id: Optional[str] = None):
        self.job_id: str = job_id or str(uuid.uuid4())[:8]
        self._lock = threading.RLock()

        # Settings
        self.settings: Dict[str, Any] = {
            "target": "",
            "hosts": [],
            "live": False,
            "offset": 0,
            "community": "public",
            "crawl": 0,
            "scope": [],
            "max_hosts": 4096,
            "gateway": "auto",
            "approval": "",   # reviewer name after finalize
        }

        # Devices keyed by device key (IP or "nbr:<name>")
        self.devices: Dict[str, Dict] = {}

        # Links keyed by "a|b" (a < b lexicographically)
        self.links: Dict[str, Dict] = {}

        # Agent execution records
        self.agent_runs: Dict[str, Dict] = {}
        for name in ("discovery", "enrichment", "links", "verification", "review"):
            self.agent_runs[name] = {
                "status": "pending",
                "started": None,
                "finished": None,
                "duration_s": None,
                "summary": "",
                "counts": {},
                "log": [],
            }

        # Job-level status
        self.status: str = "queued"  # queued|discovery|enrichment|links|verification|awaiting_review|finalizing|done|discarded|empty|error
        self.error_msg: str = ""
        self.created: str = _now_iso()
        self.updated: str = _now_iso()
        self.report_version: int = 0

        # Audit trail
        self.audit: List[Dict] = []

    # ------------------------------------------------------------------
    # Thread-safe accessors
    # ------------------------------------------------------------------

    def with_lock(self, fn):
        with self._lock:
            return fn()

    def set_status(self, status: str, error: str = ""):
        with self._lock:
            self.status = status
            if error:
                self.error_msg = error
            self.updated = _now_iso()

    def add_device(self, key: str, data: Dict, actor: str = "system"):
        """Add or completely replace a device entry."""
        with self._lock:
            old = copy.deepcopy(self.devices.get(key))
            self.devices[key] = data
            self.updated = _now_iso()
            if old is not None:
                self._audit("update_device", key, old, data, actor)
            else:
                self._audit("add_device", key, None, data, actor)

    def update_device(self, key: str, fields: Dict, actor: str = "system"):
        """Merge fields into an existing device; create it if absent."""
        with self._lock:
            if key not in self.devices:
                self.devices[key] = {}
            old = copy.deepcopy(self.devices[key])
            self.devices[key].update(fields)
            self.updated = _now_iso()
            self._audit("update_device", key, old, copy.deepcopy(self.devices[key]), actor)

    def add_link(self, key: str, data: Dict, actor: str = "system"):
        with self._lock:
            old = copy.deepcopy(self.links.get(key))
            self.links[key] = data
            self.updated = _now_iso()
            if old is not None:
                self._audit("update_link", key, old, data, actor)
            else:
                self._audit("add_link", key, None, data, actor)

    def update_link(self, key: str, fields: Dict, actor: str = "system"):
        with self._lock:
            if key not in self.links:
                self.links[key] = {}
            old = copy.deepcopy(self.links[key])
            self.links[key].update(fields)
            self.updated = _now_iso()
            self._audit("update_link", key, old, copy.deepcopy(self.links[key]), actor)

    def log_agent(self, name: str, line: str):
        with self._lock:
            if name in self.agent_runs:
                self.agent_runs[name]["log"].append(line)
            self.updated = _now_iso()

    def set_agent_status(self, name: str, status: str, summary: str = "",
                          counts: Optional[Dict] = None):
        with self._lock:
            run = self.agent_runs.setdefault(name, {})
            run["status"] = status
            if status == "running":
                run["started"] = _now_iso()
            elif status in ("done", "error", "skipped"):
                run["finished"] = _now_iso()
                if run.get("started"):
                    try:
                        fmt = "%Y-%m-%dT%H:%M:%SZ"
                        s = datetime.datetime.strptime(run["started"], fmt)
                        e = datetime.datetime.strptime(run["finished"], fmt)
                        run["duration_s"] = round((e - s).total_seconds(), 1)
                    except Exception:
                        run["duration_s"] = None
            if summary:
                run["summary"] = summary
            if counts is not None:
                run["counts"] = counts
            self.updated = _now_iso()

    # ------------------------------------------------------------------
    # Device helpers
    # ------------------------------------------------------------------

    def get_device(self, key: str) -> Optional[Dict]:
        with self._lock:
            return copy.deepcopy(self.devices.get(key))

    def all_devices(self) -> Dict[str, Dict]:
        with self._lock:
            return copy.deepcopy(self.devices)

    def all_links(self) -> Dict[str, Dict]:
        with self._lock:
            return copy.deepcopy(self.links)

    def live_devices(self) -> Dict[str, Dict]:
        """Return devices that are considered 'alive' (not neighbour-only rejected)."""
        with self._lock:
            return {k: copy.deepcopy(v) for k, v in self.devices.items()
                    if v.get("review_status") != "rejected"}

    @staticmethod
    def link_key(a: str, b: str) -> str:
        pair = sorted([a, b])
        return f"{pair[0]}|{pair[1]}"

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit(self, action: str, target: str, before, after, actor: str):
        entry = {
            "time": _now_iso(),
            "actor": actor,
            "action": action,
            "target": target,
            "before": before,
            "after": after,
        }
        self.audit.append(entry)

    def add_audit(self, actor: str, action: str, target: str, before=None, after=None):
        with self._lock:
            self._audit(action, target, before, after, actor)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        with self._lock:
            return {
                "job_id": self.job_id,
                "status": self.status,
                "error_msg": self.error_msg,
                "created": self.created,
                "updated": self.updated,
                "report_version": self.report_version,
                "settings": copy.deepcopy(self.settings),
                "devices": copy.deepcopy(self.devices),
                "links": copy.deepcopy(self.links),
                "agent_runs": copy.deepcopy(self.agent_runs),
                "audit": copy.deepcopy(self.audit),
            }

    @classmethod
    def from_dict(cls, data: Dict) -> "ScanContext":
        ctx = cls(job_id=data.get("job_id"))
        ctx.status = data.get("status", "queued")
        ctx.error_msg = data.get("error_msg", "")
        ctx.created = data.get("created", _now_iso())
        ctx.updated = data.get("updated", _now_iso())
        ctx.report_version = data.get("report_version", 0)
        ctx.settings = data.get("settings", ctx.settings)
        ctx.devices = data.get("devices", {})
        ctx.links = data.get("links", {})
        ctx.agent_runs = data.get("agent_runs", ctx.agent_runs)
        ctx.audit = data.get("audit", [])
        return ctx

    def save(self, scans_dir: str = "scans"):
        job_dir = os.path.join(scans_dir, self.job_id)
        os.makedirs(job_dir, exist_ok=True)
        path = os.path.join(job_dir, "context.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        os.replace(tmp, path)

    @classmethod
    def load(cls, job_id: str, scans_dir: str = "scans") -> "ScanContext":
        path = os.path.join(scans_dir, job_id, "context.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
