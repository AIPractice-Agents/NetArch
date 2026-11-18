"""
Agent 5 – Human-in-the-Loop (Review) Agent
This agent doesn't run autonomously; it manages the state of the job
while it is in "awaiting_review" status.  The orchestrator calls
run() once to transition to that status; all actual review actions
come through the orchestrator/app API.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict

from netarch.agents.base import BaseAgent
from netarch.context import ScanContext


class ReviewAgent(BaseAgent):
    name = "review"
    title = "Human Review"
    description = "Pause for a human to review and approve the scan results."

    def run(
        self,
        ctx: ScanContext,
        log: Callable[[str], None],
        progress: Callable[[int, int], None],
    ) -> Dict[str, Any]:
        """
        Transition the job to awaiting_review and return.
        The actual human interaction happens via the UI/CLI.
        """
        progress(1, 1)
        devices = ctx.all_devices()
        pending = sum(1 for d in devices.values()
                      if d.get("review_status") == "pending")
        auto = sum(1 for d in devices.values()
                   if d.get("_auto_approve"))
        links = ctx.all_links()
        pending_links = sum(1 for ln in links.values()
                            if ln.get("review_status") == "pending")

        summary = (
            f"Awaiting review: {pending} devices pending "
            f"({auto} auto-approve candidates), "
            f"{pending_links} links pending."
        )
        self._log(log, summary)
        return {
            "summary": summary,
            "counts": {
                "pending_devices": pending,
                "auto_approve": auto,
                "pending_links": pending_links,
            }
        }
