"""
BaseAgent: minimal contract every agent must satisfy.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from netarch.context import ScanContext


class BaseAgent:
    name: str = "base"
    title: str = "Base Agent"
    description: str = ""

    def run(
        self,
        ctx: ScanContext,
        log: Callable[[str], None],
        progress: Callable[[int, int], None],
    ) -> Dict[str, Any]:
        """
        Execute the agent.  Returns a summary dict.
        :param ctx: shared ScanContext blackboard
        :param log: callable(message) – log a line
        :param progress: callable(current, total) – update progress
        """
        raise NotImplementedError

    def _log(self, log: Callable, msg: str):
        log(f"[{self.title}] {msg}")
