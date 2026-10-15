"""Runs the checks – shared by the terminal (cli.py) and the window (gui.py)."""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from .core import CheckResult, Finding, Level

Progress = Callable[[int, int, str], None]  # (current index, total, title)


def run_checks(modules: list, on_progress: Optional[Progress] = None) -> List[CheckResult]:
    results: List[CheckResult] = []
    for i, mod in enumerate(modules):
        if on_progress:
            on_progress(i, len(modules), mod.TITLE)
        t0 = time.monotonic()
        try:
            findings = mod.run()
        except Exception as exc:  # one broken check must not stop the rest
            findings = [Finding(f"This check could not run ({type(exc).__name__})", Level.INFO,
                                detail=str(exc)[:200])]
        results.append(CheckResult(mod.ID, mod.TITLE, findings, time.monotonic() - t0))
    if on_progress:
        on_progress(len(modules), len(modules), "")
    return results


def results_from_json(data: dict) -> List[CheckResult]:
    """Rebuild results from the JSON output (e.g. from the admin run via pkexec)."""
    results = []
    for c in data.get("checks", []):
        findings = [Finding(
            title=f.get("title", ""),
            level=Level[f.get("level", "INFO")],
            detail=f.get("detail", ""),
            explain=f.get("explain", ""),
            fix=f.get("fix", ""),
            items=list(f.get("items", [])),
        ) for f in c.get("findings", [])]
        results.append(CheckResult(c.get("id", "?"), c.get("title", "?"), findings, c.get("seconds", 0.0)))
    return results
