"""Command line: kauz [--html FILE] [--json FILE|-] [--only a,b] [-v]"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import DISCLAIMER, __version__
from .checks import ALL
from .core import Level, score
from .engine import run_checks
from .report import terminal, to_html, to_json
from .utils import distro_name, is_root, real_user


def main(argv: Optional[List[str]] = None) -> int:
    if is_root():
        sys.dont_write_bytecode = True  # never leave root-owned files in the user's folder

    ap = argparse.ArgumentParser(
        prog="kauz",
        description="Kauz – the friendly security check for your Linux PC. It only reads, never changes anything.",
        epilog=DISCLAIMER,
    )
    ap.add_argument("--html", metavar="FILE", help="save a nice HTML report")
    ap.add_argument("--json", metavar="FILE", help="save the result as JSON; '-' = print only JSON")
    ap.add_argument("--only", metavar="CHECKS", help="run only these checks, e.g. --only network,ssh")
    ap.add_argument("--list", action="store_true", help="list all checks")
    ap.add_argument("-v", "--verbose", action="store_true", help="show all details and explanations")
    ap.add_argument("--no-color", action="store_true", help="output without colours")
    ap.add_argument("--version", action="version", version=f"kauz {__version__}")
    args = ap.parse_args(argv)

    if args.list:
        for mod in ALL:
            print(f"{mod.ID:<12} {mod.TITLE}")
        return 0

    selected = ALL
    if args.only:
        wanted = {w.strip() for w in args.only.split(",") if w.strip()}
        unknown = wanted - {m.ID for m in ALL}
        if unknown:
            print(f"Unknown checks: {', '.join(sorted(unknown))}. See `kauz --list`.", file=sys.stderr)
            return 64
        selected = [m for m in ALL if m.ID in wanted]

    json_only = args.json == "-"
    color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    show_progress = sys.stderr.isatty() and not json_only

    def progress(i: int, n: int, title: str) -> None:
        if show_progress:
            msg = f"🦉 Checking {title} … ({i + 1}/{n})" if title else ""
            print(f"\r\033[K{msg}", end="", file=sys.stderr, flush=True)

    results = run_checks(selected, progress)
    points = score(results)
    system, user, root = distro_name(), real_user(), is_root()

    if json_only:
        print(to_json(results, points, system))
    else:
        print(terminal(results, points, color, args.verbose, system, user, root))
        for path, content in ((args.html, lambda: to_html(results, points, system, user, root)),
                              (args.json, lambda: to_json(results, points, system))):
            if path:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(content())
                    print(f"Saved: {os.path.abspath(path)}")
                except OSError as exc:
                    print(f"Could not save {path}: {exc.strerror}", file=sys.stderr)

    worst = max((r.worst for r in results), default=Level.OK)
    # exit code: 0 = fine/notes, 1 = warnings, 2 = critical (handy for scripts & cron jobs)
    return {Level.CRIT: 2, Level.WARN: 1}.get(worst, 0)
