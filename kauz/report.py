"""Output: coloured terminal view, HTML report and JSON."""
from __future__ import annotations

import html
import json
import re
import shutil
import textwrap
from datetime import datetime
from typing import List

from . import DISCLAIMER, __version__
from .core import CheckResult, Level, mood

OWLS = {
    "happy": ["  ,___,  ", "  (^v^)  ", "  /)  )  ", ' --"-"-- '],
    "neutral": ["  ,___,  ", "  (o,o)  ", "  {`\"'}  ", '  -"-"-  '],
    "worried": ["  ,___,  ", "  (O_O) !", "  {`\"'}  ", '  -"-"-  '],
}
MESSAGES = {
    "happy": "Hoo-hoo! Your nest is well protected.",
    "neutral": "Hoo-hoo. A few things are worth a look.",
    "worried": "HOO-HOO! Quite a few doors are open – let's fix them together.",
}
ICONS = {Level.OK: "✔", Level.INFO: "ℹ", Level.WARN: "⚠", Level.CRIT: "✖"}
COLORS = {Level.OK: "32", Level.INFO: "36", Level.WARN: "33", Level.CRIT: "31"}


def code_html(text: str) -> str:
    """Escape text and turn `commands` into <code> tags."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text, quote=False))


class Painter:
    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text


def counts(results: List[CheckResult]) -> dict:
    return {lvl: sum(1 for r in results for f in r.findings if f.level == lvl) for lvl in Level}


def terminal(results: List[CheckResult], points: int, color: bool, verbose: bool,
             system: str, user: str, root: bool) -> str:
    c = Painter(color)
    width = min(shutil.get_terminal_size((90, 20)).columns, 100)
    m = mood(points)
    score_col = "32" if m == "happy" else "33" if m == "neutral" else "31"
    out = []

    side = [
        c("KAUZ", "1") + f"  security check v{__version__}",
        f"{system} · user: {user}" + (" (admin)" if root else ""),
        "Score: " + c(f"{points}/100", "1;" + score_col),
        c(MESSAGES[m], score_col),
    ]
    for a, b in zip(OWLS[m], side):
        out.append(c(a, score_col) + "  " + b)
    out.append("")

    def wrap(t: str, ind: str = "      ") -> str:
        return textwrap.fill(t, width=width, initial_indent=ind, subsequent_indent=ind)

    for r in results:
        out.append(c(f"── {r.title} ", "1") + c("─" * max(0, width - len(r.title) - 4), "2"))
        for f in sorted(r.findings, key=lambda x: -x.level):
            out.append(f"  {c(ICONS[f.level], COLORS[f.level])} {c(f.title, '1' if f.level >= Level.WARN else '0')}")
            more = verbose or f.level >= Level.WARN
            if f.detail:
                out.append(c(wrap(f.detail), "2"))
            if more and f.items:
                limit = 15 if verbose else 6
                for it in f.items[:limit]:
                    out.append(c(wrap("• " + it), "2"))
                if len(f.items) > limit:
                    out.append(c(f"      … {len(f.items) - limit} more" + ("" if verbose else " (use -v to see all)"), "2"))
            if more and f.explain:
                out.append(wrap("What does it mean? " + f.explain))
            if more and f.fix:
                out.append(c(wrap("What to do: " + f.fix), "36"))
        out.append("")

    n = counts(results)
    out.append(f"{c(str(n[Level.CRIT]) + ' critical', COLORS[Level.CRIT])} · "
               f"{c(str(n[Level.WARN]) + ' warnings', COLORS[Level.WARN])} · "
               f"{c(str(n[Level.INFO]) + ' notes', COLORS[Level.INFO])} · "
               f"{c(str(n[Level.OK]) + ' OK', COLORS[Level.OK])}")
    if not root:
        out.append(c("Tip: `sudo kauz` sees more (other users' processes, sudo rules, firewall rules).", "2"))
    out.append(c(wrap("Note: " + DISCLAIMER, ""), "2"))
    return "\n".join(out)


def to_json(results: List[CheckResult], points: int, system: str) -> str:
    return json.dumps({
        "kauz": __version__,
        "time": datetime.now().isoformat(timespec="seconds"),
        "system": system,
        "score": points,
        "checks": [{"id": r.id, "title": r.title, "seconds": round(r.seconds, 2),
                    "findings": [f.to_dict() for f in r.findings]} for r in results],
    }, ensure_ascii=False, indent=2)


def _owl_svg(m: str) -> str:
    eyes = {
        "happy": '<path d="M38 52 q8 -9 16 0" /><path d="M66 52 q8 -9 16 0" />',
        "neutral": '<circle cx="46" cy="52" r="5" fill="currentColor" stroke="none"/>'
                   '<circle cx="74" cy="52" r="5" fill="currentColor" stroke="none"/>',
        "worried": '<circle cx="46" cy="52" r="8"/><circle cx="74" cy="52" r="8"/>'
                   '<circle cx="46" cy="52" r="3" fill="currentColor" stroke="none"/>'
                   '<circle cx="74" cy="52" r="3" fill="currentColor" stroke="none"/>',
    }[m]
    return f'''<svg viewBox="0 0 120 130" class="owl {m}" aria-label="Kauz">
  <g fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round">
    <path d="M24 30 L34 14 L46 28 Q60 22 74 28 L86 14 L96 30 Q104 60 96 92 Q86 118 60 118 Q34 118 24 92 Q16 60 24 30Z" fill="var(--owl-body)"/>
    <circle cx="46" cy="52" r="15" fill="var(--bg)"/><circle cx="74" cy="52" r="15" fill="var(--bg)"/>
    {eyes}
    <path d="M56 66 L60 76 L64 66Z" fill="var(--beak)" stroke="var(--beak)"/>
    <path d="M44 92 q4 4 8 0 M56 98 q4 4 8 0 M68 92 q4 4 8 0" stroke-width="3"/>
    <path d="M44 120 v6 M52 120 v6 M68 120 v6 M76 120 v6" stroke="var(--beak)"/>
  </g>
</svg>'''


CSS = """
:root{--bg:#fbfaf7;--card:#fff;--text:#1f2328;--muted:#656d76;--line:#e6e2da;--owl-body:#e9dcc6;--beak:#d08a2b;
--ok:#1a7f37;--info:#0969da;--warn:#9a6700;--crit:#cf222e;--ok-bg:#dafbe1;--info-bg:#ddf4ff;--warn-bg:#fff8c5;--crit-bg:#ffebe9;--code:#f0eee9}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1c1f25;--text:#e6edf3;--muted:#8d96a0;--line:#2d333b;--owl-body:#4a3f30;--beak:#e3a24a;
--ok:#3fb950;--info:#58a6ff;--warn:#d29922;--crit:#f85149;--ok-bg:#12261a;--info-bg:#0c2238;--warn-bg:#2b2410;--crit-bg:#33141a;--code:#262a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;gap:24px;align-items:center;margin-bottom:28px;flex-wrap:wrap}
.owl{width:110px;color:var(--text);flex:none}
h1{margin:0;font-size:28px;letter-spacing:-.02em}.sub{color:var(--muted);font-size:14px}
.score{font-size:44px;font-weight:700;line-height:1;margin:8px 0 4px}.score small{font-size:18px;color:var(--muted);font-weight:500}
.s-happy{color:var(--ok)}.s-neutral{color:var(--warn)}.s-worried{color:var(--crit)}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.pill{font-size:13px;padding:2px 10px;border-radius:99px;font-weight:600}
.l-OK{color:var(--ok);background:var(--ok-bg)}.l-INFO{color:var(--info);background:var(--info-bg)}
.l-WARN{color:var(--warn);background:var(--warn-bg)}.l-CRIT{color:var(--crit);background:var(--crit-bg)}
.ic{font-weight:700;width:18px;flex:none}.ic.l-OK,.ic.l-INFO,.ic.l-WARN,.ic.l-CRIT{background:none}
section{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:16px 0;overflow:hidden}
section h2{margin:0;padding:14px 18px;font-size:17px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}
details{border-bottom:1px solid var(--line)}details:last-child{border-bottom:0}
summary{padding:12px 18px;cursor:pointer;display:flex;gap:10px;align-items:baseline;list-style:none}summary::-webkit-details-marker{display:none}
.body{padding:0 18px 16px 46px;font-size:15px}
.body p{margin:6px 0}.lbl{font-weight:600}.fix{background:var(--info-bg);border-radius:8px;padding:8px 12px}
code{font-family:ui-monospace,monospace;font-size:13px;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
ul{margin:6px 0;padding-left:18px;color:var(--muted);font-size:14px;word-break:break-word}
.note{color:var(--muted);font-size:13px;border:1px dashed var(--line);border-radius:10px;padding:10px 14px;margin-top:24px}
footer{color:var(--muted);font-size:13px;text-align:center;margin-top:20px}
"""


def to_html(results: List[CheckResult], points: int, system: str, user: str, root: bool) -> str:
    e = html.escape
    m = mood(points)
    n = counts(results)
    sections = []
    for r in results:
        rows = []
        for f in sorted(r.findings, key=lambda x: -x.level):
            body = ""
            if f.detail:
                body += f"<p>{code_html(f.detail)}</p>"
            if f.items:
                body += "<ul>" + "".join(f"<li>{e(i)}</li>" for i in f.items) + "</ul>"
            if f.explain:
                body += f'<p><span class="lbl">What does it mean?</span> {code_html(f.explain)}</p>'
            if f.fix:
                body += f'<p class="fix"><span class="lbl">What to do:</span> {code_html(f.fix)}</p>'
            opened = " open" if f.level >= Level.WARN else ""
            rows.append(
                f'<details{opened}><summary><span class="ic l-{f.level.name}">{ICONS[f.level]}</span>'
                f'<span>{e(f.title)}</span></summary>'
                + (f'<div class="body">{body}</div>' if body else "") + "</details>")
        badge = f'<span class="pill l-{r.worst.name}">{r.worst.label}</span>'
        sections.append(f"<section><h2>{e(r.title)} {badge}</h2>{''.join(rows)}</section>")

    pills = "".join(f'<span class="pill l-{lvl.name}">{n[lvl]} {lvl.label}</span>'
                    for lvl in (Level.CRIT, Level.WARN, Level.INFO, Level.OK))
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Kauz report</title>
<style>{CSS}</style></head><body><main>
<header>{_owl_svg(m)}<div><h1>Kauz security report</h1>
<div class="sub">{e(system)} · {e(user)}{' (admin)' if root else ''} · {when}</div>
<div class="score s-{m}">{points}<small>/100</small></div><div>{e(MESSAGES[m])}</div>
<div class="counts">{pills}</div></div></header>
{''.join(sections)}
<p class="note"><b>Note:</b> {e(DISCLAIMER)}</p>
<footer>Made with Kauz v{__version__} · Kauz only reads – it never changes your system.</footer>
</main></body></html>"""
