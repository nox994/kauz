"""Autostart: what starts automatically – and does any of it look suspicious?

Malware wants to survive a reboot ("persistence"). Typical hiding places:
  * ~/.config/autostart  (desktop autostart)
  * systemd services     (system and user)
  * cron                 (scheduled tasks)
  * shell startup files  (~/.bashrc, ~/.zshrc, fish config …)
  * /etc/ld.so.preload   (loads code into EVERY program – classic rootkit trick)
"""
from __future__ import annotations

import glob
import os
import re
from typing import List, Tuple

from ..core import Finding, Level, plural
from ..utils import has_systemd, home, is_root, read, run as sh

ID = "autostart"
TITLE = "Autostart & persistence"

# Where a command can start: line start, after ; & | ( or after exec/nohup/sh -c etc.
_CMD = r"(?:^|[;&|(`]\s*|\b(?:exec|nohup|setsid|sh|bash|zsh|env)\s+)"

# (pattern, explanation, severity)
PATTERNS: List[Tuple[str, str, Level]] = [
    (r"(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
     "downloads code from the internet and runs it immediately", Level.CRIT),
    (r"base64\s+(-d|--decode)", "decodes hidden code", Level.CRIT),
    (r"/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|\bsocat\b[^\n]*exec",
     "opens a connection back to someone else (reverse shell)", Level.CRIT),
    (r"python[0-9.]*\s+-c\s+['\"][^\n]*socket", "Python one-liner with a network connection", Level.CRIT),
    (r"\bLD_PRELOAD\s*=", "injects foreign code into programs (LD_PRELOAD)", Level.WARN),
    (_CMD + r"/(?:dev/shm|tmp|var/tmp)/\S+", "starts a program from a temp folder", Level.WARN),
    (r"\bchmod\s+[0-7]*[4-7][0-7]{3}\b|\bchmod\s+[ugo]*\+s\b", "sets SUID permissions", Level.WARN),
]


def _scan(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pat, why, lvl in PATTERNS:
            if re.search(pat, stripped):
                out.append(Finding(
                    title=f"Suspicious entry: {why}",
                    level=lvl,
                    detail=f"{source}, line {no}",
                    explain="This runs automatically. The pattern is typical for malware, but you may also "
                            "have added it yourself (e.g. an install command).",
                    fix="Check whether you recognise the entry. If not: remove the line, fully update the "
                        "system and change your passwords.",
                    items=[stripped[:160]],
                ))
                break
    return out


def _exec_lines(path: str) -> str:
    """Only the commands from Exec= lines (without the key), one per line."""
    out = []
    for l in (read(path, "") or "").splitlines():
        m = re.match(r"\s*(?:Exec\w*|TryExec)\s*=\s*-?(.*)", l)
        if m:
            out.append(m.group(1))
    return "\n".join(out)


def run() -> List[Finding]:
    findings: List[Finding] = []
    h = home()

    # 1) desktop autostart
    user_auto = sorted(glob.glob(os.path.join(h, ".config/autostart/*.desktop")))
    for f in user_auto + glob.glob("/etc/xdg/autostart/*.desktop"):
        findings += _scan(_exec_lines(f), f)

    # 2) systemd user services
    user_units = sorted(glob.glob(os.path.join(h, ".config/systemd/user/*.service")))
    for f in user_units:
        findings += _scan(_exec_lines(f), f)

    # 3) system services created by an admin (not from packages)
    custom_sys: List[str] = []
    for f in sorted(glob.glob("/etc/systemd/system/*.service")):
        if os.path.islink(f):
            continue  # links = just enabled package services
        custom_sys.append(f)
        findings += _scan(_exec_lines(f), f)

    # 4) cron
    if not is_root():
        rc, out = sh(["crontab", "-l"])
        if rc == 0:
            findings += _scan(out, "crontab (your user)")
    for f in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        findings += _scan(read(f, "") or "", f)

    # 5) shell startup files
    for rel in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".config/fish/config.fish"):
        p = os.path.join(h, rel)
        if os.path.isfile(p):
            findings += _scan(read(p, "") or "", p)
    for p in glob.glob(os.path.join(h, ".config/fish/conf.d/*.fish")):
        findings += _scan(read(p, "") or "", p)
    for p in ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"] + glob.glob("/etc/profile.d/*.sh"):
        if os.path.isfile(p):
            findings += _scan(read(p, "") or "", p)

    # 6) ld.so.preload
    pre = (read("/etc/ld.so.preload", "") or "").strip()
    if pre:
        findings.append(Finding(
            title="/etc/ld.so.preload is set",
            level=Level.CRIT,
            detail="These libraries are loaded into EVERY program.",
            explain="On normal desktops this file is empty. Rootkits use it to hide themselves.",
            fix="Find out where the entry comes from (`pacman -Qo FILE` or `dpkg -S FILE`).",
            items=pre.splitlines(),
        ))

    # overview
    overview = ([f"Autostart: {os.path.basename(f)}" for f in user_auto]
                + [f"User service: {os.path.basename(f)}" for f in user_units]
                + [f"System service (custom): {os.path.basename(f)}" for f in custom_sys])
    if has_systemd() and not is_root():
        rc, out = sh(["systemctl", "--user", "list-unit-files", "--state=enabled", "--no-legend"])
        if rc == 0:
            known = {os.path.basename(f) for f in user_units}
            overview += [f"User service enabled: {l.split()[0]}" for l in out.splitlines()
                         if l.strip() and l.split()[0] not in known]
    if overview:
        findings.append(Finding(
            title=f"{plural(len(overview), 'entry', 'entries')} start automatically",
            level=Level.INFO,
            detail="Not dangerous by itself – but do you know all of them?",
            items=overview,
        ))
    if not any(f.level >= Level.WARN for f in findings):
        findings.append(Finding("No suspicious autostart entries", Level.OK))
    return findings
