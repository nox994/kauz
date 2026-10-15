"""Users: are there hidden admin accounts or unsafe permissions?"""
from __future__ import annotations

import glob
import os
import stat
from typing import List

from ..core import Finding, Level, plural
from ..utils import is_root, read

ID = "users"
TITLE = "Users & privileges"

LOGIN_SHELLS = ("sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh")


def run() -> List[Finding]:
    findings: List[Finding] = []
    entries = [l.split(":") for l in (read("/etc/passwd", "") or "").splitlines() if l.count(":") >= 6]

    # a second account with UID 0 = a second, hidden root
    extra_root = [e[0] for e in entries if e[2] == "0" and e[0] != "root"]
    if extra_root:
        findings.append(Finding(
            title="Extra account with root privileges",
            level=Level.CRIT,
            explain="UID 0 means full admin rights. Only root should have it – a second account with "
                    "UID 0 is a classic backdoor trick.",
            fix="Check the account and remove it if needed: `sudo userdel NAME`.",
            items=extra_root,
        ))

    humans = [e[0] for e in entries
              if e[2].isdigit() and 1000 <= int(e[2]) < 60000 and os.path.basename(e[6]) in LOGIN_SHELLS]
    findings.append(Finding(
        title=f"{plural(len(humans), 'user')} can log in",
        level=Level.INFO,
        detail="Do you know all of them?",
        items=humans,
    ))

    admins = set()
    for line in (read("/etc/group", "") or "").splitlines():
        p = line.split(":")
        if len(p) >= 4 and p[0] in ("wheel", "sudo", "admin"):
            admins.update(m for m in p[3].split(",") if m)
    if admins:
        findings.append(Finding(
            title=f"Admin rights (sudo): {', '.join(sorted(admins))}",
            level=Level.INFO,
            detail="These users can change anything on the system.",
        ))

    # /etc/shadow (password hashes) must only be readable by root
    try:
        if os.stat("/etc/shadow").st_mode & stat.S_IROTH:
            findings.append(Finding(
                title="/etc/shadow is readable by everyone",
                level=Level.CRIT,
                explain="It contains the hashed passwords. Any user could copy and crack them.",
                fix="`sudo chmod 600 /etc/shadow` (Debian/Ubuntu use 640 with group shadow).",
            ))
    except OSError:
        pass

    if is_root():
        shadow = read("/etc/shadow", "") or ""
        empty = [l.split(":")[0] for l in shadow.splitlines() if l.count(":") >= 2 and l.split(":")[1] == ""]
        if empty:
            findings.append(Finding(
                title="Accounts without a password",
                level=Level.CRIT,
                fix="Set one with `sudo passwd NAME` or lock the account with `sudo passwd -l NAME`.",
                items=empty,
            ))
        nopass = []
        for f in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
            for l in (read(f, "") or "").splitlines():
                if "NOPASSWD" in l and not l.strip().startswith("#"):
                    nopass.append(f"{os.path.basename(f)}: {l.strip()}")
        if nopass:
            findings.append(Finding(
                title="sudo without password is allowed",
                level=Level.WARN,
                explain="Any program running as that user can become admin without asking.",
                fix="Remove the entry with `sudo visudo` unless you set it on purpose.",
                items=nopass,
            ))
    else:
        findings.append(Finding(
            title="Password and sudo rules need admin rights to check",
            level=Level.INFO,
            fix="Run the scan with admin rights.",
        ))

    if not any(f.level >= Level.WARN for f in findings):
        findings.append(Finding("No hidden admin accounts", Level.OK))
    return findings
