"""SSH: is a remote login server running, and is it set up safely?"""
from __future__ import annotations

import glob
import os
import re
from typing import Dict, List

from ..core import Finding, Level, plural
from ..utils import home, read, service_active, which
from . import ports

ID = "ssh"
TITLE = "SSH remote login"


def _parse(path: str, settings: Dict[str, str], depth: int = 0) -> None:
    """Read sshd_config like OpenSSH does: the FIRST value wins.
    Include files are read in place, Match blocks are ignored."""
    if depth > 5:
        return
    for raw in (read(path, "") or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"\s+|=", line, maxsplit=1)
        if len(parts) < 2:
            continue
        key, val = parts[0].lower(), parts[1].strip().strip("=").strip()
        if key == "match":
            return
        if key == "include":
            for pattern in val.split():
                if not pattern.startswith("/"):
                    pattern = os.path.join("/etc/ssh", pattern)
                for f in sorted(glob.glob(pattern)):
                    _parse(f, settings, depth + 1)
            continue
        settings.setdefault(key, val.lower())


def run() -> List[Finding]:
    installed = os.path.exists("/etc/ssh/sshd_config") or which("sshd")
    if not installed:
        return [Finding("No SSH server installed", Level.OK,
                        detail="Nobody can log in to your PC via SSH.")]

    active = service_active("sshd") or service_active("ssh") or any(
        s.port == 22 and s.proto == "tcp" for s in ports.listening_sockets())
    if not active:
        return [Finding("SSH server installed but turned off", Level.OK,
                        detail="It isn't running – so no risk.")]

    s: Dict[str, str] = {}
    _parse("/etc/ssh/sshd_config", s)
    findings: List[Finding] = [Finding(
        title="SSH server is running",
        level=Level.INFO,
        detail="Other devices can log in with a username + password or key.",
        fix="Don't need it? `sudo systemctl disable --now sshd`",
    )]

    if s.get("permitrootlogin", "prohibit-password") == "yes":
        findings.append(Finding(
            title="root may log in via SSH with a password",
            level=Level.CRIT,
            explain="root is the admin account and has the same name on every Linux system. Bots on the "
                    "internet try passwords for exactly this name around the clock.",
            fix="Set `PermitRootLogin no` in /etc/ssh/sshd_config, then `sudo systemctl restart sshd`.",
        ))

    if s.get("passwordauthentication", "yes") == "yes":
        findings.append(Finding(
            title="SSH allows password login",
            level=Level.WARN,
            explain="Passwords can be guessed or brute-forced. SSH keys are practically impossible to crack.",
            fix="Create a key (`ssh-keygen -t ed25519`, copy it with ssh-copy-id), then set "
                "`PasswordAuthentication no` in sshd_config.",
        ))

    if s.get("permitemptypasswords", "no") == "yes":
        findings.append(Finding("SSH allows empty passwords", Level.CRIT,
                                fix="Set `PermitEmptyPasswords no` in sshd_config."))

    keys = os.path.join(home(), ".ssh", "authorized_keys")
    entries = [l for l in (read(keys, "") or "").splitlines() if l.strip() and not l.startswith("#")]
    if entries:
        findings.append(Finding(
            title=f"{plural(len(entries), 'key')} may log in as you",
            level=Level.INFO,
            detail=f"From {keys}. Make sure you recognise every one of them.",
            items=[e.split()[-1] if len(e.split()) >= 3 else e[:40] + "…" for e in entries],
        ))
    return findings
