"""File permissions: are private files protected? Are there dangerous SUID files?

SUID = a file always runs with its owner's rights (often root), no matter who
starts it. In temp folders or your home folder that has no business existing –
attackers use it to keep root access.
"""
from __future__ import annotations

import glob
import os
import stat
import time
from typing import Iterator, List

from ..core import Finding, Level
from ..utils import home

ID = "permissions"
TITLE = "File permissions"

MAX_FILES = 200_000      # protection against huge folders
MAX_SECONDS = 25         # per folder tree
# Skipped paths, relative to the folder being scanned
SKIP = {".cache", ".local/share/Steam", ".steam", ".var", ".wine", ".local/share/Trash",
        "node_modules", ".git", "Games", ".local/share/containers", ".local/share/flatpak"}
SKIP_NAMES = {"node_modules", ".git", "__pycache__"}


def _walk(root: str, max_depth: int) -> Iterator[str]:
    root = root.rstrip("/") or "/"
    base_depth = root.count("/")
    count, deadline = 0, time.monotonic() + MAX_SECONDS
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        rel = os.path.relpath(dirpath, root)
        rel = "" if rel == "." else rel
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_NAMES
                       and os.path.join(rel, d) not in SKIP
                       and not os.path.islink(os.path.join(dirpath, d))]
        if dirpath.count("/") - base_depth >= max_depth:
            dirnames[:] = []
        for fn in filenames:
            count += 1
            if count > MAX_FILES or (count % 2000 == 0 and time.monotonic() > deadline):
                return
            yield os.path.join(dirpath, fn)


def run() -> List[Finding]:
    findings: List[Finding] = []
    h = home()

    # 1) SUID/SGID in suspicious places
    suspicious = []
    for root, depth in [("/tmp", 6), ("/var/tmp", 6), ("/dev/shm", 6), (h, 5)]:
        for path in _walk(root, depth):
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                suspicious.append(path)
    if suspicious:
        findings.append(Finding(
            title="SUID files in unusual places",
            level=Level.CRIT,
            explain="These files run with their owner's rights. Outside system folders that is a strong "
                    "sign of a backdoor.",
            fix="Inspect with `ls -l FILE`; if unknown, remove the bit with `sudo chmod u-s,g-s FILE` and "
                "have the file checked.",
            items=suspicious[:20],
        ))

    # 2) home folder readable by others?
    try:
        mode = os.stat(h).st_mode
        if mode & stat.S_IROTH:
            several = len([d for d in glob.glob("/home/*") if os.path.isdir(d)]) > 1
            findings.append(Finding(
                title="Your home folder is readable by other users",
                level=Level.WARN if several else Level.INFO,
                detail=f"{h} has the permissions {stat.filemode(mode)}.",
                explain="Other accounts on this PC (and services like a web server) can read your files.",
                fix=f"`chmod 700 {h}`",
            ))
    except OSError:
        pass

    # 3) SSH keys protected?
    ssh_dir = os.path.join(h, ".ssh")
    bad = []
    if os.path.isdir(ssh_dir):
        try:
            if os.stat(ssh_dir).st_mode & 0o077:
                bad.append(f"{ssh_dir} (folder)")
        except OSError:
            pass
        for f in glob.glob(os.path.join(ssh_dir, "id_*")):
            if f.endswith(".pub"):
                continue
            try:
                if os.stat(f).st_mode & 0o077:
                    bad.append(f)
            except OSError:
                pass
    if bad:
        findings.append(Finding(
            title="Private SSH keys are not protected",
            level=Level.WARN,
            explain="Whoever has your private key can log in anywhere as you.",
            fix=f"`chmod 700 {ssh_dir}` and `chmod 600 {ssh_dir}/id_*` – then `chmod 644 {ssh_dir}/*.pub`.",
            items=bad,
        ))

    # 4) world-writable files in /etc
    ww = []
    for path in _walk("/etc", 4):
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
            ww.append(path)
    if ww:
        findings.append(Finding(
            title="System files are writable by everyone",
            level=Level.CRIT,
            explain="/etc holds the system configuration. If anyone can change it, any program can grant "
                    "itself admin rights.",
            fix="`sudo chmod o-w FILE`",
            items=ww[:20],
        ))

    if not findings:
        findings.append(Finding("File permissions look good", Level.OK,
                                detail="No SUID files in temp/home folders, private files protected."))
    return findings
