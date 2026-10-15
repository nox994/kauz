"""Processes: is anything running right now that behaves suspiciously?

Three classic warning signs that can be read straight from /proc:
  1. a program runs from /tmp, /var/tmp or /dev/shm (malware often lands there)
  2. a program disguises itself as a kernel thread, e.g. "[kworker/0:1]"
     (real kernel threads have NO command line)
  3. the program file was deleted but keeps running
     (usually harmless after updates – but malware likes to delete itself too)
"""
from __future__ import annotations

import os
from typing import List

from ..core import Finding, Level, plural
from ..utils import is_root, read

ID = "processes"
TITLE = "Running processes"

TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
# Programs that legitimately run from temp folders (AppImages, installers, …)
TEMP_OK = ("/tmp/.mount_", "/tmp/_MEI", "/tmp/.org.chromium", "/tmp/pyright", "/tmp/appimage",
           "/tmp/.pressure-vessel", "/var/tmp/pressure-vessel")


def run() -> List[Finding]:
    findings: List[Finding] = []
    deleted, hidden, total = [], 0, 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        name = (read(f"/proc/{pid}/comm", "?") or "?").strip()
        raw = read(f"/proc/{pid}/cmdline", None)
        if raw is None:
            continue  # process already gone
        total += 1
        cmd = raw.replace("\x00", " ").strip()

        # 2) disguised as a kernel thread
        argv0 = raw.split("\x00", 1)[0].strip()
        if argv0.startswith("[") and argv0.endswith("]"):
            findings.append(Finding(
                title=f"Process disguised as a kernel thread: {argv0[:40]}",
                level=Level.CRIT,
                detail=f"PID {pid}",
                explain="Real kernel threads have no command line. A normal program that looks like one is "
                        "trying to hide in task managers – a typical malware trick.",
                fix=f"Look closer: `ls -l /proc/{pid}/exe` and `cat /proc/{pid}/status`.",
            ))

        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            if cmd:
                hidden += 1  # belongs to another user
            continue

        # 1) runs from a temp folder
        clean = exe.replace(" (deleted)", "")
        if clean.startswith(TEMP_DIRS) and not clean.startswith(TEMP_OK):
            findings.append(Finding(
                title=f"Program running from a temp folder: {name}",
                level=Level.CRIT,
                detail=f"PID {pid}: {exe}",
                explain="Normal programs live in /usr/bin or your home folder. Temp folders are writable by "
                        "everyone – attackers like to drop files there and run them.",
                fix=f"If you don't recognise it: `kill {pid}` and have the file checked (e.g. upload it to "
                    "virustotal.com).",
                items=[cmd[:160]],
            ))
        # 3) deleted program file
        elif exe.endswith(" (deleted)"):
            deleted.append(f"{name} (PID {pid})")

    if deleted:
        findings.append(Finding(
            title=f"{plural(len(deleted), 'program')} still running an old version",
            level=Level.INFO,
            detail="Their program file was replaced – usually by an update.",
            explain="Until the program restarts, the old code keeps running, including any old security holes.",
            fix="Restart those programs or reboot your PC once.",
            items=deleted[:20],
        ))
    if not any(f.level >= Level.WARN for f in findings):
        findings.append(Finding(f"{total} processes checked – nothing suspicious", Level.OK))
    if hidden and not is_root():
        findings.append(Finding(
            title=f"{plural(hidden, 'process', 'processes')} of other users not visible",
            level=Level.INFO,
            fix="Run the scan with admin rights for a complete check.",
        ))
    return findings
