"""System hardening: kernel protections, Secure Boot, disk encryption."""
from __future__ import annotations

import glob
import os
import re
from typing import List

from ..core import Finding, Level
from ..utils import read, run as sh

ID = "system"
TITLE = "System protection"

# sysctl -> (minimum, name, explanation, level if lower)
SYSCTLS = [
    ("kernel/randomize_va_space", 2, "Memory randomisation (ASLR)",
     "Places programs at random spots in memory so exploits can't find their target.", Level.CRIT),
    ("fs/protected_symlinks", 1, "Symlink protection",
     "Blocks tricks with links in temp folders.", Level.WARN),
    ("fs/protected_hardlinks", 1, "Hardlink protection",
     "Stops other people's files from being attacked via hardlinks.", Level.WARN),
    ("kernel/kptr_restrict", 1, "Hide kernel addresses",
     "Hides kernel memory addresses from normal programs.", Level.INFO),
    ("kernel/dmesg_restrict", 1, "Protect the kernel log",
     "Normal programs can't read the kernel log.", Level.INFO),
    ("kernel/yama/ptrace_scope", 1, "Block process snooping (ptrace)",
     "A program can't look into another program's memory (e.g. passwords from your browser).", Level.INFO),
]


def _secure_boot() -> Finding:
    if not os.path.isdir("/sys/firmware/efi"):
        return Finding("Secure Boot: not possible (legacy BIOS mode)", Level.INFO)
    files = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    try:
        with open(files[0], "rb") as f:
            on = f.read()[-1] == 1
    except (IndexError, OSError):
        return Finding("Secure Boot: status unknown", Level.INFO)
    if on:
        return Finding("Secure Boot is on", Level.OK)
    return Finding(
        title="Secure Boot is off",
        level=Level.INFO,
        explain="Secure Boot checks at startup that the bootloader and kernel haven't been tampered with. "
                "On Linux gaming PCs it's often off (Nvidia drivers) – common, but one protection less.",
        fix="Can be set up with sbctl (see the Arch Wiki page \"Secure Boot\").",
    )


def _encryption() -> Finding:
    rc, src = sh(["findmnt", "-no", "SOURCE", "/"])
    src = re.sub(r"\[.*\]$", "", src.strip())
    if rc != 0 or not src:
        return Finding("Disk encryption: status unknown", Level.INFO)
    _, out = sh(["lsblk", "-s", "-no", "TYPE", src])
    if "crypt" in out.split():
        return Finding("Disk is encrypted (LUKS)", Level.OK)
    laptop = bool(glob.glob("/sys/class/power_supply/BAT*"))
    return Finding(
        title="Disk is not encrypted",
        level=Level.WARN if laptop else Level.INFO,
        detail="Laptop detected – theft is a real risk here." if laptop else "Desktop PC detected.",
        explain="Without encryption anyone who removes the disk can read all files – your password only "
                "protects the login, not the data.",
        fix="Hard to add later; choose \"encrypt disk\" (LUKS) at your next reinstall.",
    )


def run() -> List[Finding]:
    findings: List[Finding] = []
    weak = []
    for key, minimum, name, why, lvl in SYSCTLS:
        val = (read(f"/proc/sys/{key}", "") or "").strip()
        if not val.lstrip("-").isdigit():
            continue
        if int(val) < minimum:
            dotted = key.replace("/", ".")
            findings.append(Finding(
                title=f"{name} is off",
                level=lvl,
                detail=f"{dotted} = {val} (recommended: ≥ {minimum})",
                explain=why,
                fix=f"`echo '{dotted} = {minimum}' | sudo tee -a /etc/sysctl.d/90-kauz.conf` "
                    "and then `sudo sysctl --system`",
            ))
            weak.append(name)
    if not weak:
        findings.append(Finding("Kernel protections are on", Level.OK,
                                detail="ASLR, link protection, ptrace protection and more."))
    findings.append(_secure_boot())
    findings.append(_encryption())
    return findings
