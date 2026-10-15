"""Updates: are security updates missing? Is an old kernel still running?"""
from __future__ import annotations

import os
import platform
from typing import List, Optional, Tuple

from ..core import Finding, Level, plural
from ..utils import install_hint, package_manager, run as sh, which

ID = "updates"
TITLE = "Updates"

UPDATE_CMD = {
    "pacman": "sudo pacman -Syu",
    "apt": "sudo apt update && sudo apt upgrade",
    "dnf": "sudo dnf upgrade",
    "zypper": "sudo zypper update",
    "rpm-ostree": "rpm-ostree upgrade",
}


def _pending(pm: str) -> Tuple[Optional[List[str]], str]:
    """Return (list of packages or None if unknown, note)."""
    if pm == "pacman":
        if which("checkupdates"):
            rc, out = sh(["checkupdates"], timeout=120)
            if rc == 0:
                return [l.split()[0] for l in out.splitlines() if l.strip()], ""
            if rc == 2:
                return [], ""
            return None, "checkupdates couldn't reach the package mirrors."
        _, out = sh(["pacman", "-Qu"])
        pk = [l.split()[0] for l in out.splitlines() if l.strip()]
        return pk, (f"Based on the local package list. For a fresh result install pacman-contrib: "
                    f"`{install_hint('pacman-contrib')}`")
    if pm == "apt":
        _, out = sh(["apt", "list", "--upgradable"], timeout=60)
        pk = [l.split("/")[0] for l in out.splitlines() if "/" in l]
        return pk, "Based on the local package list (run `sudo apt update` first for a fresh result)."
    if pm == "dnf":
        rc, out = sh(["dnf", "check-update", "-q"], timeout=180)
        if rc == 0:
            return [], ""
        if rc == 100:
            return [l.split()[0] for l in out.splitlines()
                    if l and not l.startswith(" ") and "." in l.split()[0]], ""
        return None, "dnf couldn't check for updates."
    if pm == "zypper":
        rc, out = sh(["zypper", "--non-interactive", "list-updates"], timeout=180)
        if rc != 0:
            return None, "zypper couldn't check for updates."
        return [l.split("|")[2].strip() for l in out.splitlines() if l.startswith("v ")], ""
    if pm == "rpm-ostree":
        rc, _ = sh(["rpm-ostree", "upgrade", "--check"], timeout=180)
        if rc == 77:
            return [], ""
        if rc == 0:
            return ["new system image available"], ""
        return None, "rpm-ostree couldn't check for updates."
    return None, ""


def _kernel_reboot_needed() -> bool:
    running = platform.release()
    mod_dirs = ["/usr/lib/modules", "/lib/modules"]
    if not any(os.path.isdir(d) for d in mod_dirs):
        return False
    return not any(os.path.isdir(os.path.join(d, running)) for d in mod_dirs)


def run() -> List[Finding]:
    findings: List[Finding] = []
    pm = package_manager()
    if not pm:
        findings.append(Finding("Package manager not recognised", Level.INFO,
                                detail="Updates could not be checked."))
    else:
        pk, note = _pending(pm)
        if pk is None:
            findings.append(Finding("Update check failed", Level.INFO, detail=note))
        elif not pk:
            findings.append(Finding("System is up to date", Level.OK, detail=note))
        else:
            findings.append(Finding(
                title=f"{plural(len(pk), 'update')} pending",
                level=Level.WARN,
                detail=note,
                explain=("Updates close security holes that are often already publicly known – and attackers "
                         "use exactly those. Updating regularly is the single most important protection."),
                fix=f"Run `{UPDATE_CMD[pm]}`" + (" and reboot." if pm == "rpm-ostree" else "."),
                items=pk[:15] + ([f"… and {len(pk) - 15} more"] if len(pk) > 15 else []),
            ))

    if which("flatpak"):
        rc, out = sh(["flatpak", "remote-ls", "--updates", "--columns=application"], timeout=60)
        apps = [l.strip() for l in out.splitlines() if l.strip()]
        if rc == 0 and apps:
            findings.append(Finding(
                title=f"{plural(len(apps), 'Flatpak update')} pending",
                level=Level.WARN,
                fix="Run `flatpak update`.",
                items=apps[:15],
            ))

    if _kernel_reboot_needed():
        findings.append(Finding(
            title="Reboot needed: an old kernel is still running",
            level=Level.WARN,
            detail=f"Running kernel: {platform.release()} – it is no longer installed.",
            explain="The kernel was updated, but the new (safer) one only becomes active after a reboot.",
            fix="Restart your PC.",
        ))
    return findings
