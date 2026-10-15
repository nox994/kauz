"""Firewall: is a firewall active that blocks unwanted connections?"""
from __future__ import annotations

import re
from typing import List

from ..core import Finding, Level, plural
from ..utils import has_systemd, install_hint, is_root, read, run as sh, service_active
from . import ports

ID = "firewall"
TITLE = "Firewall"

EXPLAIN = ("A firewall is your PC's bouncer: it decides which connections from outside are allowed in. "
           "Without one, every open port is directly reachable – especially risky on public Wi-Fi "
           "(university, café, hotel).")


def _ufw_enabled() -> bool:
    conf = read("/etc/ufw/ufw.conf", "") or ""
    return bool(re.search(r"^\s*ENABLED\s*=\s*yes", conf, re.M))


def run() -> List[Finding]:
    active = []
    if service_active("ufw") and _ufw_enabled():
        active.append("ufw")
    if service_active("firewalld"):
        active.append("firewalld")
    if service_active("nftables"):
        active.append("nftables")

    # with root we can look at the rules directly
    has_input_rules = None
    if is_root():
        rc, out = sh(["nft", "list", "ruleset"])
        if rc == 0:
            has_input_rules = "hook input" in out
            if has_input_rules and not active:
                active.append("nftables rules")

    if active:
        return [Finding(
            title=f"Firewall active: {', '.join(active)}",
            level=Level.OK,
            detail="Incoming connections are filtered.",
        )]

    if not has_systemd() and has_input_rules is None:
        return [Finding(
            title="Firewall status unknown",
            level=Level.INFO,
            detail="No systemd found – the status can't be checked without admin rights.",
            fix="Run the scan with admin rights.",
        )]

    exposed = ports.risky_exposed()
    return [Finding(
        title="No active firewall found",
        level=Level.CRIT if exposed else Level.WARN,
        detail=(f"On top of that, {plural(len(exposed), 'port is', 'ports are')} reachable from the network."
                if exposed else "No risky ports are open right now – but there's no protection if that changes."),
        explain=EXPLAIN,
        fix=(f"Install ufw: `{install_hint('ufw')}`, then `sudo ufw default deny incoming`, "
             "`sudo ufw default allow outgoing`, `sudo ufw enable` and `sudo systemctl enable --now ufw`."),
    )]
