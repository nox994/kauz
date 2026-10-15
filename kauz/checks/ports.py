"""Open ports: which programs accept connections from other devices?

How it works: the kernel lists every network socket in /proc/net/tcp, tcp6,
udp and udp6. We read those tables directly (no netstat/ss needed) and map
each socket to its process via the inode number (/proc/<pid>/fd/* links
point to "socket:[inode]").
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..core import Finding, Level, plural
from ..utils import is_root, read

ID = "network"
TITLE = "Open ports"

# (proto, port) -> (name, risk); risk: "high", "medium", "harmless"
KNOWN: Dict[Tuple[str, int], Tuple[str, str]] = {
    ("tcp", 21): ("FTP server", "high"),
    ("tcp", 22): ("SSH remote login", "medium"),
    ("tcp", 23): ("Telnet (unencrypted!)", "high"),
    ("tcp", 25): ("Mail server (SMTP)", "medium"),
    ("tcp", 80): ("Web server (HTTP)", "medium"),
    ("tcp", 111): ("RPC portmapper", "high"),
    ("tcp", 139): ("Windows file sharing (NetBIOS)", "high"),
    ("tcp", 443): ("Web server (HTTPS)", "medium"),
    ("tcp", 445): ("Windows file sharing (SMB/Samba)", "high"),
    ("tcp", 631): ("Printing service (CUPS)", "medium"),
    ("tcp", 2375): ("Docker API without encryption", "high"),
    ("tcp", 3000): ("Development web server", "medium"),
    ("tcp", 3306): ("MySQL/MariaDB database", "high"),
    ("tcp", 3389): ("Remote Desktop (RDP)", "high"),
    ("tcp", 5000): ("Development web server", "medium"),
    ("tcp", 5432): ("PostgreSQL database", "high"),
    ("udp", 5353): ("mDNS (finding devices on the network)", "harmless"),
    ("tcp", 5355): ("LLMNR (name resolution)", "medium"),
    ("udp", 5355): ("LLMNR (name resolution)", "medium"),
    ("tcp", 5900): ("VNC remote control", "high"),
    ("tcp", 6379): ("Redis database", "high"),
    ("tcp", 8000): ("Development web server", "medium"),
    ("tcp", 8080): ("Web server / proxy", "medium"),
    ("tcp", 9090): ("Cockpit web console", "medium"),
    ("tcp", 22000): ("Syncthing", "harmless"),
    ("udp", 22000): ("Syncthing", "harmless"),
    ("udp", 21027): ("Syncthing discovery", "harmless"),
    ("tcp", 27017): ("MongoDB database", "high"),
    ("tcp", 27036): ("Steam Remote Play", "harmless"),
    ("tcp", 27040): ("Steam LAN downloads", "harmless"),
    ("tcp", 53317): ("LocalSend", "harmless"),
    ("udp", 53317): ("LocalSend", "harmless"),
    ("tcp", 57621): ("Spotify (devices on LAN)", "harmless"),
    ("udp", 57621): ("Spotify (devices on LAN)", "harmless"),
}

# Port ranges: (proto, first, last, name, risk)
RANGES = [
    ("tcp", 1714, 1764, "KDE Connect", "harmless"),
    ("udp", 1714, 1764, "KDE Connect", "harmless"),
    ("udp", 27031, 27036, "Steam Remote Play / discovery", "harmless"),
]

# UDP ports a normal desktop needs that don't "offer" anything
IGNORE_UDP = {68, 546, 123, 323}  # DHCP client, DHCPv6 client, time sync


@dataclass
class Sock:
    proto: str
    ip: str
    port: int
    inode: str
    owner: Optional[Tuple[int, str]] = None


def identify(proto: str, port: int) -> Tuple[str, str]:
    if (proto, port) in KNOWN:
        return KNOWN[(proto, port)]
    for p, lo, hi, name, risk in RANGES:
        if p == proto and lo <= port <= hi:
            return name, risk
    return "Unknown service", "medium"


def _ephemeral_start() -> int:
    raw = (read("/proc/sys/net/ipv4/ip_local_port_range", "") or "").split()
    return int(raw[0]) if raw and raw[0].isdigit() else 32768


def _ip4(h: str) -> str:
    return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))


def _ip6(h: str) -> str:
    raw = b"".join(struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8))
    return socket.inet_ntop(socket.AF_INET6, raw)


def _inode_owners() -> Dict[str, Tuple[int, str]]:
    owners: Dict[str, Tuple[int, str]] = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # process of another user (not readable without root)
        name = (read(f"/proc/{pid}/comm", "?") or "?").strip()
        for fd in fds:
            try:
                link = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                owners.setdefault(link[8:-1], (int(pid), name))
    return owners


def listening_sockets() -> List[Sock]:
    found: Dict[Tuple[str, str, int], Sock] = {}
    tables = [("tcp", "/proc/net/tcp", False), ("tcp", "/proc/net/tcp6", True),
              ("udp", "/proc/net/udp", False), ("udp", "/proc/net/udp6", True)]
    for proto, path, v6 in tables:
        data = read(path)
        if not data:
            continue
        for line in data.splitlines()[1:]:
            p = line.split()
            if len(p) < 10:
                continue
            local, remote, state, inode = p[1], p[2], p[3], p[9]
            if proto == "tcp" and state != "0A":          # 0A = LISTEN
                continue
            if proto == "udp" and (state != "07" or int(remote.split(":")[1], 16) != 0):
                continue                                   # only open, unconnected UDP sockets
            ip_h, port_h = local.split(":")
            try:
                ip = _ip6(ip_h) if v6 else _ip4(ip_h)
            except (ValueError, struct.error):
                continue
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            port = int(port_h, 16)
            found.setdefault((proto, ip, port), Sock(proto, ip, port, inode))
    owners = _inode_owners()
    for s in found.values():
        s.owner = owners.get(s.inode)
    return list(found.values())


def scope(ip: str) -> str:
    if ip.startswith("127.") or ip == "::1":
        return "local"
    if ip in ("0.0.0.0", "::"):
        return "all"
    return "network"


def exposed_sockets(socks: Optional[List[Sock]] = None) -> List[Sock]:
    """Sockets reachable from other devices, minus normal desktop noise."""
    if socks is None:
        socks = listening_sockets()
    eph = _ephemeral_start()
    out = []
    for s in socks:
        if scope(s.ip) == "local":
            continue
        if s.proto == "udp":
            if s.port in IGNORE_UDP:
                continue
            # Browsers, Discord, games etc. open UDP sockets on random high ports.
            if s.port >= eph and (s.proto, s.port) not in KNOWN:
                continue
        out.append(s)
    return out


def risky_exposed() -> List[Sock]:
    return [s for s in exposed_sockets() if identify(s.proto, s.port)[1] != "harmless"]


def run() -> List[Finding]:
    socks = listening_sockets()
    exposed = exposed_sockets(socks)
    local = [s for s in socks if scope(s.ip) == "local"]
    eph = _ephemeral_start()
    random_udp = [s for s in socks if s.proto == "udp" and scope(s.ip) != "local"
                  and s.port >= eph and (s.proto, s.port) not in KNOWN]
    findings: List[Finding] = []

    # merge the same port on IPv4 and IPv6
    grouped: Dict[Tuple[str, int], List[Sock]] = {}
    for s in exposed:
        grouped.setdefault((s.proto, s.port), []).append(s)

    harmless: List[str] = []
    unknown_owner = False
    for (proto, port), lst in sorted(grouped.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        name, risk = identify(proto, port)
        owner = next((s.owner for s in lst if s.owner), None)
        who = f"{owner[1]} (PID {owner[0]})" if owner else "unknown program*"
        if not owner:
            unknown_owner = True
        addrs = ", ".join(sorted({s.ip for s in lst}))
        line = f"{proto.upper()} {port} – {name} – {who} – on {addrs}"
        if risk == "harmless":
            harmless.append(line)
            continue
        if port == 5355:
            findings.append(Finding(
                title=f"LLMNR is enabled (port 5355/{proto.upper()})",
                level=Level.WARN,
                detail=f"Program: {who}. Listening on: {addrs}.",
                explain=("LLMNR is an old Windows mechanism for finding devices on the network. Attackers on "
                         "the same network can answer these requests and capture password hashes "
                         "(LLMNR poisoning). Do NOT stop systemd-resolved – your internet needs it. "
                         "Only turn off LLMNR."),
                fix=("Run `sudo mkdir -p /etc/systemd/resolved.conf.d`, then "
                     "`printf '[Resolve]\\nLLMNR=no\\n' | sudo tee /etc/systemd/resolved.conf.d/no-llmnr.conf`, "
                     "then `sudo systemctl restart systemd-resolved`."),
                items=[line],
            ))
            continue
        findings.append(Finding(
            title=f"Port {port}/{proto.upper()} is reachable from the network ({name})",
            level=Level.CRIT if risk == "high" else Level.WARN,
            detail=f"Program: {who}. Listening on: {addrs}.",
            explain=("An open port is like a door: a program is waiting there for connections. "
                     "0.0.0.0 or :: means every device that can reach your PC is allowed to knock. "
                     + ("This service is a popular target for attacks." if risk == "high" else
                        "That isn't automatically bad, but it should be on purpose.")),
            fix=("If you don't need it, stop the program or its service – but find out what it does first. "
                 "If you only need it on this PC, configure it to listen on 127.0.0.1. "
                 f"Otherwise block it with the firewall: `sudo ufw deny {port}/{proto}`."),
            items=[line],
        ))

    if harmless:
        findings.append(Finding(
            title=f"{plural(len(harmless), 'known desktop service')} visible on the network",
            level=Level.INFO,
            detail="Typical programs like KDE Connect, Steam or mDNS.",
            explain="These services exist to find other devices on your home network. Fine on your own "
                    "Wi-Fi; on public Wi-Fi it's better if your firewall shields them.",
            items=harmless,
        ))

    if random_udp:
        names = sorted({s.owner[1] for s in random_udp if s.owner})
        findings.append(Finding(
            title=f"{plural(len(random_udp), 'UDP socket')} on random high ports (ignored)",
            level=Level.OK,
            detail="Normal for browsers, voice chat and games." + (f" Programs: {', '.join(names)}." if names else ""),
        ))

    if not exposed:
        findings.append(Finding(
            title="No ports reachable from the network",
            level=Level.OK,
            detail=f"{plural(len(local), 'service')} only listen locally (127.0.0.1) – that's fine.",
        ))
    elif local:
        findings.append(Finding(
            title=f"{plural(len(local), 'service')} only reachable from this PC",
            level=Level.OK,
            detail="Only programs on your own PC can reach them.",
        ))

    if unknown_owner and not is_root():
        findings.append(Finding(
            title="Not every port could be matched to a program",
            level=Level.INFO,
            detail="* Ports owned by other users (e.g. root) are invisible without admin rights.",
            fix="Run the scan with admin rights to see everything.",
        ))
    return findings
