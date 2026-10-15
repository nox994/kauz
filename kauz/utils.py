"""Helpers: run commands, read files, detect the system."""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
from typing import Optional, Tuple


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run(cmd: list, timeout: int = 20) -> Tuple[Optional[int], str]:
    """Run a command and return (exit code, stdout).
    The exit code is None if the command is missing or hangs."""
    if not shutil.which(cmd[0]):
        return None, ""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None, ""


def read(path: str, default: Optional[str] = None) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def is_root() -> bool:
    return os.geteuid() == 0


def real_user() -> str:
    """The real user – even when Kauz was started with sudo or pkexec."""
    if is_root():
        if os.environ.get("SUDO_USER"):
            return os.environ["SUDO_USER"]
        uid = os.environ.get("PKEXEC_UID")
        if uid and uid.isdigit():
            try:
                return pwd.getpwuid(int(uid)).pw_name
            except KeyError:
                pass
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER", "?")


def home() -> str:
    try:
        return pwd.getpwnam(real_user()).pw_dir
    except KeyError:
        return os.path.expanduser("~")


def has_systemd() -> bool:
    return os.path.isdir("/run/systemd/system")


def service_active(name: str) -> bool:
    if not has_systemd():
        return False
    _, out = run(["systemctl", "is-active", name])
    return out.strip() == "active"


def package_manager() -> Optional[str]:
    for pm in ("rpm-ostree", "pacman", "apt", "dnf", "zypper"):
        if which(pm):
            # only use rpm-ostree if the system actually booted from it
            if pm == "rpm-ostree" and not os.path.exists("/run/ostree-booted"):
                continue
            return pm
    return None


def install_hint(pkg: str) -> str:
    pm = package_manager()
    return {
        "pacman": f"sudo pacman -S {pkg}",
        "apt": f"sudo apt install {pkg}",
        "dnf": f"sudo dnf install {pkg}",
        "zypper": f"sudo zypper install {pkg}",
        "rpm-ostree": f"rpm-ostree install {pkg}",
    }.get(pm or "", f"install the package {pkg}")


def distro_name() -> str:
    data = read("/etc/os-release", "") or ""
    for line in data.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "Linux"
