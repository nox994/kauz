"""All checks. Each one has ID, TITLE and a function run() -> List[Finding].
Adding a check = create a new file and add it to this list."""
from . import autostart, firewall, permissions, ports, processes, ssh, system, updates, users

ALL = [updates, firewall, ports, ssh, autostart, processes, users, permissions, system]
