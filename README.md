# 🦉 Kauz

**The friendly security check for your Linux PC.**
Kauz looks at your system, finds weak spots and explains in plain English what they mean and how to fix them.

*Kauz is German for tawny owl – the mascot that keeps an eye on your system.*

- Only reads – **never changes** your system
- No dependencies for the terminal version, just Python 3.9+
- Works on Arch/CachyOS, Debian/Ubuntu, Fedora, openSUSE, Bazzite
- Desktop app (Qt, fits KDE), terminal output, HTML report or JSON

> ⚠️ **Kauz can make mistakes.** It's a young hobby project: it may miss real problems or flag harmless
> things. It is no replacement for professional security tools. Always check a command before you run it.
> Found a bug? Please [open an issue](https://github.com/nox994/kauz/issues).

## Installation

```bash
git clone https://github.com/nox994/kauz.git
cd kauz
```

**Desktop app** on CachyOS/Arch:
```bash
sudo pacman -S pyside6
./install-desktop.sh      # adds Kauz to your app menu
```
Then open **Kauz** from the app menu (category *System*), or run `python3 -m kauz.gui`.

Other distros: install PySide6 (`python3-pyside6` on Fedora, `python3-pyside6.qtwidgets python3-pyside6.qtsvgwidgets` on Debian/Ubuntu), then run `./install-desktop.sh`.

**Terminal only** (nothing to install):
```bash
python3 -m kauz
```

Optional, to get the `kauz` and `kauz-gui` commands everywhere: `pipx install --system-site-packages .`

## Desktop app

Click **Scan now**.

- The owl shows at a glance how your system is doing
- Every finding expands: **What does it mean?** and **What to do**
- Fix commands can be copied with one click
- **With admin rights** runs the scan through `pkexec` – KDE asks for your password once
- **Save report** creates the HTML report and opens it in your browser

## Terminal

```bash
python3 -m kauz                     # normal scan
sudo python3 -m kauz                # full scan (all processes, sudo rules, firewall rules)
python3 -m kauz -v                  # all details and explanations
python3 -m kauz --html report.html  # HTML report for the browser
python3 -m kauz --only network,ssh  # only some checks
python3 -m kauz --list              # list all checks
python3 -m kauz --json -            # JSON only (for scripts)
```

Exit code: `0` = fine, `1` = warnings, `2` = critical – handy for cron jobs.

## What gets checked?

| Check | Question | Where does the data come from? |
|---|---|---|
| `updates` | Are security updates missing? Old kernel still running? | pacman/apt/dnf/zypper, flatpak, `/usr/lib/modules` |
| `firewall` | Is a firewall active? | systemd, `/etc/ufw/ufw.conf`, `nft` |
| `network` | Which programs can be reached from the network? | `/proc/net/tcp*`, `/proc/net/udp*`, `/proc/<pid>/fd` |
| `ssh` | Is SSH running? Root login, password login? | `/etc/ssh/sshd_config` (+ includes) |
| `autostart` | Suspicious autostarts (curl\|sh, reverse shells, temp folders)? | autostart, systemd, cron, shell rc files, `/etc/ld.so.preload` |
| `processes` | Programs running from `/tmp`, disguised kernel threads? | `/proc/<pid>/exe`, `/proc/<pid>/cmdline` |
| `users` | Hidden root accounts, empty passwords, sudo without password? | `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers` |
| `permissions` | SUID files in temp/home, unprotected SSH keys? | file system |
| `system` | ASLR, kernel hardening, Secure Boot, disk encryption | `/proc/sys`, EFI variables, `lsblk` |

## How does it work?

Linux exposes almost everything as a **file**. `/proc` is a live view of the kernel: every process,
every network socket, every kernel setting. Kauz reads those files directly instead of calling tools like
`ss` or `ps` – the same way professional tools do it.

Example – open ports:
1. `/proc/net/tcp` lists every socket, e.g. `00000000:18EB ... 0A ... 12345`
   → address `0.0.0.0`, port `0x18EB = 6379`, state `0A = LISTEN`, inode `12345`
2. An entry in `/proc/<pid>/fd/` points to `socket:[12345]` → now we know which program it is.

Every finding has a severity (OK, Info, Warning, Critical). Warnings cost 7 points, critical findings 20.
The owl's face shows how your system is doing.

## Project layout

```
kauz/
├── cli.py          command line
├── gui.py          desktop app (PySide6/Qt)
├── engine.py       runs the checks (used by cli and gui)
├── core.py         Finding, Level, score
├── report.py       terminal, HTML and JSON output, the mascot
├── utils.py        run commands, read files, detect the distro
└── checks/         one file per check – each has ID, TITLE and run()
```

**Writing a new check:** create a file in `checks/`, define `ID`, `TITLE` and `run()` (returns a list of
`Finding`), add it to `checks/__init__.py`. Done.

## Roadmap

- [x] Desktop app (Qt for KDE)
- [ ] One-click fixes (only after confirmation)
- [ ] Regular scans via systemd timer + desktop notification
- [ ] Compare with the last scan ("what changed?")
- [ ] Known vulnerabilities in installed packages (arch-audit / CVE databases)
- [ ] AUR package

[See an example report](docs/example-report.html) (download it and open it in your browser)

## License

MIT – see [LICENSE](LICENSE). Provided "as is", without any warranty.
