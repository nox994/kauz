"""Kauz as a desktop app (Qt / PySide6) – follows your KDE theme.

Start:  kauz-gui   or   python3 -m kauz.gui
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import List, Optional

try:
    from PySide6.QtCore import QByteArray, QSize, Qt, QThread, QUrl, Signal
    from PySide6.QtGui import (QDesktopServices, QFont, QGuiApplication, QIcon, QPainter, QPalette,
                               QPixmap)
    from PySide6.QtSvg import QSvgRenderer
    from PySide6.QtSvgWidgets import QSvgWidget
    from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel,
                                   QMainWindow, QMessageBox, QProgressBar, QPushButton, QScrollArea,
                                   QVBoxLayout, QWidget)
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "The desktop app needs PySide6.\n"
        "  CachyOS/Arch:  sudo pacman -S pyside6\n"
        "  Debian/Ubuntu: sudo apt install python3-pyside6.qtwidgets python3-pyside6.qtsvgwidgets\n"
        "  Fedora:        sudo dnf install python3-pyside6\n"
        "  or:            pipx install 'kauz[gui]'\n"
        "Without the app, Kauz runs in the terminal:  python3 -m kauz\n")
    raise SystemExit(1)

from . import DISCLAIMER, __version__
from .checks import ALL
from .core import CheckResult, Level, mood, score
from .engine import results_from_json, run_checks
from .report import ICONS, MESSAGES, _owl_svg, code_html, to_html
from .utils import distro_name, is_root, real_user, which

LIGHT = {Level.OK: "#1a7f37", Level.INFO: "#0969da", Level.WARN: "#9a6700", Level.CRIT: "#cf222e"}
DARK = {Level.OK: "#3fb950", Level.INFO: "#58a6ff", Level.WARN: "#d29922", Level.CRIT: "#f85149"}
MOOD_LEVEL = {"happy": Level.OK, "neutral": Level.WARN, "worried": Level.CRIT}


def is_dark() -> bool:
    return QGuiApplication.palette().window().color().lightness() < 128


def muted_color() -> str:
    return QGuiApplication.palette().color(QPalette.PlaceholderText).name()


def level_color(lvl: Level) -> str:
    return (DARK if is_dark() else LIGHT)[lvl]


def owl_bytes(m: str) -> QByteArray:
    """The same owl SVG as in the HTML report – with fixed colours instead of CSS variables."""
    dark = is_dark()
    svg = _owl_svg(m)
    for var, val in (("var(--owl-body)", "#4a3f30" if dark else "#e9dcc6"),
                     ("var(--bg)", "#1c1f25" if dark else "#ffffff"),
                     ("var(--beak)", "#e3a24a" if dark else "#d08a2b"),
                     ("currentColor", "#e6edf3" if dark else "#1f2328")):
        svg = svg.replace(var, val)
    svg = svg.replace('<svg ', '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
    return QByteArray(svg.encode())


def owl_icon() -> QIcon:
    renderer = QSvgRenderer(owl_bytes("happy"))
    icon = QIcon()
    for size in (16, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        renderer.render(p)
        p.end()
        icon.addPixmap(pm)
    return icon


def commands_in(text: str) -> List[str]:
    """Find copyable commands in a fix text (they are written in `backticks`).
    Commands with placeholders like FILE or NAME are skipped – they can't be run as-is."""
    out = []
    for c in re.findall(r"`([^`]+)`", text):
        if not re.match(r"^(sudo |[a-z][\w.-]* )", c):
            continue
        if any(re.fullmatch(r"[A-Z]{3,}", tok) for tok in c.split()):
            continue
        out.append(c)
    return out[:3]


class Cancelled(Exception):
    pass


# ───────────────────────────── background scan ─────────────────────────────

class ScanWorker(QThread):
    progress = Signal(int, int, str)
    done = Signal(object, bool)   # (results, ran as root)
    failed = Signal(str)

    def __init__(self, admin: bool):
        super().__init__()
        self.admin = admin
        self.proc: Optional[subprocess.Popen] = None

    def cancel(self) -> None:
        self.requestInterruption()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def _progress(self, i: int, n: int, title: str) -> None:
        if self.isInterruptionRequested():
            raise Cancelled()
        self.progress.emit(i, n, title)

    def run(self) -> None:
        try:
            if self.admin and not is_root():
                self.done.emit(self._run_as_admin(), True)
            else:
                self.done.emit(run_checks(ALL, self._progress), is_root())
        except Cancelled:
            pass
        except Exception as exc:
            if not self.isInterruptionRequested():
                self.failed.emit(str(exc))

    def _run_as_admin(self) -> List[CheckResult]:
        """Run Kauz through pkexec (KDE asks for the password) and read the JSON result."""
        if not which("pkexec"):
            raise RuntimeError("pkexec is missing – install polkit or run `sudo python3 -m kauz` in a terminal.")
        self.progress.emit(0, 0, "Waiting for the admin password …")
        pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cmd = ["pkexec", "/usr/bin/env", f"PYTHONPATH={pkg_root}", "PYTHONDONTWRITEBYTECODE=1",
               f"SUDO_USER={real_user()}", sys.executable, "-m", "kauz", "--json", "-"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out, err = self.proc.communicate(timeout=900)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise RuntimeError("The admin scan took too long and was stopped.")
        if self.isInterruptionRequested():
            raise Cancelled()
        if self.proc.returncode in (126, 127) and not out.strip():
            raise RuntimeError("Admin rights were not granted (cancelled or wrong password).")
        try:
            return results_from_json(json.loads(out))
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError(f"The admin scan failed: {err.strip()[:300] or exc}")


# ───────────────────────────── widgets ─────────────────────────────

class FindingRow(QFrame):
    """One row per finding. Clicking the header expands/collapses the explanation."""

    def __init__(self, f, parent=None):
        super().__init__(parent)
        self.setObjectName("finding")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(6)

        head = QHBoxLayout()
        icon = QLabel(ICONS[f.level])
        icon.setFixedWidth(20)
        icon.setStyleSheet(f"color:{level_color(f.level)}; font-weight:700; font-size:15px;")
        title = QLabel(f.title)
        title.setWordWrap(True)
        if f.level >= Level.WARN:
            title.setStyleSheet("font-weight:600;")
        head.addWidget(icon, 0, Qt.AlignTop)
        head.addWidget(title, 1)
        self.has_body = bool(f.detail or f.items or f.explain or f.fix)
        self.arrow = QLabel("▾" if f.level >= Level.WARN else "▸")
        self.arrow.setVisible(self.has_body)
        self.arrow.setStyleSheet(f"color:{muted_color()};")
        head.addWidget(self.arrow, 0, Qt.AlignTop)
        lay.addLayout(head)

        self.body = QWidget()
        b = QVBoxLayout(self.body)
        b.setContentsMargins(26, 0, 0, 2)
        b.setSpacing(6)
        if f.detail:
            b.addWidget(self._text(code_html(f.detail), muted=True))
        if f.items:
            items = "".join(f"<li>{code_html(i)}</li>" for i in f.items[:20])
            more = f"<li>… {len(f.items) - 20} more</li>" if len(f.items) > 20 else ""
            b.addWidget(self._text(f"<ul style='margin:0 0 0 -24px'>{items}{more}</ul>", muted=True))
        if f.explain:
            b.addWidget(self._text(f"<b>What does it mean?</b> {code_html(f.explain)}"))
        if f.fix:
            fix = self._text(f"<b>What to do:</b> {code_html(f.fix)}")
            fix.setObjectName("fix")
            b.addWidget(fix)
            for cmd in commands_in(f.fix):
                b.addWidget(self._copy_button(cmd))
        lay.addWidget(self.body)
        self.body.setVisible(f.level >= Level.WARN and self.has_body)
        if self.has_body:
            self.setCursor(Qt.PointingHandCursor)

    def _text(self, rich: str, muted: bool = False) -> QLabel:
        lbl = QLabel(rich)
        lbl.setTextFormat(Qt.RichText)
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lbl.setCursor(Qt.IBeamCursor)
        if muted:
            lbl.setStyleSheet(f"color:{muted_color()};")
        return lbl

    def _copy_button(self, cmd: str) -> QPushButton:
        btn = QPushButton(f"⧉  {cmd if len(cmd) < 70 else cmd[:67] + '…'}")
        btn.setObjectName("copy")
        btn.setToolTip(cmd + "\n\nCopy to clipboard – then paste it into a terminal (Ctrl+Shift+V)")
        btn.setCursor(Qt.PointingHandCursor)

        def copy():
            QGuiApplication.clipboard().setText(cmd)
            btn.setText("✔  Copied – paste it into a terminal")
        btn.clicked.connect(copy)
        return btn

    def mousePressEvent(self, event):  # noqa: N802 (Qt name)
        if self.has_body and event.button() == Qt.LeftButton:
            show = not self.body.isVisible()
            self.body.setVisible(show)
            self.arrow.setText("▾" if show else "▸")
        super().mousePressEvent(event)


class CategoryCard(QFrame):
    def __init__(self, result: CheckResult, only_problems: bool, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        head = QHBoxLayout()
        head.setContentsMargins(14, 12, 14, 10)
        title = QLabel(result.title)
        title.setStyleSheet("font-weight:700; font-size:15px;")
        badge = QLabel(result.worst.label)
        c = level_color(result.worst)
        badge.setStyleSheet(f"color:{c}; border:1px solid {c}; border-radius:9px; padding:1px 9px;"
                            "font-size:12px; font-weight:600;")
        head.addWidget(title)
        head.addStretch()
        head.addWidget(badge)
        lay.addLayout(head)

        self.visible_rows = 0
        for f in sorted(result.findings, key=lambda x: -x.level):
            if only_problems and f.level < Level.WARN:
                continue
            line = QFrame()
            line.setObjectName("sep")
            line.setFixedHeight(1)
            lay.addWidget(line)
            lay.addWidget(FindingRow(f))
            self.visible_rows += 1


STYLE = """
#card { background: palette(base); border: 1px solid palette(mid); border-radius: 12px; }
#sep { background: palette(midlight); }
#fix { background: palette(alternate-base); border-radius: 6px; padding: 6px 8px; }
QPushButton#copy { text-align: left; font-family: monospace; padding: 4px 10px; }
QPushButton#primary { font-weight: 700; padding: 8px 22px; font-size: 14px; }
"""


# ───────────────────────────── main window ─────────────────────────────

class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kauz – security check")
        self.setWindowIcon(owl_icon())
        self.resize(860, 800)
        self.setMinimumSize(QSize(520, 480))
        self.results: Optional[List[CheckResult]] = None
        self.ran_as_root = False
        self.worker: Optional[ScanWorker] = None

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(14)
        self.setCentralWidget(central)

        # header: owl + score
        header = QHBoxLayout()
        header.setSpacing(20)
        self.owl = QSvgWidget()
        self.owl.setFixedSize(96, 104)
        self.owl.load(owl_bytes("neutral"))
        header.addWidget(self.owl, 0, Qt.AlignTop)

        info = QVBoxLayout()
        info.setSpacing(2)
        name = QLabel("Kauz")
        f = QFont()
        f.setPointSize(20)
        f.setBold(True)
        name.setFont(f)
        self.sub = QLabel(f"{distro_name()} · {real_user()} · v{__version__}")
        self.sub.setStyleSheet(f"color:{muted_color()};")
        self.score = QLabel("–")
        sf = QFont()
        sf.setPointSize(32)
        sf.setBold(True)
        self.score.setFont(sf)
        self.message = QLabel("Hoo-hoo! Click “Scan now” and I'll take a look at your system.")
        self.message.setWordWrap(True)
        for w in (name, self.sub, self.score, self.message):
            info.addWidget(w)
        header.addLayout(info, 1)
        root.addLayout(header)

        # toolbar
        bar = QHBoxLayout()
        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.start_scan)
        self.admin_box = QCheckBox("With admin rights (more thorough)")
        self.admin_box.setToolTip("Also sees other users' processes, sudo rules and firewall rules.\n"
                                  "Kauz asks for your password once and still changes nothing.")
        self.admin_box.setChecked(is_root())
        self.admin_box.setEnabled(not is_root())
        self.filter_box = QCheckBox("Problems only")
        self.filter_box.toggled.connect(self.render_results)
        self.save_btn = QPushButton("Save report …")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_report)
        bar.addWidget(self.scan_btn)
        bar.addWidget(self.admin_box)
        bar.addStretch()
        bar.addWidget(self.filter_box)
        bar.addWidget(self.save_btn)
        root.addLayout(bar)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(True)
        root.addWidget(self.progress)

        # results list
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.list_host = QWidget()
        self.list = QVBoxLayout(self.list_host)
        self.list.setContentsMargins(0, 0, 6, 0)
        self.list.setSpacing(12)
        self.scroll.setWidget(self.list_host)
        root.addWidget(self.scroll, 1)
        self.show_welcome()

        foot = QLabel("Kauz only reads – it never changes your system.  "
                      "<a href='#note'>Kauz can make mistakes</a>")
        foot.setAlignment(Qt.AlignCenter)
        foot.setStyleSheet(f"color:{muted_color()}; font-size:12px;")
        foot.setTextFormat(Qt.RichText)
        foot.setToolTip(DISCLAIMER)
        foot.linkActivated.connect(lambda _: QMessageBox.information(self, "About Kauz", DISCLAIMER))
        root.addWidget(foot)

    # ── content ──
    def clear_list(self) -> None:
        while self.list.count():
            item = self.list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def show_welcome(self) -> None:
        self.clear_list()
        text = QLabel(
            "<h3>What does Kauz check?</h3><ul>"
            "<li><b>Updates</b> – are security updates missing?</li>"
            "<li><b>Firewall</b> – is your PC shielded?</li>"
            "<li><b>Open ports</b> – which programs can be reached from the network?</li>"
            "<li><b>SSH</b> – is remote login set up safely?</li>"
            "<li><b>Autostart</b> – has something suspicious settled in?</li>"
            "<li><b>Processes</b> – is anything odd running right now?</li>"
            "<li><b>Users &amp; file permissions</b> – hidden admins, backdoors?</li>"
            "<li><b>System protection</b> – kernel hardening, Secure Boot, encryption</li></ul>"
            "<p>Every finding is explained – with a command to fix it that you can copy.</p>"
            f"<p style='color:{muted_color()}'><i>{DISCLAIMER}</i></p>")
        text.setWordWrap(True)
        text.setTextFormat(Qt.RichText)
        self.list.addWidget(text)
        self.list.addStretch()

    def render_results(self) -> None:
        if self.results is None:
            return
        self.clear_list()
        only = self.filter_box.isChecked()
        shown = 0
        for r in self.results:
            card = CategoryCard(r, only)
            if card.visible_rows:
                self.list.addWidget(card)
                shown += 1
            else:
                card.deleteLater()
        if only and not shown:
            ok = QLabel("🎉  No problems found.")
            ok.setAlignment(Qt.AlignCenter)
            ok.setStyleSheet("font-size:16px; padding:40px;")
            self.list.addWidget(ok)
        self.list.addStretch()
        self.scroll.verticalScrollBar().setValue(0)

    # ── scan ──
    def start_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.scan_btn.setEnabled(False)
        self.admin_box.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(ALL))
        self.progress.setValue(0)
        self.progress.setFormat("Starting …")
        self.message.setText("Hoo-hoo … let me have a look around.")
        self.worker = ScanWorker(self.admin_box.isChecked())
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def on_progress(self, i: int, n: int, title: str) -> None:
        if n == 0:                       # unknown duration (admin run)
            self.progress.setRange(0, 0)
            self.progress.setFormat(title)
            return
        self.progress.setRange(0, n)
        self.progress.setValue(i)
        self.progress.setFormat(f"Checking {title} … ({i + 1}/{n})" if title else "Done")

    def on_done(self, results: List[CheckResult], as_root: bool) -> None:
        self.results, self.ran_as_root = results, as_root
        pts = score(results)
        m = mood(pts)
        self.owl.load(owl_bytes(m))
        self.score.setText(f"{pts}<span style='font-size:16px; font-weight:400;'> / 100</span>")
        self.score.setStyleSheet(f"color:{level_color(MOOD_LEVEL[m])};")
        crit = sum(1 for r in results for f in r.findings if f.level == Level.CRIT)
        warn = sum(1 for r in results for f in r.findings if f.level == Level.WARN)
        extra = "" if as_root else "  (Tip: with admin rights Kauz sees more.)"
        self.message.setText(f"{MESSAGES[m]}  {crit} critical · {warn} warnings.{extra}")
        self.sub.setText(f"{distro_name()} · {real_user()}{' (admin)' if as_root else ''} · v{__version__}")
        self.finish()
        self.render_results()

    def on_failed(self, msg: str) -> None:
        self.finish()
        self.message.setText("Hoo? Something went wrong.")
        QMessageBox.warning(self, "Kauz", msg)

    def finish(self) -> None:
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.admin_box.setEnabled(not is_root())
        self.scan_btn.setText("Scan again")
        self.save_btn.setEnabled(self.results is not None)

    def save_report(self) -> None:
        if not self.results:
            return
        start = os.path.join(os.path.expanduser("~"), "kauz-report.html")
        path, _ = QFileDialog.getSaveFileName(self, "Save report", start, "HTML report (*.html)")
        if not path:
            return
        if not path.endswith(".html"):
            path += ".html"
        page = to_html(self.results, score(self.results), distro_name(), real_user(), self.ran_as_root)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(page)
        except OSError as exc:
            QMessageBox.warning(self, "Kauz", f"Could not save the report:\n{exc.strerror}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def closeEvent(self, event):  # noqa: N802 (Qt name)
        # stop a running scan cleanly instead of crashing on exit
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(5000)
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Kauz")
    app.setDesktopFileName("kauz")
    app.setStyleSheet(STYLE)
    win = Window()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
