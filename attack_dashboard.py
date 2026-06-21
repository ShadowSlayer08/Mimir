#!/usr/bin/env python3
"""
attack_dashboard.py  —  Front-door Attack Dashboard for the pentest console.

Authorized / lab / CTF use only.

A landing screen that puts the TARGET FORM alongside the ATTACK MODE selection,
gates on scope confirmation, then connects to pentest_console.Console — it opens
the operations console pre-filled with the target/mode and kicks off Stage-1
acquisition.

IMPORTANT — like the rest of this engine, the dashboard performs analysis and
STAGING only. Picking "Red Team" selects deeper, more intrusive ENUMERATION; it
does NOT launch exploits. Attack paths are staged for a human operator to run
manually within an authorized engagement (see docs/instructions.md).

Run:
    python3 attack_dashboard.py                 # open the dashboard
    python3 attack_dashboard.py 10.10.10.5      # pre-fill a target
"""
from __future__ import annotations

import os
import sys

from PySide6 import QtCore, QtGui, QtWidgets

# Reuse the console's palette, stylesheet and the operations window itself.
from pentest_console import (Console, QSS, BG, PANEL, PANEL2, BORDER, TXT, MUTED,
                             ACCENT)
from profiles import get_profile

__version__ = "1.0"

MODE_GREEN = "#7bd88f"
MODE_RED = "#ff5b6e"


class AttackDashboard(QtWidgets.QMainWindow):
    def __init__(self, preload_target=None):
        super().__init__()
        self.setWindowTitle(f"Attack Dashboard — Pentest Engine  v{__version__}")
        self.resize(880, 620)
        self.console = None          # the connected operations window (kept alive)
        self._build()
        if preload_target:
            self.target_edit.setText(preload_target)
        self._validate()

    # ---------- UI ----------
    def _build(self):
        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        lay = QtWidgets.QVBoxLayout(root)
        lay.setContentsMargins(22, 18, 22, 18)
        lay.setSpacing(14)

        title = QtWidgets.QLabel("⚔  Attack Dashboard")
        title.setObjectName("title")
        title.setStyleSheet("font-size:20px;font-weight:800;color:#fff;")
        sub = QtWidgets.QLabel("Acquire a target, choose an operation mode, then launch the "
                               "console. Analysis & staging only — no exploits are run.")
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(sub)

        # --- body: target form ALONGSIDE attack mode ---
        body = QtWidgets.QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self._target_form(), 1)
        body.addWidget(self._mode_panel(), 1)
        lay.addLayout(body, 1)

        # --- staging boundary banner ---
        banner = QtWidgets.QLabel(
            "Staging only — the console maps findings to MITRE ATT&CK attack paths and "
            "queues them for MANUAL, in-scope execution. The engine never launches exploits.")
        banner.setObjectName("banner")
        banner.setWordWrap(True)
        lay.addWidget(banner)

        # --- footer: launch ---
        foot = QtWidgets.QHBoxLayout()
        foot.addStretch(1)
        self.launch_btn = QtWidgets.QPushButton("⚡  Launch operation → console")
        self.launch_btn.setObjectName("accent")
        self.launch_btn.setMinimumHeight(38)
        self.launch_btn.clicked.connect(self.launch)
        foot.addWidget(self.launch_btn)
        lay.addLayout(foot)

    def _target_form(self):
        box = QtWidgets.QGroupBox("Target")
        box.setStyleSheet(self._group_qss())
        f = QtWidgets.QFormLayout(box)
        f.setContentsMargins(16, 18, 16, 16)
        f.setSpacing(12)
        f.setLabelAlignment(QtCore.Qt.AlignRight)

        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("IP / CIDR / hostname")
        self.target_edit.textChanged.connect(self._validate)
        self.target_edit.returnPressed.connect(self.launch)
        f.addRow("Target", self.target_edit)

        self.ports_edit = QtWidgets.QLineEdit()
        self.ports_edit.setPlaceholderText("optional (default ports)")
        f.addRow("Ports", self.ports_edit)

        self.authz_check = QtWidgets.QCheckBox(
            "I confirm this target is within my written, authorized engagement scope")
        self.authz_check.setStyleSheet("padding-top:6px;")
        self.authz_check.toggled.connect(self._validate)
        f.addRow("", self.authz_check)
        return box

    def _mode_panel(self):
        box = QtWidgets.QGroupBox("Attack mode")
        box.setStyleSheet(self._group_qss())
        v = QtWidgets.QVBoxLayout(box)
        v.setContentsMargins(16, 18, 16, 16)
        v.setSpacing(12)

        self.mode_group = QtWidgets.QButtonGroup(self)
        self.vapt_card = self._mode_card(
            "VAPT — safe", get_profile("vapt")["banner"], MODE_GREEN, checked=True)
        self.redteam_card = self._mode_card(
            "Red Team — in-depth", get_profile("redteam")["banner"], MODE_RED)
        self.mode_group.addButton(self.vapt_card, 0)
        self.mode_group.addButton(self.redteam_card, 1)
        self.mode_group.idToggled.connect(lambda *_: self._restyle_cards())
        v.addWidget(self.vapt_card)
        v.addWidget(self.redteam_card)
        v.addStretch(1)
        self._restyle_cards()
        return box

    def _mode_card(self, title, desc, accent, checked=False):
        btn = QtWidgets.QToolButton()
        btn.setCheckable(True)
        btn.setChecked(checked)
        btn.setText(f"{title}\n{desc}")
        btn.setToolButtonStyle(QtCore.Qt.ToolButtonTextOnly)
        btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        btn.setMinimumHeight(96)
        btn.setProperty("accent", accent)
        return btn

    def _restyle_cards(self):
        for btn in (self.vapt_card, self.redteam_card):
            accent = btn.property("accent")
            on = btn.isChecked()
            btn.setStyleSheet(
                f"QToolButton {{ text-align:left; padding:12px 14px; border-radius:10px; "
                f"background:{PANEL2 if on else PANEL}; color:{TXT}; "
                f"border:2px solid {accent if on else BORDER}; }}"
                f"QToolButton:hover {{ border-color:{accent}; }}")

    def _group_qss(self):
        return (f"QGroupBox {{ background:{PANEL}; border:1px solid {BORDER}; "
                f"border-radius:12px; margin-top:10px; font-weight:700; color:#fff; }}"
                f"QGroupBox::title {{ subcontrol-origin:margin; left:14px; padding:0 4px; }}")

    # ---------- behaviour ----------
    def _validate(self):
        ok = bool(self.target_edit.text().strip()) and self.authz_check.isChecked()
        self.launch_btn.setEnabled(ok)

    def _selected_mode(self):
        return "redteam" if self.mode_group.checkedId() == 1 else "vapt"

    def launch(self, _=False, start_scan=True):
        if not self.launch_btn.isEnabled():
            return
        target = self.target_edit.text().strip()
        mode = self._selected_mode()

        # Connect to (or reuse) the operations console and hand off the target.
        if self.console is None:
            self.console = Console()
        self.console.target_edit.setText(target)
        self.console.mode_combo.setCurrentIndex(1 if mode == "redteam" else 0)
        self.console.authz_check.setChecked(True)   # scope already confirmed here
        self.console.scan_ports = self.ports_edit.text().strip() or None
        self.console.show()
        self.console.raise_()
        self.console.activateWindow()
        if start_scan:
            self.console.acquire()
        self.hide()


def main():
    selftest = "--selftest" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    # Cross-platform high-DPI: pass through fractional scale factors so the UI
    # renders crisply on Windows 125/150% and macOS Retina (must be set before
    # the QApplication is constructed). Qt6 enables high-DPI pixmaps by default.
    try:
        QtGui.QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            QtCore.Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except Exception:
        pass
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(QSS)
    dash = AttackDashboard(preload_target=args[0] if args else None)
    dash.show()

    if selftest:
        def check():
            dash.target_edit.setText("10.10.10.5")
            dash.authz_check.setChecked(True)
            dash.redteam_card.setChecked(True)
            dash._validate()
            enabled = dash.launch_btn.isEnabled()
            mode = dash._selected_mode()
            # connect to the console WITHOUT starting a real scan
            dash.launch(start_scan=False)
            c = dash.console
            ok = (enabled and mode == "redteam" and c is not None
                  and c.target_edit.text() == "10.10.10.5"
                  and c.mode_combo.currentIndex() == 1)
            print(f"SELFTEST {'OK' if ok else 'FAIL'} | launch_enabled={enabled} "
                  f"mode={mode} console_target={c.target_edit.text() if c else None} "
                  f"console_mode_idx={c.mode_combo.currentIndex() if c else None}")
            app.quit()
            sys.exit(0 if ok else 2)
        QtCore.QTimer.singleShot(500, check)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
