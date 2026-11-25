"""
ui/theme.py — Lanwarden dark theme (PySide6 QSS). Dense, flat, no gradients.
"""

from __future__ import annotations

# Palette (flat, dark)
BG = "#0f1115"
PANEL = "#161a21"
CARD = "#1d222b"
BORDER = "#2a313c"
TEXT = "#d7dde6"
# MUTED lifted from #8a93a2 to #9aa6b6 — the old value was ~4.0:1 on PANEL
# (below the 4.5:1 WCAG AA text floor); this clears it while staying "muted".
MUTED = "#9aa6b6"
ACCENT = "#6aa0ff"  # Warden blue
GREEN = "#5ad17a"
RED = "#ef6a7a"
AMBER = "#e6b85c"
CYAN = "#5bd6d0"

QSS = f"""
* {{
    font-family: "DejaVu Sans Mono", "Consolas", monospace;
    font-size: 12px;
    color: {TEXT};
}}
QMainWindow, QWidget {{ background: {BG}; }}
QFrame#Sidebar, QFrame#Detail {{ background: {PANEL}; border: 1px solid {BORDER}; }}
QFrame#Banner {{ background: {CARD}; border: 1px solid {BORDER}; }}
QLabel#Title {{ font-size: 15px; font-weight: bold; color: {ACCENT}; }}
QLabel#SectionTitle {{ color: {MUTED}; font-size: 11px; font-weight: bold; }}
QLabel#State {{ font-weight: bold; }}
QPushButton {{
    background: {CARD}; border: 1px solid {BORDER}; padding: 6px 10px;
    border-radius: 3px; color: {TEXT};
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; }}
QPushButton#Nav {{ text-align: left; padding: 8px 12px; border: none; background: transparent; }}
QPushButton#Nav:checked {{ background: {CARD}; border-left: 2px solid {ACCENT}; color: {ACCENT}; }}
QPushButton#Danger:hover {{ border-color: {RED}; }}
QPushButton#Good:hover {{ border-color: {GREEN}; }}
/* Visible keyboard-focus ring on every interactive widget (a11y). */
QPushButton:focus, QComboBox:focus, QLineEdit:focus, QSpinBox:focus,
QPlainTextEdit:focus, QTableWidget:focus {{ border: 1px solid {ACCENT}; outline: none; }}
QTableWidget::item:focus {{ outline: 1px solid {ACCENT}; }}
QLineEdit#Filter {{ background: {CARD}; border: 1px solid {BORDER}; padding: 4px 8px; border-radius: 3px; }}
QTableWidget {{
    background: {PANEL}; gridline-color: {BORDER}; border: 1px solid {BORDER};
    selection-background-color: {ACCENT}; selection-color: {BG};
}}
QHeaderView::section {{
    background: {CARD}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 4px 6px;
}}
QComboBox, QLineEdit, QSpinBox {{
    background: {CARD}; border: 1px solid {BORDER}; padding: 4px; border-radius: 3px;
}}
QTextEdit, QPlainTextEdit {{ background: {PANEL}; border: 1px solid {BORDER}; }}
QStatusBar {{ background: {CARD}; border-top: 1px solid {BORDER}; color: {MUTED}; }}
QStatusBar QLabel {{ padding: 0 8px; border-right: 1px solid {BORDER}; }}
QCheckBox {{ spacing: 6px; }}
"""

# State → (label text, colour)
STATE_STYLES = {
    "empty": ("No devices — run a scan", MUTED),
    "loading": ("Scanning the network…", CYAN),
    "normal": ("Ready", GREEN),
    "error": ("Error", RED),
    "degraded": ("Degraded — missing capability", AMBER),
    "disconnected": ("Disconnected — no interface / gateway", AMBER),
    "permission_denied": ("Permission denied — run as root", RED),
    "running": ("Operation running…", ACCENT),
    "stopping": ("Stopping — restoring network…", AMBER),
    "restoring": ("Restoring devices…", CYAN),
    "restore_failed": ("Restore failed — check status", RED),
    "alert": ("Protection alert", RED),
}
