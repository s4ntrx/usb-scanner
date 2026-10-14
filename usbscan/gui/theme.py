from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt

SPACING = 8
MARGIN = 16
RADIUS = 8


@dataclass(frozen=True)
class Palette:
    background: str
    surface: str
    border: str
    text: str
    muted: str
    accent: str
    accent_text: str
    selection: str
    success: str
    danger: str
    severity: dict[str, str]


LIGHT = Palette(
    background="#f5f6f8", surface="#ffffff", border="#dfe2e8", text="#1b1f27", muted="#5d6675",
    accent="#0f6cbd", accent_text="#ffffff", selection="#e6f0fa", success="#1a7f37", danger="#c42b1c",
    severity={"critical": "#b3261e", "high": "#c2410c", "medium": "#a16207", "low": "#4b5563", "info": "#6b7280"},
)

DARK = Palette(
    background="#1c1f26", surface="#252932", border="#363b47", text="#e8eaf0", muted="#9aa3b2",
    accent="#4aa3f0", accent_text="#0b1220", selection="#2b3a4d", success="#4ade80", danger="#f87171",
    severity={"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#9ca3af", "info": "#9ca3af"},
)


def current_palette(app) -> Palette:
    color_scheme = getattr(app.styleHints(), "colorScheme", None)
    if color_scheme and color_scheme() == Qt.ColorScheme.Dark:
        return DARK
    return LIGHT


def build_stylesheet(p: Palette) -> str:
    return f"""
QWidget {{ font-family: "Segoe UI Variable", "Segoe UI", sans-serif; font-size: 13px; color: {p.text}; }}
QMainWindow, QDialog {{ background: {p.background}; }}
QFrame#card {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {RADIUS}px; }}
QLabel {{ background: transparent; }}
QLabel#title {{ font-size: 16px; font-weight: 600; }}
QLabel#muted {{ color: {p.muted}; }}
QPushButton {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {RADIUS}px; padding: 7px 14px; }}
QPushButton:hover {{ border-color: {p.accent}; }}
QPushButton:disabled {{ color: {p.muted}; border-color: {p.border}; }}
QPushButton#primary {{ background: {p.accent}; color: {p.accent_text}; border-color: {p.accent}; font-weight: 600; }}
QPushButton#primary:disabled {{ background: {p.border}; border-color: {p.border}; color: {p.muted}; }}
QPushButton#stop {{ background: {p.danger}; color: {p.accent_text}; border-color: {p.danger}; font-weight: 600; }}
QComboBox, QLineEdit, QPlainTextEdit {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {RADIUS}px; padding: 6px 8px; }}
QComboBox QAbstractItemView {{ background: {p.surface}; selection-background-color: {p.selection}; selection-color: {p.text}; border: 1px solid {p.border}; }}
QTableWidget {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {RADIUS}px; outline: 0; }}
QTableWidget::item {{ padding: 4px 8px; border: none; }}
QTableWidget::item:selected {{ background: {p.selection}; }}
QHeaderView::section {{ background: {p.surface}; color: {p.muted}; border: none; border-bottom: 1px solid {p.border}; padding: 6px 8px; font-weight: 600; }}
QProgressBar {{ background: {p.border}; border: none; border-radius: 3px; max-height: 6px; min-height: 6px; }}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 3px; }}
QCheckBox {{ spacing: {SPACING}px; }}
"""
