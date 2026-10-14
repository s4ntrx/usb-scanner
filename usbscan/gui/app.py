from __future__ import annotations

import sys

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from usbscan.gui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("usbscan")
    app.setOrganizationName("usbscan")
    window = MainWindow(QSettings())
    window.show()
    return app.exec()
