import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QMessageBox

from usbscan.gui.main_window import MainWindow


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(qt_app, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    main_window = MainWindow(settings, quarantine_directory=tmp_path / "vault", poll_drives=False)
    yield main_window
    main_window.close()


def wait_until(app, condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        app.processEvents()
        if time.monotonic() > deadline:
            raise TimeoutError("condition not met")
        time.sleep(0.01)


def make_infected_folder(root: Path) -> Path:
    root.mkdir()
    (root / "autorun.inf").write_text("[autorun]\nopen=setup.exe\n")
    (root / "notes.txt").write_text("harmless")
    return root


def test_scan_fills_results_table(qt_app, window, tmp_path):
    folder = make_infected_folder(tmp_path / "stick")
    window.start_scan(str(folder))
    wait_until(qt_app, lambda: not window.is_scanning)
    assert window.table.rowCount() == 1
    assert window.table.item(0, 0).text() == "HIGH"
    assert "autorun_inf" in window.table.item(0, 2).text()
    assert window.export_button.isEnabled()


def test_clean_folder_reports_no_findings(qt_app, window, tmp_path):
    folder = tmp_path / "clean"
    folder.mkdir()
    (folder / "photo.png").write_bytes(b"\x89PNG" + b"\x00" * 32)
    window.start_scan(str(folder))
    wait_until(qt_app, lambda: not window.is_scanning)
    assert window.table.rowCount() == 0
    assert window.status_title.text() == "No findings"


def test_quarantine_selected_moves_file(qt_app, window, tmp_path, monkeypatch):
    folder = make_infected_folder(tmp_path / "stick")
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes)
    window.start_scan(str(folder))
    wait_until(qt_app, lambda: not window.is_scanning)
    window.table.selectRow(0)
    window.quarantine_selected()
    assert not (folder / "autorun.inf").exists()
    assert window.table.item(0, 4).text() == "Quarantined"
    assert (tmp_path / "vault" / "manifest.jsonl").exists()


def test_stop_button_hidden_until_scanning(qt_app, window):
    assert window.stop_button.isHidden()
    assert not window.scan_button.isHidden()
