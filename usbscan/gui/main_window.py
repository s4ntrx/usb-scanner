from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QStyledItemDelegate,
    QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from usbscan.cli import DATA_DIRECTORY
from usbscan.drives import list_removable_mount_points
from usbscan.gui.icons import icon, render_pixmap
from usbscan.gui.settings_dialog import SettingsDialog
from usbscan.gui.theme import MARGIN, SPACING, build_stylesheet, current_palette
from usbscan.gui.worker import ScanWorker
from usbscan.hashing import load_hash_database
from usbscan.models import SEVERITY_RANK, FileResult, ScanSummary
from usbscan.report import write_json
from usbscan.scanner import ScanConfig, quarantine_file
from usbscan.virustotal import VirusTotalClient
from usbscan.yara_engine import YaraEngine

DRIVE_POLL_INTERVAL_MS = 2000
TABLE_COLUMNS = ["Severity", "File", "Finding", "Size", "Status"]
ROLE_RANK = Qt.ItemDataRole.UserRole
ROLE_RESULT_INDEX = Qt.ItemDataRole.UserRole + 1


def default_quarantine_directory() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "usbscan" / "quarantine"


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


class KeepForegroundDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index) -> None:
        super().initStyleOption(option, index)
        foreground = index.data(Qt.ItemDataRole.ForegroundRole)
        option.palette.setBrush(QPalette.ColorRole.HighlightedText, foreground or option.palette.brush(QPalette.ColorRole.Text))


class RankedItem(QTableWidgetItem):
    def __lt__(self, other: QTableWidgetItem) -> bool:
        return self.data(ROLE_RANK) < other.data(ROLE_RANK)


class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings, quarantine_directory: Path | None = None, poll_drives: bool = True):
        super().__init__()
        self.settings = settings
        self.quarantine_directory = quarantine_directory or default_quarantine_directory()
        self.hash_database = load_hash_database(DATA_DIRECTORY / "known_bad_hashes.txt")
        self.yara_engine = YaraEngine(DATA_DIRECTORY) if YaraEngine.is_available() else None
        self.state = "idle"
        self.summary: ScanSummary | None = None
        self.results: list[FileResult] = []
        self.manual_folders: list[str] = []
        self.detected_mounts = list_removable_mount_points()
        self.pending_mount: str | None = None
        self.worker: ScanWorker | None = None
        self.worker_thread: QThread | None = None

        self.setWindowTitle("usbscan")
        self.resize(940, 680)
        self.setMinimumSize(780, 540)
        self._build_ui()
        self._build_tray()
        self.apply_theme()
        self._rebuild_drive_combo()

        color_hints = QApplication.instance().styleHints()
        if hasattr(color_hints, "colorSchemeChanged"):
            color_hints.colorSchemeChanged.connect(lambda _scheme: self.apply_theme())

        self.drive_timer = QTimer(self)
        self.drive_timer.timeout.connect(self.refresh_drives)
        if poll_drives:
            self.drive_timer.start(DRIVE_POLL_INTERVAL_MS)

    @property
    def is_scanning(self) -> bool:
        return self.state == "scanning"

    def _build_ui(self) -> None:
        self.drive_combo = QComboBox()
        self.drive_combo.setPlaceholderText("No removable drive detected")
        self.drive_combo.setMinimumWidth(280)
        self.drive_combo.currentIndexChanged.connect(self._update_idle_status)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_drives)
        self.browse_button = QPushButton("Choose folder")
        self.browse_button.clicked.connect(self.choose_folder)
        self.scan_button = QPushButton("Scan")
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(lambda: self.start_scan())
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.hide()

        target_row = QHBoxLayout()
        target_row.setSpacing(SPACING)
        target_row.addWidget(self.drive_combo, 1)
        target_row.addWidget(self.refresh_button)
        target_row.addWidget(self.browse_button)
        target_row.addWidget(self.scan_button)
        target_row.addWidget(self.stop_button)

        self.status_icon = QLabel()
        self.status_icon.setFixedSize(36, 36)
        self.status_title = QLabel()
        self.status_title.setObjectName("title")
        self.status_detail = QLabel()
        self.status_detail.setObjectName("muted")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()

        status_text = QVBoxLayout()
        status_text.setSpacing(2)
        status_text.addWidget(self.status_title)
        status_text.addWidget(self.status_detail)

        status_row = QHBoxLayout()
        status_row.setSpacing(MARGIN)
        status_row.addWidget(self.status_icon)
        status_row.addLayout(status_text, 1)

        self.status_card = QFrame()
        self.status_card.setObjectName("card")
        card_layout = QVBoxLayout(self.status_card)
        card_layout.setContentsMargins(MARGIN, MARGIN, MARGIN, MARGIN)
        card_layout.setSpacing(MARGIN)
        card_layout.addLayout(status_row)
        card_layout.addWidget(self.progress_bar)

        self.table = QTableWidget(0, len(TABLE_COLUMNS))
        self.table.setHorizontalHeaderLabels(TABLE_COLUMNS)
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table.setItemDelegate(KeepForegroundDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 96)
        self.table.setColumnWidth(2, 240)
        self.table.setColumnWidth(3, 84)
        self.table.setColumnWidth(4, 104)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        self.detail_view = QPlainTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setFixedHeight(128)

        self.quarantine_button = QPushButton("Quarantine selected")
        self.quarantine_button.clicked.connect(self.quarantine_selected)
        self.open_quarantine_button = QPushButton("Open quarantine folder")
        self.open_quarantine_button.clicked.connect(self.open_quarantine_folder)
        self.export_button = QPushButton("Export report")
        self.export_button.clicked.connect(self.export_report)
        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self.open_settings)

        engines = ["hash list", "heuristics"] + (["YARA"] if self.yara_engine else [])
        self.engines_label = QLabel("Engines: " + ", ".join(engines))
        self.engines_label.setObjectName("muted")

        action_row = QHBoxLayout()
        action_row.setSpacing(SPACING)
        action_row.addWidget(self.quarantine_button)
        action_row.addWidget(self.open_quarantine_button)
        action_row.addWidget(self.export_button)
        action_row.addStretch(1)
        action_row.addWidget(self.engines_label)
        action_row.addWidget(self.settings_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(MARGIN, MARGIN, MARGIN, MARGIN)
        layout.setSpacing(MARGIN)
        layout.addLayout(target_row)
        layout.addWidget(self.status_card)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.detail_view)
        layout.addLayout(action_row)

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self._update_buttons()

    def _build_tray(self) -> None:
        self.tray: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.messageClicked.connect(self._scan_pending_mount)
        self.tray.show()

    def apply_theme(self) -> None:
        self.palette_tokens = current_palette(QApplication.instance())
        tokens = self.palette_tokens
        QApplication.instance().setStyleSheet(build_stylesheet(tokens))
        self.setWindowIcon(icon("usb", tokens.accent))
        if self.tray:
            self.tray.setIcon(icon("usb", tokens.accent))
        self.refresh_button.setIcon(icon("refresh", tokens.text))
        self.browse_button.setIcon(icon("folder-open", tokens.text))
        self.scan_button.setIcon(icon("scan", tokens.accent_text))
        self.stop_button.setIcon(icon("stop", tokens.accent_text))
        self.quarantine_button.setIcon(icon("archive", tokens.text))
        self.open_quarantine_button.setIcon(icon("folder-open", tokens.text))
        self.export_button.setIcon(icon("download", tokens.text))
        self.settings_button.setIcon(icon("sliders", tokens.text))
        self._update_idle_status()

    def _set_status(self, icon_name: str, color: str, title: str, detail: str, busy: bool = False) -> None:
        self.status_icon.setPixmap(render_pixmap(icon_name, color, 36))
        self.status_title.setText(title)
        self.status_detail.setText(detail)
        self.progress_bar.setVisible(busy)

    def _update_idle_status(self) -> None:
        if self.state != "idle":
            return
        tokens = self.palette_tokens
        target = self.drive_combo.currentData()
        if target:
            self._set_status("usb", tokens.accent, "Ready to scan", f"{target} is selected. Scanning is read-only.")
        else:
            self._set_status("usb", tokens.muted, "No removable drive detected", "Insert a drive, or choose a folder to scan.")
        self._update_buttons()

    def _update_buttons(self) -> None:
        has_target = self.drive_combo.currentData() is not None
        self.scan_button.setVisible(not self.is_scanning)
        self.stop_button.setVisible(self.is_scanning)
        self.scan_button.setEnabled(has_target)
        self.drive_combo.setEnabled(not self.is_scanning)
        self.refresh_button.setEnabled(not self.is_scanning)
        self.browse_button.setEnabled(not self.is_scanning)
        self.export_button.setEnabled(self.summary is not None and not self.is_scanning)
        self.quarantine_button.setEnabled(bool(self._selected_unquarantined()))

    def refresh_drives(self) -> None:
        detected = list_removable_mount_points()
        inserted = [mount for mount in detected if mount not in self.detected_mounts]
        self.detected_mounts = detected
        if not self.is_scanning:
            self._rebuild_drive_combo()
        if inserted and not self.is_scanning:
            self._announce_insert(inserted[0])

    def _rebuild_drive_combo(self) -> None:
        previous = self.drive_combo.currentData()
        self.drive_combo.blockSignals(True)
        self.drive_combo.clear()
        for mount in self.detected_mounts:
            self.drive_combo.addItem(mount, mount)
        for folder in self.manual_folders:
            self.drive_combo.addItem(f"Folder: {folder}", folder)
        index = self.drive_combo.findData(previous) if previous else -1
        self.drive_combo.setCurrentIndex(index if index >= 0 else (0 if self.drive_combo.count() else -1))
        self.drive_combo.blockSignals(False)
        self._update_idle_status()
        self._update_buttons()

    def _announce_insert(self, mount: str) -> None:
        self.pending_mount = mount
        self.drive_combo.setCurrentIndex(self.drive_combo.findData(mount))
        if self.tray and self.settings.value("notify_on_insert", True, type=bool):
            self.tray.showMessage("Drive inserted", f"{mount} detected. Click to scan it.", QSystemTrayIcon.MessageIcon.Information, 8000)

    def _scan_pending_mount(self) -> None:
        if self.pending_mount and not self.is_scanning:
            self.show()
            self.activateWindow()
            self.start_scan(self.pending_mount)

    def choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if not folder:
            return
        if folder not in self.manual_folders:
            self.manual_folders.append(folder)
        self._rebuild_drive_combo()
        self.drive_combo.setCurrentIndex(self.drive_combo.findData(folder))

    def _build_config(self, target: Path) -> ScanConfig:
        virustotal = None
        api_key = self.settings.value("virustotal_key", "", type=str)
        if api_key and self.settings.value("virustotal_enabled", False, type=bool):
            virustotal = VirusTotalClient(api_key)
        return ScanConfig(
            roots=[target],
            hash_database=self.hash_database,
            yara_engine=self.yara_engine,
            virustotal=virustotal,
        )

    def start_scan(self, target: str | None = None) -> None:
        target = target or self.drive_combo.currentData()
        if not target or self.is_scanning:
            return
        self.state = "scanning"
        self.summary = None
        self.results = []
        self.table.setRowCount(0)
        self.detail_view.clear()
        self._set_status("scan", self.palette_tokens.accent, "Scanning", f"{target}", busy=True)

        self.worker = ScanWorker(self._build_config(Path(target)))
        self.worker_thread = QThread(self)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.completed.connect(self._on_completed)
        self.worker.failed.connect(self._on_failed)
        self.worker.completed.connect(self.worker_thread.quit)
        self.worker.failed.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self._release_worker)
        self.worker_thread.start()
        self._update_buttons()

    def stop_scan(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.stop_button.setEnabled(False)
            self.status_title.setText("Stopping")

    def _release_worker(self) -> None:
        if self.worker:
            self.worker.deleteLater()
        if self.worker_thread:
            self.worker_thread.deleteLater()
        self.worker = None
        self.worker_thread = None

    def _on_progress(self, path: str, files_scanned: int) -> None:
        self.status_detail.setText(f"{files_scanned} files checked. Current: {Path(path).name}")

    def _on_failed(self, message: str) -> None:
        self.state = "idle"
        self.stop_button.setEnabled(True)
        self._set_status("alert", self.palette_tokens.danger, "Scan failed", message)
        self._update_buttons()

    def _on_completed(self, summary: ScanSummary) -> None:
        self.state = "done"
        self.summary = summary
        self.results = sorted(summary.flagged, key=lambda result: SEVERITY_RANK[result.top_severity], reverse=True)
        self.stop_button.setEnabled(True)
        self._populate_results()

        tokens = self.palette_tokens
        coverage = f"{summary.files_scanned} files in {summary.duration_seconds}s, {summary.files_skipped} skipped, {len(summary.errors)} unreadable."
        prefix = "Stopped early. " if summary.cancelled else ""
        if self.results:
            worst = self.results[0].top_severity
            self._set_status("alert", tokens.severity[worst], f"{len(self.results)} files flagged", prefix + coverage)
        else:
            self._set_status("shield-check", tokens.success, "No findings", prefix + coverage + " This does not prove the drive is clean.")
        self._update_buttons()

    def _populate_results(self) -> None:
        tokens = self.palette_tokens
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.results))
        for row, result in enumerate(self.results):
            severity_item = RankedItem(result.top_severity.upper())
            severity_item.setData(ROLE_RANK, SEVERITY_RANK[result.top_severity])
            severity_item.setData(ROLE_RESULT_INDEX, row)
            severity_item.setForeground(QColor(tokens.severity[result.top_severity]))
            font = severity_item.font()
            font.setBold(True)
            severity_item.setFont(font)

            size_item = RankedItem(human_size(result.size))
            size_item.setData(ROLE_RANK, result.size)
            finding_names = ", ".join(dict.fromkeys(finding.rule for finding in result.findings))

            self.table.setItem(row, 0, severity_item)
            self.table.setItem(row, 1, QTableWidgetItem(result.path))
            self.table.setItem(row, 2, QTableWidgetItem(finding_names))
            self.table.setItem(row, 3, size_item)
            self.table.setItem(row, 4, QTableWidgetItem("Quarantined" if result.quarantined_to else "Flagged"))
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.SortOrder.DescendingOrder)
        if self.results:
            self.table.selectRow(0)

    def _selected_results(self) -> list[tuple[int, FileResult]]:
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        selected = []
        for row in rows:
            result_index = self.table.item(row, 0).data(ROLE_RESULT_INDEX)
            selected.append((row, self.results[result_index]))
        return selected

    def _selected_unquarantined(self) -> list[tuple[int, FileResult]]:
        return [(row, result) for row, result in self._selected_results() if not result.quarantined_to]

    def _on_selection_changed(self) -> None:
        selected = self._selected_results()
        if not selected:
            self.detail_view.clear()
        else:
            self.detail_view.setPlainText(self._describe(selected[0][1]))
        self._update_buttons()

    @staticmethod
    def _describe(result: FileResult) -> str:
        lines = [result.path, f"sha256  {result.sha256}", f"size    {human_size(result.size)}"]
        if result.quarantined_to:
            lines.append(f"moved to  {result.quarantined_to}")
        lines.append("")
        lines += [f"[{f.severity}] {f.engine}/{f.rule}: {f.detail}" for f in result.findings]
        return "\n".join(lines)

    def quarantine_selected(self) -> None:
        targets = self._selected_unquarantined()
        if not targets:
            return
        answer = QMessageBox.question(
            self,
            "Quarantine files",
            f"Move {len(targets)} file(s) off the drive into the quarantine folder?\n\n"
            "A manifest records each original path so you can restore false positives.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        failures = []
        for row, result in targets:
            try:
                destination = quarantine_file(Path(result.path), result.sha256, self.quarantine_directory)
            except OSError as error:
                failures.append(f"{Path(result.path).name}: {error}")
                continue
            result.quarantined_to = str(destination)
            self.table.item(row, 4).setText("Quarantined")
        self._on_selection_changed()
        if failures:
            QMessageBox.warning(self, "Some files were not moved", "\n".join(failures))

    def open_quarantine_folder(self) -> None:
        self.quarantine_directory.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.quarantine_directory)))

    def export_report(self) -> None:
        if not self.summary:
            return
        destination, _ = QFileDialog.getSaveFileName(self, "Export report", "usbscan-report.json", "JSON (*.json)")
        if destination:
            write_json(self.summary, Path(destination))

    def open_settings(self) -> None:
        SettingsDialog(self.settings, self).exec()

    def closeEvent(self, event) -> None:
        if self.worker:
            self.worker.cancel()
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait(5000)
        super().closeEvent(event)
