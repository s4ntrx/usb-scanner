from __future__ import annotations

import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from usbscan.scanner import ScanConfig, scan

PROGRESS_INTERVAL_SECONDS = 0.1


class ScanWorker(QObject):
    progress = Signal(str, int)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, config: ScanConfig):
        super().__init__()
        self._config = config
        self._cancel_requested = threading.Event()
        self._files_seen = 0
        self._last_emit = 0.0

    def cancel(self) -> None:
        self._cancel_requested.set()

    def _report(self, path: Path) -> None:
        self._files_seen += 1
        now = time.monotonic()
        if now - self._last_emit >= PROGRESS_INTERVAL_SECONDS:
            self._last_emit = now
            self.progress.emit(str(path), self._files_seen)

    @Slot()
    def run(self) -> None:
        try:
            summary = scan(self._config, on_file=self._report, should_cancel=self._cancel_requested.is_set)
        except Exception as error:
            self.failed.emit(str(error))
            return
        self.completed.emit(summary)
