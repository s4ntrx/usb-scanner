from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QVBoxLayout

from usbscan.gui.theme import MARGIN, SPACING


class SettingsDialog(QDialog):
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self._settings = settings
        self.setWindowTitle("Settings")
        self.setMinimumWidth(420)

        self.notify_checkbox = QCheckBox("Show a notification when a drive is inserted")
        self.notify_checkbox.setChecked(settings.value("notify_on_insert", True, type=bool))

        self.virustotal_checkbox = QCheckBox("Look up executable hashes on VirusTotal")
        self.virustotal_checkbox.setChecked(settings.value("virustotal_enabled", False, type=bool))

        self.api_key_input = QLineEdit(settings.value("virustotal_key", "", type=str))
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setPlaceholderText("VirusTotal API key")

        key_note = QLabel(
            "Only SHA-256 hashes are sent, never file contents. The free tier allows four lookups "
            "per minute, so drives with many executables scan slowly. The key is stored unencrypted "
            "in the Windows registry for the current user."
        )
        key_note.setObjectName("muted")
        key_note.setWordWrap(True)

        form = QFormLayout()
        form.setSpacing(SPACING)
        form.addRow(self.notify_checkbox)
        form.addRow(self.virustotal_checkbox)
        form.addRow("API key", self.api_key_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(MARGIN, MARGIN, MARGIN, MARGIN)
        layout.setSpacing(MARGIN)
        layout.addLayout(form)
        layout.addWidget(key_note)
        layout.addWidget(buttons)

    def _save(self) -> None:
        self._settings.setValue("notify_on_insert", self.notify_checkbox.isChecked())
        self._settings.setValue("virustotal_enabled", self.virustotal_checkbox.isChecked())
        self._settings.setValue("virustotal_key", self.api_key_input.text().strip())
        self.accept()
