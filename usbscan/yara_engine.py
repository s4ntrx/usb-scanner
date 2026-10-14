from __future__ import annotations

from pathlib import Path

from usbscan.models import Finding

try:
    import yara
except ImportError:
    yara = None

YARA_TIMEOUT_SECONDS = 30


class YaraEngine:
    def __init__(self, rules_directory: Path):
        rule_files = {path.stem: str(path) for path in sorted(rules_directory.glob("*.yar*"))}
        if not rule_files:
            raise FileNotFoundError(f"no .yar files in {rules_directory}")
        self._rules = yara.compile(filepaths=rule_files)

    @staticmethod
    def is_available() -> bool:
        return yara is not None

    def scan(self, path: Path) -> list[Finding]:
        matches = self._rules.match(filepath=str(path), timeout=YARA_TIMEOUT_SECONDS)
        return [
            Finding(
                "yara",
                match.rule,
                match.meta.get("severity", "high"),
                match.meta.get("description", "YARA rule matched"),
            )
            for match in matches
        ]
