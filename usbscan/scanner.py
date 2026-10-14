from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from usbscan.hashing import sha256_of_file
from usbscan.heuristics import EXECUTABLE_EXTENSIONS, analyze_file
from usbscan.models import SEVERITY_RANK, FileResult, Finding, ScanSummary
from usbscan.virustotal import VirusTotalClient
from usbscan.yara_engine import YaraEngine


@dataclass
class ScanConfig:
    roots: list[Path]
    hash_database: dict[str, str]
    yara_engine: YaraEngine | None = None
    virustotal: VirusTotalClient | None = None
    max_file_size: int = 256 * 1024 * 1024
    quarantine_directory: Path | None = None
    quarantine_min_severity: str = "high"


def _quarantine(result: FileResult, directory: Path) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{result.sha256[:12]}_{Path(result.path).name}.quarantined"
    shutil.move(result.path, destination)
    return str(destination)


def _scan_file(path: Path, root: Path, config: ScanConfig) -> FileResult:
    size = path.stat().st_size
    sha256 = sha256_of_file(path)
    findings: list[Finding] = []
    if sha256 in config.hash_database:
        findings.append(Finding("hash", "known_bad_hash", "critical", config.hash_database[sha256]))
    findings += analyze_file(path, root, size)
    if config.yara_engine:
        findings += config.yara_engine.scan(path)
    if config.virustotal and path.suffix.lower() in EXECUTABLE_EXTENSIONS:
        findings += config.virustotal.lookup(sha256)
    return FileResult(str(path), sha256, size, findings)


def scan(config: ScanConfig, on_file: Callable[[Path], None] | None = None) -> ScanSummary:
    started = time.monotonic()
    summary = ScanSummary(roots=[str(root) for root in config.roots])
    quarantine_threshold = SEVERITY_RANK[config.quarantine_min_severity]

    for root in config.roots:
        for directory, _, filenames in os.walk(root, followlinks=False):
            for filename in filenames:
                path = Path(directory) / filename
                if path.is_symlink():
                    summary.files_skipped += 1
                    continue
                try:
                    if path.stat().st_size > config.max_file_size:
                        summary.files_skipped += 1
                        continue
                    if on_file:
                        on_file(path)
                    result = _scan_file(path, root, config)
                    summary.files_scanned += 1
                    if not result.findings:
                        continue
                    if config.quarantine_directory and SEVERITY_RANK[result.top_severity] >= quarantine_threshold:
                        result.quarantined_to = _quarantine(result, config.quarantine_directory)
                    summary.flagged.append(result)
                except (OSError, RuntimeError) as error:
                    summary.errors.append(f"{path}: {error}")

    summary.duration_seconds = round(time.monotonic() - started, 2)
    return summary
