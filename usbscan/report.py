from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from usbscan.models import SEVERITY_RANK, ScanSummary


def write_json(summary: ScanSummary, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")


def print_summary(summary: ScanSummary) -> None:
    print(f"\nScanned {summary.files_scanned} files in {summary.duration_seconds}s "
          f"({summary.files_skipped} skipped, {len(summary.errors)} errors)")
    if not summary.flagged:
        print("No findings. This does not prove the drive is clean.")
        return
    ordered = sorted(summary.flagged, key=lambda result: SEVERITY_RANK[result.top_severity], reverse=True)
    for result in ordered:
        print(f"\n[{result.top_severity.upper()}] {result.path}")
        print(f"  sha256: {result.sha256}")
        for finding in result.findings:
            print(f"  - {finding.engine}/{finding.rule} ({finding.severity}): {finding.detail}")
        if result.quarantined_to:
            print(f"  quarantined to: {result.quarantined_to}")
