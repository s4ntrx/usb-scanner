from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    engine: str
    rule: str
    severity: str
    detail: str


@dataclass
class FileResult:
    path: str
    sha256: str
    size: int
    findings: list[Finding] = field(default_factory=list)
    quarantined_to: str | None = None

    @property
    def top_severity(self) -> str:
        return max((f.severity for f in self.findings), key=SEVERITY_RANK.get, default="info")


@dataclass
class ScanSummary:
    roots: list[str]
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0
    cancelled: bool = False
    flagged: list[FileResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
