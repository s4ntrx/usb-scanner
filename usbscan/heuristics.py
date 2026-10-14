from __future__ import annotations

import math
import re
import stat
from collections import Counter
from pathlib import Path

from usbscan.models import Finding

HEADER_BYTES = 64 * 1024
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_ENTROPY_BYTES = 4 * 1024 * 1024
PACKED_ENTROPY_THRESHOLD = 7.4

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".sh", ".appimage",
}
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".sh"}
DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".zip", ".mp3", ".mp4",
}
EXECUTABLE_MAGIC = {
    b"MZ": "Windows PE",
    b"\x7fELF": "ELF",
    b"\xcf\xfa\xed\xfe": "Mach-O",
}
LNK_LAUNCHERS = ("cmd.exe", "powershell", "mshta", "wscript", "cscript", "rundll32", "regsvr32")

DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|mp[34])\s*\.(exe|scr|com|bat|cmd|js|vbs|ps1|lnk|hta)$",
    re.IGNORECASE,
)

SCRIPT_PATTERNS = {
    "encoded_powershell": re.compile(rb"powershell[^\r\n]{0,80}-(enc|encodedcommand)\b", re.I),
    "base64_decode_exec": re.compile(rb"frombase64string", re.I),
    "invoke_expression": re.compile(rb"\b(iex|invoke-expression)\b", re.I),
    "download_cradle": re.compile(rb"(downloadstring|downloadfile|invoke-webrequest|net\.webclient)", re.I),
    "certutil_download": re.compile(rb"certutil[^\r\n]{0,60}-urlcache", re.I),
    "bitsadmin_transfer": re.compile(rb"bitsadmin[^\r\n]{0,60}/transfer", re.I),
    "mshta_remote": re.compile(rb"mshta[^\r\n]{0,40}https?://", re.I),
    "wscript_shell": re.compile(rb"wscript\.shell", re.I),
    "curl_pipe_shell": re.compile(rb"(curl|wget)[^\r\n|]{0,120}\|\s*(ba|z)?sh\b", re.I),
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in Counter(data).values())


def _check_autorun(path: Path, root: Path) -> list[Finding]:
    is_root_autorun = path.name.lower() == "autorun.inf" and path.parent == root
    if not is_root_autorun:
        return []
    return [Finding("heuristic", "autorun_inf", "high", "autorun.inf at drive root can launch code on older systems")]


def _check_double_extension(path: Path) -> list[Finding]:
    if DOUBLE_EXTENSION.search(path.name):
        return [Finding("heuristic", "double_extension", "high", f"{path.name} imitates a document or media file")]
    return []


def _check_disguised_executable(path: Path, header: bytes) -> list[Finding]:
    if path.suffix.lower() not in DECOY_EXTENSIONS:
        return []
    for magic, kind in EXECUTABLE_MAGIC.items():
        if header.startswith(magic):
            return [Finding("heuristic", "disguised_executable", "high", f"{kind} binary named {path.suffix}")]
    return []


def _check_hidden_executable(path: Path, root: Path) -> list[Finding]:
    if path.parent != root or path.suffix.lower() not in EXECUTABLE_EXTENSIONS:
        return []
    attributes = getattr(path.stat(), "st_file_attributes", 0)
    if attributes & stat.FILE_ATTRIBUTE_HIDDEN:
        return [Finding("heuristic", "hidden_root_executable", "medium", "hidden executable at drive root")]
    return []


def _check_shortcut(path: Path, header: bytes) -> list[Finding]:
    if path.suffix.lower() != ".lnk":
        return []
    haystack = header.lower() + header.decode("utf-16le", errors="ignore").lower().encode()
    launchers = [name for name in LNK_LAUNCHERS if name.encode() in haystack]
    if not launchers:
        return []
    return [Finding("heuristic", "shortcut_launches_interpreter", "high", f"shortcut targets {', '.join(launchers)}")]


def _check_script_content(path: Path, size: int) -> list[Finding]:
    if path.suffix.lower() not in SCRIPT_EXTENSIONS or size > MAX_SCRIPT_BYTES:
        return []
    content = path.read_bytes()
    hits = [name for name, pattern in SCRIPT_PATTERNS.items() if pattern.search(content)]
    if not hits:
        return []
    severity = "high" if len(hits) >= 2 else "medium"
    return [Finding("heuristic", "suspicious_script", severity, f"matched: {', '.join(hits)}")]


def _check_packed_binary(path: Path, header: bytes, size: int) -> list[Finding]:
    is_binary = any(header.startswith(magic) for magic in EXECUTABLE_MAGIC)
    if not is_binary or size > MAX_ENTROPY_BYTES * 8:
        return []
    with path.open("rb") as handle:
        sample = handle.read(MAX_ENTROPY_BYTES)
    entropy = shannon_entropy(sample)
    if entropy >= PACKED_ENTROPY_THRESHOLD:
        return [Finding("heuristic", "high_entropy_binary", "low", f"entropy {entropy:.2f}/8, possibly packed or encrypted")]
    return []


def analyze_file(path: Path, root: Path, size: int) -> list[Finding]:
    with path.open("rb") as handle:
        header = handle.read(HEADER_BYTES)
    findings: list[Finding] = []
    findings += _check_autorun(path, root)
    findings += _check_double_extension(path)
    findings += _check_disguised_executable(path, header)
    findings += _check_hidden_executable(path, root)
    findings += _check_shortcut(path, header)
    findings += _check_script_content(path, size)
    findings += _check_packed_binary(path, header, size)
    return findings
