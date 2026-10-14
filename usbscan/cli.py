from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from usbscan import __version__
from usbscan.drives import list_removable_mount_points
from usbscan.hashing import load_hash_database
from usbscan.models import SEVERITY_RANK
from usbscan.report import print_summary, write_json
from usbscan.scanner import ScanConfig, scan
from usbscan.virustotal import VirusTotalClient
from usbscan.yara_engine import YaraEngine

DATA_DIRECTORY = Path(__file__).parent / "data"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="usbscan", description="Layered malware scanner for removable drives.")
    parser.add_argument("paths", nargs="*", type=Path, help="mount points or folders; defaults to detected removable drives")
    parser.add_argument("--rules", type=Path, default=DATA_DIRECTORY, help="directory containing .yar files")
    parser.add_argument("--hashes", type=Path, default=DATA_DIRECTORY / "known_bad_hashes.txt")
    parser.add_argument("--virustotal", action="store_true", help="look up executable hashes on VirusTotal (needs VT_API_KEY)")
    parser.add_argument("--quarantine", type=Path, help="move high-severity files into this folder")
    parser.add_argument("--quarantine-min", choices=list(SEVERITY_RANK), default="high")
    parser.add_argument("--max-size-mb", type=int, default=256)
    parser.add_argument("--json", type=Path, dest="json_path", help="write a JSON report to this path")
    parser.add_argument("--version", action="version", version=f"usbscan {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    roots = [path.resolve() for path in args.paths] or [Path(mount) for mount in list_removable_mount_points()]
    if not roots:
        print("No removable drives detected. Pass a path explicitly.", file=sys.stderr)
        return 2

    yara_engine = None
    if YaraEngine.is_available():
        yara_engine = YaraEngine(args.rules)
    else:
        print("yara-python not installed; skipping YARA engine (pip install 'usbscan[yara]').", file=sys.stderr)

    virustotal = None
    if args.virustotal:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            print("--virustotal requires the VT_API_KEY environment variable.", file=sys.stderr)
            return 2
        virustotal = VirusTotalClient(api_key)

    config = ScanConfig(
        roots=roots,
        hash_database=load_hash_database(args.hashes),
        yara_engine=yara_engine,
        virustotal=virustotal,
        max_file_size=args.max_size_mb * 1024 * 1024,
        quarantine_directory=args.quarantine,
        quarantine_min_severity=args.quarantine_min,
    )

    print(f"Scanning: {', '.join(str(root) for root in roots)}")
    summary = scan(config)
    print_summary(summary)
    if args.json_path:
        write_json(summary, args.json_path)

    has_serious_finding = any(SEVERITY_RANK[result.top_severity] >= SEVERITY_RANK["high"] for result in summary.flagged)
    return 1 if has_serious_finding else 0
