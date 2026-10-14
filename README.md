# usbscan

Layered malware scanner for removable drives. Read-only by default, cross-platform (Windows, Linux, macOS), Python 3.9+.

## What it checks

| Layer | Catches | Needs |
| --- | --- | --- |
| Hash blocklist | Known samples | `data/known_bad_hashes.txt` |
| USB heuristics | Root `autorun.inf`, double extensions (`invoice.pdf.exe`), executables renamed to `.jpg`/`.pdf`, hidden root executables, shortcuts that launch `cmd`/`powershell`/`mshta`, script droppers, packed binaries | nothing |
| YARA | Anything you write a rule for | `yara-python` |
| VirusTotal (opt-in) | Reputation of executable hashes across ~70 engines | `VT_API_KEY` |

## Install

```bash
git clone https://github.com/s4ntrx/usb-scanner.git
cd usb-scanner
pip install -e ".[yara]"
```

## Use

```bash
usbscan                               # scan every detected removable drive
usbscan /media/me/STICK --json reports/stick.json
usbscan E:\ --quarantine quarantine   # move high-severity files off the drive
VT_API_KEY=... usbscan /mnt/usb --virustotal
```

Exit codes: `0` nothing serious, `1` high or critical finding, `2` usage error.

VirusTotal mode sends only SHA-256 hashes, never file contents. The free tier allows four lookups per minute, and the client throttles itself to match.

## Extend coverage

- Drop more `.yar` files into `usbscan/data/` or pass `--rules DIR`.
- Append hashes from a feed such as MalwareBazaar to `known_bad_hashes.txt`.

## Limits

- No behavioral analysis or sandboxing: new or custom malware with no matching hash or rule will pass.
- No deep archive or document-macro inspection yet.
- Firmware-level attacks (BadUSB) live in the drive's controller and are invisible to any file scanner.
- "No findings" is not a clean bill of health. Treat unknown drives as untrusted and mount them read-only when you can.

## Test

```bash
pip install -e ".[dev,yara]" && pytest
```

The tests use the harmless EICAR antivirus test string, assembled at runtime.
