from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def load_hash_database(path: Path) -> dict[str, str]:
    database: dict[str, str] = {}
    if not path.is_file():
        return database
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, label = line.partition(" ")
        database[digest.lower()] = label.strip() or "known malicious hash"
    return database
