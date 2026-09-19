from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

MAGIC_BYTES: dict[str, tuple[bytes, ...]] = {
    ".pdf": (b"%PDF-",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ".docx": (b"PK\x03\x04",),
    ".xlsx": (b"PK\x03\x04",),
    ".gz": (b"\x1f\x8b",),
    ".exe": (b"MZ",),
    ".elf": (b"\x7fELF",),
}


@dataclass(frozen=True)
class FileSignature:
    path: str
    size: int
    sha256: str
    extension: str
    magic_matches_extension: bool | None


def inspect_file(path: Path) -> FileSignature:
    if not path.is_file():
        raise FileNotFoundError(path)

    digest = hashlib.sha256()
    prefix = b""
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            if not prefix:
                prefix = chunk[:16]
            digest.update(chunk)
            size += len(chunk)

    extension = path.suffix.lower()
    expected = MAGIC_BYTES.get(extension)
    magic_matches = None if expected is None else any(prefix.startswith(item) for item in expected)
    return FileSignature(
        path=str(path),
        size=size,
        sha256=digest.hexdigest(),
        extension=extension,
        magic_matches_extension=magic_matches,
    )

\n