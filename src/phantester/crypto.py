from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canary import CanaryGuard
from .errors import IntegrityError

MAGIC = b"PHANTESTER\x01"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
LENGTH_SIZE = 4


def _derive_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"phantester-file-encryption-v1",
    ).derive(master_key)


def _temporary_target(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    return tempfile.NamedTemporaryFile(mode="w+b", dir=path.parent, delete=False)


def _commit_without_overwrite(temporary_path: Path, target: Path) -> None:
    os.link(temporary_path, target)
    temporary_path.unlink()


def protect_file(source: Path, target: Path, guard: CanaryGuard) -> None:
    guard.require_healthy()
    if not source.is_file():
        raise FileNotFoundError(source)
    if target.exists():
        raise FileExistsError(f"refusing to overwrite: {target}")

    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    metadata = json.dumps(
        {"name": source.name, "size": source.stat().st_size},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    prefix = MAGIC + salt + nonce + struct.pack(">I", len(metadata)) + metadata
    encryptor = Cipher(algorithms.AES(_derive_key(guard.key, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    temporary = _temporary_target(target)
    temporary_path = Path(temporary.name)
    try:
        with temporary, source.open("rb") as plain:
            temporary.write(prefix)
            while chunk := plain.read(1024 * 1024):
                temporary.write(encryptor.update(chunk))
            temporary.write(encryptor.finalize())
            temporary.write(encryptor.tag)
            temporary.flush()
            os.fsync(temporary.fileno())
        guard.require_healthy()
        _commit_without_overwrite(temporary_path, target)
    except Exception:
        temporary.close()
        temporary_path.unlink(missing_ok=True)
        raise


def restore_file(source: Path, target: Path, guard: CanaryGuard) -> None:
    guard.require_healthy()
    if target.exists():
        raise FileExistsError(f"refusing to overwrite: {target}")
    minimum = len(MAGIC) + SALT_SIZE + NONCE_SIZE + LENGTH_SIZE + TAG_SIZE
    if not source.is_file() or source.stat().st_size < minimum:
        raise IntegrityError("invalid or truncated protected file")

    temporary = _temporary_target(target)
    temporary_path = Path(temporary.name)
    try:
        with source.open("rb") as encrypted, temporary:
            magic = encrypted.read(len(MAGIC))
            if magic != MAGIC:
                raise IntegrityError("invalid protected-file signature")
            salt = encrypted.read(SALT_SIZE)
            nonce = encrypted.read(NONCE_SIZE)
            length_raw = encrypted.read(LENGTH_SIZE)
            metadata_length = struct.unpack(">I", length_raw)[0]
            if metadata_length > 64 * 1024:
                raise IntegrityError("protected-file metadata is too large")
            metadata = encrypted.read(metadata_length)
            if len(metadata) != metadata_length:
                raise IntegrityError("truncated protected-file metadata")
            prefix = magic + salt + nonce + length_raw + metadata
            ciphertext_size = source.stat().st_size - len(prefix) - TAG_SIZE
            encrypted.seek(-TAG_SIZE, os.SEEK_END)
            tag = encrypted.read(TAG_SIZE)
            encrypted.seek(len(prefix))
            decryptor = Cipher(
                algorithms.AES(_derive_key(guard.key, salt)), modes.GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(prefix)
            remaining = ciphertext_size
            while remaining:
                chunk = encrypted.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise IntegrityError("truncated ciphertext")
                temporary.write(decryptor.update(chunk))
                remaining -= len(chunk)
            try:
                temporary.write(decryptor.finalize())
            except InvalidTag as exc:
                raise IntegrityError("protected-file authentication failed") from exc
            temporary.flush()
            os.fsync(temporary.fileno())
        guard.require_healthy()
        _commit_without_overwrite(temporary_path, target)
    except Exception:
        temporary.close()
        temporary_path.unlink(missing_ok=True)
        raise
