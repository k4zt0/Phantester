from __future__ import annotations

import hashlib
import json
import os
import string
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canary import CanaryGuard
from .errors import IntegrityError
from .signatures import MAGIC_BYTES, inspect_file

MAGIC_V1 = b"PHANTESTER\x01"
MAGIC = b"PHANTESTER\x02"
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

    signature = inspect_file(source)
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    metadata = json.dumps(
        {
            "name": source.name,
            "size": signature.size,
            "sha256": signature.sha256,
            "extension": signature.extension,
            "magic_matches_extension": signature.magic_matches_extension,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    prefix = MAGIC + salt + nonce + struct.pack(">I", len(metadata)) + metadata
    encryptor = Cipher(algorithms.AES(_derive_key(guard.key, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    temporary = _temporary_target(target)
    temporary_path = Path(temporary.name)
    digest = hashlib.sha256()
    encrypted_size = 0
    try:
        with temporary, source.open("rb") as plain:
            temporary.write(prefix)
            while chunk := plain.read(1024 * 1024):
                digest.update(chunk)
                encrypted_size += len(chunk)
                temporary.write(encryptor.update(chunk))
            temporary.write(encryptor.finalize())
            temporary.write(encryptor.tag)
            temporary.flush()
            os.fsync(temporary.fileno())
        if encrypted_size != signature.size or digest.hexdigest() != signature.sha256:
            raise IntegrityError("source changed while it was being protected")
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
            if magic not in {MAGIC_V1, MAGIC}:
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
            try:
                expected = json.loads(metadata)
                expected_name = expected["name"]
                expected_size = expected["size"]
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise IntegrityError("invalid protected-file metadata") from exc
            if not isinstance(expected_size, int) or expected_size < 0 or not isinstance(
                expected_name, str
            ):
                raise IntegrityError("invalid protected-file metadata values")
            if magic == MAGIC:
                try:
                    expected_sha256 = expected["sha256"]
                    expected_extension = expected["extension"]
                    expected_magic = expected["magic_matches_extension"]
                except KeyError as exc:
                    raise IntegrityError("invalid protected-file metadata") from exc
                if (
                    not isinstance(expected_sha256, str)
                    or len(expected_sha256) != 64
                    or any(character not in string.hexdigits for character in expected_sha256)
                    or not isinstance(expected_extension, str)
                    or Path(expected_name).suffix.lower() != expected_extension
                    or (expected_magic is not None and not isinstance(expected_magic, bool))
                ):
                    raise IntegrityError("invalid protected-file metadata values")
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
            digest = hashlib.sha256()
            restored_size = 0
            while remaining:
                chunk = encrypted.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise IntegrityError("truncated ciphertext")
                plaintext = decryptor.update(chunk)
                digest.update(plaintext)
                restored_size += len(plaintext)
                temporary.write(plaintext)
                remaining -= len(chunk)
            try:
                final = decryptor.finalize()
            except InvalidTag as exc:
                raise IntegrityError("protected-file authentication failed") from exc
            digest.update(final)
            restored_size += len(final)
            temporary.write(final)
            temporary.flush()
            os.fsync(temporary.fileno())
        if restored_size != expected_size:
            raise IntegrityError("restored file size does not match metadata")
        if magic == MAGIC:
            with temporary_path.open("rb") as restored:
                prefix_bytes = restored.read(16)
            expected_magics = MAGIC_BYTES.get(expected_extension)
            restored_magic = (
                None
                if expected_magics is None
                else any(prefix_bytes.startswith(item) for item in expected_magics)
            )
            if digest.hexdigest() != expected_sha256 or restored_magic != expected_magic:
                raise IntegrityError("restored file signature or digest does not match metadata")
        guard.require_healthy()
        _commit_without_overwrite(temporary_path, target)
    except Exception:
        temporary.close()
        temporary_path.unlink(missing_ok=True)
        raise
