import json
import os
import ssl
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from phantester.canary import CanaryGuard
from phantester.crypto import (
    MAGIC_V1,
    NONCE_SIZE,
    SALT_SIZE,
    _derive_key,
    protect_file,
    restore_file,
)
from phantester.errors import IntegrityError
from phantester.policy import Action, Assessment, Risk, enforce_policy
from phantester.signatures import inspect_file
from phantester.tls import create_verified_context


@pytest.fixture
def guard(tmp_path: Path) -> CanaryGuard:
    instance = CanaryGuard(tmp_path / "state", os.urandom(32))
    instance.initialize()
    return instance


def test_authenticated_round_trip(tmp_path: Path, guard: CanaryGuard) -> None:
    source = tmp_path / "document.pdf"
    protected = tmp_path / "document.pdf.enc"
    restored = tmp_path / "restored.pdf"
    source.write_bytes(b"%PDF-1.7\n" + os.urandom(100_000))
    protect_file(source, protected, guard)
    restore_file(protected, restored, guard)
    assert restored.read_bytes() == source.read_bytes()
    assert inspect_file(restored).magic_matches_extension is True


def test_modified_ciphertext_is_rejected(tmp_path: Path, guard: CanaryGuard) -> None:
    source, protected = tmp_path / "input.bin", tmp_path / "input.enc"
    source.write_bytes(os.urandom(2048))
    protect_file(source, protected, guard)
    content = bytearray(protected.read_bytes())
    content[-20] ^= 1
    protected.write_bytes(content)
    with pytest.raises(IntegrityError, match="authentication failed"):
        restore_file(protected, tmp_path / "output.bin", guard)
    assert not (tmp_path / "output.bin").exists()


def test_legacy_v1_artifact_can_be_restored(tmp_path: Path, guard: CanaryGuard) -> None:
    plaintext = b"%PDF-1.7\nlegacy"
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    metadata = json.dumps(
        {"name": "legacy.pdf", "size": len(plaintext)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    prefix = MAGIC_V1 + salt + nonce + struct.pack(">I", len(metadata)) + metadata
    encryptor = Cipher(
        algorithms.AES(_derive_key(guard.key, salt)), modes.GCM(nonce)
    ).encryptor()
    encryptor.authenticate_additional_data(prefix)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    protected = tmp_path / "legacy.enc"
    protected.write_bytes(prefix + ciphertext + encryptor.tag)

    restored = tmp_path / "legacy.pdf"
    restore_file(protected, restored, guard)
    assert restored.read_bytes() == plaintext


def test_broken_canary_denies_operations(tmp_path: Path, guard: CanaryGuard) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"important")
    (guard.state_dir / "master.canary").write_text("tampered", encoding="utf-8")
    with pytest.raises(IntegrityError, match="canary integrity failure"):
        protect_file(source, tmp_path / "output.enc", guard)
    assert not (tmp_path / "output.enc").exists()
    assert (guard.state_dir / "LOCKED").exists()
    assert (guard.state_dir / "integrity-incident.json").exists()


def test_repaired_canary_does_not_bypass_persistent_lock(
    tmp_path: Path, guard: CanaryGuard
) -> None:
    original = (guard.state_dir / "master.canary").read_bytes()
    (guard.state_dir / "master.canary").write_text("tampered", encoding="utf-8")
    assert guard.verify().healthy is False
    (guard.state_dir / "master.canary").write_bytes(original)
    status = guard.verify()
    assert status.healthy is False
    assert "persistent integrity lock is active" in status.failures


def test_unwritable_incident_state_still_returns_unhealthy_status(tmp_path: Path) -> None:
    guard = CanaryGuard(tmp_path / "missing" / "state", os.urandom(32))
    status = guard.verify()
    assert status.healthy is False
    assert any("incident record unavailable" in failure for failure in status.failures)
    with pytest.raises(IntegrityError, match="canary integrity failure"):
        guard.require_healthy()


def test_policy_cannot_override_failed_canary() -> None:
    assessment = Assessment(risk=Risk.LOW, action=Action.ALLOW_READ_ONLY, reason="model")
    assert enforce_policy(assessment, canaries_healthy=False) is Action.DENY_AND_ISOLATE


def test_tls_context_requires_verification(guard: CanaryGuard) -> None:
    context = create_verified_context(guard=guard)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3


def test_tls_client_certificate_pair_is_required(
    tmp_path: Path, guard: CanaryGuard
) -> None:
    with pytest.raises(ValueError, match="supplied together"):
        create_verified_context(guard=guard, client_cert=tmp_path / "client.pem")


def test_tls_context_is_denied_after_canary_failure(guard: CanaryGuard) -> None:
    (guard.state_dir / "master.canary").write_text("tampered", encoding="utf-8")
    with pytest.raises(IntegrityError, match="canary integrity failure"):
        create_verified_context(guard=guard)
