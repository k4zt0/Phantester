import os
import ssl
from pathlib import Path

import pytest

from phantester.canary import CanaryGuard
from phantester.crypto import protect_file, restore_file
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


def test_broken_canary_denies_operations(tmp_path: Path, guard: CanaryGuard) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"important")
    (guard.state_dir / "master.canary").write_text("tampered", encoding="utf-8")
    with pytest.raises(IntegrityError, match="canary integrity failure"):
        protect_file(source, tmp_path / "output.enc", guard)
    assert not (tmp_path / "output.enc").exists()


def test_policy_cannot_override_failed_canary() -> None:
    assessment = Assessment(risk=Risk.LOW, action=Action.ALLOW_READ_ONLY, reason="model")
    assert enforce_policy(assessment, canaries_healthy=False) is Action.DENY_AND_ISOLATE


def test_tls_context_requires_verification() -> None:
    context = create_verified_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_tls_client_certificate_pair_is_required(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="supplied together"):
        create_verified_context(client_cert=tmp_path / "client.pem")

\n