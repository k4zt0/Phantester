from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .errors import IntegrityError, UnsafeStateError

CANARY_VERSION = 1
CANARY_NAMES = ("local.canary", "master.canary")
LOCK_NAME = "LOCKED"
INCIDENT_NAME = "integrity-incident.json"


def load_master_key() -> bytes:
    value = os.environ.get("PHANTESTER_MASTER_KEY")
    if value is None:
        raise UnsafeStateError("PHANTESTER_MASTER_KEY is not set")
    try:
        key = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise UnsafeStateError("PHANTESTER_MASTER_KEY must be valid base64") from exc
    if len(key) != 32:
        raise UnsafeStateError("PHANTESTER_MASTER_KEY must decode to exactly 32 bytes")
    return key


def _mac(key: bytes, name: str, payload: bytes) -> str:
    message = b"phantester-canary-v1\0" + name.encode() + b"\0" + payload
    return hmac.new(key, message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class CanaryStatus:
    healthy: bool
    failures: tuple[str, ...]


class CanaryGuard:
    def __init__(self, state_dir: Path, key: bytes) -> None:
        self.state_dir = state_dir.resolve()
        self.key = key

    def initialize(self) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in CANARY_NAMES:
            path = self.state_dir / name
            if path.exists():
                raise FileExistsError(f"refusing to overwrite existing canary: {path}")
            payload = secrets.token_bytes(64)
            document = {
                "version": CANARY_VERSION,
                "name": name,
                "payload": base64.b64encode(payload).decode("ascii"),
                "hmac_sha256": _mac(self.key, name, payload),
            }
            self._atomic_create(path, json.dumps(document, sort_keys=True).encode())

    def verify(self) -> CanaryStatus:
        failures: list[str] = []
        if (self.state_dir / LOCK_NAME).exists():
            failures.append("persistent integrity lock is active")
        elif (self.state_dir / INCIDENT_NAME).exists():
            failures.append("persistent integrity incident is active")
        for name in CANARY_NAMES:
            path = self.state_dir / name
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                payload = base64.b64decode(document["payload"], validate=True)
                expected = _mac(self.key, name, payload)
                valid = (
                    document["version"] == CANARY_VERSION
                    and document["name"] == name
                    and hmac.compare_digest(document["hmac_sha256"], expected)
                )
                if not valid:
                    failures.append(f"{name}: authentication failed")
            except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                failures.append(f"{name}: {type(exc).__name__}")
        if failures and not (self.state_dir / LOCK_NAME).exists():
            failures.extend(self._record_incident(failures))
        return CanaryStatus(not failures, tuple(failures))

    def require_healthy(self) -> None:
        status = self.verify()
        if not status.healthy:
            details = "; ".join(status.failures)
            raise IntegrityError(f"operation denied: canary integrity failure ({details})")

    @staticmethod
    def _atomic_create(path: Path, data: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _record_incident(self, failures: list[str]) -> list[str]:
        persistence_failures: list[str] = []
        incident = {
            "version": CANARY_VERSION,
            "detected_at": datetime.now(UTC).isoformat(),
            "failures": failures,
            "response": (
                "operations locked; preserve evidence, isolate the host, verify backups, "
                "investigate, and rotate the master key"
            ),
        }
        try:
            self._atomic_create(
                self.state_dir / INCIDENT_NAME,
                json.dumps(incident, sort_keys=True).encode(),
            )
        except FileExistsError:
            pass
        except OSError as exc:
            persistence_failures.append(f"incident record unavailable: {type(exc).__name__}")
        try:
            self._atomic_create(self.state_dir / LOCK_NAME, b"manual recovery required\n")
        except FileExistsError:
            pass
        except OSError as exc:
            persistence_failures.append(f"integrity lock unavailable: {type(exc).__name__}")
        return persistence_failures
