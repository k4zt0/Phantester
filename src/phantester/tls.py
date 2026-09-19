from __future__ import annotations

import ssl
from pathlib import Path

from .canary import CanaryGuard


def create_verified_context(
    *,
    guard: CanaryGuard,
    ca_file: Path | None = None,
    client_cert: Path | None = None,
    client_key: Path | None = None,
) -> ssl.SSLContext:
    guard.require_healthy()
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(ca_file) if ca_file else None,
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    if (client_cert is None) != (client_key is None):
        raise ValueError("client_cert and client_key must be supplied together")
    if client_cert and client_key:
        context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return context
