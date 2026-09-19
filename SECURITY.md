# Security policy

## Security boundary

The language model is untrusted. Only `ConstrainedAgent` may translate its
output into operations, and that agent exposes no shell, network, deletion, or
overwrite capability. Cryptography uses AES-256-GCM with a per-artifact HKDF
key, authenticated metadata, a random 96-bit nonce, and atomic writes.

The master key must be supplied by a secret manager through
`PHANTESTER_MASTER_KEY`; never commit it or place it beside protected files.
Production deployments should use a KMS or HSM and short-lived process access.

## Canary failure response

An unreadable or unauthenticated canary creates `LOCKED` and
`integrity-incident.json` in the canary state directory. All subsequent
cryptographic operations stop. Preserve
originals and artifacts, isolate the host, investigate the event, restore from
an independently verified backup, rotate the master key, and initialize a new
vault. Never delete the lock to bypass investigation.

## TLS

Phantester delegates TLS to Python/OpenSSL, requires TLS 1.3, normal hostname
and certificate verification, and a healthy canary guard when creating a
context. Optional mTLS is supported. Certificate pinning should be used only
with a tested rotation and recovery policy. A master canary gates TLS
configuration but cannot replace TLS or continuously attest an established
connection.

## Reporting

Do not open public issues containing vulnerabilities, keys, protected files, or
personal data. Use GitHub private vulnerability reporting when enabled.
