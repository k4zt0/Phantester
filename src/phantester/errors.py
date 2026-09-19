class PhantesterError(Exception):
    """Base error for explicit Phantester failures."""


class IntegrityError(PhantesterError):
    """Raised when authenticated data or a canary fails verification."""


class UnsafeStateError(PhantesterError):
    """Raised when an operation is denied because the system is unsafe."""

\n