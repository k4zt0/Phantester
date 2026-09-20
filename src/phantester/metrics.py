from __future__ import annotations

import math
from typing import Any


def is_valid_assessment(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"action", "reason", "risk"}
        and all(isinstance(item, str) for item in value.values())
    )


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    probability = successes / total
    denominator = 1 + z**2 / total
    center = (probability + z**2 / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            probability * (1 - probability) / total + z**2 / (4 * total**2)
        )
        / denominator
    )
    return center - margin, center + margin
