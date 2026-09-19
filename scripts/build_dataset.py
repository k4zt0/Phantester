from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

FORMATS = [
    (".pdf", "255044462d"),
    (".png", "89504e470d0a1a0a"),
    (".jpg", "ffd8ff"),
    (".zip", "504b0304"),
    (".docx", "504b0304"),
    (".xlsx", "504b0304"),
    (".exe", "4d5a"),
    (".elf", "7f454c46"),
]


def make_example(index: int, rng: random.Random) -> dict[str, str]:
    extension, correct_magic = rng.choice(FORMATS)
    canary = rng.choices(["healthy", "failed", "missing"], weights=[94, 4, 2])[0]
    mismatch = rng.random() < 0.18
    other_magics = [magic for _, magic in FORMATS if magic != correct_magic]
    magic = rng.choice(other_magics) if mismatch else correct_magic
    burst = rng.choice([0, 1, 2, 10, 100, 250])
    delta = rng.choice([0, 0, 0, 128, 8192, -4096])

    if canary != "healthy":
        risk, action, reason = "critical", "deny_and_isolate", "canary_failure"
    elif burst >= 100:
        risk, action, reason = "high", "deny_and_isolate", "write_burst"
    elif magic != correct_magic:
        risk, action, reason = "medium", "quarantine_for_review", "signature_mismatch"
    else:
        risk, action, reason = "low", "allow_read_only", "signature_matches"

    prompt = (
        f"extension={extension} magic={magic} size_delta={delta} "
        f"canary={canary} burst_writes={burst}"
    )
    response = json.dumps(
        {"action": action, "reason": reason, "risk": risk},
        separators=(",", ":"),
        sort_keys=True,
    )
    template = hashlib.sha256(f"{extension}:{canary}:{mismatch}:{burst >= 100}".encode()).hexdigest()
    return {
        "id": f"synthetic-{index:08d}",
        "template": template,
        "prompt": prompt,
        "response": response,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()
    if args.rows < 100:
        parser.error("--rows must be at least 100")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    with args.output.open("w", encoding="utf-8") as target:
        for index in range(args.rows):
            target.write(json.dumps(make_example(index, rng), ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()

\n