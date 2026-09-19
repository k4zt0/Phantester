from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def read_rows(path: Path) -> list[dict[str, str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_generated_splits_have_no_prompt_leakage_and_cover_every_action(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    source = tmp_path / "all.jsonl"
    output = tmp_path / "splits"
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "build_dataset.py"),
            "--output",
            str(source),
            "--rows",
            "5000",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "split_dataset.py"),
            "--input",
            str(source),
            "--output-dir",
            str(output),
        ],
        check=True,
    )

    splits = {
        name: read_rows(output / f"{name}.jsonl")
        for name in ("train", "validation", "test")
    }
    prompt_sets = {
        name: {row["prompt"] for row in rows} for name, rows in splits.items()
    }
    assert prompt_sets["train"].isdisjoint(prompt_sets["validation"])
    assert prompt_sets["train"].isdisjoint(prompt_sets["test"])
    assert prompt_sets["validation"].isdisjoint(prompt_sets["test"])
    expected_actions = {
        "allow_read_only",
        "quarantine_for_review",
        "deny_and_isolate",
    }
    for rows in splits.values():
        actions = {json.loads(row["response"])["action"] for row in rows}
        assert actions == expected_actions

