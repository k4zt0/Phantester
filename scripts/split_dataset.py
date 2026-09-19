from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for line in args.input.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        groups[row.pop("template")].append(row)

    targets = {"train": 0.8, "validation": 0.1, "test": 0.1}
    assigned = {name: 0 for name in targets}
    assignments: dict[str, str] = {}
    total_rows = sum(len(rows) for rows in groups.values())
    for template, rows in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        split = min(
            targets,
            key=lambda name: assigned[name] / (total_rows * targets[name]),
        )
        assignments[template] = split
        assigned[split] += len(rows)
    handles = {
        name: (args.output_dir / f"{name}.jsonl").open("w", encoding="utf-8")
        for name in ("train", "validation", "test")
    }
    counts = {name: 0 for name in handles}
    try:
        for template, rows in groups.items():
            split = assignments[template]
            for row in rows:
                handles[split].write(json.dumps(row, ensure_ascii=True) + "\n")
                counts[split] += 1
    finally:
        for handle in handles.values():
            handle.close()
    if not all(counts.values()):
        raise SystemExit(f"one or more dataset splits are empty: {counts}")
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
