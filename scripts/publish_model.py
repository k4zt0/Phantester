from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from huggingface_hub import HfApi


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--repo-id", required=True)
    args = parser.parse_args()
    if not args.model.is_dir():
        parser.error("--model must be a checkpoint directory")
    shutil.copy2(Path(__file__).parents[1] / "MODEL_CARD.md", args.model / "README.md")
    api = HfApi()
    api.create_repo(args.repo_id, repo_type="model", private=False, exist_ok=True)
    api.upload_folder(
        folder_path=args.model,
        repo_id=args.repo_id,
        repo_type="model",
        commit_message="Publish validated Phantester adapter",
    )


if __name__ == "__main__":
    main()

\n