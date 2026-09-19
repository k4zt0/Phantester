#!/usr/bin/env bash
set -euo pipefail

python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[train,test]'
python -m pytest -q
python scripts/build_dataset.py --output data/generated/all.jsonl --rows 100000
python scripts/split_dataset.py \
  --input data/generated/all.jsonl \
  --output-dir data/generated

nvidia-smi
torchrun --standalone --nproc_per_node=4 scripts/train.py \
  --train-file data/generated/train.jsonl \
  --validation-file data/generated/validation.jsonl \
  --output-dir checkpoints/smoke \
  --max-steps 20

torchrun --standalone --nproc_per_node=4 scripts/train.py \
  --train-file data/generated/train.jsonl \
  --validation-file data/generated/validation.jsonl \
  --output-dir checkpoints/phantester-gpt2-xl-lora

python scripts/evaluate.py \
  --model checkpoints/phantester-gpt2-xl-lora \
  --data data/generated/test.jsonl
