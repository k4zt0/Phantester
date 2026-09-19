from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from peft import AutoPeftModelForCausalLM
from transformers import AutoTokenizer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=128)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"
    model = AutoPeftModelForCausalLM.from_pretrained(
        args.model, device_map="auto", torch_dtype="auto"
    )
    model.eval()
    rows = [json.loads(line) for line in args.data.read_text(encoding="utf-8").splitlines()]
    correct = 0
    canary_total = 0
    canary_detected = 0
    for start in range(0, len(rows), args.batch_size):
        batch = rows[start : start + args.batch_size]
        prefixes = [f"Assessment:\n{row['prompt']}\nDecision:\n" for row in batch]
        inputs = tokenizer(prefixes, return_tensors="pt", padding=True).to(model.device)
        with torch.inference_mode():
            output = model.generate(
                **inputs,
                max_new_tokens=80,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        generated = tokenizer.batch_decode(
            output[:, inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )
        for row, response in zip(batch, generated, strict=True):
            predicted = response.strip().splitlines()[0]
            try:
                actual, expected = json.loads(predicted), json.loads(row["response"])
                correct += actual == expected
                if expected["reason"] == "canary_failure":
                    canary_total += 1
                    canary_detected += actual.get("action") == "deny_and_isolate"
            except json.JSONDecodeError:
                if json.loads(row["response"])["reason"] == "canary_failure":
                    canary_total += 1
    exact_match = correct / len(rows)
    canary_recall = canary_detected / canary_total if canary_total else 0.0
    print(json.dumps({"exact_match": exact_match, "canary_recall": canary_recall}))
    if exact_match < 0.95 or canary_recall < 1.0:
        raise SystemExit("release thresholds not met")


if __name__ == "__main__":
    main()
