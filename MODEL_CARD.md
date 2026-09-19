---
base_model: openai-community/gpt2-xl
library_name: peft
license: apache-2.0
tags:
  - cybersecurity
  - ransomware-defense
  - file-integrity
---

# Phantester

Phantester is a GPT-2 XL LoRA adapter for classifying constrained,
structured file-integrity telemetry and recommending defensive actions.

## Intended use

Use only behind a deterministic policy engine. The model must not receive keys,
perform cryptography, delete files, or directly trigger containment.

## Limitations

The initial corpus is synthetic and does not establish real-world ransomware
detection accuracy. GPT-2 XL is not instruction-tuned and has a limited context
window. Any output outside the documented schema is untrusted.

## Release gate

Do not publish a checkpoint until it reaches at least 95% exact-match accuracy
and 100% recall for canary failures on a reviewed held-out set, while all
cryptographic fail-closed tests pass.

## Training and evaluation

The published adapter was trained for three epochs on 80,000 synthetic
examples, validated on 10,000 examples, and evaluated on a disjoint 10,000
example test split. Identical prompts are confined to one split.

| Metric | Result |
|---|---:|
| Exact JSON decision match | 100% |
| Canary-failure recall | 100% |
| Training loss | 0.7183 |
| Training runtime, H100 80GB | 20m 25s |

These results measure deterministic synthetic policy routing. They do not
measure real-world ransomware detection and must not be interpreted as a
production false-positive or false-negative rate.
