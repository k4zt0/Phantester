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
