# Phantester

Phantester is a defensive LLM-agent project for file-signature inspection,
authenticated file protection, tamper-evident canaries, fail-closed incident
response, and verified TLS/mTLS transport.

The model is advisory. Cryptographic operations, key access, integrity
decisions, and containment are implemented by deterministic code and cannot be
overridden by model output.

**Repositories:** [GitHub](https://github.com/k4zt0/Phantester) |
[Hugging Face](https://huggingface.co/KaztoRay/Phantester)

## Security architecture

- **File signatures:** extension, known magic bytes, size, and SHA-256.
- **Protection:** AES-256-GCM with unique salt and nonce per file. HKDF-SHA256
  derives a file key from an externally managed 256-bit master key.
- **Canaries:** independent local and master canaries use HMAC-SHA256. A missing
  or altered canary makes writes and decryption fail closed.
- **Response:** deny mutation, preserve evidence, isolate the affected scope,
  and require operator review before recovery.
- **Transport:** certificate validation, hostname checks, and TLS 1.3 are
  mandatory. Context creation requires healthy local and master canaries.
  Optional mTLS uses an operator-supplied client certificate.
- **Agent boundary:** the fine-tuned model emits constrained assessments. It
  never receives encryption keys or directly modifies files.

Canaries detect compromise; they are not encryption keys and do not replace
offline, immutable, versioned backups. TLS protects transport, not files at rest.

## Local usage

```powershell
cd C:\Users\jeong\Phantester
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[test]"
$env:PHANTESTER_MASTER_KEY = .\.venv\Scripts\python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
phantester init-canaries .\state
phantester verify-canaries .\state
phantester inspect .\sample.pdf
phantester protect .\state .\sample.pdf .\sample.pdf.enc
phantester restore .\state .\sample.pdf.enc .\restored.pdf
```

Store the master key in KMS or a secret manager in production. Never commit it.
See [SECURITY.md](SECURITY.md) for the persistent-lock recovery procedure and
the exact security boundary.

## Training

The base is `openai-community/gpt2-xl`. LoRA is the default because deterministic
policy enforcement matters more than allowing an unconstrained model to control
security operations.

```bash
python scripts/build_dataset.py --output data/generated/all.jsonl --rows 100000
python scripts/split_dataset.py --input data/generated/all.jsonl --output-dir data/generated
torchrun --standalone --nproc_per_node=4 scripts/train.py \
  --train-file data/generated/train.jsonl \
  --validation-file data/generated/validation.jsonl \
  --output-dir checkpoints/phantester-gpt2-xl-lora
python scripts/evaluate.py \
  --model checkpoints/phantester-gpt2-xl-lora \
  --data data/generated/test.jsonl
```

Synthetic examples cover file formats, tampering, canary states, and write
bursts. Before a production claim, add legally redistributable, human-reviewed
examples from the target environment and evaluate on a separately sourced
held-out corpus. Synthetic test accuracy alone is not real-world accuracy.

## Remote host

The verified environment has 1x NVIDIA H100 80GB, about 1.5TiB RAM, and 2TB
free storage. `scripts/train_remote.sh` creates a Python 3.12 environment,
installs dependencies, runs tests, benchmarks 20 steps, estimates remaining
time, and then starts distributed training.

Expected elapsed time for 100,000 sequence-length-512 examples:

| Stage | Estimate |
|---|---:|
| Setup and GPT-2 XL download | 10-40 minutes |
| Dataset build and split | 2-10 minutes |
| LoRA training, 3 epochs, 1x H100 | 2-5 hours |
| Held-out generation evaluation | 10-40 minutes |
| Upload | 5-20 minutes |
| **Total** | **2 hours 27 minutes-6 hours 10 minutes** |

The remote benchmark prints a measured ETA. Full-parameter fine-tuning would
take longer and requires a separate DeepSpeed/FSDP validation path.

## Publishing

```powershell
gh auth login
hf auth login
gh repo create k4zt0/Phantester --public --source . --remote origin --push
python scripts/publish_model.py --model checkpoints/phantester-gpt2-xl-lora `
  --repo-id KaztoRay/Phantester
```

Publish only after the release gate passes and the model card is reviewed.
