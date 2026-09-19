from __future__ import annotations

import argparse
import json
import time

from datasets import load_dataset
from peft import LoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainerCallback,
    TrainingArguments,
)


class TimingCallback(TrainerCallback):
    def __init__(self) -> None:
        self.started = 0.0

    def on_train_begin(self, args, state, control, **kwargs):
        self.started = time.monotonic()

    def on_log(self, args, state, control, logs=None, **kwargs):
        if state.global_step and self.started:
            seconds_per_step = (time.monotonic() - self.started) / state.global_step
            remaining = max(state.max_steps - state.global_step, 0) * seconds_per_step
            print(json.dumps({"step": state.global_step, "eta_seconds": round(remaining)}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="openai-community/gpt2-xl")
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--validation-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--epochs", type=float, default=3.0)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--max-steps", type=int, default=-1)
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        torch_dtype="auto",
        attn_implementation="sdpa",
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.config.use_cache = False
    model = get_peft_model(
        model,
        LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            target_modules=["c_attn", "c_proj"],
        ),
    )
    files = {"train": args.train_file, "validation": args.validation_file}
    dataset = load_dataset("json", data_files=files)

    def tokenize(batch):
        texts = [
            f"Assessment:\n{prompt}\nDecision:\n{response}{tokenizer.eos_token}"
            for prompt, response in zip(batch["prompt"], batch["response"], strict=True)
        ]
        return tokenizer(texts, truncation=True, max_length=args.max_length)

    tokenized = dataset.map(
        tokenize,
        batched=True,
        remove_columns=dataset["train"].column_names,
    )
    checkpoint_steps = min(250, args.max_steps) if args.max_steps > 0 else 250
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        per_device_train_batch_size=4,
        per_device_eval_batch_size=4,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        warmup_ratio=0.05,
        weight_decay=0.01,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=checkpoint_steps,
        save_steps=checkpoint_steps,
        save_total_limit=2,
        bf16=True,
        gradient_checkpointing=True,
        ddp_find_unused_parameters=False,
        report_to="none",
        load_best_model_at_end=True,
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
        callbacks=[TimingCallback()],
    )
    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)


if __name__ == "__main__":
    main()
\n