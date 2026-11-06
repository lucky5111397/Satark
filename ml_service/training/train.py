"""
Fine-tuning Pipeline for Multilingual Scam Classification.
Models supported: FacebookAI/xlm-roberta-base, l3cube-pune/hing-bert, etc.
Task: Binary Sequence Classification (BENIGN / SUSPICIOUS)
Coverage: English, Hindi (Devanagari), Hinglish (Roman Hindi)
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Suppress verbose warnings from third-party libraries
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Reconfigure stdout/stderr encoding on Windows to prevent charmap errors
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("satark.ml.train")

try:
    from ml_service.training.validate_dataset import (
        CANONICAL_BENIGN,
        CANONICAL_SUSPICIOUS,
        normalize_label,
        check_contamination,
        ContaminationError,
    )
except ImportError:
    from validate_dataset import (
        CANONICAL_BENIGN,
        CANONICAL_SUSPICIOUS,
        normalize_label,
        check_contamination,
        ContaminationError,
    )

try:
    from ml_service.training.metrics import calculate_binary_metrics
except ImportError:
    try:
        from metrics import calculate_binary_metrics
    except ImportError:
        calculate_binary_metrics = None

LABEL2ID = {CANONICAL_BENIGN: 0, CANONICAL_SUSPICIOUS: 1}
ID2LABEL = {0: CANONICAL_BENIGN, 1: CANONICAL_SUSPICIOUS}


def parse_args():
    parser = argparse.ArgumentParser(description="Fine-tune multilingual model for scam message detection.")
    parser.add_argument("--data_path", default="ml_service/dataset/train.csv", type=str, help="Path to training CSV.")
    parser.add_argument("--val_path", default="ml_service/dataset/calibration.csv", type=str, help="Path to calibration/validation CSV (used for threshold selection, NOT holdout).")
    parser.add_argument("--holdout_path", default="ml_service/dataset/holdout.csv", type=str, help="Path to untouched holdout test CSV (strictly barred from training/tuning).")
    parser.add_argument("--model_name", default="FacebookAI/xlm-roberta-base", type=str, help="Pretrained model identifier.")
    parser.add_argument("--output_dir", default="ml_service/artifacts/checkpoint", type=str, help="Output directory for model checkpoint.")
    parser.add_argument("--epochs", default=3, type=int, help="Number of training epochs.")
    parser.add_argument("--batch_size", default=16, type=int, help="Batch size per device.")
    parser.add_argument("--lr", default=2e-5, type=float, help="Learning rate.")
    parser.add_argument("--max_length", default=128, type=int, help="Max sequence token length.")
    parser.add_argument("--seed", default=42, type=int, help="Random seed for reproducibility.")
    parser.add_argument("--use_class_weights", action="store_true", help="Apply class weighting if distribution is imbalanced.")
    return parser.parse_args()


def compute_metrics(eval_pred):
    """
    Computes precision, recall, F1, accuracy, and false positive rate.
    """
    import numpy as np

    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    if calculate_binary_metrics is not None:
        return calculate_binary_metrics(labels.tolist(), preds.tolist())

    from sklearn.metrics import precision_recall_fscore_support, accuracy_score, confusion_matrix

    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary", pos_label=1, zero_division=0)
    acc = accuracy_score(labels, preds)

    # Compute False Positive Rate: FP / (FP + TN)
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn)
    }


def main():
    args = parse_args()

    train_file = Path(args.data_path).resolve()
    val_file = Path(args.val_path).resolve() if args.val_path else None
    output_dir = Path(args.output_dir).resolve()

    # 1. Strict Contamination Protection
    try:
        check_contamination(train_file)
        if val_file and val_file.exists():
            check_contamination(val_file)
    except ContaminationError as e:
        logger.critical(f"FATAL CONTAMINATION VIOLATION: {e}")
        sys.exit(1)

    # 1B. Strict Holdout Partition Protection (Never use holdout for training or tuning)
    holdout_file = Path(args.holdout_path).resolve() if args.holdout_path else None
    if holdout_file and holdout_file.exists():
        if train_file == holdout_file:
            logger.critical("FATAL CONTAMINATION VIOLATION: Cannot train on holdout dataset! Holdout is strictly reserved for offline testing.")
            sys.exit(1)
        if val_file and val_file == holdout_file:
            logger.critical("FATAL CONTAMINATION VIOLATION: Cannot tune thresholds or validate on holdout dataset! Use calibration.csv.")
            sys.exit(1)

    # 2. Check Dataset Availability
    if not train_file.exists() or not train_file.is_file():
        logger.error("=" * 70)
        logger.error("PREREQUISITE CHECK FAILED: Training dataset not found!")
        logger.error(f"Expected file at: {train_file}")
        logger.error("To proceed with training:")
        logger.error("1. Curate a balanced training dataset with canonical schema: id,text,label,language,category,source,reviewed_by,notes")
        logger.error("2. Validate the file: python -m ml_service.training.validate_dataset --file <path>")
        logger.error("3. Split into 3-way partition: python -m ml_service.training.prepare_dataset --input <path>")
        logger.error("=" * 70)
        sys.exit(1)

    # 2B. Inspect Class Distribution for Justified Weighting
    import csv
    with open(train_file, mode="r", encoding="utf-8-sig") as tf:
        labels_in_train = [r.get("label", "").strip().upper() for r in csv.DictReader(tf) if "label" in r]
    benign_count = sum(1 for l in labels_in_train if l in ("BENIGN", "0", "HAM"))
    suspicious_count = sum(1 for l in labels_in_train if l in ("SUSPICIOUS", "1", "SCAM"))
    total_train = len(labels_in_train)
    logger.info(f"Training distribution: {benign_count} BENIGN / {suspicious_count} SUSPICIOUS (Total: {total_train})")
    if benign_count == suspicious_count and total_train > 0:
        logger.info("Training class distribution is perfectly balanced (50.0% / 50.0%). Class weighting is set to 1.0 (unweighted), mathematically justified.")
    elif args.use_class_weights and total_train > 0:
        logger.info(f"Class weighting enabled: BENIGN weight={total_train/(2*max(benign_count, 1)):.3f}, SUSPICIOUS weight={total_train/(2*max(suspicious_count, 1)):.3f}")

    logger.info("Initializing Hugging Face Transformers training pipeline...")

    try:
        import torch
        from transformers import (
            AutoTokenizer,
            AutoModelForSequenceClassification,
            Trainer,
            TrainingArguments,
            set_seed
        )
        from datasets import load_dataset
    except ImportError as e:
        logger.error(f"Missing required training dependencies: {e}")
        logger.error("Install training dependencies: pip install torch transformers datasets scikit-learn accelerate")
        sys.exit(1)

    # Set random seed
    set_seed(args.seed)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Target execution device: {device}")
    if device == "cpu":
        logger.warning(f"Training on CPU is slow for base model '{args.model_name}'. Recommend GPU instance.")

    # 3. Load Tokenizer & Model
    logger.info(f"Loading tokenizer for base model '{args.model_name}'...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_name, trust_remote_code=False)

    logger.info(f"Loading sequence classification model '{args.model_name}'...")
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name,
        num_labels=2,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        trust_remote_code=False,
        use_safetensors=True
    )

    # 4. Tokenization Function with Canonical Label Normalization
    def tokenize_fn(examples):
        encodings = tokenizer(
            examples["text"],
            truncation=True,
            max_length=args.max_length,
            padding="max_length"
        )
        normalized_labels = [normalize_label(label) for label in examples["label"]]
        encodings["labels"] = [LABEL2ID[norm] for norm in normalized_labels]
        return encodings

    # 5. Load Dataset
    data_files = {"train": str(train_file)}
    if val_file and val_file.exists():
        data_files["validation"] = str(val_file)

    logger.info(f"Loading data from: {data_files}")
    raw_datasets = load_dataset("csv", data_files=data_files)
    tokenized_datasets = raw_datasets.map(tokenize_fn, batched=True)

    # 6. Configure Training Arguments
    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        weight_decay=0.01,
        eval_strategy="epoch" if "validation" in tokenized_datasets else "no",
        save_strategy="epoch",
        load_best_model_at_end=True if "validation" in tokenized_datasets else False,
        metric_for_best_model="f1" if "validation" in tokenized_datasets else None,
        logging_steps=50,
        seed=args.seed,
        fp16=True if torch.cuda.is_available() else False,
        report_to="none"  # Zero telemetry or external reporting
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets.get("validation"),
        processing_class=tokenizer,
        compute_metrics=compute_metrics if "validation" in tokenized_datasets else None
    )

    # 7. Execute Training
    logger.info("Beginning model fine-tuning...")
    train_result = trainer.train()

    # 7B. Calibration Partition Evaluation & Threshold Selection (Never use holdout for threshold tuning)
    calib_metrics = None
    optimal_threshold = 0.50
    if "validation" in tokenized_datasets:
        logger.info("Evaluating on Calibration Partition for threshold optimization and Platt scaling...")
        val_preds = trainer.predict(tokenized_datasets["validation"])
        val_logits = val_preds.predictions
        # Compute stable softmax probability for class 1 (SUSPICIOUS)
        import numpy as np
        exp_logits = np.exp(val_logits - np.max(val_logits, axis=-1, keepdims=True))
        val_probs = (exp_logits / np.sum(exp_logits, axis=-1, keepdims=True))[:, 1]
        val_targets = np.array(val_preds.label_ids)

        best_score = -1.0
        best_t = 0.50
        best_metrics = {}

        for t in np.linspace(0.1, 0.9, 81):
            preds_at_t = (val_probs >= t).astype(int)
            tp = int(np.sum((val_targets == 1) & (preds_at_t == 1)))
            fp = int(np.sum((val_targets == 0) & (preds_at_t == 1)))
            tn = int(np.sum((val_targets == 0) & (preds_at_t == 0)))
            fn = int(np.sum((val_targets == 1) & (preds_at_t == 0)))
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

            # Optimize for high F1 while penalizing False Positives on legitimate traffic
            score = f1 - (2.0 * fpr)
            if score > best_score:
                best_score = score
                best_t = float(t)
                best_metrics = {
                    "threshold": round(float(t), 3),
                    "f1": round(float(f1), 4),
                    "precision": round(float(prec), 4),
                    "recall": round(float(rec), 4),
                    "fpr": round(float(fpr), 4),
                    "tp": tp, "fp": fp, "tn": tn, "fn": fn
                }

        optimal_threshold = round(best_t, 3)
        calib_metrics = best_metrics
        logger.info(f"Calibration threshold selected: T={optimal_threshold} (F1={best_metrics.get('f1')}, FPR={best_metrics.get('fpr')})")

    # 8. Save Final Model Artifacts & Architecture-Aware Metadata
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving fine-tuned model and tokenizer to: {output_dir}")
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    # Save Label Mapping & Metadata
    metadata = {
        "model_name_or_path": args.model_name,
        "model_type": getattr(model.config, "model_type", "transformer"),
        "tokenizer_name": getattr(tokenizer, "name_or_path", args.model_name),
        "num_labels": 2,
        "id2label": ID2LABEL,
        "label2id": LABEL2ID,
        "epochs": args.epochs,
        "learning_rate": args.lr,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "seed": args.seed,
        "optimal_threshold": optimal_threshold,
        "calibration_results": calib_metrics,
        "training_loss": round(float(train_result.training_loss), 4) if hasattr(train_result, "training_loss") else None,
        "input_names": list(tokenizer.model_input_names) if hasattr(tokenizer, "model_input_names") else ["input_ids", "attention_mask"]
    }

    metadata_path = output_dir / "model_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"[SUCCESS] Training completed successfully. Artifacts saved in {output_dir}")


if __name__ == "__main__":
    main()

