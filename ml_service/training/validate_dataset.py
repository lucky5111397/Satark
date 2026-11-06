"""
Dataset Validation, Normalization, and Contamination Protection Utility.
Audits candidate datasets against schema requirements, class balance,
language distribution, duplicates, missing values, and strictly blocks
evaluation benchmarks and test fixtures from accidental training contamination.
"""

import argparse
import csv
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any, Optional

# Canonical 8-Column Schema for Satark ML Training Datasets
REQUIRED_COLUMNS = [
    "id",
    "text",
    "label",
    "language",
    "category",
    "source",
    "reviewed_by",
    "notes"
]

# Optional Governance Extension Columns for ML Traceability & Audit
GOVERNANCE_COLUMNS = [
    "source_id",
    "source_url",
    "license",
    "provenance_type",
    "reviewer_status",
    "review_timestamp",
    "label_confidence"
]

# Canonical Binary Labels
CANONICAL_BENIGN = "BENIGN"
CANONICAL_SUSPICIOUS = "SUSPICIOUS"
CANONICAL_LABELS = {CANONICAL_BENIGN, CANONICAL_SUSPICIOUS}

# Explicit Label Mapping from External Corrupted/Heterogeneous Formats
LABEL_MAPPING = {
    "benign": CANONICAL_BENIGN,
    "suspicious": CANONICAL_SUSPICIOUS,
    "genuine": CANONICAL_BENIGN,
    "scam": CANONICAL_SUSPICIOUS,
    "ham": CANONICAL_BENIGN,
    "0": CANONICAL_BENIGN,
    "1": CANONICAL_SUSPICIOUS,
    "clean": CANONICAL_BENIGN,
    "fraud": CANONICAL_SUSPICIOUS
}

ALLOWED_LANGUAGES = {"en", "hi", "hinglish"}

# Forbidden Benchmark Datasets (Strict Contamination Barrier)
FORBIDDEN_FILE_NAMES = {
    "test_set.csv",
    "benchmark_indicbert.csv",
    "dev_set.csv",
    "probe_set.csv",
    "sample_eval.csv"
}

FORBIDDEN_DIR_NAMES = {"eval", "fixtures"}

FORBIDDEN_PROVENANCES = {
    "synthetic-indicbert-eval",
    "synthetic-ai-draft",
    "synthetic-ai-dev-draft",
    "synthetic-ai-probe-draft",
    "test-fixture",
    "frozen_test_set",
    "eval_audit",
    "benchmark"
}

FORBIDDEN_ID_PREFIXES = ("BM", "T0", "D0", "P0", "FX")


class ContaminationError(ValueError):
    """Raised when an evaluation benchmark or test fixture is detected in a training path."""
    pass


def check_contamination(file_path: Optional[Path] = None, rows: Optional[List[Dict[str, str]]] = None) -> None:
    """
    Guards against accidental training contamination with frozen benchmarks.
    Raises ContaminationError if the file or rows originate from an evaluation benchmark.
    """
    if file_path is not None:
        resolved_path = Path(file_path).resolve()
        file_name = resolved_path.name.lower()

        # 1. Check exact forbidden file name
        if file_name in {f.lower() for f in FORBIDDEN_FILE_NAMES}:
            raise ContaminationError(
                f"FATAL CONTAMINATION VIOLATION: '{resolved_path.name}' is a frozen evaluation/benchmark dataset. "
                "It must NEVER be used for training, fine-tuning, or hyperparameter selection."
            )

        # 2. Check forbidden directory path (e.g. eval/ or fixtures/)
        for parent_part in resolved_path.parts:
            if parent_part.lower() in FORBIDDEN_DIR_NAMES:
                raise ContaminationError(
                    f"FATAL CONTAMINATION VIOLATION: Path '{resolved_path}' is inside protected directory '{parent_part}'. "
                    "All datasets in eval/ and fixtures/ are strictly reserved for testing and validation."
                )

    # 3. Check row provenance and benchmark ID prefixes if rows are provided
    if rows:
        benchmark_id_count = 0
        forbidden_source_count = 0
        total_checked = min(len(rows), 100)

        for r in rows[:total_checked]:
            row_id = (r.get("id") or "").strip()
            source = (r.get("source") or "").strip().lower()

            if any(row_id.startswith(pfx) for pfx in FORBIDDEN_ID_PREFIXES):
                benchmark_id_count += 1
            if source in FORBIDDEN_PROVENANCES or "eval" in source or "benchmark" in source or "frozen" in source:
                forbidden_source_count += 1

        if forbidden_source_count > 0:
            raise ContaminationError(
                f"FATAL CONTAMINATION VIOLATION: Dataset contains {forbidden_source_count} row(s) with forbidden "
                "evaluation provenance (e.g. frozen_test_set, eval_audit, synthetic-indicbert-eval). "
                "Training data must not be harvested from frozen benchmarks."
            )

        if benchmark_id_count > 0:
            raise ContaminationError(
                f"FATAL CONTAMINATION VIOLATION: Dataset contains {benchmark_id_count} row(s) carrying benchmark "
                f"ID prefixes ({FORBIDDEN_ID_PREFIXES}). Frozen evaluation rows must never be used in training."
            )


def normalize_label(raw_label: Any) -> str:
    """
    Normalizes a raw label string into CANONICAL_BENIGN or CANONICAL_SUSPICIOUS.
    Raises ValueError for unknown, empty, or ambiguous labels.
    """
    if raw_label is None:
        raise ValueError("Label cannot be null or empty.")

    cleaned = str(raw_label).strip().lower()
    if not cleaned:
        raise ValueError("Label cannot be empty whitespace.")

    if cleaned in LABEL_MAPPING:
        return LABEL_MAPPING[cleaned]

    raise ValueError(
        f"Invalid label '{raw_label}'. Allowed raw labels: {list(LABEL_MAPPING.keys())}. "
        f"Must map strictly to {CANONICAL_BENIGN} or {CANONICAL_SUSPICIOUS}."
    )


def normalize_language(raw_lang: Any) -> str:
    """
    Normalizes language identifier to 'en', 'hi', or 'hinglish'.
    Raises ValueError for unsupported languages.
    """
    if raw_lang is None:
        raise ValueError("Language cannot be null or empty.")

    cleaned = str(raw_lang).strip().lower()
    # Normalize common variations
    if cleaned in ("hi-latn", "hindi-latin", "roman-hindi", "roman-hinglish", "hindi-english", "hinglish"):
        cleaned = "hinglish"
    elif cleaned in ("hindi", "hi-in", "hi"):
        cleaned = "hi"
    elif cleaned in ("english", "en-in", "en-us", "en"):
        cleaned = "en"

    if cleaned not in ALLOWED_LANGUAGES:
        raise ValueError(
            f"Unsupported language '{raw_lang}'. Must be one of {sorted(ALLOWED_LANGUAGES)}."
        )

    return cleaned


def normalize_row(row: Dict[str, str], auto_normalize_labels: bool = True) -> Dict[str, str]:
    """
    Converts a raw CSV row dictionary into canonical 8-column format.
    Validates character length, normalizes label and language, and trims whitespace.
    """
    row_id = (row.get("id") or "").strip()
    if not row_id:
        raise ValueError("Row is missing required unique identifier 'id'.")

    text = (row.get("text") or "").strip()
    if not text:
        raise ValueError(f"Row '{row_id}' has empty message text.")
    if len(text) > 2000:
        raise ValueError(f"Row '{row_id}' text length ({len(text)} chars) exceeds maximum 2000 chars.")

    raw_label = row.get("label", "")
    label = normalize_label(raw_label) if auto_normalize_labels else str(raw_label).strip()
    if label not in CANONICAL_LABELS:
        raise ValueError(f"Row '{row_id}' label '{label}' is not a canonical label {CANONICAL_LABELS}.")

    language = normalize_language(row.get("language", ""))
    category = (row.get("category") or "general").strip().lower()
    source = (row.get("source") or "unspecified").strip()
    reviewed_by = (row.get("reviewed_by") or "").strip()
    notes = (row.get("notes") or "").strip()

    res = {
        "id": row_id,
        "text": text,
        "label": label,
        "language": language,
        "category": category,
        "source": source,
        "reviewed_by": reviewed_by,
        "notes": notes
    }
    for col in GOVERNANCE_COLUMNS:
        if col in row:
            res[col] = (str(row[col]) if row[col] is not None else "").strip()
    return res


def audit_dataset(file_path: Path, auto_normalize: bool = False) -> Dict[str, Any]:
    """
    Performs comprehensive structural, statistical, and contamination audit on a dataset CSV.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    # 1. Contamination check on file path
    try:
        check_contamination(file_path)
    except ContaminationError as ce:
        return {
            "valid": False,
            "error": str(ce),
            "contamination_detected": True,
            "total_rows": 0
        }

    rows: List[Dict[str, str]] = []
    with open(file_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []

        # Schema Conformance Check
        missing_columns = [col for col in REQUIRED_COLUMNS if col not in fieldnames]
        if missing_columns:
            return {
                "valid": False,
                "error": f"Missing required canonical columns: {missing_columns}",
                "fieldnames": fieldnames,
                "total_rows": 0
            }

        for row in reader:
            rows.append(row)

    total_rows = len(rows)
    if total_rows == 0:
        return {
            "valid": False,
            "error": "Dataset contains zero rows.",
            "total_rows": 0
        }

    # Contamination check on rows content
    try:
        check_contamination(file_path, rows=rows)
    except ContaminationError as ce:
        return {
            "valid": False,
            "error": str(ce),
            "contamination_detected": True,
            "total_rows": total_rows
        }

    # 2. Anomaly and Distribution Audit
    seen_ids = set()
    duplicate_ids = []
    seen_texts = set()
    duplicate_texts = []
    empty_texts = []
    oversized_texts = []
    invalid_labels = []
    invalid_languages = []

    normalized_rows = []
    labels = []
    languages = []
    categories = []
    text_lengths = []

    for idx, raw_row in enumerate(rows, start=2):
        row_id = (raw_row.get("id") or "").strip()
        text = (raw_row.get("text") or "").strip()
        raw_label = (raw_row.get("label") or "").strip()
        raw_lang = (raw_row.get("language") or "").strip()
        cat = (raw_row.get("category") or "").strip()

        # Check ID
        if not row_id:
            duplicate_ids.append(f"Row {idx}: Empty ID")
        elif row_id in seen_ids:
            duplicate_ids.append(f"Row {idx}: Duplicate ID '{row_id}'")
        else:
            seen_ids.add(row_id)

        # Check Text
        if not text:
            empty_texts.append(f"Row {idx}")
        elif len(text) > 2000:
            oversized_texts.append(f"Row {idx} ({len(text)} chars)")
        else:
            text_lengths.append(len(text))
            if text in seen_texts:
                duplicate_texts.append(f"Row {idx}: Duplicate text")
            else:
                seen_texts.add(text)

        # Check Label
        try:
            norm_lbl = normalize_label(raw_label)
            if not auto_normalize and raw_label not in CANONICAL_LABELS:
                invalid_labels.append(f"Row {idx}: '{raw_label}' (use canonical {CANONICAL_LABELS} or pass --normalize)")
            else:
                labels.append(norm_lbl)
        except ValueError as ve:
            invalid_labels.append(f"Row {idx}: {ve}")

        # Check Language
        try:
            norm_lang = normalize_language(raw_lang)
            languages.append(norm_lang)
        except ValueError as ve:
            invalid_languages.append(f"Row {idx}: {ve}")

        if cat:
            categories.append(cat)

        if auto_normalize and text and row_id:
            try:
                norm_row = normalize_row(raw_row, auto_normalize_labels=True)
                normalized_rows.append(norm_row)
            except Exception:
                pass

    label_counts = Counter(labels)
    lang_counts = Counter(languages)
    cat_counts = Counter(categories)

    benign_count = label_counts.get(CANONICAL_BENIGN, 0)
    suspicious_count = label_counts.get(CANONICAL_SUSPICIOUS, 0)
    balance_ratio = (
        round(min(benign_count, suspicious_count) / max(benign_count, suspicious_count, 1), 3)
    )

    avg_len = round(sum(text_lengths) / max(len(text_lengths), 1), 1)
    min_len = min(text_lengths) if text_lengths else 0
    max_len = max(text_lengths) if text_lengths else 0

    is_valid = (
        len(empty_texts) == 0
        and len(oversized_texts) == 0
        and len(invalid_labels) == 0
        and len(invalid_languages) == 0
        and len(duplicate_ids) == 0
    )

    return {
        "valid": is_valid,
        "total_rows": total_rows,
        "duplicate_ids_count": len(duplicate_ids),
        "duplicate_ids": duplicate_ids[:10],
        "duplicate_texts_count": len(duplicate_texts),
        "empty_texts_count": len(empty_texts),
        "oversized_texts_count": len(oversized_texts),
        "invalid_labels_count": len(invalid_labels),
        "invalid_labels": invalid_labels[:10],
        "invalid_languages_count": len(invalid_languages),
        "invalid_languages": invalid_languages[:10],
        "label_distribution": dict(label_counts),
        "language_distribution": dict(lang_counts),
        "category_distribution": dict(cat_counts.most_common(10)),
        "class_balance_ratio": balance_ratio,
        "text_length_stats": {
            "min": min_len,
            "max": max_len,
            "mean": avg_len
        },
        "normalized_rows": normalized_rows if auto_normalize else None
    }


def print_audit_report(report: Dict[str, Any]):
    """Prints a structured audit report to stdout with safe encoding."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print("=" * 70)
    print("SATARK DATASET VALIDATION AUDIT REPORT")
    print("=" * 70)

    if not report.get("valid"):
        print("[FAIL] VALIDATION STATUS: FAILED")
        if "error" in report:
            print(f"Error: {report['error']}")
    else:
        print("[PASS] VALIDATION STATUS: PASSED")

    print(f"\nTotal Records: {report.get('total_rows', 0)}")
    print(f"Duplicate IDs: {report.get('duplicate_ids_count', 0)}")
    print(f"Duplicate Texts: {report.get('duplicate_texts_count', 0)}")
    print(f"Empty Texts: {report.get('empty_texts_count', 0)}")
    print(f"Oversized (>2000 chars): {report.get('oversized_texts_count', 0)}")

    if report.get("invalid_labels_count", 0) > 0:
        print(f"Invalid Labels: {report['invalid_labels_count']} (e.g. {report.get('invalid_labels', [])[:3]})")

    if report.get("invalid_languages_count", 0) > 0:
        print(f"Invalid Languages: {report['invalid_languages_count']} (e.g. {report.get('invalid_languages', [])[:3]})")

    print("\n--- Canonical Label Distribution ---")
    for lbl, cnt in report.get("label_distribution", {}).items():
        pct = round(cnt / max(report.get("total_rows", 1), 1) * 100, 1)
        print(f"  {lbl:12}: {cnt:6} ({pct}%)")
    print(f"  Class Balance Ratio (min/max): {report.get('class_balance_ratio', 0)}")

    print("\n--- Language Distribution ---")
    for lang, cnt in report.get("language_distribution", {}).items():
        pct = round(cnt / max(report.get("total_rows", 1), 1) * 100, 1)
        print(f"  {lang:12}: {cnt:6} ({pct}%)")

    len_stats = report.get("text_length_stats", {})
    print("\n--- Text Length (Chars) ---")
    print(f"  Min: {len_stats.get('min')}, Mean: {len_stats.get('mean')}, Max: {len_stats.get('max')}")

    if report.get("category_distribution"):
        print("\n--- Top Categories ---")
        for cat, cnt in report["category_distribution"].items():
            print(f"  {cat:24}: {cnt:4}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Audit a Satark dataset CSV for training readiness and schema compliance.")
    parser.add_argument("--file", required=True, type=str, help="Path to the dataset CSV to audit.")
    parser.add_argument("--normalize", action="store_true", help="Accept and normalize legacy labels (e.g. genuine/scam -> BENIGN/SUSPICIOUS).")
    args = parser.parse_args()

    report = audit_dataset(Path(args.file), auto_normalize=args.normalize)
    print_audit_report(report)

    if not report.get("valid"):
        sys.exit(1)


if __name__ == "__main__":
    main()
