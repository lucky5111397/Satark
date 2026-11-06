"""
Dataset Curation and Ingestion Pipeline for SATARK (Phase 6A).

Orchestrates:
1. Contamination firewall verification.
2. Canonical schema enforcement (8 columns: id, text, label, language, category, source, reviewed_by, notes).
3. Label normalization (BENIGN / SUSPICIOUS).
4. Language normalization (en, hi, hinglish).
5. Automated PII scrubbing and verification.
6. Template fingerprint tracking and deduplication.
7. Human review audit tracking.
"""

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional

# Reconfigure stdout/stderr encoding on Windows
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
logger = logging.getLogger("satark.curation")

from ml_service.training.validate_dataset import (
    REQUIRED_COLUMNS,
    GOVERNANCE_COLUMNS,
    CANONICAL_BENIGN,
    CANONICAL_SUSPICIOUS,
    normalize_label,
    normalize_language,
    check_contamination,
    ContaminationError
)
from ml_service.training.prepare_dataset import extract_template_fingerprint
from ml_service.curation.pii_scrubber import scrub_text, has_unmasked_pii


def process_curated_record(
    record: Dict[str, str],
    auto_scrub_pii: bool = True
) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """
    Validates, normalizes, and scrubs a single input record.
    Returns:
        (normalized_row, None) on success
        (None, error_message) on failure
    """
    row_id = (record.get("id") or "").strip()
    if not row_id:
        return None, "Missing 'id' column"

    raw_text = (record.get("text") or "").strip()
    if not raw_text:
        return None, f"Record '{row_id}' has empty text"
    if len(raw_text) > 2000:
        return None, f"Record '{row_id}' text length ({len(raw_text)}) exceeds 2000 chars"

    # Normalize Label
    try:
        label = normalize_label(record.get("label", ""))
    except ValueError as e:
        return None, f"Record '{row_id}' label error: {e}"

    # Normalize Language
    try:
        language = normalize_language(record.get("language", ""))
    except ValueError as e:
        return None, f"Record '{row_id}' language error: {e}"

    # PII Scrubbing
    processed_text = raw_text
    if auto_scrub_pii:
        processed_text, _ = scrub_text(raw_text)

    category = (record.get("category") or "general").strip().lower()
    source = (record.get("source") or "unspecified").strip()
    reviewed_by = (record.get("reviewed_by") or "").strip()
    notes = (record.get("notes") or "").strip()

    normalized_row = {
        "id": row_id,
        "text": processed_text,
        "label": label,
        "language": language,
        "category": category,
        "source": source,
        "reviewed_by": reviewed_by,
        "notes": notes
    }

    # Governance attributes
    for col in GOVERNANCE_COLUMNS:
        if col in record:
            normalized_row[col] = (str(record[col]) if record[col] is not None else "").strip()

    return normalized_row, None


def curate_corpus(
    input_file: Path,
    output_file: Optional[Path] = None,
    auto_scrub_pii: bool = True,
    deduplicate_texts: bool = True
) -> Dict[str, Any]:
    """
    Ingests and audits a batch dataset against SATARK Phase 6A quality standards.
    """
    input_path = Path(input_file).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Candidate dataset not found at: {input_path}")

    # 1. Contamination Firewall Check
    check_contamination(file_path=input_path)

    valid_rows: List[Dict[str, str]] = []
    errors: List[str] = []
    seen_ids = set()
    seen_texts = set()
    seen_templates = set()
    pii_violations = 0
    human_reviewed_count = 0

    with open(input_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            normalized, err = process_curated_record(row, auto_scrub_pii=auto_scrub_pii)
            if err:
                errors.append(f"Row {idx}: {err}")
                continue

            # ID uniqueness
            r_id = normalized["id"]
            if r_id in seen_ids:
                errors.append(f"Row {idx}: Duplicate ID '{r_id}'")
                continue
            seen_ids.add(r_id)

            # Text deduplication
            t = normalized["text"]
            if deduplicate_texts and t in seen_texts:
                errors.append(f"Row {idx}: Duplicate text (ID '{r_id}')")
                continue
            seen_texts.add(t)

            # Audit remaining unmasked PII
            if has_unmasked_pii(t):
                pii_violations += 1

            # Track template fingerprints
            fp = extract_template_fingerprint(t)
            seen_templates.add(fp)

            # Track genuine human review (truthful audit standard)
            rev_by = (normalized.get("reviewed_by") or "").strip().lower()
            rev_status = (normalized.get("reviewer_status") or "").strip().lower()
            is_human = (
                rev_by not in ("unreviewed", "none", "auto", "synthetic_generated", "") and
                rev_status in ("human_verified", "audited", "verified")
            )
            if is_human:
                human_reviewed_count += 1

            valid_rows.append(normalized)

    # Secondary Contamination Check on row contents
    check_contamination(rows=valid_rows)

    stats = {
        "input_file": str(input_path),
        "total_records_processed": len(valid_rows) + len(errors),
        "valid_records": len(valid_rows),
        "errors_count": len(errors),
        "unique_templates": len(seen_templates),
        "pii_violations_remaining": pii_violations,
        "human_reviewed_count": human_reviewed_count,
        "human_review_percentage": round(human_reviewed_count / len(valid_rows) * 100, 2) if valid_rows else 0.0,
        "class_distribution": {
            CANONICAL_BENIGN: sum(1 for r in valid_rows if r["label"] == CANONICAL_BENIGN),
            CANONICAL_SUSPICIOUS: sum(1 for r in valid_rows if r["label"] == CANONICAL_SUSPICIOUS)
        },
        "language_distribution": {
            "en": sum(1 for r in valid_rows if r["language"] == "en"),
            "hi": sum(1 for r in valid_rows if r["language"] == "hi"),
            "hinglish": sum(1 for r in valid_rows if r["language"] == "hinglish")
        }
    }

    # Write output if requested
    if output_file and valid_rows:
        out_p = Path(output_file).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        has_gov = any(k in valid_rows[0] for k in GOVERNANCE_COLUMNS)
        fieldnames = REQUIRED_COLUMNS + GOVERNANCE_COLUMNS if has_gov else REQUIRED_COLUMNS
        with open(out_p, mode="w", encoding="utf-8", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(valid_rows)
        logger.info(f"Curated dataset successfully saved to: {out_p}")

    return stats


def parse_args():
    parser = argparse.ArgumentParser(description="SATARK Dataset Curation & PII Sanitization Pipeline")
    parser.add_argument("--input", required=True, type=str, help="Path to input raw CSV file.")
    parser.add_argument("--output", default=None, type=str, help="Destination path for sanitized CSV.")
    parser.add_argument("--no_pii_scrub", action="store_true", help="Disable automatic PII scrubbing.")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        stats = curate_corpus(
            input_file=Path(args.input),
            output_file=Path(args.output) if args.output else None,
            auto_scrub_pii=not args.no_pii_scrub
        )
        print("=" * 65)
        print("SATARK DATASET CURATION AUDIT REPORT")
        print("=" * 65)
        print(f"Valid Records:            {stats['valid_records']}")
        print(f"Rejections / Errors:      {stats['errors_count']}")
        print(f"Unique Templates:         {stats['unique_templates']}")
        print(f"Human Reviewed:           {stats['human_reviewed_count']} ({stats['human_review_percentage']}%)")
        print(f"PII Violations Detected:  {stats['pii_violations_remaining']}")
        print(f"Class Balance:            {stats['class_distribution']}")
        print(f"Language Breakdown:       {stats['language_distribution']}")
        print("=" * 65)
    except ContaminationError as ce:
        logger.critical(f"FATAL CONTAMINATION VIOLATION: {ce}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Curation pipeline error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

