"""
Dataset Preparation and Three-Way Stratified Split Pipeline.
Splits audited candidate datasets into Train (70%), Calibration (15%), and Holdout (15%) partitions,
preserving class balance and language distributions while preventing near-duplicate and template leakage.
Never allows calibration or holdout partitions to be exposed to model training gradients.
"""

import argparse
import csv
import json
import random
import re
import sys
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Dict, Tuple, Set, Any

from .validate_dataset import (
    audit_dataset,
    check_contamination,
    normalize_row,
    REQUIRED_COLUMNS,
    GOVERNANCE_COLUMNS,
    CANONICAL_BENIGN,
    CANONICAL_SUSPICIOUS,
    ContaminationError
)


def extract_template_fingerprint(text: str) -> str:
    """
    Extracts a generalized structural template fingerprint from message text
    by normalizing specific entities (numbers, amounts, URLs, phones, dates).
    Used to ensure identical structural templates do not leak across splits.
    """
    if not text or not isinstance(text, str):
        return ""

    lowered = text.lower().strip()

    # 1. Normalize URLs and domains
    t = re.sub(
        r'(?:hxxps?|https?|ftp)://\S+|www\.\S+|\b[a-zA-Z0-9.-]+\.(?:com|in|org|net|xyz|top|site|online|live|click|app|cc|co)\b(?:/\S*)?',
        '<url>',
        lowered,
        flags=re.IGNORECASE
    )

    # 2. Normalize Indian phone numbers and masked phone sequences
    t = re.sub(r'\b(?:\+?91[\-\s]?)?[6-9]\d{9}\b|\b\d{2}[xX]{5,8}\d{2}\b', '<phone>', t)

    # 3. Normalize currency markers and amounts
    t = re.sub(r'(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d+)?', '<amt>', t)

    # 4. Normalize standalone dates / times
    t = re.sub(r'\b\d{1,2}[-/](?:[a-z]{3}|\d{1,2})[-/]\d{2,4}\b|\b\d{1,2}:\d{2}(?:\s*(?:am|pm))?\b', '<time>', t)

    # 5. Normalize account masking patterns (e.g. XX1049, A/c ...4912)
    t = re.sub(r'[xX]{2,}\d{2,}', '<acct>', t)

    # 6. Normalize remaining standalone digits
    t = re.sub(r'\b\d+\b', '<num>', t)

    # 7. Collapse punctuation and whitespace
    t = re.sub(r'[^\w\s<>]', ' ', t)
    t = re.sub(r'\s+', ' ', t).strip()

    return t


def split_three_way_grouped(
    rows: List[Dict[str, str]],
    train_ratio: float = 0.70,
    calib_ratio: float = 0.15,
    holdout_ratio: float = 0.15,
    seed: int = 42
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], List[Dict[str, str]], Dict[str, Any]]:
    """
    Performs group-aware, stratified 3-way split across (label, language) strata.
    Groups near-duplicate and identical template fingerprints atomically into the same
    partition to guarantee ZERO cross-split template leakage.
    """
    if not (0.99 <= (train_ratio + calib_ratio + holdout_ratio) <= 1.01):
        raise ValueError("Split ratios must sum to 1.0 (e.g. 0.70, 0.15, 0.15).")

    random.seed(seed)

    # 1. Cluster rows by template fingerprint
    template_clusters = defaultdict(list)
    for row in rows:
        fp = extract_template_fingerprint(row.get("text", ""))
        template_clusters[fp].append(row)

    # 2. Assign each template cluster to a stratum based on dominant (label, language)
    strata = defaultdict(list)
    for fp, cluster in template_clusters.items():
        # Stratum key determined by majority label and language in the cluster
        labels = [r.get("label") for r in cluster]
        langs = [r.get("language") for r in cluster]
        stratum_key = (Counter(labels).most_common(1)[0][0], Counter(langs).most_common(1)[0][0])
        strata[stratum_key].append(cluster)

    train_clusters = []
    calib_clusters = []
    holdout_clusters = []

    # 3. Stratified allocation of clusters using normalized global deficit balancing
    total_all_rows = len(rows)
    target_train_total = total_all_rows * train_ratio
    target_calib_total = total_all_rows * calib_ratio
    target_holdout_total = total_all_rows * holdout_ratio

    cur_train_total = 0.0
    cur_calib_total = 0.0
    cur_holdout_total = 0.0

    for stratum_key, clusters in strata.items():
        random.shuffle(clusters)

        for c in clusters:
            c_len = len(c)
            # Normalized deficit: remaining fraction of split target
            deficits = [
                ((target_train_total - cur_train_total) / train_ratio, "train"),
                ((target_calib_total - cur_calib_total) / calib_ratio, "calib"),
                ((target_holdout_total - cur_holdout_total) / holdout_ratio, "holdout"),
            ]
            # Randomize tie-breaking so identical deficits do not skew to first partition
            random.shuffle(deficits)
            deficits.sort(key=lambda x: x[0], reverse=True)
            chosen = deficits[0][1]

            if chosen == "train":
                train_clusters.append(c)
                cur_train_total += c_len
            elif chosen == "calib":
                calib_clusters.append(c)
                cur_calib_total += c_len
            else:
                holdout_clusters.append(c)
                cur_holdout_total += c_len

    # 4. Ensure non-empty partitions at cluster level without breaking cluster atomicity
    if not calib_clusters and len(train_clusters) > 1:
        calib_clusters.append(train_clusters.pop())
    if not holdout_clusters and len(train_clusters) > 1:
        holdout_clusters.append(train_clusters.pop())

    # 5. Flatten clusters into individual rows
    train_rows = [row for c in train_clusters for row in c]
    calib_rows = [row for c in calib_clusters for row in c]
    holdout_rows = [row for c in holdout_clusters for row in c]

    # Final shuffle within each split
    random.shuffle(train_rows)
    random.shuffle(calib_rows)
    random.shuffle(holdout_rows)

    # 5. Verify zero cross-split template overlap
    train_fps = {extract_template_fingerprint(r["text"]) for r in train_rows}
    calib_fps = {extract_template_fingerprint(r["text"]) for r in calib_rows}
    holdout_fps = {extract_template_fingerprint(r["text"]) for r in holdout_rows}

    leakage_train_calib = train_fps.intersection(calib_fps)
    leakage_train_holdout = train_fps.intersection(holdout_fps)
    leakage_calib_holdout = calib_fps.intersection(holdout_fps)

    total_leakage = len(leakage_train_calib) + len(leakage_train_holdout) + len(leakage_calib_holdout)
    if total_leakage > 0:
        raise RuntimeError(
            f"Cross-split template leakage detected! "
            f"Train-Calib: {len(leakage_train_calib)}, Train-Holdout: {len(leakage_train_holdout)}, "
            f"Calib-Holdout: {len(leakage_calib_holdout)}"
        )

    split_stats = {
        "total_input_rows": len(rows),
        "total_unique_templates": len(template_clusters),
        "train": {
            "count": len(train_rows),
            "ratio": round(len(train_rows) / max(len(rows), 1), 3),
            "label_distribution": dict(Counter(r["label"] for r in train_rows)),
            "language_distribution": dict(Counter(r["language"] for r in train_rows))
        },
        "calibration": {
            "count": len(calib_rows),
            "ratio": round(len(calib_rows) / max(len(rows), 1), 3),
            "label_distribution": dict(Counter(r["label"] for r in calib_rows)),
            "language_distribution": dict(Counter(r["language"] for r in calib_rows))
        },
        "holdout": {
            "count": len(holdout_rows),
            "ratio": round(len(holdout_rows) / max(len(rows), 1), 3),
            "label_distribution": dict(Counter(r["label"] for r in holdout_rows)),
            "language_distribution": dict(Counter(r["language"] for r in holdout_rows))
        },
        "leakage_verification": {
            "train_calib_overlap": len(leakage_train_calib),
            "train_holdout_overlap": len(leakage_train_holdout),
            "calib_holdout_overlap": len(leakage_calib_holdout),
            "status": "PASSED (Zero template leakage across partitions)"
        }
    }

    return train_rows, calib_rows, holdout_rows, split_stats


def prepare_dataset(
    input_file: Path,
    output_dir: Path,
    train_ratio: float = 0.70,
    calib_ratio: float = 0.15,
    holdout_ratio: float = 0.15,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Audits input dataset, protects against frozen benchmark contamination,
    normalizes labels into canonical BENIGN/SUSPICIOUS, executes group-aware
    stratified 3-way partition, and exports train.csv, calibration.csv, holdout.csv,
    and split_report.json.
    """
    resolved_input = input_file.resolve()

    # 1. Contamination Barrier
    check_contamination(resolved_input)

    # 2. Audit input file
    print(f"Auditing candidate input file: {resolved_input}...")
    report = audit_dataset(resolved_input, auto_normalize=True)
    if not report.get("valid"):
        raise ValueError(f"Input dataset failed audit: {report.get('error', 'Schema or data integrity errors')}")

    # 3. Read and normalize rows
    raw_rows = []
    with open(resolved_input, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            raw_rows.append(r)

    # Contamination check on rows content
    check_contamination(resolved_input, rows=raw_rows)

    normalized_rows = [normalize_row(r, auto_normalize_labels=True) for r in raw_rows]

    print(
        f"Loaded {len(normalized_rows)} validated canonical rows. "
        f"Partitioning (Train: {train_ratio*100:.0f}%, Calib: {calib_ratio*100:.0f}%, Holdout: {holdout_ratio*100:.0f}%)..."
    )

    # 4. Perform group-aware 3-way split
    train_rows, calib_rows, holdout_rows, stats = split_three_way_grouped(
        normalized_rows,
        train_ratio=train_ratio,
        calib_ratio=calib_ratio,
        holdout_ratio=holdout_ratio,
        seed=seed
    )

    # 5. Export partitions
    output_dir.mkdir(parents=True, exist_ok=True)
    train_path = output_dir / "train.csv"
    calib_path = output_dir / "calibration.csv"
    holdout_path = output_dir / "holdout.csv"
    report_path = output_dir / "split_report.json"

    # Preserve governance columns if present in candidate rows
    fieldnames = list(REQUIRED_COLUMNS)
    if normalized_rows and any(col in normalized_rows[0] for col in GOVERNANCE_COLUMNS):
        fieldnames += [col for col in GOVERNANCE_COLUMNS if col in normalized_rows[0]]

    for path, data_subset in [(train_path, train_rows), (calib_path, calib_rows), (holdout_path, holdout_rows)]:
        with open(path, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data_subset)

    with open(report_path, mode="w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print("\n" + "=" * 70)
    print("SATARK THREE-WAY DATASET PARTITION REPORT")
    print("=" * 70)
    print(f"Total Canonical Rows:   {stats['total_input_rows']}")
    print(f"Unique Templates:       {stats['total_unique_templates']}")
    print(f"  Train Split (70%):    {stats['train']['count']} rows -> {train_path}")
    print(f"  Calibration (15%):    {stats['calibration']['count']} rows -> {calib_path}")
    print(f"  Holdout Test (15%):   {stats['holdout']['count']} rows -> {holdout_path}")
    print(f"Leakage Verification:   {stats['leakage_verification']['status']}")
    print("=" * 70 + "\n")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Prepare and 3-way split candidate dataset for Satark ML fine-tuning.")
    parser.add_argument("--input", required=True, type=str, help="Path to input candidate dataset CSV.")
    parser.add_argument("--output_dir", default="ml_service/dataset", type=str, help="Destination directory for splits.")
    parser.add_argument("--train_ratio", default=0.70, type=float, help="Fraction for training split (default: 0.70).")
    parser.add_argument("--calib_ratio", default=0.15, type=float, help="Fraction for calibration split (default: 0.15).")
    parser.add_argument("--holdout_ratio", default=0.15, type=float, help="Fraction for holdout split (default: 0.15).")
    parser.add_argument("--seed", default=42, type=int, help="Random seed for reproducibility.")
    args = parser.parse_args()

    prepare_dataset(
        Path(args.input),
        Path(args.output_dir),
        train_ratio=args.train_ratio,
        calib_ratio=args.calib_ratio,
        holdout_ratio=args.holdout_ratio,
        seed=args.seed
    )


if __name__ == "__main__":
    main()
