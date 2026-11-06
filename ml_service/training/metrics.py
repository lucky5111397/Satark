"""
Evaluation and Subgroup Metrics Utility for Satark Scam Detection.
Computes comprehensive global classification metrics, language-stratified metrics
(English, Hindi, Hinglish), and hard-negative subgroup metrics (OTP negation,
contextual negation, and genuine banking alerts).
"""

from collections import defaultdict
from typing import Dict, List, Any, Optional, Sequence


def calculate_binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, Any]:
    """
    Computes standard binary classification metrics:
    Precision, Recall, F1, Accuracy, and False Positive Rate (FPR) for class 1 (SUSPICIOUS).
    """
    total = len(y_true)
    if total == 0:
        return {
            "total": 0,
            "tp": 0, "fp": 0, "tn": 0, "fn": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "fpr": 0.0,
            "f1": 0.0
        }

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for yt, yp in zip(y_true, y_pred):
        if yt == 1 and yp == 1:
            tp += 1
        elif yt == 0 and yp == 1:
            fp += 1
        elif yt == 0 and yp == 0:
            tn += 1
        elif yt == 1 and yp == 0:
            fn += 1

    acc = (tp + tn) / total
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    return {
        "total": total,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "f1": round(float(f1), 4)
    }


def compute_subgroup_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    languages: Sequence[str],
    categories: Sequence[str],
    probs: Optional[Sequence[float]] = None
) -> Dict[str, Any]:
    """
    Computes multi-dimensional evaluation metrics:
    1. Overall performance (Accuracy, Precision, Recall, F1, FPR, Confusion Matrix).
    2. Language breakdown (English, Hindi, Hinglish).
    3. Hard-negative metrics for genuine messages:
       - OTP negation advisories
       - Contextual negation notices
       - Bank credit/debit alerts
       - Utility/service notifications
    """
    if not (len(y_true) == len(y_pred) == len(languages) == len(categories)):
        raise ValueError("y_true, y_pred, languages, and categories must have identical lengths.")

    # 1. Overall Metrics
    overall = calculate_binary_metrics(y_true, y_pred)

    # 2. Per-Language Breakdown
    lang_indices = defaultdict(list)
    for idx, lang in enumerate(languages):
        norm_l = (lang or "unknown").strip().lower()
        if norm_l in ("hi-latn", "hindi-latin", "roman-hindi"):
            norm_l = "hinglish"
        lang_indices[norm_l].append(idx)

    per_language = {}
    for lang in ["en", "hi", "hinglish"]:
        idxs = lang_indices.get(lang, [])
        sub_true = [y_true[i] for i in idxs]
        sub_pred = [y_pred[i] for i in idxs]
        m = calculate_binary_metrics(sub_true, sub_pred)
        per_language[lang] = m

    # 3. Hard-Negative Category Metrics on Genuine Samples (Ground Truth 0)
    # Define category mappings for hard-negatives
    OTP_NEGATION_CATS = {"otp_negation", "bank_otp"}
    CONTEXTUAL_NEGATION_CATS = {"contextual_negation", "genuine_kyc_reminder"}
    BANKING_TRANSACTIONAL_CATS = {
        "bank_credit", "bank_debit", "bank_service", "statement_alert",
        "bank_debit_credit", "bank_statement_notice", "transaction_alert", "transactional"
    }

    hard_negative_groups = {
        "otp_negation": {"total": 0, "fp": 0, "tn": 0, "fpr": 0.0},
        "contextual_negation": {"total": 0, "fp": 0, "tn": 0, "fpr": 0.0},
        "bank_transactional": {"total": 0, "fp": 0, "tn": 0, "fpr": 0.0}
    }

    for idx, (yt, yp, cat) in enumerate(zip(y_true, y_pred, categories)):
        if yt != 0:
            continue  # Hard negative metrics focus exclusively on genuine messages

        c_norm = (cat or "").strip().lower()

        target_group = None
        if c_norm in OTP_NEGATION_CATS or "otp" in c_norm and "negation" in c_norm:
            target_group = "otp_negation"
        elif c_norm in CONTEXTUAL_NEGATION_CATS or "negation" in c_norm:
            target_group = "contextual_negation"
        elif c_norm in BANKING_TRANSACTIONAL_CATS or "bank" in c_norm:
            target_group = "bank_transactional"

        if target_group:
            hard_negative_groups[target_group]["total"] += 1
            if yp == 1:
                hard_negative_groups[target_group]["fp"] += 1
            else:
                hard_negative_groups[target_group]["tn"] += 1

    for grp, vals in hard_negative_groups.items():
        if vals["total"] > 0:
            vals["fpr"] = round(float(vals["fp"] / vals["total"]), 4)

    # 4. Per-Category Breakdown Across All 12 Canonical Categories
    cat_indices = defaultdict(list)
    for idx, cat in enumerate(categories):
        norm_cat = (cat or "unknown").strip().lower()
        cat_indices[norm_cat].append(idx)

    per_category = {}
    for cat_name, idxs in sorted(cat_indices.items()):
        sub_true = [y_true[i] for i in idxs]
        sub_pred = [y_pred[i] for i in idxs]
        per_category[cat_name] = calculate_binary_metrics(sub_true, sub_pred)

    return {
        "overall": overall,
        "per_language": per_language,
        "per_category": per_category,
        "hard_negatives": hard_negative_groups
    }


def format_metrics_report(metrics: Dict[str, Any], title: str = "SATARK EVALUATION METRICS") -> str:
    """Formats metrics dictionary into a readable terminal/markdown report."""
    o = metrics.get("overall", {})
    pl = metrics.get("per_language", {})
    pc = metrics.get("per_category", {})
    hn = metrics.get("hard_negatives", {})

    lines = []
    lines.append("=" * 70)
    lines.append(title)
    lines.append("=" * 70)
    lines.append(f"Total Evaluated: {o.get('total', 0)}")
    lines.append(f"Accuracy:  {o.get('accuracy', 0.0)*100:.2f}%")
    lines.append(f"Precision: {o.get('precision', 0.0)*100:.2f}%")
    lines.append(f"Recall:    {o.get('recall', 0.0)*100:.2f}%")
    lines.append(f"F1 Score:  {o.get('f1', 0.0)*100:.2f}%")
    lines.append(f"FPR:       {o.get('fpr', 0.0)*100:.2f}%")
    lines.append(f"FNR:       {o.get('fnr', 0.0)*100:.2f}%")
    lines.append(f"Confusion: TP={o.get('tp', 0)} | FP={o.get('fp', 0)} | TN={o.get('tn', 0)} | FN={o.get('fn', 0)}")

    lines.append("\n--- Language Breakdown ---")
    for lang, m in pl.items():
        lines.append(
            f"  [{lang:8}] Total: {m.get('total', 0):3} | "
            f"Prec: {m.get('precision', 0.0)*100:.1f}% | "
            f"Rec: {m.get('recall', 0.0)*100:.1f}% | "
            f"FPR: {m.get('fpr', 0.0)*100:.1f}% | "
            f"FNR: {m.get('fnr', 0.0)*100:.1f}% | "
            f"F1: {m.get('f1', 0.0)*100:.1f}%"
        )

    lines.append("\n--- Category Breakdown ---")
    for cat, m in pc.items():
        lines.append(
            f"  [{cat:28}] Total: {m.get('total', 0):3} | "
            f"Prec: {m.get('precision', 0.0)*100:.1f}% | "
            f"Rec: {m.get('recall', 0.0)*100:.1f}% | "
            f"FPR: {m.get('fpr', 0.0)*100:.1f}% | "
            f"F1: {m.get('f1', 0.0)*100:.1f}%"
        )

    lines.append("\n--- Hard-Negative False Positive Rate (FPR on Genuine Alerts) ---")
    for grp, m in hn.items():
        lines.append(
            f"  {grp:22}: Total={m.get('total', 0):3} | "
            f"FP={m.get('fp', 0):2} | "
            f"FPR={m.get('fpr', 0.0)*100:.2f}%"
        )
    lines.append("=" * 70)

    return "\n".join(lines)

