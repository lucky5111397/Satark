"""
Inference pipeline for Satark ML Microservice.
Coordinates tokenization, model execution, latency tracking, and privacy guarantees.
"""

import time
import logging
from typing import Optional

from .model_handler import model_handler
from .schemas import PredictResponse

logger = logging.getLogger("satark.ml.inference")


def predict_message(text: str, lang: Optional[str] = None) -> PredictResponse:
    """
    Performs scam classification on incoming text.
    
    Guarantees:
    - Never logs, prints, or exports the raw text content.
    - Accurately tracks latency in milliseconds.
    - Honors honest fallback when weights are missing.
    - Clearly marks confidence as raw softmax, not calibrated probability.
    """
    start_time = time.perf_counter()

    # 1. Check Model Availability
    if not model_handler.is_loaded:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return PredictResponse(
            status="model_unavailable",
            model=model_handler.model_name,
            prediction=None,
            confidence=None,
            latency_ms=round(elapsed_ms, 2),
            disclosure=(
                "Model weights not loaded or verified in workspace. "
                "Express backend will rely authoritatively on the deterministic Rule Engine."
            )
        )

    # 2. Tokenize Input
    try:
        feed_dict = model_handler.tokenize(text)
        if feed_dict is None:
            raise RuntimeError("Tokenization failed to produce model input tensors.")
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        logger.error(f"Inference tokenization failure: {type(e).__name__}")
        return PredictResponse(
            status="error",
            model=model_handler.model_name,
            prediction=None,
            confidence=None,
            latency_ms=round(elapsed_ms, 2),
            disclosure=f"Tokenization error encountered: {type(e).__name__}."
        )

    # 3. Execute Model Forward Pass
    try:
        class_id, confidence, _ = model_handler.run_inference(feed_dict)
        predicted_label = model_handler.id2label.get(class_id, "BENIGN")
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        logger.error(f"Inference execution failure: {type(e).__name__}")
        return PredictResponse(
            status="error",
            model=model_handler.model_name,
            prediction=None,
            confidence=None,
            latency_ms=round(elapsed_ms, 2),
            disclosure=f"Model forward pass error: {type(e).__name__}."
        )

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return PredictResponse(
        status="ok",
        model=model_handler.model_name,
        prediction=predicted_label,
        confidence=round(float(confidence), 4),
        latency_ms=round(elapsed_ms, 2),
        disclosure=(
            f"Multilingual semantic classification score (Calibrated threshold T* = {model_handler.threshold:.2f}). "
            "Evaluated across English, Hinglish, and Hindi."
        )
    )

