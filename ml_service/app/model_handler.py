"""
Model Lifecycle Handler for Satark ML Microservice.
Manages ONNX Runtime sessions, tokenizer initialization, and safe fallback.
Ensures model weights and calibrated metadata are loaded ONCE at application startup.
Guarantees zero outbound network calls, strict CPU execution, and robust error containment.
"""

import json
import logging
import os
import re
import threading
from typing import Optional, Tuple, Dict, Any, List
import numpy as np

from .config import settings

# Configure logger without leaking private message text
logger = logging.getLogger("satark.ml.model_handler")


def mask_entities(text: str) -> str:
    """
    Applies regex-based aggressive entity masking for URLs and phone numbers,
    used when evaluating the legacy IndicBERTv2 scam classification model.
    """
    if not text or not isinstance(text, str):
        return ""

    # 1. Mask URLs, naked domains, and obfuscated protocols
    masked = re.sub(
        r'(?:hxxps?|https?|ftp)://\S+|www\.\S+|\b[a-zA-Z0-9.-]+\.(?:com|in|org|net|xyz|top|site|online|live|click|vip|info|app|cc|co|pw)\b(?:/\S*)?',
        '[URL]',
        text,
        flags=re.IGNORECASE
    )

    # 2. Mask Indian mobile numbers and contact phone sequences
    masked = re.sub(
        r'(?:\+?91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}\b|(?:\+?91[\-\s]?)?[6-9]\d{9}\b',
        '[PHONE]',
        masked
    )

    return masked


class ModelHandler:
    """
    Thread-safe model manager handling ONNX Runtime inference sessions,
    calibrated thresholds, and Hugging Face tokenizers.
    """

    def __init__(self):
        self.session = None
        self.tokenizer = None
        self.runtime: str = "none"
        self.is_loaded: bool = False
        self.load_error: Optional[str] = None
        self.input_names: List[str] = []
        self.output_names: List[str] = []
        self.metadata: Dict[str, Any] = {}
        self.model_name: str = settings.model_name
        self.threshold: float = settings.confidence_threshold
        self.id2label: Dict[int, str] = {0: "BENIGN", 1: "SUSPICIOUS"}
        self.label2id: Dict[str, int] = {"BENIGN": 0, "SUSPICIOUS": 1}
        self.uses_entity_masking: bool = False
        self._lock = threading.Lock()

    def _load_metadata(self) -> None:
        """
        Attempts to load accompanying model_metadata.json to extract
        calibrated decision threshold, input tensor signatures, and labels.
        """
        meta_path = settings.resolve_metadata_path()
        if meta_path.exists() and meta_path.is_file():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

                # Extract calibrated threshold
                calib_thresh = self.metadata.get("optimal_threshold") or self.metadata.get("threshold")
                if calib_thresh is not None:
                    self.threshold = float(calib_thresh)
                    logger.info(f"Loaded optimal calibrated decision threshold: T* = {self.threshold:.3f}")

                # Extract model identifier
                meta_name = (
                    self.metadata.get("model_name") or
                    self.metadata.get("base_model") or
                    self.metadata.get("model_name_or_path")
                )
                if meta_name:
                    self.model_name = str(meta_name)

                # Check if legacy entity masking is requested
                if "indicbert" in self.model_name.lower():
                    self.uses_entity_masking = True
                    logger.info("Entity masking enabled for IndicBERT model architecture.")
                else:
                    self.uses_entity_masking = False

                logger.info(f"Model metadata successfully loaded from: {meta_path}")

            except Exception as e:
                logger.warning(f"Failed to parse model_metadata.json: {e}. Using default settings.")
        else:
            logger.info("No local model_metadata.json found. Using defaults from environment/settings.")

    def load(self) -> bool:
        """
        Attempts to load the tokenizer and model artifact at startup.
        Never throws unhandled exceptions that crash the service;
        instead sets is_loaded=False and records the diagnostic state.
        """
        with self._lock:
            model_file = settings.resolve_model_path()
            tokenizer_dir = settings.resolve_tokenizer_path()

            logger.info("Initializing Satark ML ModelHandler...")
            logger.info(f"Target model path: {model_file}")

            # 1. Verify Model Artifact Existence and Integrity
            if not model_file.exists() or not model_file.is_file():
                self.is_loaded = False
                self.runtime = "none"
                self.load_error = (
                    f"Model artifact not found at '{model_file}'. "
                    "Inference will return 'model_unavailable' until an ONNX artifact is placed here."
                )
                logger.warning(self.load_error)
                return False

            # Verify non-empty file
            try:
                if model_file.stat().st_size == 0:
                    self.is_loaded = False
                    self.runtime = "none"
                    self.load_error = f"Model artifact at '{model_file}' is 0 bytes (corrupted or empty)."
                    logger.error(self.load_error)
                    return False
            except Exception as e:
                self.is_loaded = False
                self.runtime = "none"
                self.load_error = f"Cannot inspect model artifact: {e}"
                logger.error(self.load_error)
                return False

            # 2. Load Associated Metadata & Thresholds
            self._load_metadata()

            # 3. Attempt ONNX Runtime Session Loading
            try:
                import onnxruntime as ort

                # Configure CPU execution provider with optimal thread allocation
                sess_options = ort.SessionOptions()
                sess_options.intra_op_num_threads = max(1, os.cpu_count() or 2)
                sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

                logger.info("Loading ONNX Runtime InferenceSession...")
                self.session = ort.InferenceSession(
                    str(model_file),
                    sess_options=sess_options,
                    providers=["CPUExecutionProvider"]
                )

                self.input_names = [inp.name for inp in self.session.get_inputs()]
                self.output_names = [out.name for out in self.session.get_outputs()]
                self.runtime = "onnx"
                logger.info(f"ONNX model loaded successfully. Inputs: {self.input_names}, Outputs: {self.output_names}")

            except ImportError:
                self.is_loaded = False
                self.runtime = "none"
                self.load_error = "onnxruntime is not installed in the Python environment."
                logger.error(self.load_error)
                return False
            except Exception as e:
                self.is_loaded = False
                self.runtime = "none"
                self.load_error = f"Failed to load ONNX model artifact: {type(e).__name__}"
                logger.error(f"ONNX session creation error: {e}")
                return False

            # 4. Attempt Tokenizer Loading (Strictly Local - Zero Outbound Network Calls)
            try:
                from transformers import AutoTokenizer

                if tokenizer_dir.exists() and tokenizer_dir.is_dir():
                    logger.info(f"Loading local tokenizer from '{tokenizer_dir}'...")
                    self.tokenizer = AutoTokenizer.from_pretrained(
                        str(tokenizer_dir), local_files_only=True, trust_remote_code=False
                    )
                else:
                    self.is_loaded = False
                    self.runtime = "none"
                    self.load_error = (
                        f"Local tokenizer directory not found at '{tokenizer_dir}'. "
                        "Outbound network downloads are strictly prohibited by security rules."
                    )
                    logger.warning(self.load_error)
                    return False

                logger.info("Tokenizer loaded successfully.")
            except Exception as e:
                self.is_loaded = False
                self.load_error = f"Failed to load tokenizer: {type(e).__name__}"
                logger.error(f"Tokenizer load error: {e}")
                return False

            self.is_loaded = True
            self.load_error = None
            logger.info("Satark ML ModelHandler successfully initialized and ready for inference.")
            return True

    def tokenize(self, text: str) -> Optional[dict]:
        """
        Tokenizes text using the loaded tokenizer with length bounds and
        multilingual script preservation (English, Roman Hinglish, Devanagari Hindi).
        """
        if not self.tokenizer:
            return None

        # 1. Truncate text to maximum configured length
        bounded_text = text[: settings.max_text_length]

        # 2. Apply entity masking only if configured for legacy architectures
        processed_text = mask_entities(bounded_text) if self.uses_entity_masking else bounded_text

        # 3. Tokenize processed text
        encoded = self.tokenizer(
            processed_text,
            max_length=settings.max_token_length,
            padding="max_length",
            truncation=True,
            return_tensors="np"
        )

        feed_dict = {}
        if "input_ids" in self.input_names:
            feed_dict["input_ids"] = encoded["input_ids"].astype(np.int64)
        if "attention_mask" in self.input_names:
            feed_dict["attention_mask"] = encoded["attention_mask"].astype(np.int64)
        if "token_type_ids" in self.input_names:
            if "token_type_ids" in encoded:
                feed_dict["token_type_ids"] = encoded["token_type_ids"].astype(np.int64)
            else:
                feed_dict["token_type_ids"] = np.zeros_like(encoded["input_ids"], dtype=np.int64)

        return feed_dict

    def tokenize_batch(self, texts: List[str]) -> Optional[dict]:
        """
        Tokenizes a batch of texts using the loaded tokenizer with length bounds and
        multilingual script preservation.
        """
        if not self.tokenizer:
            return None

        bounded_texts = [t[: settings.max_text_length] for t in texts]
        processed_texts = [
            mask_entities(t) if self.uses_entity_masking else t
            for t in bounded_texts
        ]

        encoded = self.tokenizer(
            processed_texts,
            max_length=settings.max_token_length,
            padding="max_length",
            truncation=True,
            return_tensors="np"
        )

        feed_dict = {}
        if "input_ids" in self.input_names:
            feed_dict["input_ids"] = encoded["input_ids"].astype(np.int64)
        if "attention_mask" in self.input_names:
            feed_dict["attention_mask"] = encoded["attention_mask"].astype(np.int64)
        if "token_type_ids" in self.input_names:
            if "token_type_ids" in encoded:
                feed_dict["token_type_ids"] = encoded["token_type_ids"].astype(np.int64)
            else:
                feed_dict["token_type_ids"] = np.zeros_like(encoded["input_ids"], dtype=np.int64)

        return feed_dict

    def run_inference(self, feed_dict: dict) -> Tuple[int, float, float]:
        """
        Executes a forward pass on the ONNX session using optimal calibrated threshold.
        Returns:
            (predicted_class_id, confidence_score, raw_scam_probability)
        """
        if not self.session or not self.is_loaded:
            raise RuntimeError("InferenceSession is not active.")

        outputs = self.session.run(self.output_names, feed_dict)
        logits = outputs[0]  # Shape: [1, num_classes]

        # Compute numerically stable softmax
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probabilities = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

        scam_prob = float(probabilities[0][1])

        # Apply optimal calibrated threshold (T*)
        if scam_prob >= self.threshold:
            predicted_class = 1  # SUSPICIOUS
            confidence = scam_prob
        else:
            predicted_class = 0  # BENIGN
            confidence = float(probabilities[0][0])

        return predicted_class, round(confidence, 4), round(scam_prob, 4)

    def run_batch_inference(self, feed_dict: dict) -> List[Tuple[int, float, float]]:
        """
        Executes a forward pass on a batch of inputs in the ONNX session using the calibrated threshold.
        Returns:
            List of (predicted_class_id, confidence_score, raw_scam_probability) for each item in the batch.
        """
        if not self.session or not self.is_loaded:
            raise RuntimeError("InferenceSession is not active.")

        outputs = self.session.run(self.output_names, feed_dict)
        logits = outputs[0]  # Shape: [batch_size, num_classes]

        # Compute numerically stable softmax across batch
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probabilities = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

        batch_results = []
        for i in range(len(probabilities)):
            scam_prob = float(probabilities[i][1])
            if scam_prob >= self.threshold:
                predicted_class = 1  # SUSPICIOUS
                confidence = scam_prob
            else:
                predicted_class = 0  # BENIGN
                confidence = float(probabilities[i][0])
            batch_results.append((predicted_class, round(confidence, 4), round(scam_prob, 4)))

        return batch_results


# Global singleton instance
model_handler = ModelHandler()
