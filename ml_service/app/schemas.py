"""
Pydantic data schemas for Satark ML Microservice requests and responses.
Enforces strict boundaries, input validation, and transparent error schemas.
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


class PredictRequest(BaseModel):
    """
    Inbound prediction request payload.
    Boundaries:
    - Text: 1 to 2000 characters.
    - Optional language indicator ('en', 'hi', 'hinglish').
    """
    text: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Raw message text to be classified. Must be between 1 and 2000 characters."
    )
    lang: Optional[str] = Field(
        default=None,
        strict=True,
        max_length=8,
        description="Optional language hint ('en', 'hi', 'hinglish')."
    )

    @field_validator("text")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Text cannot be empty or whitespace only.")
        return v

    @field_validator("lang")
    @classmethod
    def validate_language(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = v.strip().lower()
        allowed = {"en", "hi", "hinglish"}
        if normalized not in allowed:
            raise ValueError("Language must be en, hi, or hinglish.")
        return normalized


class PredictResponse(BaseModel):
    """
    Outbound prediction response payload.
    Provides clear status, prediction, raw softmax confidence, latency, and honest disclosure.
    """
    status: Literal["ok", "model_unavailable", "error"] = Field(
        ...,
        description="Status of the inference operation."
    )
    model: str = Field(
        ...,
        description="Identifier of the model performing inference."
    )
    prediction: Optional[Literal["BENIGN", "SUSPICIOUS"]] = Field(
        default=None,
        description="Predicted class label. Null when model is unavailable or in error."
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Raw softmax confidence score [0.0 - 1.0]. Not calibrated probability."
    )
    latency_ms: float = Field(
        ...,
        description="End-to-end inference execution time in milliseconds."
    )
    disclosure: str = Field(
        ...,
        description="Forensic disclosure regarding model calibration, limitations, and fallback."
    )


class HealthResponse(BaseModel):
    """
    Health check response detailing service readiness and model weight status.
    """
    status: Literal["ok"] = Field(default="ok")
    service: str = Field(default="satark-ml-service")
    version: str = Field(default="1.0.0")
    model_loaded: bool = Field(
        ...,
        description="Indicates whether model weights are currently loaded in memory."
    )
    model_name: str = Field(...)
    model_path: str = Field(
        ...,
        description="File path checked for model artifact."
    )
    runtime: Literal["onnx", "torch", "none"] = Field(
        ...,
        description="Active execution engine."
    )
    disclosure: str = Field(
        ...,
        description="Human-readable readiness status."
    )

