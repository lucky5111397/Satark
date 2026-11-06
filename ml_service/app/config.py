"""
Configuration settings for Satark ML Microservice.
Enforces loopback binding, character length limits, and model artifact paths.
"""

import os
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Base directory for the ml_service package
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment configuration from ml_service/.env if present
_env_path = BASE_DIR / ".env"
if _env_path.exists():
    load_dotenv(_env_path)

class Settings(BaseModel):
    # Network & Security
    # Invariant: Must bind strictly to 127.0.0.1 for local privacy preservation
    host: Literal["127.0.0.1"] = Field(
        default_factory=lambda: os.getenv("HOST", "127.0.0.1"), validate_default=True
    )
    port: int = Field(default=int(os.getenv("PORT", "8000")))

    # Model Artifact Paths
    model_name: str = Field(default=os.getenv("MODEL_NAME", "FacebookAI/xlm-roberta-base"))
    model_path: Path = Field(
        default=Path(os.getenv("MODEL_PATH", str(BASE_DIR / "artifacts" / "model_quantized.onnx")))
    )
    tokenizer_path: Path = Field(
        default=Path(os.getenv("TOKENIZER_PATH", str(BASE_DIR / "artifacts" / "tokenizer")))
    )

    # Boundaries and Inference Hyperparameters
    max_text_length: int = Field(default=int(os.getenv("MAX_TEXT_LENGTH", "2000")))
    max_token_length: int = Field(default=int(os.getenv("MAX_TOKEN_LENGTH", "128")))
    # Calibrated optimal decision threshold (T* = 0.62 suppresses false alarms on legitimate banking/OTP traffic)
    confidence_threshold: float = Field(default=float(os.getenv("CONFIDENCE_THRESHOLD", "0.62")))

    # Label Mappings: Class 0 is 'BENIGN', Class 1 is 'SUSPICIOUS'
    id2label: dict[int, str] = {0: "BENIGN", 1: "SUSPICIOUS"}
    label2id: dict[str, int] = {"BENIGN": 0, "SUSPICIOUS": 1}

    def resolve_model_path(self) -> Path:
        """Returns absolute path to the model file."""
        if self.model_path.is_absolute():
            return self.model_path
        return BASE_DIR / self.model_path

    def resolve_tokenizer_path(self) -> Path:
        """Returns absolute path to tokenizer directory."""
        if self.tokenizer_path.is_absolute():
            return self.tokenizer_path
        return BASE_DIR / self.tokenizer_path

    def resolve_metadata_path(self) -> Path:
        """Returns absolute path to model_metadata.json if present."""
        model_dir = self.resolve_model_path().parent
        meta_in_dir = model_dir / "model_metadata.json"
        if meta_in_dir.exists():
            return meta_in_dir
        return BASE_DIR / "artifacts" / "model_metadata.json"


settings = Settings()

