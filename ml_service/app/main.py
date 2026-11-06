"""
FastAPI application entry point for Satark Multilingual Scam Detection ML Microservice.
Provides secure localhost-only endpoints for health checks and text classification.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from .config import settings
from .model_handler import model_handler
from .inference import predict_message
from .schemas import PredictRequest, PredictResponse, HealthResponse

# Configure structured logging with strict omission of user message text
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("satark.ml.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Loads model weights once upon startup and cleans up on shutdown.
    """
    logger.info("Starting Satark ML Microservice...")
    model_handler.load()
    yield
    logger.info("Shutting down Satark ML Microservice...")


app = FastAPI(
    title="Satark ML Microservice",
    description="Local Multilingual Scam Detection Inference Service using XLM-RoBERTa",
    version="1.0.0",
    docs_url=None,    # Disable Swagger UI in production to minimize attack surface
    redoc_url=None,   # Disable ReDoc in production
    lifespan=lifespan
)

# 1. Strict CORS Middleware: Only allow local loopback origins
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "http://127.0.0.1:5173",
    "http://localhost:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"]
)


# 2. Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# 3. Privacy-Preserving Validation Error Handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Custom handler to prevent leaking input text inside validation error responses.
    """
    # Error locations and messages can contain user-controlled keys or values.
    # Return only known field names and our own fixed messages.
    field_messages = {
        "text": "Text must be a string of 1 to 2000 characters and cannot be blank.",
        "lang": "Language must be en, hi, or hinglish.",
        "body": "Request body must be a valid JSON object."
    }
    sanitized_errors = []
    for err in exc.errors():
        location = tuple(err.get("loc", ()))
        field = location[1] if location in (("body", "text"), ("body", "lang")) else "body"
        sanitized_errors.append({
            "field": field,
            "msg": field_messages[field]
        })
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "Invalid request payload", "details": sanitized_errors}
    )


# 4. Generic 500 Error Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catches unhandled errors and returns a generic response with zero stack-trace leakage.
    """
    logger.error(f"Unhandled server exception: {type(exc).__name__}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal inference service error"}
    )


# ==============================================================================
# Endpoints
# ==============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health and readiness probe.
    Transparently reveals if model weights are loaded and active.
    """
    model_file = settings.resolve_model_path()
    return HealthResponse(
        status="ok",
        service="satark-ml-service",
        version="1.0.0",
        model_loaded=model_handler.is_loaded,
        model_name=settings.model_name,
        model_path=str(model_file),
        runtime=model_handler.runtime,
        disclosure=(
            "Model is active and ready for inference."
            if model_handler.is_loaded
            else "Model weights not found. Microservice will report 'model_unavailable' to caller."
        )
    )


@app.post("/predict", response_model=PredictResponse)
async def predict(payload: PredictRequest):
    """
    Scam message classification endpoint.
    Accepts text payload and returns structured classification result.
    """
    return predict_message(payload.text, payload.lang)


if __name__ == "__main__":
    import uvicorn
    # Enforces strict 127.0.0.1 binding per security and privacy invariants
    uvicorn.run("ml_service.app.main:app", host=settings.host, port=settings.port, reload=False)

