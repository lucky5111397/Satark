# Satark optional ML service

This FastAPI service accepts text from the Express backend over loopback and can run a local ONNX classifier. The deterministic rules engine works without this service. ML is disabled by default in Express; missing model or tokenizer assets produce `model_unavailable`, without a fabricated prediction.

The service code supports CPU ONNX inference. A model filename or committed metadata does not establish model identity, quantization, accuracy, or successful inference. The current private bundle has not been revalidated for public release. Synthetic data, not real-world accuracy.

## Dependency status before enabling ML

The publication cleanup prepares updated Python dependency pins and a Transformers v5 source migration after advisories were found in the previous stack. No packages were installed during this review, and the migrated Python service, training pipeline, and real model inference remain unverified at runtime. Use Python 3.11 or newer, review the dependency audit, and complete a compatible-environment regression pass before enabling ML. Source edits alone do not establish a working or security-cleared model service.

No Python packages are installed by the Node client/server setup. Inference dependencies are in `requirements.txt`; optional training/export and test dependencies are listed separately in `requirements-training.txt` and `requirements-dev.txt`.

## Local configuration

Run commands from the repository root in PowerShell. In a compatible Python environment, install the reviewed requirements before performing the pending runtime checks:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r ml_service/requirements.txt
Copy-Item ml_service/.env.example ml_service/.env
```

The default artifact layout is:

```text
ml_service/artifacts/
  model_quantized.onnx
  model_metadata.json
  tokenizer/
    config.json
    tokenizer_config.json
    tokenizer.json
    ...other files required by the matching tokenizer
```

Weights and the tokenizer bundle are excluded from Git. The runtime does not download them. See [artifact requirements](artifacts/README.md) for the alternate layout of the existing private bundle and its verification limits.

Start the service with an explicit loopback bind:

```powershell
uvicorn ml_service.app.main:app --host 127.0.0.1 --port 8000
Invoke-RestMethod http://127.0.0.1:8000/health
```

`HOST` in the service settings accepts only `127.0.0.1`; a non-loopback value fails validation. The Uvicorn CLI has its own bind option, so retain the explicit `--host 127.0.0.1` shown above. `/health` reports `model_loaded`; file presence alone is insufficient. After verifying the service and bundle, enable it in `server/.env`:

```dotenv
ML_ENABLED=true
ML_SERVICE_URL=http://127.0.0.1:8000
```

## API and privacy behavior

- `GET /health`: readiness and model status; includes the local artifact path.
- `POST /predict`: JSON `{ "text": "Synthetic example", "lang": "en" }`; `lang` is optional and accepts `en`, `hi`, or `hinglish`.
- Text is bounded to 1–2,000 characters; whitespace-only input is rejected. Language must be a string of at most eight characters.
- Validation responses use fixed messages and allowlisted field names. Inference logs omit message contents.
- Tokenizer loading uses `local_files_only=True`. Prediction code has no third-party API lookup, URL reputation lookup, or remote model download.
- Do not expose this optional unauthenticated development service to a public network. Binding settings are not a network firewall.

## Training, export, and evaluation

`curation/` generates or scrubs candidate data; `training/` validates data, prepares partitions, trains, exports, quantizes, and evaluates. `dataset/` contains synthetic data and its schema. The notebook in `notebooks/` is an alternate training workflow, with empty saved outputs.

Training may download a base model and requires the separate training requirements. The evaluator loads tokenizers and PyTorch models with `local_files_only=True` and `trust_remote_code=False`; PyTorch loading requires Safetensors. A tokenizer identifier must already be cached or supplied as a matching local directory. Evaluation does not download missing assets.

These commands describe the existing CLIs; they were not executed as part of the source-only publication review. Use a fresh output directory so a training experiment does not overwrite frozen artifacts:

```powershell
python -m ml_service.training.validate_dataset --file ml_service/dataset/train.csv
python -m ml_service.training.train --data_path ml_service/dataset/train.csv --val_path ml_service/dataset/calibration.csv --output_dir scratch/ml-training/checkpoint
python -m ml_service.training.export_onnx --checkpoint_dir scratch/ml-training/checkpoint --output_file scratch/ml-training/model.onnx --manifest_file scratch/ml-training/manifest.json
python -m ml_service.training.quantize_onnx --input_file scratch/ml-training/model.onnx --output_file scratch/ml-training/model_quantized.onnx
python -m ml_service.training.evaluate --model_path scratch/ml-training/model_quantized.onnx --tokenizer_path scratch/ml-training/tokenizer --data_file ml_service/dataset/calibration.csv --output_file scratch/ml-training/calibration-report.json
```

The training script uses `calibration.csv` for validation and threshold selection. Do not use holdout results to select models, thresholds, or hyperparameters. The frozen `eval/test_set.csv` is reserved for explicitly authorized evaluation milestones; follow [the evaluation policy](../eval/EVAL_POLICY.md). Do not run model comparison against the holdout as a development task.

Synthetic generation does not read a benchmark by default and reports benchmark isolation as `NOT_RUN`. An explicit `--benchmark` enables that check; access to a frozen benchmark still requires milestone authorization:

```powershell
python -m ml_service.curation.synthetic_generator --mode pilot --output scratch/pilot.csv
```

Evaluator misclassification reports retain sample IDs and metadata, without message snippets. Review any custom dataset's provenance, rights, and privacy before using or publishing it.

## Verification

After installing a reviewed, compatible Python stack and the test dependencies from `requirements-dev.txt`, run the focused API/privacy regressions:

```powershell
python -m unittest ml_service.tests.test_validation ml_service.tests.test_publication_privacy ml_service.tests.test_synthetic_generator
```

These tests use synthetic inputs, a fake inference runtime, and a temporary benchmark fixture; they do not validate real model inference or read the frozen evaluation dataset. Real bundle loading, offline inference, and numerical parity require a separate runtime verification pass.
