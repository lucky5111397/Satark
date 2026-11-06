# Local model artifacts

This directory holds optional local ONNX and tokenizer assets. Large model files and the tokenizer bundle are ignored by Git. There is currently no published, verified model download link. The Node application remains usable with `ML_ENABLED=false`.

## Default layout

The checked-in environment template and Python settings expect:

```text
artifacts/
  model_quantized.onnx
  model_metadata.json
  tokenizer/
    config.json
    tokenizer_config.json
    tokenizer.json
    ...matching tokenizer assets
```

Paths in `ml_service/.env` are relative to `ml_service/`:

```dotenv
MODEL_PATH=artifacts/model_quantized.onnx
TOKENIZER_PATH=artifacts/tokenizer
MODEL_NAME=FacebookAI/xlm-roberta-base
```

The name `model_quantized.onnx` is a configured filename, not proof of quantization or measured performance. Obtain assets only from a source whose identity, rights, and integrity have been verified. Keep graph external-data files beside their graph with the exact filenames it references. Do not rename just one component of a bundle.

## Existing private bundle layout

The local workspace also has an ignored graph named `model_dynamic_gemm_fixed.onnx`, its `model_dynamic_gemm_fixed.onnx.data` external weights, and tokenizer files directly inside `artifacts/`. These files are not included in a public clone. To select that layout locally, the explicit overrides are:

```dotenv
MODEL_PATH=artifacts/model_dynamic_gemm_fixed.onnx
TOKENIZER_PATH=artifacts
```

These settings select paths only. They do not establish model identity, compatibility, calibration, or inference readiness. Do not enable ML until a matching graph, external data, tokenizer, label mapping, and metadata have passed verification. There is no automatic download or fallback to a remote tokenizer in the runtime.

## Metadata is a contract, not a validation result

The committed `model_metadata.json` describes an XLM-R model contract with `validation_status: CONTRACT_SPECIFIED`. `manifest.json` records `checkpoint_status: PENDING_LOCAL_WEIGHT_BUNDLE`. Its `calibration_metadata_sha256` does not match the currently committed metadata file. This discrepancy remains unresolved; do not describe the manifest as verified provenance or successful parity evidence.

The publication cleanup preserves these files, model thresholds, and private weights. Revalidate their relationship to the actual bundle in a separate controlled model review. Runtime loading checks file availability and whether the ONNX session/tokenizer load; it does not verify manifest hashes or authenticate the bundle.

## Verification needed before use

1. Install the reviewed updated dependency stack and complete the pending compatibility checks described in the [ML service README](../README.md).
2. Verify bundle provenance, usage rights, file hashes, model/tokenizer identity, external data, and the intended label order and threshold.
3. In an offline test environment, load the bundle, check `/health`, and verify genuine and suspicious synthetic requests plus unavailable-model behavior.
4. Validate export parity and document actual runtime measurements before claiming model performance, quantization, or accuracy.

Until then, retain `ML_ENABLED=false`. Missing or unloadable artifacts must remain `model_unavailable`; unavailable evidence must never be presented as safe.
