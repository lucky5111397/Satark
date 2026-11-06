# Post-test source changes

## 6 November 2026: publication cleanup and privacy fixes

These changes were made after the existing recorded evaluations. No frozen-test or holdout evaluation was run, no fixture rows were inspected, and no detection weights, rule phrases or thresholds were tuned.

- `server/detection/classifier.js`: enforce loopback origins, reject redirects, retain a bounded deadline through response-body reading, validate response schemas, use local disclosures, and describe the synchronous stub as not invoked rather than claiming weights are absent.
- `server/detection/analyzeMessage.js`: retain standalone URLs up to the API's accepted 2,048-character boundary instead of truncating them to 500. Client evidence rendering uses the same limit.
- Express language hints are normalized before the optional ML request.
- The optional Python stack and training/export APIs were migrated in source. Installation, regression, training/export and real-model parity remain unverified. No model weights, tokenizer bundle, manifest, checkpoint or calibration threshold was changed.
- Validation errors and generated ML evaluation reports omit raw input text. Synthetic generation no longer selects a frozen benchmark by default.

Detector SHA-256 at the end of this cleanup, using the evaluation harness's filename-sorted `server/data/*.js` and `server/detection/*.js` byte concatenation:

`f8238871eb07af70260bef86d5f80365f5de44de9d72c6e8e63350be919fd6df`

Hash-only integrity checks match the pre-cleanup fixtures:

| Protected fixture | SHA-256 |
| --- | --- |
| `eval/test_set.csv` | `09661d914ddd90ca1cf2de78abd2db49e438b20638c4fd71e4e01607c6b9d86f` |
| `ml_service/dataset/holdout.csv` | `8d83ee0d3d7c7062687c8bc867fed0bb0d9b870c1a235758b2c8c6e94b1ba58f` |

Existing reports remain historical and do not validate this revision. Refresh the development benchmark only after runtime regressions pass. **Synthetic data, not real-world accuracy.**
