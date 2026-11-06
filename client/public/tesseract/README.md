# Local English and Hindi OCR

From the project root, run `npm --prefix client run setup:ocr` once with network access.
The script uses the already installed Tesseract.js and core version 5.1.1; it installs no packages.
It copies the worker and all four WASM core bundles here and downloads `eng.traineddata`
and `hin.traineddata` from the official [tessdata_fast 4.1.0 release](https://github.com/tesseract-ocr/tessdata_fast/tree/4.1.0).
It also copies/downloads the accompanying Apache license notices.

Generated assets are ignored by Git. Repeat setup after a fresh clone before running or building
the client. The script prints each asset's byte size and SHA256 and rejects files over 5,000,000 bytes.
Downloads are checked against pinned SHA256 hashes; verified existing language files are reused offline.
The source `worker.js` bootstrap and this README remain versioned.

At runtime, `MediaInput.jsx` uses `createWorker('eng+hin', 1, ...)` with local paths:

- `workerPath`: `/tesseract/worker.js` (loads the local `worker.min.js`)
- `corePath`: `/tesseract/core`
- `langPath`: `/tesseract/lang-data`, with `gzip: false`

The `.wasm.js` core bundles contain their own WASM bytes; separate `.wasm` downloads are unnecessary.
Both language files load together. No native Tesseract install, API key, or OCR environment variable is needed.
No CDN fallback is configured. OCR images/text stay in memory; language caching is disabled.
Recognition errors leave an editable manual transcription field. The worker is released after recognition,
failure, or cancellation; the bootstrap also closes workers that fail during v5 initialization.

Test with a clear PNG/JPEG/WebP screenshot below 4 MiB. Click **Extract Text for Review**, correct the result,
then **Confirm & Use in Analyzer**. Text is sent to Express only when you click the analysis button.
