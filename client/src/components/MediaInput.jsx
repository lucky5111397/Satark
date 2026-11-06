import React, { useState, useRef, useEffect } from 'react';
import { Camera, QrCode, Upload, AlertCircle, Check, X, Shield, FileText, ArrowRight, Copy, Loader2 } from 'lucide-react';
import jsQR from 'jsqr';
import { createWorker } from 'tesseract.js';
import { imageFileError, routeQrPayload } from '../lib/media.js';

/**
 * MediaInput Component:
 * Provides privacy-first local Screenshot OCR and QR decoding workflows.
 * 
 * Strict Security Guarantees:
 * - Images are never uploaded to any backend or third-party service.
 * - Processing occurs strictly in volatile client memory.
 * - Validates file types (PNG, JPEG, WebP) and 4 MiB size ceiling.
 * - Decoded QR URLs are displayed as inert plain text; NEVER auto-navigated or fetched.
 * - Text extracted from screenshots requires explicit user confirmation before analysis.
 * - Clean up: Object URLs are revoked on cancellation and unmount.
 */
export default function MediaInput({
  initialMode = 'ocr',
  activeTab,
  onTabChange,
  onTextExtracted,
  onUrlExtracted,
  onClose
}) {
  const [mode, setMode] = useState(activeTab || initialMode || 'ocr'); // 'ocr' | 'qr'
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [fileError, setFileError] = useState(null);
  
  // OCR states
  const [ocrText, setOcrText] = useState('');
  const [ocrStep, setOcrStep] = useState('idle'); // 'idle' | 'loaded' | 'processing' | 'review'
  const [ocrError, setOcrError] = useState(null);
  const [ocrProgress, setOcrProgress] = useState(null);

  // QR states
  const [qrResult, setQrResult] = useState(null);
  const [qrScanning, setQrScanning] = useState(false);
  const [qrError, setQrError] = useState(null);
  const [qrCopied, setQrCopied] = useState(false);
  const [hasNativeDetector, setHasNativeDetector] = useState(false);

  const fileInputRef = useRef(null);
  const imageElementRef = useRef(null);
  const ocrJobRef = useRef(null);
  const mediaVersionRef = useRef(0);

  // Cancel pending results as well as the worker, so old images cannot overwrite a new review.
  const stopOcr = () => {
    const job = ocrJobRef.current;
    ocrJobRef.current = null;
    if (job) {
      job.cancel();
      if (job.worker) void job.worker.terminate().catch(() => {});
    }
  };

  useEffect(() => () => {
    mediaVersionRef.current += 1;
    stopOcr();
  }, []);

  // Sync mode if activeTab prop changes externally
  useEffect(() => {
    if (activeTab && activeTab !== mode && (activeTab === 'ocr' || activeTab === 'qr')) {
      handleModeChange(activeTab, false);
    }
  }, [activeTab]);

  // Check for native BarcodeDetector support
  useEffect(() => {
    if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
      setHasNativeDetector(true);
    } else {
      setHasNativeDetector(false);
    }
  }, []);

  // Cleanup object URLs on unmount or file reset
  useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  const selectFile = (file) => {
    if (!file) return;
    handleClearFile();
    const error = imageFileError(file);
    if (error) {
      setFileError(error);
      return;
    }

    const objectUrl = URL.createObjectURL(file);
    setSelectedFile(file);
    setPreviewUrl(objectUrl);
    setOcrStep('loaded');
  };

  const handleFileSelect = (e) => selectFile(e.target.files?.[0]);
  const handleDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  };
  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    selectFile(e.dataTransfer.files?.[0]);
  };

  const handleClearFile = () => {
    mediaVersionRef.current += 1;
    stopOcr();
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    setSelectedFile(null);
    setPreviewUrl(null);
    setFileError(null);
    setQrResult(null);
    setQrError(null);
    setQrCopied(false);
    setQrScanning(false);
    setOcrText('');
    setOcrError(null);
    setOcrProgress(null);
    setOcrStep('idle');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleCopyQr = async () => {
    if (!qrResult) return;
    try {
      await navigator.clipboard.writeText(qrResult);
      setQrCopied(true);
      setTimeout(() => setQrCopied(false), 2000);
    } catch {
      // Ignore clipboard write failures gracefully
    }
  };

  // All worker, WASM and language requests stay on this application's origin.
  const handlePerformOcr = async () => {
    if (!selectedFile || ocrJobRef.current) return;
    setOcrStep('processing');
    setOcrError(null);
    setOcrProgress(null);

    let rejectJob;
    const interrupted = new Promise((_, reject) => { rejectJob = reject; });
    const job = { worker: null, cancel: () => rejectJob(new Error('OCR cancelled')) };
    ocrJobRef.current = job;
    const isCurrent = () => ocrJobRef.current === job;
    const assetRoot = new URL(`${import.meta.env.BASE_URL}tesseract/`, window.location.href).href;

    try {
      const startingWorker = createWorker('eng+hin', 1, {
        workerPath: `${assetRoot}worker.js`,
        corePath: `${assetRoot}core`,
        langPath: `${assetRoot}lang-data`,
        workerBlobURL: false,
        gzip: false,
        cacheMethod: 'none',
        // v5 initialization errors do not always reject createWorker's promise.
        // The local worker wrapper closes failed workers; this race releases the UI.
        errorHandler: () => rejectJob(new Error('Local OCR failed')),
        logger: ({ status, progress }) => {
          if (isCurrent() && status === 'recognizing text') {
            setOcrProgress(Math.round(progress * 100));
          }
        }
      }).then(async (worker) => {
        if (!isCurrent()) {
          await worker.terminate();
          throw new Error('OCR cancelled');
        }
        job.worker = worker;
        return worker;
      });

      const worker = await Promise.race([startingWorker, interrupted]);
      const { data } = await Promise.race([
        worker.recognize(selectedFile, {}, { text: true, blocks: false, hocr: false, tsv: false }),
        interrupted
      ]);
      if (isCurrent()) {
        const extracted = typeof data.text === 'string' ? data.text.trim() : '';
        setOcrText(extracted);
        if (!extracted) setOcrError('No text was found. Try a clearer image or type the message below.');
      }
    } catch {
      if (isCurrent()) {
        setOcrError('Text extraction failed. Check that the local OCR assets are available, retry with a clear image, or type the message below.');
      }
    } finally {
      if (isCurrent()) {
        ocrJobRef.current = null;
        setOcrStep('review');
        setOcrProgress(null);
      }
      if (job.worker) await job.worker.terminate().catch(() => {});
    }
  };

  // Confirm OCR text and send to main message analyzer
  const handleConfirmOcrText = () => {
    const trimmed = ocrText.trim();
    if (!trimmed) return;
    onTextExtracted(trimmed);
    handleClearFile();
    if (onClose) onClose();
  };

  // Local QR decoding via window.BarcodeDetector or pure local jsqr
  const handleScanQr = async () => {
    if (!imageElementRef.current) return;
    const version = mediaVersionRef.current;
    setQrScanning(true);
    setQrError(null);
    setQrResult(null);

    try {
      const img = imageElementRef.current;
      await img.decode();
      if (version !== mediaVersionRef.current) return;
      let decodedText = null;

      // 1. Try native Chromium BarcodeDetector if available
      if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
        try {
          const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
          const barcodes = await detector.detect(img);
          if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
            decodedText = barcodes[0].rawValue;
          }
        } catch {
          // Fall through to jsQR
        }
      }

      // 2. Pure local client-side jsQR fallback via offscreen canvas
      if (!decodedText) {
        const width = img.naturalWidth || img.width;
        const height = img.naturalHeight || img.height;

        if (width && height) {
          const canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          if (ctx) {
            ctx.drawImage(img, 0, 0, width, height);
            const imageData = ctx.getImageData(0, 0, width, height);
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
              inversionAttempts: 'attemptBoth'
            });
            if (code && code.data) {
              decodedText = code.data;
            }
          }
        }
      }

      if (version !== mediaVersionRef.current) return;
      if (decodedText) {
        setQrResult(decodedText);
      } else {
        setQrError('No QR code detected in this image. Ensure the QR code is clearly visible and well-lit.');
      }
    } catch (err) {
      if (version === mediaVersionRef.current) setQrError('Failed to decode QR code. Please verify image clarity.');
    } finally {
      if (version === mediaVersionRef.current) setQrScanning(false);
    }
  };

  const handleSendQrToAnalyzer = () => {
    if (!qrResult) return;
    const payload = routeQrPayload(qrResult);
    if (payload.field === 'url') onUrlExtracted(payload.value);
    else onTextExtracted(payload.value);
    handleClearFile();
    if (onClose) onClose();
  };

  const handleModeChange = (nextMode, notifyParent = true) => {
    mediaVersionRef.current += 1;
    stopOcr();
    setMode(nextMode);
    setQrResult(null);
    setQrError(null);
    setQrCopied(false);
    setQrScanning(false);
    setOcrText('');
    setOcrError(null);
    setOcrStep(selectedFile ? 'loaded' : 'idle');
    if (notifyParent && onTabChange) onTabChange(nextMode);
  };

  return (
    <div onDragOver={handleDragOver} onDrop={handleDrop} className="bg-[#FAF8F3] border border-[#005147]/20 rounded-xl p-4 sm:p-5 space-y-4 shadow-xs animate-in fade-in duration-150">
      {/* Header with Mode Switcher & Close */}
      <div className="flex items-center justify-between border-b border-[#0D1C2E]/10 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-[#005147]/10 text-[#005147]">
            <Camera className="w-4 h-4" />
          </div>
          <h3 className="text-sm font-bold text-[#0D1C2E]">
            Screenshot OCR & QR Import / छवि आयात
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {/* Tab Selector */}
          <div role="tablist" aria-label="Media input mode" className="inline-flex rounded-lg border border-[#0D1C2E]/15 p-0.5 bg-white text-xs">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'ocr'}
              onClick={() => handleModeChange('ocr')}
              className={`px-2.5 py-1 rounded-md font-medium transition-all cursor-pointer ${
                mode === 'ocr'
                  ? 'bg-[#005147] text-white shadow-2xs'
                  : 'text-[#0D1C2E]/70 hover:text-[#0D1C2E]'
              }`}
            >
              Screenshot OCR
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'qr'}
              onClick={() => handleModeChange('qr')}
              className={`px-2.5 py-1 rounded-md font-medium transition-all cursor-pointer ${
                mode === 'qr'
                  ? 'bg-[#005147] text-white shadow-2xs'
                  : 'text-[#0D1C2E]/70 hover:text-[#0D1C2E]'
              }`}
            >
              QR Decoder
            </button>
          </div>

          {onClose && (
            <button
              type="button"
              onClick={() => { handleClearFile(); onClose(); }}
              className="p-1 rounded-md text-[#0D1C2E]/50 hover:text-[#0D1C2E] hover:bg-black/5"
              aria-label="Close media drawer"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Privacy & Zero-Retention Notice */}
      <div className="flex items-start gap-2 text-[11px] text-[#005147] bg-[#005147]/8 rounded-lg p-2.5 border border-[#005147]/15">
        <Shield className="w-4 h-4 shrink-0 mt-0.5" />
        <span>
          <strong>Local Memory Security:</strong> Images are processed exclusively in your browser memory and never uploaded to any server. Object references are revoked when done.
        </span>
      </div>

      {/* File Upload / Drop Area */}
      {!previewUrl ? (
        <div className="space-y-2">
          <label 
            htmlFor="media-file-input"
            className="flex flex-col items-center justify-center border-2 border-dashed border-[#0D1C2E]/20 hover:border-[#005147] rounded-xl p-6 bg-white/70 hover:bg-white transition-all cursor-pointer text-center group"
          >
            <div className="w-10 h-10 rounded-full bg-[#005147]/10 text-[#005147] flex items-center justify-center mb-2 group-hover:scale-105 transition-transform">
              <Upload className="w-5 h-5" />
            </div>
            <span className="text-xs sm:text-sm font-semibold text-[#0D1C2E]">
              {mode === 'ocr' ? 'Select or drop scam screenshot' : 'Select or drop QR code image'}
            </span>
            <span className="text-[11px] text-[#0D1C2E]/60 mt-1">
              Supports PNG, JPEG, WebP • Maximum size 4 MiB
            </span>
            <input
              id="media-file-input"
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp"
              onChange={handleFileSelect}
              className="hidden"
            />
          </label>
          {fileError && (
            <div className="flex items-center gap-1.5 text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-lg p-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{fileError}</span>
            </div>
          )}
        </div>
      ) : (
        /* Image Preview & Processing Controls */
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-4 items-start bg-white p-3.5 rounded-xl border border-[#0D1C2E]/10">
            {/* Image Thumbnail */}
            <div className="relative shrink-0 w-full sm:w-44 h-36 bg-slate-100 rounded-lg overflow-hidden border border-slate-200 flex items-center justify-center">
              <img
                ref={imageElementRef}
                src={previewUrl}
                alt="Selected scam screenshot or QR"
                className="max-w-full max-h-full object-contain"
              />
              <button
                type="button"
                onClick={handleClearFile}
                className="absolute top-1 right-1 p-1 bg-black/60 hover:bg-black/80 text-white rounded-md transition-colors"
                title="Remove image"
                aria-label="Remove image"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Processing Panel */}
            <div className="flex-1 min-w-0 space-y-2.5">
              <div className="flex items-center justify-between text-xs text-[#0D1C2E]/70">
                <span className="font-mono truncate">{selectedFile?.name}</span>
                <span className="shrink-0">{((selectedFile?.size || 0) / 1024).toFixed(1)} KB</span>
              </div>

              {/* MODE: OCR */}
              {mode === 'ocr' && (
                <div className="space-y-3">
                  {ocrStep === 'loaded' && (
                    <div className="space-y-2">
                      <p className="text-xs text-[#0D1C2E]/80">
                        Extract English and Hindi text locally, then review it before analysis.
                      </p>
                      <button
                        type="button"
                        onClick={handlePerformOcr}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#005147] hover:bg-[#0B5248] text-white text-xs font-semibold transition-colors cursor-pointer"
                      >
                        <FileText className="w-3.5 h-3.5" />
                        <span>Extract Text for Review</span>
                      </button>
                    </div>
                  )}

                  {ocrStep === 'processing' && (
                    <div className="space-y-2">
                      <p role="status" aria-live="polite" className="flex items-center gap-2 text-xs text-[#005147]">
                        <Loader2 className="w-4 h-4 animate-spin" />
                        {ocrProgress === null ? 'Loading English and Hindi OCR...' : `Extracting text: ${ocrProgress}%`}
                      </p>
                      <button type="button" onClick={() => { stopOcr(); setOcrStep('review'); }} className="text-xs underline text-[#0D1C2E] cursor-pointer">
                        Cancel OCR and type manually
                      </button>
                    </div>
                  )}

                  {ocrStep === 'review' && (
                    <div className="space-y-2">
                      {ocrError ? (
                        <p role="alert" className="text-xs text-amber-900 bg-amber-50 border border-amber-200 rounded-lg p-2">{ocrError}</p>
                      ) : (
                        <p className="text-xs text-[#005147]">Review the extracted text and correct any mistakes before using it.</p>
                      )}

                      <label htmlFor="ocr-review-text" className="text-xs font-bold text-[#0D1C2E] block">
                        Review / Edit Extracted Message Text:
                      </label>
                      <textarea
                        id="ocr-review-text"
                        rows={3}
                        value={ocrText}
                        onChange={(e) => setOcrText(e.target.value)}
                        placeholder="Type, transcribe or paste text visible in the screenshot..."
                        className="w-full text-xs sm:text-sm p-2.5 rounded-lg border border-[#0D1C2E]/20 bg-[#F4F1E8]/40 focus:bg-white focus:border-[#005147] focus:outline-hidden"
                      />

                      <div className="flex items-center gap-2 pt-1">
                        <button
                          type="button"
                          disabled={!ocrText.trim()}
                          onClick={handleConfirmOcrText}
                          className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                            ocrText.trim()
                              ? 'bg-[#005147] hover:bg-[#0B5248] text-white cursor-pointer'
                              : 'bg-slate-200 text-slate-400 cursor-not-allowed'
                          }`}
                        >
                          <Check className="w-3.5 h-3.5" />
                          <span>Confirm & Use in Analyzer</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setOcrStep('loaded')}
                          className="px-2.5 py-1.5 text-xs text-[#0D1C2E]/70 hover:text-[#0D1C2E]"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* MODE: QR Decoder */}
              {mode === 'qr' && (
                <div className="space-y-3">
                  {!qrResult && (
                    <div className="space-y-2">
                      <p className="text-xs text-[#0D1C2E]/80">
                        Scan the loaded image for QR code links without navigating or fetching.
                      </p>
                      
                      {!hasNativeDetector && (
                        <div className="text-[11px] text-emerald-900 bg-emerald-50 border border-emerald-200 rounded-lg p-2 leading-relaxed">
                          <strong>Local QR Engine Active:</strong> Cross-browser offline QR decoding is active via <code className="font-mono text-emerald-950 font-bold">jsqr</code> (runs 100% in local browser memory with zero network requests).
                        </div>
                      )}

                      <button
                        type="button"
                        disabled={qrScanning}
                        onClick={handleScanQr}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#005147] hover:bg-[#0B5248] text-white text-xs font-semibold transition-colors cursor-pointer"
                      >
                        <QrCode className="w-3.5 h-3.5" />
                        <span>{qrScanning ? 'Scanning QR...' : 'Decode QR Code Locally'}</span>
                      </button>

                      {qrError && (
                        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-lg p-2">
                          {qrError}
                        </div>
                      )}
                    </div>
                  )}

                  {qrResult && (
                    <div className="space-y-2">
                      <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-800">
                        <Check className="w-4 h-4 text-emerald-600" />
                        <span>QR Code Decoded Successfully (Plain Text Only):</span>
                      </div>

                      {/* Displayed strictly as plain text. NEVER an <a> tag that auto-navigates. */}
                      <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg font-mono text-xs text-slate-800 break-all select-all">
                        {qrResult}
                      </div>

                      <div className="flex items-center gap-2 pt-1">
                        <button
                          type="button"
                          onClick={handleSendQrToAnalyzer}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#005147] hover:bg-[#0B5248] text-white text-xs font-semibold transition-colors cursor-pointer"
                        >
                          <ArrowRight className="w-3.5 h-3.5" />
                          <span>{routeQrPayload(qrResult).field === 'url' ? 'Send to URL Analyzer' : 'Use in Message Analyzer'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleCopyQr}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium transition-colors cursor-pointer"
                        >
                          {qrCopied ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-600" />
                              <span className="text-emerald-700 font-semibold">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

