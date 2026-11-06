/** Keep decoded QR payloads inert; this function never opens or fetches them. */
export function routeQrPayload(payload) {
  const value = typeof payload === 'string' ? payload.trim() : '';
  if (/^https?:\/\//i.test(value)) return { field: 'url', value };

  const paymentScheme = /^(?:upi|intent|tez|gpay|phonepe|paytmmp|bhim):\/\//i.test(value);
  const paymentParameters = /(?:^|[?&#])pa=[^&\s]+/i.test(value);
  const barePaymentLink = /^(?:pay\?)?pa=[^&\s]+(?:&|$)/i.test(value);
  if (/^upi:\/\//i.test(value) || (paymentScheme && paymentParameters) || barePaymentLink) {
    return { field: 'text', value: `UPI payment request from QR code:\n${value}` };
  }
  return { field: 'text', value };
}

/** Used by both the submit button and the submission handler. */
export function canAnalyze(text, url) {
  return typeof text === 'string' && typeof url === 'string'
    && text.length <= 2000 && url.length <= 2048
    && Boolean(text.trim() || url.trim());
}

/** One validation path for the file picker and drag-and-drop. */
export function imageFileError(file) {
  if (!file || !['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
    return 'Invalid file format. Please select a PNG, JPEG, or WebP image.';
  }
  if (file.size > 4 * 1024 * 1024) {
    return 'File size exceeds 4 MiB limit. Please select a smaller screenshot.';
  }
  return null;
}
