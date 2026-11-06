/* Local Tesseract v5 bootstrap. Never forward OCR errors to external services. */
const sendMessage = self.postMessage.bind(self);
self.postMessage = (message, ...options) => {
  sendMessage(message, ...options);
  // v5 can leave initialization pending when language data cannot be loaded.
  // Forward the failure to the UI's errorHandler, then release this worker.
  if (message?.status === 'reject') self.close();
};
self.addEventListener('error', () => self.close());
importScripts('./worker.min.js');
