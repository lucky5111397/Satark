// Ensure Vite dev server runs persistently in daemon/background environments without exiting on stdin EOF
process.env.CI = 'true';

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Inline plugin injecting strict CSP meta tag exclusively into build output
function cspPlugin() {
  return {
    name: 'satark-csp-injector',
    apply: 'build',
    transformIndexHtml(html) {
      const cspDirectives = [
        "default-src 'self'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "worker-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "font-src 'self'",
        "connect-src 'self' http://127.0.0.1:5000 http://localhost:5000",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join('; ');

      const metaTag = `\n    <meta http-equiv="Content-Security-Policy" content="${cspDirectives}" />`;
      return html.replace('</head>', `${metaTag}\n  </head>`);
    }
  };
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    cspPlugin()
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true
  },
  preview: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true
  }
});

