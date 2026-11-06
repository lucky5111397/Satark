/**
 * Server entrypoint for Satark detection backend.
 * 
 * Rules:
 * - Reads PORT, HOST, CLIENT_ORIGIN from environment.
 * - Prints ONLY a single startup line with host and port.
 * - Enforces request and header timeouts against slowloris attacks.
 */

import dotenv from 'dotenv';
import { createApp } from './app.js';

dotenv.config();

const PORT = parseInt(process.env.PORT || '5000', 10);
const HOST = process.env.HOST || '127.0.0.1';
// Support both localhost and 127.0.0.1 loopback origins for local development
let clientOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173';
if (clientOrigin.includes('http://localhost:5173') && !clientOrigin.includes('http://127.0.0.1:5173')) {
  clientOrigin = `${clientOrigin},http://127.0.0.1:5173`;
}

const app = createApp({ clientOrigin });

const server = app.listen(PORT, HOST, () => {
  // Print only a clean startup line with host and port
  process.stdout.write(`Satark server listening on http://${HOST}:${PORT}\n`);
});

// Configure request and header timeouts (10s request, 11s headers)
server.requestTimeout = 10000;
server.headersTimeout = 11000;
server.keepAliveTimeout = 5000;

