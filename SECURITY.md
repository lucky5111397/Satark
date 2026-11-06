# Security

Satark is a local prototype. It has no accounts or authentication and is not configured as a public multi-user service. Keep Express and the optional ML service bound to loopback unless you separately design and review a hosted deployment.

## Runtime boundaries

- Express validates input types/lengths, limits JSON bodies to 10 KiB, applies Helmet/rate limiting, and sends `Cache-Control: no-store` on API routes.
- CORS uses an exact origin allowlist. CORS is not authentication or a firewall.
- React renders user text as strings/elements. Submitted URLs and QR payloads are never automatically opened or fetched.
- Optional ML calls accept only literal loopback origins (with `localhost` mapped to `127.0.0.1`), reject redirects and bound the timeout including the response body.
- The application does not persist or log raw runtime messages. Review infrastructure logging before hosting. Evaluation tools should also omit message snippets.
- OCR uses locally prepared assets. Dependency/setup/training downloads occur separately from inference.

## Before publishing changes

Review the actual files selected for commit, not just `.gitignore`. Exclude credentials, private messages, model binaries, generated reports and notebook outputs. A pattern scan cannot establish that every possible secret or personal identifier is absent.

Run audits and regression suites after changes. New advisories can appear after a clean audit. Python requirements pin direct dependencies; audit the resolved transitive environment too. The Transformers 5 migration needs installation, regression and model-parity validation before ML is enabled.

Historical synthetic results do not establish real-world safety. Never tune on frozen test/holdout rows.

## Reporting a vulnerability

Use private vulnerability reporting if the repository maintainer enables it. Do not put credentials, private messages or exploit details affecting users in public issues. No private contact address or response-time commitment is configured here.
