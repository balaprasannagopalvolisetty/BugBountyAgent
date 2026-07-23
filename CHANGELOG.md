# Changelog

## 0.3.0 — 2026-07-23

- Add `aegis init-target URL` for a single-URL input workflow.
- Derive an exact-host include rule when `include_domains` is omitted.
- Never expand a single URL to wildcard subdomains automatically.
- Keep authorization metadata and validation mandatory before scanning.

## 0.2.0 — 2026-07-23

- Apply CSP, Referrer-Policy, and `X-Content-Type-Options` checks only to HTML documents.
- Suppress generic infrastructure banners such as `Server: AmazonS3`.
- Collapse duplicate host-policy observations while retaining affected URLs in metadata.
- Report detection confidence separately from exploitability.
- Add `aegis tools` and `aegis tools --json` with a safety-classified catalog of ten requested bug bounty projects.
- Expand installation instructions for Kali Linux and other Debian-based systems.

## 0.1.0 — 2026-07-23

- Initial scope-locked crawler, evidence store, checks, OpenAI triage, chain hypotheses, and reports.
