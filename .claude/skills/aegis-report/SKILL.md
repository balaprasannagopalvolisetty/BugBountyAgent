---
name: Aegis report analyst
description: Analyze an existing Aegis JSON or Markdown report, distinguish scanner observations from reportable vulnerabilities, and prioritize coverage gaps. Use when the user asks Claude to review scan results, validate findings, explain network mapping, or perform gap analysis.
argument-hint: <report.json-or-report.md>
allowed-tools: Read Grep Glob
disallowed-tools: Bash WebFetch WebSearch
---

Analyze the Aegis report at `$ARGUMENTS` without making network requests or running scanners.

1. Read `CLAUDE.md` and the supplied report. Prefer `report.json` when both JSON and Markdown exist.
2. Confirm the scan identifier, target project, timestamps, request count, and whether the scan completed.
3. Summarize the network layer: hosts, resolved addresses, DNS relationships, provider hints, TLS trust, certificate identity and lifetime, protocol, cipher, ALPN, and key strength. State what was not mapped.
4. Review each observation against its exact request/response evidence. Separate detection confidence from exploitability.
5. Classify every material item as one of:
   - reportable candidate requiring human validation;
   - potentially useful lead with missing impact evidence;
   - informational hardening;
   - false positive or not applicable.
6. Explain chain hypotheses as hypotheses only. Do not invent missing steps, credentials, responses, or impact.
7. Review every coverage gap. Prioritize authenticated authorization boundaries, business logic, truncated crawling, unresolved hosts, TLS failures, and missing specialist coverage.
8. Treat the coverage percentage as assessment completeness, never as a security rating.
9. Redact cookies, tokens, API keys, credentials, personal data, and private certificate material.
10. Finish with a short next-step plan limited to non-destructive manual validation permitted by the program.

If the path is missing or only an SQLite database is supplied, ask for the generated `report.json` or `report.md`. Do not run `aegis scan`, external tools, payloads, or active probes.
