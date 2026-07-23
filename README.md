# BugBountyAgent — Aegis Bounty AI

Aegis is a scope-locked, evidence-first assistant for **authorized** web security assessments and bug bounty programs. It maps a permitted attack surface, performs low-impact checks, optionally triages captured evidence with an LLM, proposes hypotheses for human validation, and produces reproducible reports.

It is intentionally not an autonomous exploitation framework. It does not submit forms, mutate state, brute-force credentials, evade WAFs, fetch cloud metadata, generate weaponized deserialization payloads, or claim that an LLM observation proves a vulnerability. Those actions are too risky to make a safe default and frequently violate bounty rules.

## What works in v0.1

- Exact-domain and wildcard scope rules, excluded hosts/paths, port allowlists, authorization expiry, and public-IP enforcement
- DNS/IP preflight checks before each network request
- Async crawl of links, forms, scripts, redirects, and likely endpoints found in JavaScript
- Passive header, cookie, disclosure, CORS, redirect, and exposed-document observations
- Opt-in, read-only active CORS validation
- Optional `subfinder` / `amass` discovery and Nuclei adapter, with all results re-filtered through scope
- SQLite evidence ledger and deterministic deduplication
- OpenAI Responses API triage with evidence-bounded prompts and secret redaction
- Rule-based chain hypotheses for analyst review
- JSON, Markdown, and standalone HTML reports
- Request budgets, concurrency limits, per-host rate limiting, and a descriptive user agent

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Copy the example configuration and fill in the program scope and authorization metadata:

```powershell
Copy-Item configs\example.yaml scope.yaml
```

`authorization.confirmed` must be `true`, the reference and authorizer must be filled in, and the authorization must not be expired. Aegis refuses to scan otherwise.

## Use

```powershell
aegis validate scope.yaml
aegis doctor
aegis scan scope.yaml
```

To enable AI triage, set `ai.enabled: true` and provide `OPENAI_API_KEY` in the environment. No key is stored in the configuration or database.

Useful commands:

```powershell
aegis scan scope.yaml --dry-run
aegis scan scope.yaml --no-ai
aegis report runs\<scan-id>\evidence.sqlite3
```

## Pipeline

1. Validate authorization and compile scope rules.
2. Resolve every candidate host and reject private, loopback, link-local, multicast, reserved, or unspecified addresses unless private-network testing was explicitly allowed.
3. Discover and normalize in-scope assets.
4. Crawl with a global request budget and per-host limits.
5. Record raw observations; never silently turn an observation into a confirmed vulnerability.
6. Optionally ask OpenAI to rank evidence and suggest non-destructive manual validation.
7. Build clearly labeled chain hypotheses.
8. Render reports with request IDs, evidence, confidence, and remediation.

## External tools

External tools are optional. If installed, discovery supports `subfinder` and `amass`. Nuclei is disabled unless `scan.use_nuclei` is true. Aegis passes only explicit arguments, applies its rate limit, and imports only in-scope results. You remain responsible for reviewing selected templates against each program's rules.

## Development

```powershell
python -m ruff check .
python -m mypy src
python -m pytest --cov=aegis_bounty --cov-report=term-missing
```

## Safety model

A configuration file is not a substitute for permission. Only test systems you own or have explicit authorization to assess. Keep the program rules, safe-harbor terms, scope reference, test accounts, rate caps, and prohibited techniques with the engagement record. Stop when a target behaves unexpectedly or the program asks you to stop.
