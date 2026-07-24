# Aegis Bounty AI project guidance

## Purpose

Aegis is a scope-locked, evidence-first assistant for authorized web security assessments. It accepts a single URL through `aegis scan-url URL` or a reviewed YAML configuration, maps the authorized network and HTTP surface, records evidence, performs coverage gap analysis, and generates JSON, Markdown, and HTML reports.

Scanner output is an observation, not proof of a vulnerability. Preserve the distinction between detection confidence and exploitability. Never describe a finding as reportable without evidence of security impact and human validation.

## Safety boundary

- Work only with targets covered by explicit, current authorization.
- Never treat the existence of a URL, config file, or stored scan as proof of authorization.
- Keep hostname, wildcard, path, port, rate, request-budget, and private-network rules enforced by `ScopePolicy` and `SafeHttpClient`.
- Do not weaken authorization validation, scope enforcement, public-IP checks, request budgets, rate limits, or secret redaction.
- Do not autonomously run scans, payloads, credential testing, brute force, exploitation, cloud-metadata access, form submission, or state-changing requests.
- Do not use `--break-system-packages`, `--dangerously-skip-permissions`, or equivalent safety bypasses.
- Do not read or commit API keys, `.env` files, private keys, authorization profiles, or secrets captured in evidence.
- Treat `runs/`, reports, and SQLite evidence as potentially sensitive. Quote only the minimum evidence required and redact tokens, cookies, credentials, and personal data.

## Architecture

- `src/aegis_bounty/config.py`: validated configuration and authorization limits.
- `src/aegis_bounty/scope.py`: URL, hostname, port, path, and IP scope decisions.
- `src/aegis_bounty/recon.py`: scope-filtered passive discovery and optional Nuclei adapter.
- `src/aegis_bounty/network.py`: low-impact DNS and TLS mapping; no port scanning.
- `src/aegis_bounty/http_client.py`: scoped, rate-limited HTTP transport.
- `src/aegis_bounty/crawler.py`: bounded HTTP and JavaScript endpoint discovery.
- `src/aegis_bounty/checks.py`: content-aware observations.
- `src/aegis_bounty/triage.py`: host-policy deduplication.
- `src/aegis_bounty/gap_analysis.py`: assessment coverage ledger; its score is not a security score.
- `src/aegis_bounty/storage.py`: SQLite evidence ledger.
- `src/aegis_bounty/reporting.py`: JSON, Markdown, and HTML reports.
- `src/aegis_bounty/tool_catalog.py`: safety classification for requested external projects.
- `src/aegis_bounty/orchestrator.py`: end-to-end assessment pipeline.

## External tool policy

- Subfinder is the only requested project integrated into discovery, and runs only when `discover_subdomains` is explicitly enabled.
- PayloadsAllTheThings, NahamSec Resources, AllAboutBugBounty, and awesome-bugbounty-tools are analyst references only.
- dirsearch and APKLeaks are external specialist tools and are never launched automatically.
- reconFTW, Osmedeus, and scan4all are intentionally excluded from automatic execution because Aegis cannot enforce its scope and traffic budget inside their workflows.
- Use `aegis tools --json` to inspect the canonical catalog. Do not duplicate or silently change these classifications.

## Development workflow

Use Python 3.11 or newer in a virtual environment.

```bash
python -m pip install -e '.[dev]'
python -m ruff format .
python -m ruff check .
python -m mypy src
python -m pytest --cov=aegis_bounty --cov-report=term-missing
```

Before changing code:

1. Read the affected module and its tests.
2. Preserve unrelated worktree changes.
3. Add regression tests for bug fixes and safety decisions.
4. Run formatting, linting, type checking, and the complete test suite.
5. For end-to-end testing, use only `configs/local-lab.yaml` with a local service owned by the operator.

## Claude Code skills

- `/aegis-report <report.json-or-report.md>` performs evidence-based report and gap analysis without network activity.
- `/aegis-tool-plan <report.json-or-report.md>` recommends which registered capability can close a coverage gap without launching external tools.
