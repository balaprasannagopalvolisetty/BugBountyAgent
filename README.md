# BugBountyAgent — Aegis Bounty AI

Aegis is a scope-locked, evidence-first assistant for **authorized** web security assessments and bug bounty programs. It maps a permitted attack surface, performs low-impact checks, optionally triages captured evidence with an LLM, proposes hypotheses for human validation, and produces reproducible reports.

It is intentionally not an autonomous exploitation framework. It does not submit forms, mutate state, brute-force credentials, evade WAFs, fetch cloud metadata, generate weaponized deserialization payloads, or claim that an LLM observation proves a vulnerability. Those actions are too risky to make a safe default and frequently violate bounty rules.

## What works in v0.5

- Exact-domain and wildcard scope rules, excluded hosts/paths, port allowlists, authorization expiry, and public-IP enforcement
- DNS/IP preflight checks before each network request
- Async crawl of links, forms, scripts, redirects, and likely endpoints found in JavaScript
- Content-aware header, cookie, disclosure, CORS, redirect, and exposed-document observations
- Opt-in, read-only active CORS validation
- Optional `subfinder` / `amass` discovery and Nuclei adapter, with all results re-filtered through scope
- SQLite evidence ledger and deterministic deduplication
- OpenAI Responses API triage with evidence-bounded prompts and secret redaction
- Rule-based chain hypotheses for analyst review
- JSON, Markdown, and standalone HTML reports
- Request budgets, concurrency limits, per-host rate limiting, and a descriptive user agent
- Separate detection-confidence and exploitability labels
- Host-policy deduplication and suppression of document-header noise on static assets
- A safety-classified catalog for common bug bounty tools and research collections
- Low-impact DNS and TLS mapping for each authorized host, including addresses, records, provider hints, certificate identity and lifetime, protocol, cipher, and key strength
- Coverage gap analysis that separates tested areas from unavailable, disabled, external, and manual-only assessment areas

## Install

Kali Linux, Debian, or Ubuntu:

```bash
sudo apt update
sudo apt install -y python3-full python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp configs/example.yaml scope.yaml
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item configs\example.yaml scope.yaml
```

Fill in the actual program scope and authorization metadata. `authorization.confirmed` must be `true`, the reference and authorizer must be genuine, and the authorization must not be expired. Aegis refuses to scan otherwise. Do not use `--break-system-packages` on Kali; use the virtual environment.

After pulling a release that adds Python dependencies, refresh the active virtual environment:

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
aegis doctor
```

If `aegis doctor` reports that `dnspython` or `cryptography` is missing, the editable project was updated but its virtual-environment dependencies were not. The install command above repairs it without modifying Kali's system Python.

## Use

Scan directly from one URL. On first use for a hostname, Aegis asks for the real authorization details in the terminal and stores them in `~/.aegis/authorizations/`. No YAML editing is required:

```bash
aegis scan-url https://vast.ai/ --dry-run
aegis scan-url https://vast.ai/ --no-ai
```

Later scans of the same exact hostname need only the URL. Use `--reauthorize` when the program reference or expiration changes. Aegis derives only the exact hostname and never silently expands it to wildcard subdomains.

The YAML workflow remains available for engagements that need custom exclusions, wildcard scope, rate limits, or other settings:

```bash
aegis init-target https://vast.ai/ --output scope.yaml
# Complete the authorization section once for this custom configuration.
aegis validate scope.yaml
aegis doctor
aegis scan scope.yaml
```

To enable AI triage, set `ai.enabled: true` and provide `OPENAI_API_KEY` in the environment. No key is stored in the configuration or database.

Useful commands:

```bash
aegis scan scope.yaml --dry-run
aegis scan scope.yaml --no-ai
aegis report runs/<scan-id>/evidence.sqlite3
```

## Pipeline

1. Validate authorization and compile scope rules.
2. Resolve every candidate host and reject private, loopback, link-local, multicast, reserved, or unspecified addresses unless private-network testing was explicitly allowed.
3. Discover and normalize in-scope assets.
4. Map DNS records, resolved addresses, hosting hints, and HTTPS certificate/transport metadata without port scanning.
5. Crawl with a global request budget and per-host limits.
6. Record raw observations; never silently turn an observation into a confirmed vulnerability.
7. Optionally ask OpenAI to rank evidence and suggest non-destructive manual validation.
8. Build clearly labeled chain hypotheses.
9. Calculate a coverage gap analysis, including authenticated, business-logic, discovery, and optional-tool gaps.
10. Render reports with the network map, coverage ledger, request IDs, evidence, confidence, and remediation.

## External tools

External tools are optional. If installed, discovery supports `subfinder` and `amass`. Nuclei is disabled unless `scan.use_nuclei` is true. Aegis passes only explicit arguments, applies its rate limit, and imports only in-scope results. You remain responsible for reviewing selected templates against each program's rules.

Inspect the complete catalog and local installation status with:

```powershell
aegis tools
aegis tools --json
```

| Project | Role in Aegis | Automatic execution |
| --- | --- | --- |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Analyst reference corpus | Never |
| [dirsearch](https://github.com/maurosoria/dirsearch) | External active path discovery | Never |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Integrated passive subdomain discovery | Only when `discover_subdomains` is enabled |
| [NahamSec beginner resources](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters) | Learning reference | Never |
| [reconFTW](https://github.com/six2dez/reconftw) | Broad external orchestrator | Never |
| [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) | Analyst reference | Never |
| [Osmedeus](https://github.com/j3ssie/osmedeus) | Broad external orchestrator | Never |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | External local APK analysis | Never |
| [scan4all](https://github.com/GhostTroops/scan4all) | High-impact external framework | Never |
| [awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools) | Curated tool index | Never |

`dirsearch`, reconFTW, Osmedeus, and scan4all can generate traffic outside Aegis request accounting or invoke intrusive modules. They are deliberately not launched by `aegis scan`. Payload and learning repositories are not vendored or treated as executable input.

Every scan report includes the status of all ten requested projects so an analyst can see which capability was covered, disabled, unavailable, intentionally excluded, or retained as reference material. The coverage percentage measures how much of the assessment plan ran; it is not a security score and never proves that a target is safe.

## Development

```powershell
python -m ruff check .
python -m mypy src
python -m pytest --cov=aegis_bounty --cov-report=term-missing
```

## Claude Code AI help

The repository includes a project `CLAUDE.md`, guarded `.claude/settings.json`, and two project skills. Claude Code receives the architecture, development workflow, evidence standards, and safety classifications automatically when started from the repository root.

On Kali Linux, install Claude Code and open this repository:

```bash
curl -fsSL https://claude.ai/install.sh | bash
cd ~/Desktop/BugBountyAgent
claude
```

Inside Claude Code, use:

```text
/aegis-scan https://vast.ai/
/aegis-report runs/<scan-id>/report.json
/aegis-tool-plan runs/<scan-id>/report.json
```

`/aegis-scan` is manual-only: Claude cannot select it autonomously. It asks for the target's real authorization reference, authorizing organization, expiration, and confirmation; refreshes the active virtual environment; runs the exact-host assessment; and analyzes the report in the same Claude session. The deterministic scan uses `--no-ai` because Claude Code itself performs the AI review afterward.

The shared permissions allow tests, linting, type checking, read-only Git inspection, configuration validation, and tool-catalog inspection. They deny autonomous configuration-file scans, external scanner execution, Git pushes, secret files, and modification of generated evidence.

## Safety model

A configuration file is not a substitute for permission. Only test systems you own or have explicit authorization to assess. Keep the program rules, safe-harbor terms, scope reference, test accounts, rate caps, and prohibited techniques with the engagement record. Stop when a target behaves unexpectedly or the program asks you to stop.
