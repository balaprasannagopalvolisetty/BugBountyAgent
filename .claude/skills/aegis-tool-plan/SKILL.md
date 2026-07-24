---
name: Aegis tool coverage planner
description: Map Aegis coverage gaps to the ten registered bug bounty projects while respecting their integration and safety classification. Use when the user asks which tool could improve coverage or how the requested repositories help an assessment.
argument-hint: <report.json-or-report.md>
allowed-tools: Read Grep Glob
disallowed-tools: Bash WebFetch WebSearch
---

Create a capability plan for the Aegis report at `$ARGUMENTS`. Do not execute any tool or make network requests.

Read these sources first:

- `src/aegis_bounty/tool_catalog.py` for the canonical integration and safety classification.
- `src/aegis_bounty/gap_analysis.py` for coverage semantics.
- The supplied report for actual gaps and tool availability.

Use the projects only in these roles:

- PayloadsAllTheThings: human-reviewed methodology and payload reference; never dispatch automatically.
- dirsearch: bounded active path discovery only when program rules explicitly permit brute-force traffic.
- Subfinder: passive subdomain discovery through Aegis only when wildcard scope is explicitly authorized.
- NahamSec Resources: learning and methodology reference.
- reconFTW: broad external orchestrator; never auto-run from Aegis or Claude Code.
- AllAboutBugBounty: learning and methodology reference.
- Osmedeus: external workflow orchestrator; never auto-run from Aegis or Claude Code.
- APKLeaks: local analysis of an authorized APK, with secret-aware handling.
- scan4all: intrusive broad scanner; intentionally excluded from automatic execution.
- awesome-bugbounty-tools: curated reference index whose linked tools require independent review.

For each uncovered area, provide:

1. the gap and evidence from the report;
2. the most relevant registered capability, if any;
3. whether it is integrated, external, reference-only, unavailable, or excluded;
4. the authorization or program-rule prerequisite;
5. a safe human-controlled next step;
6. residual coverage that still requires authenticated, browser, mobile, business-logic, or manual review.

Do not recommend installing every project. Do not imply that tool installation closes a gap or proves security. Prefer existing Aegis functionality before external tools.
