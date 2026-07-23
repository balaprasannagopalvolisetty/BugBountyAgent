from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from aegis_bounty.chains import ChainEngine
from aegis_bounty.config import AppConfig
from aegis_bounty.crawler import Crawler
from aegis_bounty.http_client import SafeHttpClient
from aegis_bounty.llm import OpenAITriage
from aegis_bounty.models import ScanSummary
from aegis_bounty.recon import NucleiAdapter, ReconEngine
from aegis_bounty.reporting import write_reports
from aegis_bounty.scope import ScopePolicy
from aegis_bounty.storage import EvidenceStore
from aegis_bounty.triage import collapse_host_observations


def create_scan_id(now: datetime | None = None) -> str:
    timestamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


class ScanOrchestrator:
    def __init__(self, config: AppConfig, base_directory: Path | None = None):
        self.config = config
        self.base_directory = (base_directory or Path.cwd()).resolve()
        self.scope = ScopePolicy(config.target)

    def dry_run(self) -> dict[str, object]:
        seeds = [self.scope.require_url(seed) for seed in self.config.target.seeds]
        return {
            "project": self.config.project,
            "seeds": seeds,
            "include_domains": self.config.target.include_domains,
            "exclude_domains": self.config.target.exclude_domains,
            "excluded_paths": self.config.target.exclude_paths,
            "request_budget": self.config.scan.max_requests,
            "requests_per_second": self.config.scan.requests_per_second,
            "active_validation": self.config.scan.active_validation,
            "subdomain_discovery": self.config.scan.discover_subdomains,
            "nuclei": self.config.scan.use_nuclei,
            "ai": self.config.ai.enabled,
        }

    async def run(self, *, disable_ai: bool = False) -> ScanSummary:
        started = datetime.now(UTC)
        scan_id = create_scan_id(started)
        output_root = self.config.output.directory
        if not output_root.is_absolute():
            output_root = self.base_directory / output_root
        run_directory = output_root / scan_id
        run_directory.mkdir(parents=True, exist_ok=False)
        store = EvidenceStore(run_directory / "evidence.sqlite3")
        store.start_scan(scan_id, self.config.project, started.isoformat())
        errors: list[str] = []
        endpoint_count = 0
        try:
            recon = ReconEngine(self.scope, run_directory)
            assets, recon_messages = await recon.discover(
                self.config.target.seeds, self.config.scan.discover_subdomains
            )
            errors.extend(recon_messages)
            for asset in assets:
                store.add_asset(scan_id, asset)

            seeds = list(self.config.target.seeds)
            seeded_hosts = {urlsplit(seed).hostname for seed in seeds}
            for asset in assets:
                if asset.hostname not in seeded_hosts:
                    seeds.append(f"https://{asset.hostname}/")

            async with SafeHttpClient(
                self.scope,
                self.config.scan.user_agent,
                self.config.scan.timeout_seconds,
                self.config.scan.requests_per_second,
                self.config.scan.max_requests,
            ) as client:
                crawler = Crawler(
                    client,
                    self.scope,
                    max_depth=self.config.scan.max_depth,
                    max_pages_per_host=self.config.scan.max_pages_per_host,
                    concurrency=self.config.scan.concurrency,
                    active_validation=self.config.scan.active_validation,
                )
                crawl = await crawler.crawl(seeds)
                endpoint_count = len(crawl.endpoints)
                errors.extend(crawl.errors)
                for exchange in crawl.exchanges:
                    store.add_exchange(scan_id, exchange)
                store.add_observations(scan_id, collapse_host_observations(crawl.observations))

                if self.config.scan.use_nuclei:
                    adapter = NucleiAdapter(
                        self.scope, run_directory, self.config.scan.requests_per_second
                    )
                    nuclei_items, nuclei_errors = await adapter.scan(
                        [endpoint.url for endpoint in crawl.endpoints],
                        self.config.scan.nuclei_severities,
                    )
                    store.add_observations(scan_id, nuclei_items)
                    errors.extend(nuclei_errors)

            observations = store.observations(scan_id)
            if self.config.ai.enabled and not disable_ai:
                if not os.environ.get("OPENAI_API_KEY"):
                    errors.append("AI triage skipped: OPENAI_API_KEY is not set")
                else:
                    try:
                        ai_items = await OpenAITriage(self.config.ai).analyze(observations)
                        store.add_observations(scan_id, ai_items)
                        observations = store.observations(scan_id)
                    except Exception as exc:  # provider failures must not discard scan evidence
                        errors.append(f"AI triage failed: {type(exc).__name__}: {exc}")

            chains = ChainEngine().build(observations)
            store.add_chains(scan_id, chains)
            if errors:
                (run_directory / "errors.log").write_text(
                    "\n".join(errors) + "\n", encoding="utf-8"
                )
            finished = datetime.now(UTC)
            store.finish_scan(scan_id, finished.isoformat())
            paths = write_reports(store, scan_id, run_directory, list(self.config.output.formats))
            return ScanSummary(
                scan_id=scan_id,
                project=self.config.project,
                started_at=started,
                finished_at=finished,
                assets=len(assets),
                endpoints=endpoint_count,
                requests=len(store.exchanges(scan_id)),
                observations=len(store.observations(scan_id)),
                chains=len(chains),
                report_paths=[str(path.resolve()) for path in paths],
            )
        finally:
            store.close()
