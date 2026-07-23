from __future__ import annotations

import asyncio
import re
from collections import defaultdict, deque
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from aegis_bounty.checks import analyze_active_cors, analyze_exchange
from aegis_bounty.http_client import SafeHttpClient
from aegis_bounty.models import Endpoint, HttpExchange, Observation
from aegis_bounty.scope import ScopePolicy, ScopeViolation, normalize_url

JS_ENDPOINT = re.compile(
    r"(?P<quote>['\"])(?P<path>/(?:api|v\d+|graphql|rest|admin|internal|debug|swagger|openapi)[^'\"\s]{0,300})(?P=quote)",
    re.IGNORECASE,
)


class CrawlResult:
    def __init__(self) -> None:
        self.endpoints: list[Endpoint] = []
        self.exchanges: list[HttpExchange] = []
        self.observations: list[Observation] = []
        self.errors: list[str] = []


def extract_endpoints(base_url: str, body: str, content_type: str, depth: int) -> list[Endpoint]:
    found: dict[str, Endpoint] = {}
    if "html" in content_type.lower() or "<html" in body[:1_000].lower():
        soup = BeautifulSoup(body, "html.parser")
        selectors = (("a", "href", "link"), ("form", "action", "form"), ("script", "src", "script"))
        for tag, attribute, label in selectors:
            for node in soup.find_all(tag):
                raw = node.get(attribute)
                if not isinstance(raw, str) or not raw.strip():
                    continue
                joined = urljoin(base_url, raw.strip())
                try:
                    normalized = normalize_url(joined)
                except (ScopeViolation, ValueError):
                    continue
                found[normalized] = Endpoint(
                    url=normalized,
                    method="GET",
                    source_url=base_url,
                    depth=depth + 1,
                    tags={label},
                )
    if "javascript" in content_type.lower() or urlsplit(base_url).path.endswith(".js"):
        for match in JS_ENDPOINT.finditer(body[:1_000_000]):
            joined = urljoin(base_url, match.group("path"))
            try:
                normalized = normalize_url(joined)
            except (ScopeViolation, ValueError):
                continue
            found[normalized] = Endpoint(
                url=normalized,
                source_url=base_url,
                depth=depth + 1,
                tags={"javascript-discovery"},
            )
    return list(found.values())


class Crawler:
    def __init__(
        self,
        client: SafeHttpClient,
        scope: ScopePolicy,
        *,
        max_depth: int,
        max_pages_per_host: int,
        concurrency: int,
        active_validation: bool,
    ):
        self.client = client
        self.scope = scope
        self.max_depth = max_depth
        self.max_pages_per_host = max_pages_per_host
        self.concurrency = concurrency
        self.active_validation = active_validation

    async def crawl(self, seeds: list[str]) -> CrawlResult:
        result = CrawlResult()
        queue: deque[Endpoint] = deque()
        seen: set[str] = set()
        per_host: defaultdict[str, int] = defaultdict(int)
        for seed in seeds:
            try:
                queue.append(Endpoint(url=self.scope.require_url(seed), depth=0, tags={"seed"}))
            except ScopeViolation as exc:
                result.errors.append(str(exc))
        lock = asyncio.Lock()

        async def next_endpoint() -> Endpoint | None:
            async with lock:
                while queue:
                    endpoint = queue.popleft()
                    host = urlsplit(endpoint.url).hostname or ""
                    if endpoint.url in seen or endpoint.depth > self.max_depth:
                        continue
                    if per_host[host] >= self.max_pages_per_host:
                        continue
                    if not self.scope.url_allowed(endpoint.url).allowed:
                        continue
                    seen.add(endpoint.url)
                    per_host[host] += 1
                    result.endpoints.append(endpoint)
                    return endpoint
                return None

        async def add_endpoints(items: list[Endpoint]) -> None:
            async with lock:
                queue.extend(item for item in items if item.url not in seen)

        async def worker() -> None:
            while True:
                endpoint = await next_endpoint()
                if endpoint is None:
                    return
                try:
                    response, exchange = await self.client.request("GET", endpoint.url)
                    result.exchanges.append(exchange)
                    result.observations.extend(analyze_exchange(exchange))
                    content_type = response.headers.get("content-type", "")
                    discovered = extract_endpoints(
                        endpoint.url, exchange.body_preview, content_type, endpoint.depth
                    )
                    location = response.headers.get("location")
                    if location:
                        try:
                            redirected = normalize_url(urljoin(endpoint.url, location))
                            discovered.append(
                                Endpoint(
                                    url=redirected,
                                    source_url=endpoint.url,
                                    depth=endpoint.depth + 1,
                                    tags={"redirect"},
                                )
                            )
                        except (ScopeViolation, ValueError):
                            pass
                    await add_endpoints(discovered)
                    if self.active_validation and response.status_code < 500:
                        await self._cors_probe(endpoint.url, exchange, result)
                except (httpx.HTTPError, ScopeViolation, RuntimeError, ValueError) as exc:
                    result.errors.append(f"{endpoint.url}: {exc}")

        # Workers re-check the shared queue. Yielding after each fetch lets newly found work be seen.
        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers)
        return result

    async def _cors_probe(self, url: str, baseline: HttpExchange, result: CrawlResult) -> None:
        origin = "https://aegis-invalid.example"
        try:
            _response, exchange = await self.client.request("GET", url, headers={"Origin": origin})
        except (httpx.HTTPError, ScopeViolation, RuntimeError, ValueError) as exc:
            result.errors.append(f"CORS probe {url}: {exc}")
            return
        result.exchanges.append(exchange)
        result.observations.extend(analyze_active_cors(baseline, exchange, origin))
