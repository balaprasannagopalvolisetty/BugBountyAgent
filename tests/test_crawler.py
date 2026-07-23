from __future__ import annotations

import httpx
import pytest

from aegis_bounty.config import TargetConfig
from aegis_bounty.crawler import Crawler, extract_endpoints
from aegis_bounty.models import HttpExchange
from aegis_bounty.scope import ScopePolicy


def test_extracts_html_and_javascript_endpoints() -> None:
    html = '<a href="/a">A</a><form action="/submit"></form><script src="/app.js"></script>'
    items = extract_endpoints("https://example.com/", html, "text/html", 0)
    assert {item.url for item in items} == {
        "https://example.com/a",
        "https://example.com/submit",
        "https://example.com/app.js",
    }
    js = "const endpoint = '/api/v1/users';"
    items = extract_endpoints("https://example.com/app.js", js, "application/javascript", 1)
    assert items[0].url == "https://example.com/api/v1/users"


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def request(self, method: str, url: str, *, headers=None):  # type: ignore[no-untyped-def]
        self.calls.append(url)
        body = '<a href="/next">next</a>' if url.endswith("/") else "done"
        request = httpx.Request(method, url, headers=headers)
        response = httpx.Response(
            200, request=request, headers={"content-type": "text/html"}, text=body
        )
        exchange = HttpExchange(
            request_id=f"r{len(self.calls)}",
            method=method,
            url=url,
            status_code=200,
            response_headers={"content-type": "text/html"},
            body_preview=body,
        )
        return response, exchange


@pytest.mark.asyncio
async def test_crawler_follows_only_in_scope_discovery() -> None:
    target = TargetConfig(
        seeds=["https://example.com/"], include_domains=["example.com"], allowed_ports=[443]
    )
    scope = ScopePolicy(target)
    client = FakeClient()
    crawler = Crawler(
        client,  # type: ignore[arg-type]
        scope,
        max_depth=2,
        max_pages_per_host=5,
        concurrency=2,
        active_validation=False,
    )
    result = await crawler.crawl(target.seeds)
    assert client.calls == ["https://example.com/", "https://example.com/next"]
    assert len(result.exchanges) == 2
