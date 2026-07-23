from __future__ import annotations

from aegis_bounty.checks import analyze_active_cors, analyze_exchange
from aegis_bounty.models import HttpExchange


def exchange(**overrides: object) -> HttpExchange:
    values: dict[str, object] = {
        "request_id": "req1",
        "method": "GET",
        "url": "https://example.com/",
        "status_code": 200,
        "response_headers": {},
        "body_preview": "ok",
    }
    values.update(overrides)
    return HttpExchange.model_validate(values)


def test_missing_headers_are_observations() -> None:
    items = analyze_exchange(
        exchange(
            response_headers={"content-type": "text/html; charset=utf-8"},
            body_preview="<!doctype html><html></html>",
        )
    )
    titles = {item.title for item in items}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security" in titles


def test_detects_stack_trace_and_technology_disclosure() -> None:
    items = analyze_exchange(
        exchange(
            body_preview="Traceback (most recent call last): secret omitted",
            response_headers={"server": "framework/1.2"},
        )
    )
    assert any(item.kind == "information_disclosure" for item in items)
    assert any(item.kind == "technology_disclosure" for item in items)


def test_static_javascript_does_not_get_document_header_noise() -> None:
    items = analyze_exchange(
        exchange(
            url="https://static.example.com/app.js",
            response_headers={
                "content-type": "application/javascript",
                "strict-transport-security": "max-age=31536000",
                "server": "AmazonS3",
            },
            body_preview="console.log('ok')",
        )
    )
    assert not any(item.kind == "missing_security_header" for item in items)
    assert not any(item.kind == "technology_disclosure" for item in items)


def test_external_redirect_does_not_claim_open_redirect() -> None:
    items = analyze_exchange(
        exchange(status_code=302, response_headers={"location": "https://other.test/x"})
    )
    item = next(item for item in items if item.kind == "external_redirect")
    assert "does not prove" in item.evidence


def test_active_cors_reflection() -> None:
    baseline = exchange()
    probe = exchange(
        request_id="req2",
        response_headers={
            "access-control-allow-origin": "https://aegis-invalid.example",
            "access-control-allow-credentials": "true",
        },
    )
    items = analyze_active_cors(baseline, probe, "https://aegis-invalid.example")
    assert len(items) == 1
    assert items[0].severity.value == "medium"


def test_cookie_attributes_are_checked_without_value() -> None:
    items = analyze_exchange(
        exchange(response_headers={"set-cookie": "session=[REDACTED]; Path=/"})
    )
    cookie_items = [item for item in items if item.kind == "cookie_security"]
    assert len(cookie_items) == 3
    assert all("REDACTED" in item.evidence for item in cookie_items)
