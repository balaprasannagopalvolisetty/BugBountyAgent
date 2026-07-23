from __future__ import annotations

from aegis_bounty.tool_catalog import TOOL_CATALOG, Integration, ToolKind


def test_requested_tool_catalog_is_complete_and_safety_classified() -> None:
    assert len(TOOL_CATALOG) == 10
    slugs = {tool.slug for tool in TOOL_CATALOG}
    assert {
        "subfinder",
        "dirsearch",
        "reconftw",
        "osmedeus",
        "apkleaks",
        "scan4all",
    } <= slugs
    subfinder = next(tool for tool in TOOL_CATALOG if tool.slug == "subfinder")
    scan4all = next(tool for tool in TOOL_CATALOG if tool.slug == "scan4all")
    assert subfinder.integration is Integration.INTEGRATED
    assert scan4all.kind is ToolKind.HIGH_IMPACT
    assert scan4all.integration is Integration.BLOCKED_AUTO


def test_reference_projects_are_not_executables() -> None:
    references = [tool for tool in TOOL_CATALOG if tool.kind is ToolKind.REFERENCE]
    assert len(references) == 4
    assert all(tool.executable is None for tool in references)
