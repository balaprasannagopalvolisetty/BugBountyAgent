from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from aegis_bounty.cli import app

runner = CliRunner()


def test_init_target_creates_locked_exact_host_config(tmp_path: Path) -> None:
    output = tmp_path / "scope.yaml"
    result = runner.invoke(app, ["init-target", "https://vast.ai/", "--output", str(output)])
    assert result.exit_code == 0
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["target"]["seeds"] == ["https://vast.ai/"]
    assert "include_domains" not in data["target"]
    assert data["authorization"]["confirmed"] is False
    assert "no wildcard subdomains" in result.stdout


def test_init_target_refuses_overwrite_without_force(tmp_path: Path) -> None:
    output = tmp_path / "scope.yaml"
    output.write_text("keep", encoding="utf-8")
    result = runner.invoke(app, ["init-target", "https://example.com", "-o", str(output)])
    assert result.exit_code == 2
    assert output.read_text(encoding="utf-8") == "keep"
