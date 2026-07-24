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


def test_scan_url_prompts_once_then_reuses_exact_host_profile(tmp_path: Path) -> None:
    env = {"AEGIS_CONFIG_HOME": str(tmp_path / "aegis-home")}
    answers = "https://program.example/scope\nExample Security\n2099-12-31T23:59:59Z\ny\n"
    first = runner.invoke(
        app,
        ["scan-url", "https://vast.ai/", "--dry-run"],
        input=answers,
        env=env,
    )
    assert first.exit_code == 0
    assert '"seeds": [\n    "https://vast.ai/"' in first.stdout
    assert '"include_domains": [\n    "vast.ai"' in first.stdout
    assert "Saved exact-host authorization profile" in first.stdout

    second = runner.invoke(
        app,
        ["scan-url", "https://vast.ai/", "--dry-run"],
        env=env,
    )
    assert second.exit_code == 0
    assert "One-time authorization setup" not in second.stdout


def test_scan_url_accepts_complete_noninteractive_authorization(tmp_path: Path) -> None:
    env = {"AEGIS_CONFIG_HOME": str(tmp_path / "aegis-home")}
    result = runner.invoke(
        app,
        [
            "scan-url",
            "https://vast.ai/",
            "--dry-run",
            "--authorization-reference",
            "https://program.example/scope",
            "--authorized-by",
            "Example Security",
            "--authorization-expires-at",
            "2099-12-31T23:59:59Z",
            "--confirm-authorization",
        ],
        env=env,
    )
    assert result.exit_code == 0
    assert "Saved exact-host authorization profile" in result.stdout
    assert "One-time authorization setup" not in result.stdout


def test_scan_url_refuses_incomplete_noninteractive_authorization(tmp_path: Path) -> None:
    env = {"AEGIS_CONFIG_HOME": str(tmp_path / "aegis-home")}
    result = runner.invoke(
        app,
        [
            "scan-url",
            "https://vast.ai/",
            "--dry-run",
            "--authorization-reference",
            "https://program.example/scope",
        ],
        env=env,
    )
    assert result.exit_code == 2
    assert "Non-interactive setup requires" in result.stdout


def test_stored_authorization_is_bound_to_exact_hostname(tmp_path: Path) -> None:
    env = {"AEGIS_CONFIG_HOME": str(tmp_path / "aegis-home")}
    answers = "program-ref\nExample Security\n2099-12-31T23:59:59Z\ny\n"
    first = runner.invoke(
        app,
        ["scan-url", "https://vast.ai/", "--dry-run"],
        input=answers,
        env=env,
    )
    assert first.exit_code == 0

    other = runner.invoke(
        app,
        ["scan-url", "https://cloud.vast.ai/", "--dry-run"],
        input="new-program-ref\nExample Security\n2099-12-31T23:59:59Z\nn\n",
        env=env,
    )
    assert other.exit_code == 2
    assert "One-time authorization setup for exact host cloud.vast.ai" in other.stdout
