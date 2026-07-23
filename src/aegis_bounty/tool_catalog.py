from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass
from enum import StrEnum


class ToolKind(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    ORCHESTRATOR = "orchestrator"
    LOCAL_ANALYSIS = "local-analysis"
    REFERENCE = "reference"
    HIGH_IMPACT = "high-impact"


class Integration(StrEnum):
    INTEGRATED = "integrated"
    EXTERNAL = "external"
    REFERENCE_ONLY = "reference-only"
    BLOCKED_AUTO = "not-auto-run"


@dataclass(frozen=True)
class ToolSpec:
    slug: str
    name: str
    homepage: str
    kind: ToolKind
    integration: Integration
    executable: str | None
    purpose: str
    safety_note: str

    def installed_path(self) -> str | None:
        return shutil.which(self.executable) if self.executable else None

    def as_json(self) -> dict[str, str | None]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["integration"] = self.integration.value
        data["installed_path"] = self.installed_path()
        return data


TOOL_CATALOG: tuple[ToolSpec, ...] = (
    ToolSpec(
        slug="payloadsallthethings",
        name="PayloadsAllTheThings",
        homepage="https://github.com/swisskyrepo/PayloadsAllTheThings",
        kind=ToolKind.REFERENCE,
        integration=Integration.REFERENCE_ONLY,
        executable=None,
        purpose="Vulnerability methodology and payload reference corpus",
        safety_note="Never dispatch payloads automatically; analysts select techniques allowed by scope.",
    ),
    ToolSpec(
        slug="dirsearch",
        name="dirsearch",
        homepage="https://github.com/maurosoria/dirsearch",
        kind=ToolKind.ACTIVE,
        integration=Integration.EXTERNAL,
        executable="dirsearch",
        purpose="Web path discovery",
        safety_note="Active brute-force traffic; run separately only when program rules allow it.",
    ),
    ToolSpec(
        slug="subfinder",
        name="subfinder",
        homepage="https://github.com/projectdiscovery/subfinder",
        kind=ToolKind.PASSIVE,
        integration=Integration.INTEGRATED,
        executable="subfinder",
        purpose="Passive subdomain enumeration",
        safety_note="Aegis re-filters every result through include and exclude scope rules.",
    ),
    ToolSpec(
        slug="nahamsec-resources",
        name="Resources for Beginner Bug Bounty Hunters",
        homepage="https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters",
        kind=ToolKind.REFERENCE,
        integration=Integration.REFERENCE_ONLY,
        executable=None,
        purpose="Learning and methodology index",
        safety_note="Reference material only.",
    ),
    ToolSpec(
        slug="reconftw",
        name="reconFTW",
        homepage="https://github.com/six2dez/reconftw",
        kind=ToolKind.ORCHESTRATOR,
        integration=Integration.BLOCKED_AUTO,
        executable="reconftw.sh",
        purpose="Broad reconnaissance and vulnerability workflow orchestration",
        safety_note="May invoke many active tools; Aegis will not auto-run or imply its traffic budget applies.",
    ),
    ToolSpec(
        slug="allaboutbugbounty",
        name="AllAboutBugBounty",
        homepage="https://github.com/daffainfo/AllAboutBugBounty",
        kind=ToolKind.REFERENCE,
        integration=Integration.REFERENCE_ONLY,
        executable=None,
        purpose="Bug bounty techniques and reference material",
        safety_note="Reference material only.",
    ),
    ToolSpec(
        slug="osmedeus",
        name="Osmedeus",
        homepage="https://github.com/j3ssie/osmedeus",
        kind=ToolKind.ORCHESTRATOR,
        integration=Integration.BLOCKED_AUTO,
        executable="osmedeus",
        purpose="Security workflow orchestration",
        safety_note="Workflow behavior is external to Aegis scope and request-budget enforcement.",
    ),
    ToolSpec(
        slug="apkleaks",
        name="APKLeaks",
        homepage="https://github.com/dwisiswant0/apkleaks",
        kind=ToolKind.LOCAL_ANALYSIS,
        integration=Integration.EXTERNAL,
        executable="apkleaks",
        purpose="Local APK URI, endpoint, and secret discovery",
        safety_note="Analyze only APKs you are authorized to inspect; results can contain secrets.",
    ),
    ToolSpec(
        slug="scan4all",
        name="scan4all",
        homepage="https://github.com/GhostTroops/scan4all",
        kind=ToolKind.HIGH_IMPACT,
        integration=Integration.BLOCKED_AUTO,
        executable="scan4all",
        purpose="Broad fingerprinting, port scanning, PoC and credential-testing framework",
        safety_note="Includes intrusive capabilities and is intentionally never launched by Aegis.",
    ),
    ToolSpec(
        slug="awesome-bugbounty-tools",
        name="awesome-bugbounty-tools",
        homepage="https://github.com/vavkamil/awesome-bugbounty-tools",
        kind=ToolKind.REFERENCE,
        integration=Integration.REFERENCE_ONLY,
        executable=None,
        purpose="Curated bug bounty tool index",
        safety_note="Reference material only; listed tools require independent review.",
    ),
)


def executable_tools() -> tuple[ToolSpec, ...]:
    return tuple(tool for tool in TOOL_CATALOG if tool.executable)
