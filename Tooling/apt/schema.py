"""findings.json schema: the validated contract passed between APT phases.

Each phase writes a findings file (metadata + a phase-specific payload). The
runner validates it against the matching model before handing it to the next
phase. Keeping the payload structured (not prose) is what makes the handoff
machine-usable and keeps each phase's context lean: raw tool output stays on
disk (referenced by `raw_artifacts`), and only distilled findings cross the
phase boundary.

Requires pydantic v2.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


class Phase(str, Enum):
    recon = "recon"
    enumeration = "enumeration"
    vuln_assessment = "vuln_assessment"
    exploitation = "exploitation"
    post_exploitation = "post_exploitation"
    reporting = "reporting"
    mitigation = "mitigation"


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


# --- shared sub-models -----------------------------------------------------

class Service(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None


class Endpoint(BaseModel):
    method: str = "GET"
    path: str
    status: Optional[int] = None
    notes: Optional[str] = None


class Param(BaseModel):
    endpoint: str
    name: str
    location: Literal["query", "body", "header", "path", "cookie"] = "query"
    example: Optional[str] = None


class Vulnerability(BaseModel):
    id: str = Field(description="Stable id assigned by the agent, e.g. VULN-001.")
    title: str
    type: str = Field(description="Vulnerability class, e.g. 'SQL Injection'.")
    location: str = Field(description="Endpoint, parameter, or file:line where it lives.")
    evidence: str = Field(description="What was observed that indicates the vulnerability.")
    confidence: Confidence = Confidence.medium
    owasp_web: Optional[str] = Field(default=None, description="OWASP Web Top 10 entry, e.g. 'A03:2021 Injection'.")
    owasp_llm: Optional[str] = Field(default=None, description="OWASP LLM Top 10 entry, if chatbot-related.")
    cwe: Optional[str] = None


class ExploitAttempt(BaseModel):
    vuln_id: str = Field(description="References a Vulnerability.id from the prior phase.")
    technique: str = Field(description="Short description of the approach taken.")
    outcome: Literal["success", "failure", "partial", "inconclusive"]
    evidence: str
    oracle_confirmed: Optional[bool] = Field(
        default=None,
        description="True if the target's own records confirm the exploit (filled from /api/Challenges).",
    )
    challenge_key: Optional[str] = Field(
        default=None, description="Juice Shop challenge key, if identified."
    )


class RawArtifact(BaseModel):
    tool: str
    path: str = Field(description="Path on disk to the raw tool output for this phase.")
    description: Optional[str] = None


# --- per-phase payloads ----------------------------------------------------

class ReconPayload(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)


class EnumPayload(BaseModel):
    routes: list[Endpoint] = Field(default_factory=list)
    params: list[Param] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    hidden_paths: list[str] = Field(default_factory=list)
    api_surface: list[str] = Field(default_factory=list)


class VulnPayload(BaseModel):
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class ExploitPayload(BaseModel):
    attempts: list[ExploitAttempt] = Field(default_factory=list)


class PostExploitPayload(BaseModel):
    footholds: list[str] = Field(default_factory=list)
    reachable_data: list[str] = Field(default_factory=list)
    escalations: list[str] = Field(default_factory=list)


class ReportingPayload(BaseModel):
    report_path: Optional[str] = None
    summary: str = ""


class MitigationItem(BaseModel):
    vuln_id: str
    recommendation: str
    reference: Optional[str] = None


class MitigationPayload(BaseModel):
    items: list[MitigationItem] = Field(default_factory=list)


# --- the envelope: one concrete model per phase ----------------------------

class FindingsBase(BaseModel):
    apt_schema_version: str = SCHEMA_VERSION
    run_id: str
    target: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: str = Field(description="A few sentences a human (or the next phase) can read first.")
    raw_artifacts: list[RawArtifact] = Field(default_factory=list)
    next_steps: list[str] = Field(
        default_factory=list, description="What the next phase should focus on."
    )


class ReconFindings(FindingsBase):
    phase: Literal[Phase.recon] = Phase.recon
    payload: ReconPayload


class EnumFindings(FindingsBase):
    phase: Literal[Phase.enumeration] = Phase.enumeration
    payload: EnumPayload


class VulnFindings(FindingsBase):
    phase: Literal[Phase.vuln_assessment] = Phase.vuln_assessment
    payload: VulnPayload


class ExploitFindings(FindingsBase):
    phase: Literal[Phase.exploitation] = Phase.exploitation
    payload: ExploitPayload


class PostExploitFindings(FindingsBase):
    phase: Literal[Phase.post_exploitation] = Phase.post_exploitation
    payload: PostExploitPayload


class ReportingFindings(FindingsBase):
    phase: Literal[Phase.reporting] = Phase.reporting
    payload: ReportingPayload


class MitigationFindings(FindingsBase):
    phase: Literal[Phase.mitigation] = Phase.mitigation
    payload: MitigationPayload


FINDINGS_MODELS: dict[Phase, type[FindingsBase]] = {
    Phase.recon: ReconFindings,
    Phase.enumeration: EnumFindings,
    Phase.vuln_assessment: VulnFindings,
    Phase.exploitation: ExploitFindings,
    Phase.post_exploitation: PostExploitFindings,
    Phase.reporting: ReportingFindings,
    Phase.mitigation: MitigationFindings,
}


def model_for(phase: Phase) -> type[FindingsBase]:
    return FINDINGS_MODELS[phase]
