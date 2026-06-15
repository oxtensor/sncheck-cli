"""Typed result models shared across the SNCheck pipeline."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity of a single finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric ordering used for thresholds and sorting (higher = worse)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """How confident a rule is that a match is a real signal."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Category(str, Enum):
    """Rule category grouping."""

    BITTENSOR = "bittensor"
    SHELL = "shell"
    PYTHON = "python"
    DOCKER = "docker"
    DEPENDENCY = "dependency"


class RiskLevel(str, Enum):
    """Overall risk level for a scan."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class TargetType(str, Enum):
    """The kind of target being scanned."""

    GITHUB = "github"
    LOCAL = "local"


class Target(BaseModel):
    """Normalized metadata about the scan target."""

    type: TargetType
    raw: str
    path: str | None = None
    owner: str | None = None
    repo: str | None = None
    url: str | None = None


class Finding(BaseModel):
    """A single risk signal produced by a rule."""

    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    impact: str
    recommendation: str
    file: str
    line: int | None = None
    evidence: str
    confidence: Confidence


class Summary(BaseModel):
    """Counts of findings by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    """The complete output of a scan."""

    schema_version: str = "0.1"
    tool: str = "sncheck"
    tool_version: str
    target: Target
    commit: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    overall_risk: RiskLevel = RiskLevel.UNKNOWN
    summary: Summary = Field(default_factory=Summary)
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
