"""
Risk scoring model for process suspicion assessment.
"""

from dataclasses import dataclass, field
from typing import List

# Score thresholds
LEVEL_LOW = "LOW"
LEVEL_MEDIUM = "MEDIUM"
LEVEL_HIGH = "HIGH"
LEVEL_CRITICAL = "CRITICAL"

_SEVERITY_ORDER = {LEVEL_LOW: 0, LEVEL_MEDIUM: 1, LEVEL_HIGH: 2, LEVEL_CRITICAL: 3}


def level_for_score(score: int) -> str:
    if score >= 70:
        return LEVEL_CRITICAL
    if score >= 45:
        return LEVEL_HIGH
    if score >= 20:
        return LEVEL_MEDIUM
    return LEVEL_LOW


def max_level(a: str, b: str) -> str:
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b


@dataclass
class RiskFlag:
    """A single suspicious indicator contributing to the risk score."""

    code: str  # e.g. "DELETED_EXE", "RWX_REGIONS"
    title: str
    detail: str
    weight: int = 0  # Points contributed to the total score (before capping)
    severity: str = LEVEL_LOW  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class RiskInfo:
    """Aggregated heuristic risk assessment for a process."""

    pid: int
    score: int = 0
    level: str = LEVEL_LOW
    flags: List[RiskFlag] = field(default_factory=list)

    @property
    def is_elevated(self) -> bool:
        return self.score >= 20
