"""SQLAlchemy models for the whole pipeline.

Importing this package registers every table on `Base.metadata`, which the
migration runner relies on — so import from here, not from submodules, when you
need the metadata to be complete.
"""

from aegisai.models.analysis import AttackChain, Report, RiskScore
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.base import Base, new_id, utcnow
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.models.policy import PolicyContract, Violation
from aegisai.models.regression import RegressionResult, RegressionTest
from aegisai.models.runtime import RuntimeEvent
from aegisai.models.scan import Profile, Scan
from aegisai.models.target import Target

__all__ = [
    "AttackCase",
    "AttackChain",
    "AttackVariant",
    "Base",
    "ControlEvaluation",
    "Evidence",
    "Finding",
    "PolicyContract",
    "Profile",
    "RegressionResult",
    "RegressionTest",
    "Report",
    "RiskScore",
    "RuntimeEvent",
    "Scan",
    "Target",
    "Violation",
    "new_id",
    "utcnow",
]
