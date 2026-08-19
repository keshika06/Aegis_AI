"""Controlled vocabularies shared by the pipeline, the API, and the CLI.

These strings appear in reports and JSON output, so they are part of the public
contract. Add members; do not rename them.
"""

from enum import StrEnum


class TargetType(StrEnum):
    LLM = "llm"
    CHATBOT = "chatbot"
    RAG = "rag"
    AGENT = "agent"
    API = "api"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Stage(StrEnum):
    """Pipeline stages, named after the boxes in the architecture diagram."""

    DISCOVERY = "1"
    ATTACK_PLANNER = "2A"
    EVASION_ORCHESTRATOR = "2B"
    TARGET_EXECUTION = "3/4"
    RUNTIME_OBSERVABILITY = "5"
    EXPECTED_VS_OBSERVED = "6"
    EVIDENCE_FUSION = "7"
    ATTACK_CHAIN = "8"
    RISK_SCORING = "9"
    REPORTING = "10"
    CLOSED_LOOP = "11"


STAGE_LABELS: dict[Stage, str] = {
    Stage.DISCOVERY: "Application Discovery",
    Stage.ATTACK_PLANNER: "Attack Planner",
    Stage.EVASION_ORCHESTRATOR: "Evasion Orchestrator",
    Stage.TARGET_EXECUTION: "Target Execution",
    Stage.RUNTIME_OBSERVABILITY: "Runtime Observability",
    Stage.EXPECTED_VS_OBSERVED: "Expected vs Observed",
    Stage.EVIDENCE_FUSION: "Evidence Fusion",
    Stage.ATTACK_CHAIN: "Attack Chain Builder",
    Stage.RISK_SCORING: "Risk Scoring",
    Stage.REPORTING: "Reporting",
    Stage.CLOSED_LOOP: "Closed-Loop Replay",
}


class DiscoveryConfidence(StrEnum):
    """How a discovered fact was established.

    Required on every discovered fact: AegisAI never presents an assumption as
    something it observed.
    """

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    CONFIGURED = "CONFIGURED"
    UNKNOWN = "UNKNOWN"


class AttackSource(StrEnum):
    PLANNER = "2A"
    EVASION = "2B"


class TransformationFamily(StrEnum):
    NONE = "none"
    REPRESENTATION = "representation"
    ENCODING = "encoding"
    SEMANTIC = "semantic"
    CONTEXT = "context"
    FRAGMENTATION = "fragmentation"
    ROLE = "role"
    RAG_CONTEXT = "rag_context"
    MUTATION = "mutation"
    CANARY = "canary"
    ADAPTIVE = "adaptive"


class ControlVerdict(StrEnum):
    """Stage 3/4 outcome vocabulary.

    AegisAI records what the target's own controls decided; it never blocks its
    own probes.
    """

    REJECTED = "REJECTED_BY_TARGET_CONTROL"
    ACCEPTED = "ACCEPTED_BY_TARGET_CONTROL"
    REFUSED = "REFUSED_BY_TARGET_LLM"
    ERROR = "ERROR_TIMEOUT"


class RuntimeEventType(StrEnum):
    LLM_IO = "llm_io"
    RAG_RETRIEVAL = "rag_retrieval"
    TOOL_CALL = "tool_call"
    API_CALL = "api_call"
    DB_ACCESS = "db_access"
    AUTHZ_DECISION = "authz_decision"
    NETWORK_CALLBACK = "network_callback"
    HTTP_EXCHANGE = "http_exchange"


class EvidenceType(StrEnum):
    CANARY = "canary"
    TOOL_LOG = "tool_log"
    API_LOG = "api_log"
    DB_LOG = "db_log"
    CALLBACK = "callback"
    POLICY_VIOLATION = "policy_violation"
    PII_DETECTION = "pii_detection"
    RESPONSE_TEXT = "response_text"


DETERMINISTIC_EVIDENCE: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.CANARY,
        EvidenceType.TOOL_LOG,
        EvidenceType.DB_LOG,
        EvidenceType.CALLBACK,
        EvidenceType.POLICY_VIOLATION,
    }
)
"""Evidence types that can, on their own, support a CONFIRMED verdict.

`RESPONSE_TEXT` is deliberately absent: a model saying something alarming is a
signal, not proof.
"""


class FindingVerdict(StrEnum):
    SUSPECTED = "SUSPECTED"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"


class RiskLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RegressionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    REGRESSED = "REGRESSED"
    EXHAUSTED = "EXHAUSTED"


class RegressionVerdict(StrEnum):
    PASS = "PASS"
    REGRESSED = "REGRESSED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AdvisorStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "ADVISOR_UNAVAILABLE"
    """Recorded when no LLM provider answered.

    The pipeline continues deterministically; an LLM failure never becomes a
    "resolved" or "safe" result.
    """
