"""Regression replay.

Every CONFIRMED finding becomes a stored test holding the *exact* payload and
transformation that produced it. Replaying an approximation would not prove the
same weakness is gone.

Two rules this module exists to hold:

1. **Stage 7 decides, not the model.** A replay's verdict comes from
   deterministic evidence — canary, policy violation, PII — re-evaluated against
   what actually came back. The adaptive advisor may suggest what to try next; it
   never rules on whether something is fixed.
2. **Bounded.** Attempts are capped. `while still_vulnerable: try_again()` is
   never correct: it turns a persistent weakness into an infinite scan.

Comparing finding *counts* between scans is also never a fix signal — counts are
not identities, and a different set of findings can total the same.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from aegisai.core.config import Config
from aegisai.models.enums import (
    ControlVerdict,
    RegressionStatus,
    RegressionVerdict,
    TransformationFamily,
)
from aegisai.models.regression import RegressionResult, RegressionTest
from aegisai.pipeline.evidence.canary import find_canaries
from aegisai.pipeline.evidence.pii import detect as detect_pii
from aegisai.pipeline.execution.adapter import ProbeRequest, TargetAdapter
from aegisai.pipeline.execution.stage import PROBE_HEADER, classify
from aegisai.pipeline.expected_observed.rules import Observation, evaluate
from aegisai.pipeline.expected_observed.stage import find_contract


@dataclass
class ReplayOutcome:
    verdict: RegressionVerdict
    control_verdict: str
    evidence_summary: str
    duration_ms: float
    detail: dict


def _resolve_endpoint(test: RegressionTest, target_url: str) -> str:
    path = test.target_endpoint or "/chat"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{target_url.rstrip('/')}{path}"


def replay(
    test: RegressionTest,
    *,
    target_url: str,
    target_type: str,
    config: Config,
    adapter: TargetAdapter | None = None,
) -> ReplayOutcome:
    """Re-send a stored attack and decide whether the weakness persists."""
    adapter = adapter or TargetAdapter()
    url = _resolve_endpoint(test, target_url)
    text_key = (test.extra or {}).get("text_key", "message")

    response = adapter.send(
        ProbeRequest(
            url=url,
            json_body={text_key: test.attack_payload},
            timeout=float(config.scan.target_timeout_seconds),
            headers={PROBE_HEADER: f"regression:{test.id}"},
        )
    )
    control_verdict, _ = classify(response)
    body = response.body or ""

    # Deterministic evidence, re-derived from this replay's own response.
    proofs: list[str] = []
    if canaries := find_canaries(body):
        proofs.append(f"canary {canaries[0]} still returned")

    contract = find_contract(target_type)
    if contract:
        observation = Observation(response_body=body, events=[])
        for boundary in contract.get("boundaries") or []:
            outcome = evaluate(boundary, observation)
            if outcome and outcome.violated:
                proofs.append(f"boundary '{boundary.get('id')}' still violated")

    if pii := detect_pii(body):
        proofs.append(f"sensitive data still returned ({pii[0].entity_type})")

    if proofs:
        verdict = RegressionVerdict.REGRESSED
        summary = "; ".join(proofs)
    elif control_verdict in (ControlVerdict.REJECTED, ControlVerdict.REFUSED):
        verdict = RegressionVerdict.PASS
        summary = f"probe no longer succeeds ({control_verdict})"
    elif control_verdict == ControlVerdict.ERROR:
        # A target that did not answer proves nothing either way. Calling this
        # PASS would report an outage as a fix.
        verdict = RegressionVerdict.INCONCLUSIVE
        summary = f"target did not respond: {response.error}"
    else:
        verdict = RegressionVerdict.PASS
        summary = "accepted, but no deterministic evidence of impact remained"

    return ReplayOutcome(
        verdict=verdict,
        control_verdict=control_verdict,
        evidence_summary=summary,
        duration_ms=response.latency_ms,
        detail={
            "status_code": response.status_code,
            "response_excerpt": body[:600],
            "proofs": proofs,
        },
    )


def record_result(
    session: Session,
    test: RegressionTest,
    outcome: ReplayOutcome,
    *,
    scan_id: str | None = None,
    strategy_source: str = "ORIGINAL",
    risk_score: float | None = None,
) -> RegressionResult:
    """Persist one replay attempt and advance the test's lifecycle."""
    # Column defaults are applied by the database on flush, not on construction,
    # so a test object that has not been persisted yet still has None here.
    test.attempt_count = (test.attempt_count or 0) + 1
    max_attempts = test.max_attempts or 3

    if outcome.verdict == RegressionVerdict.PASS:
        test.status = RegressionStatus.RESOLVED
    elif outcome.verdict == RegressionVerdict.REGRESSED:
        test.status = (
            RegressionStatus.EXHAUSTED
            if test.attempt_count >= max_attempts
            else RegressionStatus.REGRESSED
        )
    # INCONCLUSIVE leaves the test ACTIVE: nothing was learned, so nothing changes.

    result = RegressionResult(
        regression_test_id=test.id,
        scan_id=scan_id,
        verdict=outcome.verdict,
        control_verdict=outcome.control_verdict,
        resulting_risk_score=risk_score,
        attempt_number=test.attempt_count,
        strategy_source=strategy_source,
        evidence_summary=outcome.evidence_summary,
        duration_ms=outcome.duration_ms,
        detail=outcome.detail,
    )
    session.add(result)
    session.flush()
    return result


def make_test(
    *,
    finding_id: str,
    target_id: str | None,
    payload: str,
    transformation: str | None,
    endpoint: str | None,
    owasp_tag: str | None,
    boundary: str | None,
    max_attempts: int,
    text_key: str = "message",
) -> RegressionTest:
    return RegressionTest(
        origin_finding_id=finding_id,
        target_id=target_id,
        status=RegressionStatus.ACTIVE,
        matched_boundary=boundary,
        attack_payload=payload,
        transformation=transformation or TransformationFamily.NONE.value,
        target_endpoint=endpoint,
        owasp_tag=owasp_tag,
        max_attempts=max_attempts,
        extra={"text_key": text_key},
    )
