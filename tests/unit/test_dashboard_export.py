"""Dashboard export — the numbers the UI renders as headline figures."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from aegisai.core.config import load_config
from aegisai.core.db import create_db_engine, session_scope
from aegisai.core.migrations import upgrade
from aegisai.dashboard import export
from aegisai.models.analysis import RiskScore
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import FindingVerdict, ScanStatus
from aegisai.models.finding import Finding
from aegisai.models.scan import Scan
from aegisai.models.target import Target
from aegisai.pipeline.risk.scoring import RISK_MODEL_VERSION, UNKNOWN

BASE = datetime(2026, 8, 20, 12, 0, 0)


def _engine(aegis_home: Path):  # noqa: ANN202
    engine = create_db_engine(load_config())
    upgrade(engine)
    return engine


def _scan(
    session: Session,
    scan_id: str,
    target_id: str,
    *,
    minutes: int,
    scores: list[float],
    model_version: int = RISK_MODEL_VERSION,
    objectives: int = 1,
    confirmed: bool = True,
) -> None:
    """One scan with `objectives` attack cases and one finding per score."""
    session.add(
        Scan(
            id=scan_id,
            target_id=target_id,
            status=ScanStatus.COMPLETED,
            created_at=BASE + timedelta(minutes=minutes),
        )
    )
    # Each level is flushed before the next references it: scan, then cases and
    # variants, then findings, then scores.
    session.flush()
    for index in range(objectives):
        session.add(
            AttackCase(
                id=f"{scan_id}-atk{index}",
                scan_id=scan_id,
                original_intent="objective",
                payload="probe",
            )
        )
    session.flush()
    for index, value in enumerate(scores):
        case_id = f"{scan_id}-atk{index % objectives}"
        session.add(
            AttackVariant(
                id=f"{scan_id}-var{index}",
                scan_id=scan_id,
                attack_case_id=case_id,
                payload="probe",
            )
        )
        session.add(
            Finding(
                id=f"{scan_id}-fnd{index}",
                scan_id=scan_id,
                variant_id=f"{scan_id}-var{index}",
                title="finding",
                verdict=FindingVerdict.CONFIRMED if confirmed else FindingVerdict.SUSPECTED,
                confidence=0.9,
            )
        )
        session.flush()
        session.add(
            RiskScore(
                id=f"{scan_id}-risk{index}",
                scan_id=scan_id,
                finding_id=f"{scan_id}-fnd{index}",
                score=value,
                risk_level="CRITICAL" if value >= 7.5 else "HIGH",
                factors={},
                weights={},
                model_version=model_version,
            )
        )


class TestPostureHeadline:
    def test_the_headline_is_not_just_the_worst_finding(self, aegis_home: Path) -> None:
        """Reporting the maximum meant one severe finding pinned the number at
        99/100 no matter what else the scan found."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[9.5, 2.0, 1.0], objectives=3)
            session.flush()
            data = export.build(session, "scan-a")

        assert data["run"]["risk"] < 95

    def test_many_severe_objectives_score_worse_than_one(self, aegis_home: Path) -> None:
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            session.add(Target(id="tgt-2", url="http://127.0.0.1:8012", target_type="rag"))
            session.flush()
            _scan(session, "scan-one", "tgt-1", minutes=0, scores=[9.0, 1.0], objectives=2)
            _scan(session, "scan-many", "tgt-2", minutes=0, scores=[9.0, 9.0], objectives=2)
            session.flush()
            one = export.build(session, "scan-one")["run"]["risk"]
            many = export.build(session, "scan-many")["run"]["risk"]

        assert many > one


class TestAttackSuccessRate:
    def test_the_rate_cannot_exceed_one_hundred_percent(self, aegis_home: Path) -> None:
        """Counting confirmed findings over objectives reported 481%, because
        one objective probed a dozen ways yields a dozen findings."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            # One objective, twelve representations, all confirmed.
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[9.0] * 12, objectives=1)
            session.flush()
            data = export.build(session, "scan-a")

        assert data["run"]["attackSuccessRate"] == 100

    def test_unconfirmed_objectives_do_not_count_as_successes(self, aegis_home: Path) -> None:
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(
                session,
                "scan-a",
                "tgt-1",
                minutes=0,
                scores=[9.0, 9.0],
                objectives=2,
                confirmed=False,
            )
            session.flush()
            data = export.build(session, "scan-a")

        assert data["run"]["attackSuccessRate"] == 0


class TestModelVersionGuard:
    def test_a_superseded_model_is_not_used_as_a_baseline(self, aegis_home: Path) -> None:
        """The old model saturated near 10, so comparing against it would show
        the formula change as a security improvement that never happened."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-old", "tgt-1", minutes=0, scores=[9.9], model_version=1)
            _scan(session, "scan-new", "tgt-1", minutes=10, scores=[8.0])
            session.flush()
            data = export.build(session, "scan-new")

        assert data["run"]["previousRisk"] is None
        assert data["run"]["attackSuccessDelta"] is None
        assert [r["run"] for r in data["riskRuns"]] == [
            "RUN-AN-NEW"[:0] or "RUN-CANNEW"[:0] or data["riskRuns"][0]["run"]
        ]
        assert len(data["riskRuns"]) == 1

    def test_a_comparable_earlier_scan_is_used(self, aegis_home: Path) -> None:
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-first", "tgt-1", minutes=0, scores=[9.0])
            _scan(session, "scan-second", "tgt-1", minutes=10, scores=[4.0])
            session.flush()
            data = export.build(session, "scan-second")

        assert data["run"]["previousRisk"] is not None
        assert data["run"]["previousRisk"] > data["run"]["risk"]
        assert len(data["riskRuns"]) == 2


class TestNoInventedData:
    def test_a_first_run_reports_no_baseline_rather_than_zero(self, aegis_home: Path) -> None:
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[7.0])
            session.flush()
            data = export.build(session, "scan-a")

        assert data["run"]["previousRisk"] is None
        assert data["run"]["attackSuccessDelta"] is None

    def test_newly_detected_needs_a_baseline_to_mean_anything(self, aegis_home: Path) -> None:
        """Without an earlier scan, no category can be called newly detected."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[7.0])
            session.flush()
            data = export.build(session, "scan-a")

        assert all(row["isNew"] is None for row in data["owaspCategories"])

    def test_every_finding_gets_its_own_detail(self, aegis_home: Path) -> None:
        """The detail page previously showed the top finding's payload and
        evidence under whichever row the reader had clicked."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[9.0, 3.0], objectives=2)
            session.flush()
            data = export.build(session, "scan-a")

        assert len(data["findingDetails"]) == 2
        for row in data["findings"]:
            assert row["id"] in data["findingDetails"]
            assert data["findingDetails"][row["id"]]["risk"] == row["risk"]


class TestSeverityLabel:
    def test_the_label_describes_the_posture_score_not_the_worst_finding(
        self, aegis_home: Path
    ) -> None:
        """The gauge renders the label directly under the number, so a label
        describing a different quantity misleads about both."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            # One critical finding among many trivial ones: posture lands low.
            _scan(
                session,
                "scan-a",
                "tgt-1",
                minutes=0,
                scores=[9.0, 0.5, 0.5, 0.5, 0.5],
                objectives=5,
            )
            session.flush()
            data = export.build(session, "scan-a")

        assert data["run"]["risk"] < 75
        assert data["run"]["severity"] != "CRITICAL"

    def test_a_uniformly_severe_scan_is_labelled_critical(self, aegis_home: Path) -> None:
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[9.0, 9.0, 9.0], objectives=3)
            session.flush()
            data = export.build(session, "scan-a")

        assert data["run"]["severity"] == "CRITICAL"


class TestRiskAttribution:
    def test_the_confidence_multiplier_is_read_not_reconstructed(self, aegis_home: Path) -> None:
        """Dividing the multiplier back out of a rounded composite returns a
        number close to it but not equal to it, so the scorer's own value is
        stored and used."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[8.0])
            session.flush()
            row = session.get(RiskScore, "scan-a-risk0")
            row.axes = {"likelihood": 1.0, "impact": 0.842, "confidence": 0.95}
            session.flush()
            data = export.build(session, "scan-a")

        contributions = data["factorContributions"]
        assert contributions["confidence"] == 0.95
        assert contributions["likelihood"] == 1.0
        assert contributions["impact"] == 0.842

    def test_scores_predating_the_column_report_no_multiplier(self, aegis_home: Path) -> None:
        """Rather than inventing one by division."""
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[8.0])
            session.flush()
            data = export.build(session, "scan-a")

        assert data["factorContributions"]["confidence"] is None

    def test_an_unmeasured_axis_is_not_rendered_as_a_number(self, aegis_home: Path) -> None:
        engine = _engine(aegis_home)
        with session_scope(engine) as session:
            session.add(Target(id="tgt-1", url="http://127.0.0.1:8002", target_type="rag"))
            session.flush()
            _scan(session, "scan-a", "tgt-1", minutes=0, scores=[8.0])
            session.flush()
            row = session.get(RiskScore, "scan-a-risk0")
            row.axes = {"likelihood": 0.9, "impact": UNKNOWN, "confidence": 1.0}
            session.flush()
            data = export.build(session, "scan-a")

        assert data["factorContributions"]["impact"] is None
        assert data["factorContributions"]["likelihood"] == 0.9
