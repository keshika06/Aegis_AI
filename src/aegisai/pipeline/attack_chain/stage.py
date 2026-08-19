"""Stage 8 — Attack Chain Builder.

Correlates a finding's individual facts into the path an attacker actually
walked: intent → how it was represented → what the target's control decided →
what the application then did → what proves it.

The value is that individually unremarkable steps become one legible exploit
path. "The filter accepted a Base64 payload" and "a tool ran with an
out-of-policy argument" are each a shrug; chained, they are a report finding.

OWASP tags are attached only where the underlying evidence supports them — a
category is never forced onto a finding that does not fit it.
"""

from __future__ import annotations

import networkx as nx
from sqlalchemy import select

from aegisai.knowledge_base.library import owasp_name
from aegisai.models.analysis import AttackChain
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import Stage, TransformationFamily
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.pipeline.base import ScanContext, StageResult

SEVERITY_BY_EVIDENCE = {
    "canary": 0.9,
    "policy_violation": 0.85,
    "tool_log": 0.8,
    "pii_detection": 0.6,
    "response_text": 0.3,
}


class AttackChainStage:
    stage = Stage.ATTACK_CHAIN

    def run(self, ctx: ScanContext) -> StageResult:
        findings = list(ctx.session.scalars(select(Finding).where(Finding.scan_id == ctx.scan_id)))
        if not findings:
            return StageResult(ok=True, summary="no findings to correlate", counts={"chains": 0})

        evidence_by_finding: dict[str, list[Evidence]] = {}
        for item in ctx.session.scalars(select(Evidence).where(Evidence.scan_id == ctx.scan_id)):
            evidence_by_finding.setdefault(item.finding_id or "", []).append(item)

        variants = {
            v.id: v
            for v in ctx.session.scalars(
                select(AttackVariant).where(AttackVariant.scan_id == ctx.scan_id)
            )
        }
        cases = {
            c.id: c
            for c in ctx.session.scalars(
                select(AttackCase).where(AttackCase.scan_id == ctx.scan_id)
            )
        }
        evaluations = {
            e.id: e
            for e in ctx.session.scalars(
                select(ControlEvaluation).where(ControlEvaluation.scan_id == ctx.scan_id)
            )
        }

        # Findings that share an objective are one story, not several: the same
        # boundary reached through five encodings is one weakness with five
        # routes, and reporting it five times buries the point.
        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            variant = variants.get(finding.variant_id or "")
            case = cases.get(variant.attack_case_id) if variant else None
            grouped.setdefault(case.id if case else "unattributed", []).append(finding)

        created = 0
        for case_id, group in grouped.items():
            case = cases.get(case_id)
            graph = nx.DiGraph()

            intent = case.original_intent if case else "unknown intent"
            graph.add_node("intent", label=intent, kind="intent")

            severity = 0.0
            owasp_tags: set[str] = set()
            routes: set[str] = set()

            for finding in group:
                variant = variants.get(finding.variant_id or "")
                evaluation = evaluations.get(finding.control_evaluation_id or "")
                transformation = (
                    variant.transformation if variant else TransformationFamily.NONE.value
                )
                routes.add(transformation)

                route_node = f"route:{transformation}"
                graph.add_node(route_node, label=transformation, kind="representation")
                graph.add_edge("intent", route_node, label="expressed as")

                control_node = f"control:{evaluation.verdict if evaluation else 'unknown'}"
                graph.add_node(
                    control_node,
                    label=evaluation.verdict if evaluation else "unknown",
                    kind="control_decision",
                )
                graph.add_edge(route_node, control_node, label="target control")

                finding_node = f"finding:{finding.id}"
                graph.add_node(
                    finding_node, label=finding.verdict, kind="finding", title=finding.title
                )
                graph.add_edge(control_node, finding_node, label="produced")

                if finding.owasp_tag:
                    owasp_tags.add(finding.owasp_tag)

                for item in evidence_by_finding.get(finding.id, []):
                    evidence_node = f"evidence:{item.id}"
                    graph.add_node(
                        evidence_node,
                        label=item.evidence_type,
                        kind="evidence",
                        deterministic=item.deterministic,
                    )
                    graph.add_edge(finding_node, evidence_node, label="proven by")
                    severity = max(severity, SEVERITY_BY_EVIDENCE.get(item.evidence_type, 0.2))

            ctx.session.add(
                AttackChain(
                    scan_id=ctx.scan_id,
                    title=f"{intent} via {len(routes)} representation(s)",
                    finding_ids=[f.id for f in group],
                    graph=nx.node_link_data(graph, edges="edges"),
                    owasp_tags=sorted(owasp_tags),
                    severity=round(severity, 3),
                )
            )
            created += 1

        ctx.session.flush()

        mapped = {t for chain in grouped for f in grouped[chain] if (t := f.owasp_tag)}
        named = ", ".join(sorted(f"{t} ({owasp_name(t) or '?'})" for t in mapped)) or "none"
        return StageResult(
            ok=True,
            summary=f"{created} attack chain(s); OWASP: {named}",
            counts={"chains": created, "owasp_categories": len(mapped)},
        )
