"""Stage 5 — Runtime Observability.

Collects what the target application actually *did* after accepting a probe, not
just what it said. A model producing alarming text and an application performing
an unauthorized action are different severities, and only runtime events can
tell them apart.

Events are pulled from the target rather than pushed to a collector, because the
scanner is a CLI process with no lifetime beyond the scan. Targets that expose
no telemetry simply yield nothing here — that is a coverage gap to report, not a
failure.
"""

from __future__ import annotations

import httpx
from sqlalchemy import select

from aegisai.models.attack import AttackVariant
from aegisai.models.enums import RuntimeEventType, Stage
from aegisai.models.runtime import RuntimeEvent
from aegisai.pipeline.base import ScanContext, StageResult

EVENT_PATHS = ("/events", "/_aegis/events", "/telemetry/events")

KNOWN_TYPES = {e.value for e in RuntimeEventType}


class ObservabilityStage:
    stage = Stage.RUNTIME_OBSERVABILITY

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def run(self, ctx: ScanContext) -> StageResult:
        base = ctx.target_url.rstrip("/")
        events = self._fetch(base)

        if events is None:
            return StageResult(
                ok=True,
                summary="target exposes no runtime telemetry — behavioural checks limited",
                counts={"events": 0},
            )

        # A target's event log outlives any single scan, so a naive collect picks
        # up activity from earlier scans and manual testing. An event tagged with
        # a probe id we did not issue is provably not ours and is dropped;
        # untagged events are kept, since they may still be ours and dropping
        # them would silently lose coverage against a partially-instrumented
        # target.
        own_probe_ids = {
            variant_id
            for (variant_id,) in ctx.session.execute(
                select(AttackVariant.id).where(AttackVariant.scan_id == ctx.scan_id)
            )
        }

        counts: dict[str, int] = {}
        stored = 0
        foreign = 0
        for event in events:
            event_type = str(event.get("event_type", "")).strip()
            if not event_type:
                continue

            probe_id = event.get("probe_id")
            if probe_id and probe_id not in own_probe_ids:
                foreign += 1
                continue

            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

            ctx.session.add(
                RuntimeEvent(
                    scan_id=ctx.scan_id,
                    # Set from the correlation header the target echoed back, so a
                    # tool call can be traced to the exact probe that triggered it.
                    variant_id=probe_id,
                    event_type=event_type,
                    source="target_telemetry",
                    payload=payload,
                )
            )
            counts[event_type] = counts.get(event_type, 0) + 1
            stored += 1

        ctx.session.flush()

        attributed = sum(1 for e in events if e.get("probe_id") in own_probe_ids)
        detail = ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or "none"
        summary = f"{stored} runtime event(s) [{detail}]; {attributed} attributed to a probe"
        if foreign:
            summary += f"; {foreign} from other activity ignored"
        return StageResult(
            ok=True,
            summary=summary,
            counts={"events": stored, "attributed": attributed, "foreign": foreign, **counts},
        )

    def _fetch(self, base: str) -> list[dict] | None:
        """Try known telemetry paths. None means the target exposes none."""
        for path in EVENT_PATHS:
            try:
                res = httpx.get(f"{base}{path}", timeout=self.timeout)
            except Exception:  # noqa: BLE001 - absent telemetry is normal
                continue
            if res.status_code != 200:
                continue
            try:
                data = res.json()
            except ValueError:
                continue

            events = data.get("events") if isinstance(data, dict) else data
            if isinstance(events, list):
                return [e for e in events if isinstance(e, dict)]
        return None
