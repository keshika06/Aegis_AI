"""Remediation derived from what a probe actually did.

Stage 7 previously chose between two fixed paragraphs on one `if` over the
attack category, so a scan of 174 findings carried 2 distinct mitigations. Both
read as generic advice — "add input validation and an output filter" — which is
true of almost any finding and therefore actionable for none. A remediation that
does not name the boundary that broke, the tool that ran, or the event the
application emitted is indistinguishable from a textbook, and a reader learns to
skip it.

What follows composes guidance from facts the scan established:

    the contract rule that fired   which invariant broke, and so what to restore
    the runtime events observed    what the application actually did
    the control verdict            whether any deployed control existed at all
    the transformation family      whether a control generalises across form
    the evidence type              what to watch for to catch a recurrence

Keyed on the scanner's own controlled vocabularies — the rule kinds in
`expected_observed.rules.RULES` and `RuntimeEventType` — never on a particular
target's boundary names. A table keyed on `must_not_retrieve_across_tenants`
would produce good advice for Lab 2 and nothing at all for the next target.

Every entry interpolates an observed specific: the tool that ran, the argument
it carried, the event the target emitted. That is the line between advice about
this finding and advice about its category.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegisai.models.enums import ControlVerdict, RuntimeEventType, TransformationFamily


@dataclass
class RemediationInputs:
    rules: list[str] = field(default_factory=list)
    """Contract rule kinds that fired for this probe."""

    boundaries: list[str] = field(default_factory=list)
    observed: list[str] = field(default_factory=list)
    """What each rule recorded seeing, used to name specifics."""

    event_types: list[str] = field(default_factory=list)
    tools_called: list[str] = field(default_factory=list)
    unauthorized_tools: list[str] = field(default_factory=list)
    control_verdict: str | None = None
    transformation: str | None = None
    evidence_types: list[str] = field(default_factory=list)


@dataclass
class Remediation:
    summary: str
    """One line naming the invariant that broke."""

    mitigations: list[str] = field(default_factory=list)
    """Restore the broken invariant. Ordered most-direct first."""

    preventive: list[str] = field(default_factory=list)
    """Architectural controls that would have stopped it earlier."""

    detection: list[str] = field(default_factory=list)
    """What to monitor to catch a recurrence."""


# --- What each contract rule means was violated -----------------------------
#
# The rule kind is the most precise thing a scan knows: it is the invariant the
# target's own owner wrote down, and the reason it is now false.

RULE_SUMMARY = {
    "response_must_not_match": "A forbidden pattern reached the caller in the response body.",
    "response_must_not_contain_any": (
        "Content the contract forbids disclosing was returned verbatim."
    ),
    "tool_must_not_be_called": "A tool outside the assistant's remit was invoked.",
    "tool_argument_must_match": "A tool ran with an argument outside its permitted set.",
    "tool_argument_must_not_exceed": "A tool ran with a value above its authorized ceiling.",
    "event_must_not_occur": "The application performed an operation the contract forbids.",
}

# `event_must_not_occur` is the least self-describing rule: on its own it says
# only that something forbidden happened. Naming the operation is the difference
# between a line a reader acts on and one they scroll past, so the summary comes
# from the event the target emitted.
EVENT_SUMMARY = {
    RuntimeEventType.CROSS_TENANT_RETRIEVAL.value: (
        "Another tenant's document was returned to the caller."
    ),
    RuntimeEventType.DOCUMENT_INGESTED.value: (
        "The corpus was written to without an authenticated caller."
    ),
    RuntimeEventType.TOOL_CALL.value: "A privileged tool ran as a result of model output.",
    RuntimeEventType.NETWORK_CALLBACK.value: (
        "The application made an outbound request it should not have."
    ),
    RuntimeEventType.DB_ACCESS.value: "The application read from a datastore it should not have.",
}

RULE_MITIGATION = {
    "response_must_not_match": (
        "Filter model output before it reaches the caller. The contract already defines the "
        "pattern that must never appear, so the same expression can run as an egress check — "
        "the boundary is specified, it is simply not enforced anywhere."
    ),
    "response_must_not_contain_any": (
        "Enforce the document classification that already exists in the corpus metadata. The "
        "content was returned because retrieval never consulted it, so filtering the response "
        "is the wrong layer: the record should not have been a retrieval candidate."
    ),
    "tool_must_not_be_called": (
        "Bind the tool set to the caller's role rather than exposing every tool to the model. "
        "The model chose a tool it should never have been offered, which is an authorization "
        "gap in the host application, not a prompting mistake."
    ),
    "tool_argument_must_match": (
        "Validate tool arguments against the permitted set at the call boundary, server-side. "
        "The model is untrusted input, so an argument it supplies must be checked by the code "
        "that executes the call, not by the prompt asking it to behave."
    ),
    "tool_argument_must_not_exceed": (
        "Enforce the ceiling in the code that performs the action. A limit stated in a prompt "
        "is a request; a limit checked before execution is a control."
    ),
    "event_must_not_occur": (
        "Enforce the precondition for this operation in the application, not in the prompt."
    ),
}

# --- What each observed runtime event says the application did --------------

EVENT_MITIGATION = {
    RuntimeEventType.CROSS_TENANT_RETRIEVAL.value: (
        "Scope retrieval to the requesting tenant inside the query itself — a metadata filter "
        "applied to the index, not a check on the results. The application recorded the tenant "
        "on every document and then ranked across all of them, so the data needed to enforce "
        "this is already present and simply unused."
    ),
    RuntimeEventType.DOCUMENT_INGESTED.value: (
        "Require authentication and authorization on the corpus write path. An unauthenticated "
        "write lets an attacker plant material that is retrieved later for a different caller, "
        "which turns a single request into persistent, shared compromise."
    ),
    RuntimeEventType.TOOL_CALL.value: (
        "Route tool invocation through a mediator that checks caller, tool and arguments before "
        "execution, instead of acting on the model's output directly."
    ),
    RuntimeEventType.RAG_RETRIEVAL.value: (
        "Delimit retrieved content and mark it as data, never as instructions. Splicing document "
        "bodies into the prompt undelimited is what lets a document issue commands."
    ),
    RuntimeEventType.AUTHZ_DECISION.value: (
        "Make the authorization decision binding. The application computed one and then did not "
        "act on it, so the check exists and its result is discarded."
    ),
}

# --- What the target's control decision says about its defences -------------

VERDICT_PREVENTIVE = {
    ControlVerdict.ACCEPTED: (
        "No deployed control rejected this probe — it reached the model untouched. Before tuning "
        "anything, note that there is currently nothing to tune: add an input control so there "
        "is a decision point at all."
    ),
    ControlVerdict.REFUSED: (
        "No deployed control stopped this; the model declined on its own. Alignment is not a "
        "security control — it varies with sampling, phrasing and model version, so a result "
        "that depends on it is not reproducible and must not be counted as a defence."
    ),
    ControlVerdict.REJECTED: (
        "A control rejected this representation. Confirm it generalises: the same objective sent "
        "in another form is the usual way such a control is bypassed."
    ),
}

EVIDENCE_DETECTION = {
    "canary": (
        "Alert on canary tokens appearing in any outbound response. Legitimate output has no "
        "path to them, so a match is a high-signal, near-zero-false-positive breach indicator."
    ),
    "pii_detection": (
        "Scan outbound responses for sensitive-data patterns and alert on matches, so disclosure "
        "surfaces at the time it happens rather than at the next audit."
    ),
    "tool_log": (
        "Log every tool invocation with its caller, arguments and authorization decision, and "
        "alert on any call that executed while its decision was 'deny'."
    ),
    "policy_violation": (
        "Run the expected-behaviour contract continuously against production traffic, not only "
        "in scans, so a boundary crossing is detected when it occurs."
    ),
}


def _specifics(inputs: RemediationInputs) -> str:
    """The observed detail worth quoting back, if any."""
    if inputs.unauthorized_tools:
        return ", ".join(sorted(set(inputs.unauthorized_tools)))
    if inputs.tools_called:
        return ", ".join(sorted(set(inputs.tools_called)))
    return ""


def build(inputs: RemediationInputs) -> Remediation:
    """Compose remediation for one probe from what the scan observed."""
    rules = [r for r in dict.fromkeys(inputs.rules) if r]
    events = [e for e in dict.fromkeys(inputs.event_types) if e]

    # Prefer a summary that names the operation over one that merely reports a
    # rule fired.
    summaries: list[str] = []
    for rule in rules:
        if rule == "event_must_not_occur":
            named = [EVENT_SUMMARY[e] for e in events if e in EVENT_SUMMARY]
            summaries.extend(named or [RULE_SUMMARY[rule]])
        elif rule in RULE_SUMMARY:
            summaries.append(RULE_SUMMARY[rule])
    summary = summaries[0] if summaries else "Observed behaviour crossed a declared boundary."
    if not rules:
        summary = (
            "No declared boundary was crossed; this finding rests on evidence outside the contract."
        )

    mitigations: list[str] = []
    for rule in rules:
        if text := RULE_MITIGATION.get(rule):
            mitigations.append(text)

    # Events describe what the application did, which is often a layer beneath
    # the rule that noticed. Both matter, and they are not interchangeable.
    for event in events:
        if text := EVENT_MITIGATION.get(event):
            if text not in mitigations:
                mitigations.append(text)

    tools = _specifics(inputs)
    if tools and any(r.startswith("tool_") for r in rules):
        mitigations.insert(
            0,
            f"Revoke or gate the tool(s) this probe reached: {tools}. Each ran without an "
            f"authorization check the application was in a position to make.",
        )

    preventive: list[str] = []
    if verdict_text := VERDICT_PREVENTIVE.get(inputs.control_verdict):
        preventive.append(verdict_text)

    if inputs.transformation and inputs.transformation != TransformationFamily.NONE.value:
        preventive.append(
            f"This objective succeeded when expressed as '{inputs.transformation}'. Normalise "
            f"input to a canonical form before any control inspects it, or the control only ever "
            f"sees the representations someone thought to enumerate."
        )
    elif inputs.transformation == TransformationFamily.NONE.value:
        preventive.append(
            "This worked with the payload sent exactly as written — nothing had to be encoded or "
            "disguised. No attacker sophistication is required, so treat it as reachable by "
            "anyone who can send a request."
        )

    detection: list[str] = []
    for evidence in dict.fromkeys(inputs.evidence_types):
        if text := EVIDENCE_DETECTION.get(evidence):
            detection.append(text)

    return Remediation(
        summary=summary,
        mitigations=mitigations,
        preventive=preventive,
        detection=detection,
    )
