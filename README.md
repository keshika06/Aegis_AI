# AegisAI

AI application security validation platform, delivered as a CLI scanner.

AegisAI discovers an AI application's attack surface, plans OWASP-mapped attacks
against what it actually found, generates evasion variants of those attacks,
sends them to an authorized target, records what the target's **own** security
controls did, observes the resulting runtime behaviour, and confirms impact with
deterministic evidence rather than by trusting the model's own output.

> **Status: Phase 0.** The command tree, configuration, database schema,
> diagnostics, and the authorization gate are implemented. Pipeline stages are
> stubbed and land in later phases — a stub exits non-zero, so nothing mistakes
> it for a clean run.

## Core principles

| Principle | What it means in the code |
|---|---|
| **Observe, don't block** | AegisAI never filters its own probes. It records what the target decided: `REJECTED` / `ACCEPTED` / `REFUSED` / `ERROR`. |
| **Authorized targets only** | A scan runs only against a target explicitly registered *and* authorized. No flag overrides this. |
| **Evidence over suspicion** | `CONFIRMED` requires deterministic evidence — a retrieved canary, an unauthorized tool call, a policy-contract violation. Response text alone caps at `SUSPECTED`. |
| **The LLM is never the judge** | Ollama proposes attacks and strategies. It never decides whether something is a vulnerability. |
| **Synthetic data only** | Every canary, PII record, and lab fixture is synthetic. |

## Install

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"      # includes what the bundled labs need to run
```

Scanning a target needs only the core dependencies. *Hosting* one needs FastAPI
and uvicorn, so those live in a `labs` extra that `dev` pulls in — install
`.[labs]` alone if you want to run a lab without the test tooling.

## Quick start

```bash
aegisai init        # config file, working directories, database schema
aegisai doctor      # verify Python, Ollama, Docker, database
```

`doctor` is read-only and tells you the command that fixes anything it finds:

```
✓ Python        3.11.9
✓ Config        ~/.aegisai/config.toml
✓ Database      schema v1
✓ Ollama        v0.32.14 (qwen2.5:0.5b)
✓ Docker        daemon v29.5.2
✓ Disk          141.3 GB free

All checks passed. Ready to scan.
```

Register a target before scanning it:

```bash
aegisai target add http://localhost:8001 --type chatbot --authorize
aegisai target list
```

Scanning anything unauthorized is refused, by design:

```
$ aegisai scan run http://localhost:9999
✗ Target is registered but not authorized for scanning: http://localhost:9999
  Authorize it with:  aegisai target authorize tgt-3f9070c707dd
```

## Command tree

| Command | Purpose | Status |
|---|---|---|
| `aegisai doctor [--fix]` | Verify the environment | ✅ |
| `aegisai init` | Config, directories, schema | ✅ |
| `aegisai config show/get/set/path` | Inspect and edit configuration | ✅ |
| `aegisai target add/authorize/list/show/remove` | Authorization registry | ✅ |
| `aegisai scan list` | List scans | ✅ |
| `aegisai discover <target>` | Stage 1 attack-surface recon | Phase 2 |
| `aegisai scan run <target>` | Full 11-stage pipeline | Phase 1 |
| `aegisai scan status/cancel/report` | Scan lifecycle and reports | ✅ |
| `aegisai findings list/show` | Findings and evidence | Phase 5 |
| `aegisai chain show` · `aegisai risk show` | Attack chains, risk scores | Phase 5 |
| `aegisai attack library/plan/variants` | Payload library and generated attacks | Phase 2 / 3 |
| `aegisai regression list/run` | Closed-loop replay, CI gate | Phase 6 |
| `aegisai labs up/down/status` | Bundled demo labs | Phase 1 / 7 |
| `aegisai serve` | REST API for the dashboard | Phase 8 |

Every read command accepts `--json`, in either position:

```bash
aegisai target list --json | jq '.[].url'
aegisai --json target list
```

### Exit codes

CI branches on these, so they are part of the public contract.

| Code | Meaning |
|---|---|
| `0` | Clean run, nothing actionable |
| `1` | A `CONFIRMED` finding or `REGRESSED` test exists — CI should fail |
| `2` | Usage or configuration error |
| `3` | Target unreachable, unregistered, or unauthorized |
| `4` | Missing or unhealthy dependency — run `aegisai doctor` |

## The bundled labs

Three applications, so the pipeline can be demonstrated safely and repeatably —
two intentionally vulnerable, and one built properly as the control case. Both bind to localhost only and contain synthetic data
and synthetic canaries exclusively.

```bash
aegisai labs up          # all three
aegisai labs up lab2     # just one
aegisai labs status
```

| Lab | Port | Shape | Tests the path where… |
|---|---|---|---|
| `lab1` | 8001 | Customer-support chatbot | …the **user** attacks the model directly |
| `lab2` | 8002 | RAG knowledge assistant | …a **document** attacks the model, and the user reaches documents they should not |
| `lab3` | 8003 | **Defended** support chatbot | …the same application as `lab1`, built properly |

`lab2` exists because retrieval introduces vulnerability classes a chatbot
cannot have. Its deliberate flaws, and what makes each one provable rather than
merely suspicious:

| Flaw | OWASP | Proven by |
|---|---|---|
| Retrieval ignores tenant and classification metadata it records | LLM08 | A second canary that exists only in another tenant's restricted document |
| Retrieved bodies are spliced into the prompt undelimited | LLM01 | Instructions inside a document being obeyed |
| `POST /ingest` takes no credential | LLM04 | A `document_ingested` runtime event |
| Model prose is scraped for an email directive | LLM06 | A `send_summary_email` tool call to an attacker-chosen address |
| No output filtering | LLM05 / LLM02 | A markdown beacon, and synthetic PII from a restricted record |

Each maps to a boundary in `configs/expected-behaviour/lab2-rag.yaml`, so Stage 6
catches it deterministically rather than by reading the response and guessing.

### `lab3`, the control case

`lab3` is deliberately the *same application* as `lab1` — same persona, same
discount tool, same canary, measured against the same contract — with the
security actually implemented. Scanning both is a controlled comparison rather
than two unrelated results.

| Layer | What it does | Why `lab1` fails it |
|---|---|---|
| Input inspection | Normalises a probe — base64/hex decoded, homoglyphs folded, leetspeak undone, zero-width stripped — *then* matches injection signatures | `lab1` has no input control at all |
| Secret placement | The canary is held server-side and never enters the prompt | `lab1` puts it in the system prompt and asks the model to keep it |
| Role separation | User text is only ever a `user` turn | `lab1` concatenates it into the prompt |
| Egress filtering | Canary, system-prompt phrases and PII are redacted before the reply is returned | `lab1` has no output filter |
| Tool authorization | The model may only *request* a discount; a server-side authorizer enforces the ceiling | `lab1` scrapes the model's prose and acts on it |
| Tool allowlist | A tool absent from the allowlist has no code path | `lab1` has no allowlist |

Normalising *before* matching is the part that matters: a filter reading raw
text catches the one representation someone thought to enumerate, and nothing
else. It is the difference between a control that holds across an evasion family
and one that holds against a single payload.

## Configuration

Lives at `~/.aegisai/config.toml`. Any value can be overridden per-invocation
with an `AEGISAI_<SECTION>_<KEY>` environment variable:

```bash
AEGISAI_LLM_MODEL=llama3.2:3b aegisai doctor
```

## The pipeline

Stage names match the architecture diagram, and so do the module names under
`src/aegisai/pipeline/`, so the code and the diagram cannot drift apart.

| Stage | Name | Question it answers |
|---|---|---|
| 1 | Application Discovery | What is actually exposed? |
| 2A | Attack Planner | What should we try, and why? |
| 2B | Evasion Orchestrator | How many ways can the same intent be expressed? |
| 3/4 | Target Execution | What did the target do with it? |
| 5 | Runtime Observability | What happened downstream? |
| 6 | Expected vs Observed | Did that violate policy? |
| 7 | Evidence Fusion | Can we prove it? |
| 8 | Attack Chain Builder | How do findings connect? |
| 9 | Risk Scoring | How bad, explainably? |
| 10 | Reporting | What does a human need to see? |
| 11 | Closed-Loop Replay | What do we try next time? |

### How risk is scored

Stage 9 computes `risk = likelihood x impact`, scaled by how far the evidence
can be trusted. Three factors feed each axis, chosen to be independent of one
another:

| Axis | Factor | What it measures |
|---|---|---|
| Likelihood | `exploitability` | What the target's own control did about the probe |
| Likelihood | `reproducibility` | How many representations of this objective worked |
| Likelihood | `attack_complexity` | How much craft the successful representation needed |
| Impact | `business_impact` | Severity the target's own contract assigns |
| Impact | `blast_radius` | Who is affected beyond the attacker's own session |
| Impact | `data_sensitivity` | What actually left the boundary |

A product rather than a flat mean, because under a mean a single high factor
drags the composite up and nothing pulls it back down — every confirmed finding
converges on the same near-maximum number and the score stops ranking anything.
A weakness has to be *both* reachable and consequential to score highly.

Evidence confidence is deliberately not a seventh averaged factor. It is not a
component of risk but a measure of how far the result can be trusted, so it
scales the composite instead of contributing to it.

A factor that could not be established is recorded as `UNKNOWN` and excluded
from its axis, with the remaining weights re-normalised. An unmeasured factor
scored as "no risk" is how a scanner talks itself into a reassuring answer.

The **posture score** the dashboard shows for a whole scan is 70% the worst
objective plus 30% the mean across objectives — scored per *objective*, so
twelve representations of one weakness count once. Reporting the maximum alone
pinned the headline to whatever single finding scored highest and never moved
again.

Scores carry a `model_version`. Changing the model bumps it, and anything that
compares scans across time skips scores from a superseded model rather than
plotting them on one line — a formula change must never read as a security
improvement.

## Development

```bash
pytest tests -q            # test suite
ruff check src tests       # lint
ruff format src tests      # format
```

Schema changes go in `src/aegisai/core/migrations.py` as a new numbered
`Migration`. Never drop or recreate a table — a database holds real scan history,
and `create_all` will not alter a table that already exists, so adding a column
needs its own migration guarded by `column_exists`.

## Safety

AegisAI is for authorized security testing only: intentionally vulnerable labs,
or systems whose owner has explicitly authorized the test. The authorization
registry is enforced in code before any probe is dispatched, including by
`discover`. All test data, canaries, and lab content are synthetic — no real
personal, medical, financial, or customer data anywhere.
