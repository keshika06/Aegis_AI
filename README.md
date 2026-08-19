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
pip install -e ".[dev]"
```

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
| `aegisai scan status/cancel/report` | Scan lifecycle and reports | Phase 1 / 6 |
| `aegisai findings list/show` | Findings and evidence | Phase 5 |
| `aegisai chain show` · `aegisai risk show` | Attack chains, risk scores | Phase 5 |
| `aegisai attack library/plan/variants` | Payload library and generated attacks | Phase 2 / 3 |
| `aegisai regression list/run` | Closed-loop replay, CI gate | Phase 6 |
| `aegisai labs up/down/status` | Bundled vulnerable labs | Phase 1 / 7 |
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
