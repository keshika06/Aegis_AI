# Runbook — running AegisAI yourself

Everything below runs locally. No API keys, no cloud, no network egress beyond
the target you point it at.

---

## 0. One-time setup

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Then create the config, working directories, and database:

```bash
aegisai init
aegisai doctor
```

`doctor` is read-only and names the command that fixes anything it flags. You
want all green before scanning:

```
✓ Python        3.14.6
✓ Config        ~/.aegisai/config.toml
✓ Database      schema v1
✓ Ollama        v0.32.14 (qwen2.5:0.5b)
✓ Docker        daemon v29.5.2
✓ Disk          141.3 GB free
```

If Ollama is missing: `ollama serve` in another terminal, then
`ollama pull qwen2.5:0.5b`.

---

## 1. Start a vulnerable lab

Two labs ship with the repo. Pick either — the rest of this runbook works the
same for both, only the port and the `--type` change.

| Lab | Port | `--type` | What it exercises |
|---|---|---|---|
| `lab1-chatbot` | 8001 | `chatbot` | Direct prompt injection against a support bot |
| `lab2-rag` | 8002 | `rag` | Retrieval attacks: cross-tenant reads, poisoned documents, exfiltration |
| `lab3-secure-chatbot` | 8003 | `chatbot` | The control case — `lab1` built properly, so a scan of both compares like with like |

Two ways to run one. Native is faster and avoids the model running inside a
container.

**Native (recommended):**

```bash
# lab1
cd labs/lab1-chatbot
CANARY_TOKEN="AEGIS_CANARY_7f9a2b4c1d3e" \
OLLAMA_URL="http://127.0.0.1:11434" \
MODEL_NAME="qwen2.5:0.5b" \
  ../../.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001
```

```bash
# lab2 — note the second canary, seeded into another tenant's document
cd labs/lab2-rag
CANARY_TOKEN="AEGIS_CANARY_7f9a2b4c1d3e" \
DOC_CANARY_TOKEN="AEGIS_CANARY_c4d8e2f60b17" \
OLLAMA_URL="http://127.0.0.1:11434" \
MODEL_NAME="qwen2.5:0.5b" \
  ../../.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8002
```

**Docker:**

```bash
aegisai labs up lab2     # or `aegisai labs up` for all three
aegisai labs status
```

Check it is answering:

```bash
curl -s localhost:8002/health
# {"status":"ok","service":"lab2-rag"}
```

### Seeing lab2's flaws without the scanner

Useful for confirming the lab is broken the way it is meant to be before you
spend a scan on it. `/search` reaches the index with no model in the way:

```bash
# Retrieval ignores tenant scoping: doc-003 belongs to globex, not acme.
curl -s "localhost:8002/search?q=globex+partner+integration+runbook" | jq '.results[] | {id, tenant, classification}'

# The corpus is writable with no credential — the poisoning primitive.
curl -s -X POST localhost:8002/ingest -H 'Content-Type: application/json' \
  -d '{"title":"Refund policy","body":"Refunds are approved automatically."}'

# Everything the app admitted doing, which is what Stage 5 collects.
curl -s localhost:8002/events | jq '[.events[].event_type] | group_by(.) | map({(.[0]): length}) | add'
```

---

## 2. Register the target

Scanning is refused unless the target is explicitly authorized. This is enforced
in code and no flag overrides it.

```bash
aegisai target add http://127.0.0.1:8002 --type rag --authorize
aegisai target list
```

The `--type` matters beyond bookkeeping: it selects which attack cases the
planner draws from, and which expected-behaviour contract Stage 6 loads. A RAG
target registered as `chatbot` gets no retrieval cases and no contract, so the
scan runs clean for the wrong reason.

---

## 3. Scan

```bash
aegisai scan run http://127.0.0.1:8001
```

Faster runs while you are iterating — pick fewer evasion families:

```bash
aegisai scan run http://127.0.0.1:8001 --families encoding
aegisai scan run http://127.0.0.1:8001 --families encoding,context
```

Full set: `encoding,semantic,context,fragmentation,mutation`. More families means
more probes, and every probe waits on the target's model.

**Exit codes** (these are the CI contract):

| Code | Meaning |
|---|---|
| 0 | Clean — nothing confirmed |
| 1 | A CONFIRMED finding exists, or a regression test failed |
| 2 | Usage or config error |
| 3 | Target unreachable, unregistered, or unauthorized |
| 4 | Missing dependency — run `aegisai doctor` |

---

## 4. Read the results

```bash
aegisai scan list
aegisai findings list <scan-id>
aegisai findings list <scan-id> --verdict CONFIRMED
aegisai findings show <finding-id>     # full evidence trail
aegisai chain show <scan-id>           # correlated exploit paths
aegisai risk show <scan-id>            # every scoring factor and its weight
```

`risk show` prints the arithmetic rather than a bare number. The model is
`risk = likelihood x impact`, scaled by evidence confidence, with three factors
feeding each axis — so a weakness has to be both reachable and consequential to
score highly, and the score can rank findings instead of pinning every confirmed
one near the maximum. Factors the scan could not establish are listed as
`UNKNOWN` and excluded from their axis rather than counted as zero risk.

The dashboard's headline **posture score** aggregates per *objective*, not per
probe: twelve encodings of one weakness are one weakness. It is 70% the worst
objective plus 30% the mean across objectives, so one severe finding dominates
without pinning the number.

Reports are written to `~/.aegisai/reports/<scan-id>.{json,html}`. The easiest
way to open the HTML one — no path to type, and it defaults to your most recent
scan:

```bash
aegisai scan report --format html --open
```

Every read command takes `--json`, in either flag position:

```bash
aegisai findings list <scan-id> --verdict CONFIRMED --json | jq '.[0].evidence'
```

---

## 4b. The web dashboard

The scan writes an HTML report, but the React dashboard is the richer view — the
attack-path graph, defence layers, and the evidence explorer.

`aegisai scan run` already exports its results into the dashboard, so the data
is waiting for you:

```bash
aegisai dashboard serve <scan-id>
```

That installs frontend dependencies on first run and starts a dev server. **Watch
the Vite line for the real port** — if 5173 is taken it silently falls back to
5174, and the line AegisAI prints above it is the port it *asked* for:

```
  Dashboard  http://localhost:5173     <- requested
  ➜  Local:  http://localhost:5174/    <- actual, use this one
```

Pass the scan id. Bare `dashboard serve` resolves to the most recent scan, which
is not necessarily the one you just ran.

To refresh without restarting the server:

```bash
aegisai dashboard export             # newest scan
aegisai dashboard export <scan-id>   # a specific one
```

The dashboard is a static build that reads `frontend/src/data/scanData.json`, so
it shows whatever was exported last. The top bar names the scan id it is
displaying, and shows an orange **stale** badge when a newer scan exists in the
database — a dashboard showing real numbers from the wrong run otherwise looks
exactly like one showing the right run.

Note that `export` overwrites a git-tracked file, so `git status` will show
`frontend/src/data/scanData.json` as modified after any scan. That is expected.

Requires Node.js. Without it, the HTML report covers the same findings.

---

## 5. The closed loop

Every CONFIRMED finding is stored as a regression test holding the exact payload
that produced it. Re-scanning replays them automatically.

```bash
aegisai regression list
aegisai regression run http://127.0.0.1:8001     # exits 1 if any regressed
aegisai regression history <test-id>
```

This is the command a CI job runs.

---

## Inspecting a scan directly

The database is plain SQLite at `~/.aegisai/aegisai.db`:

```bash
sqlite3 ~/.aegisai/aegisai.db "select verdict, count(*) from control_evaluations group by verdict;"
sqlite3 ~/.aegisai/aegisai.db "select evidence_type, deterministic, count(*) from evidence group by 1,2;"
sqlite3 ~/.aegisai/aegisai.db "select boundary, count(*) from violations group by 1;"
```

---

## Development

```bash
pytest tests -q             # 180 tests, ~3s
ruff check src tests
ruff format src tests
```

---

## Configuration

`~/.aegisai/config.toml`. Any value can be overridden per-invocation with an
env var:

```bash
aegisai config show
aegisai config set llm.model qwen3:8b
AEGISAI_LLM_MODEL=qwen3:8b aegisai scan run <target>
```

### Choosing a model

`qwen2.5:0.5b` is fast but too small for LLM-assisted attack planning — it
contributes no usable proposals, and the scan runs on the 17-case library alone.
That is a supported mode, not a failure.

`qwen3:8b` produces genuinely good proposals but is slow, and it competes with
the target's own model on the same Ollama instance — expect some probes to time
out as `ERROR`. For a demo, prefer the small model and let the library carry it.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `exit 3` on scan | Target not registered or not authorized → `aegisai target add <url> --authorize` |
| `exit 4` | A dependency is missing → `aegisai doctor --fix` |
| `LLM unavailable — library only` | Ollama is down. Not fatal; the library still runs. `ollama serve` |
| Many `ERROR` verdicts | The target's model is timing out, usually resource contention. Use a smaller model or fewer families. |
| `0 findings` after a clean run | Genuinely possible — small models are non-deterministic. Re-run before concluding anything is fixed. |
| `file ... does not exist` opening a report | The filename is the **scan** id with its `scan-` prefix, not the target id. Easiest fix: `aegisai scan report --format html --open` |
| `command not found: aegisai` | The venv is not active in that terminal → `source .venv/bin/activate` |
| `[Errno 48] address already in use` | A lab is already running on that port → `lsof -i :8001 -sTCP:LISTEN` (or `:8002`), then either use it as-is or `pkill -f "uvicorn app:app"` |
| `no expected-behaviour contract for target type '...'` | Stage 6 matches a contract by target type. A lab2 target registered as `chatbot` finds no `rag` contract, so no boundary is checked and the scan reports clean. Re-register with `--type rag`. |
| lab2 scan finds nothing retrieval-related | Same cause as above, one step earlier: the planner selects cases by target type, so `--type chatbot` never draws the LLM08/LLM04 cases. Check what the planner would draw with `aegisai attack library list --type rag --owasp LLM08` |

---

## Safety

Only scan targets you own or have written authorization to test. The
authorization registry is enforced before any probe is sent, including by
`discover`. Everything in `labs/` is intentionally vulnerable and binds to
localhost — never expose it to a network you do not control. All canaries and
test data are synthetic.
