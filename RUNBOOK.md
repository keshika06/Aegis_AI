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

## 1. Start the vulnerable lab

Two ways. Native is faster and avoids the model running inside a container.

**Native (recommended):**

```bash
cd labs/lab1-chatbot
CANARY_TOKEN="AEGIS_CANARY_7f9a2b4c1d3e" \
OLLAMA_URL="http://127.0.0.1:11434" \
MODEL_NAME="qwen2.5:0.5b" \
  ../../.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001
```

**Docker:**

```bash
aegisai labs up lab1
aegisai labs status
```

Check it is answering:

```bash
curl -s localhost:8001/health
# {"status":"ok","service":"lab1-chatbot"}
```

---

## 2. Register the target

Scanning is refused unless the target is explicitly authorized. This is enforced
in code and no flag overrides it.

```bash
aegisai target add http://127.0.0.1:8001 --type chatbot --authorize
aegisai target list
```

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
| `[Errno 48] address already in use` | A lab is already running on that port → `lsof -i :8001 -sTCP:LISTEN`, then either use it as-is or `pkill -f "uvicorn app:app"` |

---

## Safety

Only scan targets you own or have written authorization to test. The
authorization registry is enforced before any probe is sent, including by
`discover`. Everything in `labs/` is intentionally vulnerable and binds to
localhost — never expose it to a network you do not control. All canaries and
test data are synthetic.
