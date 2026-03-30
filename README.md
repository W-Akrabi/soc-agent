# SOC Agent

Terminal-first SOC investigation and response orchestration.

`soc-agent` ingests normalized alerts, builds a deterministic investigation plan, runs specialist agents, correlates against prior incidents, gates remediation actions behind policy and approvals, and preserves a replayable evidence trail.

## License and Commercial Use

This repository is source-available under the PolyForm Noncommercial License 1.0.0. Commercial use is not allowed without separate written permission from the copyright holder.

That means this repository is **not** OSI-approved open source in its current form. If you want an OSI-approved release later, you will need to change the license before publishing it that way.

See [LICENSE](LICENSE) for the repository terms.

## What Was Verified

The repository was verified locally on March 30, 2026 with:

- `python3 main.py investigate simulated --dry-run`
- `SOC_PROVIDER=ollama SOC_MODEL=qwen3:8b OLLAMA_BASE_URL=http://127.0.0.1:11434 python3 main.py investigate simulated`
- `python3 -m pytest`

Current result:

- `260 passed`
- `8 skipped` for optional environment-specific checks such as PostgreSQL-backed paths

## Fastest First Run

If you just want to confirm the project works, you do **not** need API keys. The dry-run path uses the built-in mock model provider.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 main.py investigate simulated --dry-run
```

Expected outcome:

- a terminal investigation run completes successfully
- a markdown report is written under `./reports`
- a case database is written under the path configured by `SOC_DB_PATH`
- an event log is written if `SOC_EVENT_LOG_DIR` is set

You can also confirm the full local test suite:

```bash
python3 -m pytest
```

## Setup After Forking

After forking and cloning the repository, every user should start the same way:

```bash
git clone <your-fork-url>
cd soc-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Then choose exactly one provider setup below.

### Option 1: Anthropic

Edit `.env`:

```dotenv
SOC_PROVIDER=anthropic
SOC_MODEL=claude-sonnet-4-6
ANTHROPIC_API_KEY=your_key_here
```

Run:

```bash
python3 main.py investigate simulated
```

### Option 2: OpenAI-Compatible

Edit `.env`:

```dotenv
SOC_PROVIDER=openai
SOC_MODEL=gpt-4.1
OPENAI_API_KEY=your_key_here
OPENAI_BASE_URL=https://api.openai.com/v1
```

Run:

```bash
python3 main.py investigate simulated
```

### Option 3: Local Ollama

Edit `.env`:

```dotenv
SOC_PROVIDER=ollama
SOC_MODEL=qwen3:8b
OLLAMA_BASE_URL=http://127.0.0.1:11434
```

Start Ollama, then verify the local API:

```bash
ollama list
curl http://127.0.0.1:11434/api/tags
```

If the desktop app is installed on macOS, opening `Ollama.app` is usually enough to start the local server.

Run:

```bash
python3 main.py investigate simulated
```

If you only want a guaranteed local smoke test before configuring a live provider, use:

```bash
python3 main.py investigate simulated --dry-run
```

## CLI Help

Top-level help now shows the subcommand interface:

```bash
python3 main.py --help
python3 main.py investigate --help
python3 main.py worker --help
python3 main.py api --help
```

Legacy flag-based entry points still work, but the subcommand interface is the clearest starting point for new users.

## Common Workflows

### Investigate One Alert

```bash
python3 main.py investigate simulated --dry-run
python3 main.py investigate alerts/sample_intrusion.json --dry-run
python3 main.py investigate alerts/sample_brute_force.json --dry-run
python3 main.py investigate alerts/sample_malware.json --dry-run
```

### Watch a Folder

```bash
mkdir -p alerts/incoming
python3 main.py watch alerts/incoming --dry-run
```

### Recall and Replay

```bash
python3 main.py recall web-prod-01 --limit 5
python3 main.py replay <run-id> --dry-run
```

### Approval Queue

```bash
python3 main.py approve list
python3 main.py approve action <action-id> --reviewed-by analyst1 --approver-token <token>
python3 main.py reject <action-id> --reviewed-by analyst1 --approver-token <token>
python3 main.py rollback <action-id> --reviewed-by analyst1 --approver-token <token>
```

### Remote Workers

```bash
python3 main.py worker start --dry-run
python3 main.py worker inspect --limit 25
python3 main.py worker reap --lease-timeout 600
```

### API Mode

```bash
python3 main.py api serve --dry-run
```

Main endpoints:

- `GET /health`
- `GET /metrics`
- `GET /api/metrics`
- `GET /api/approvals`
- `POST /api/investigations`

## Provider Setup

Dry-run mode does not need a provider. Live runs do.

### Anthropic

```bash
export SOC_PROVIDER=anthropic
export ANTHROPIC_API_KEY=...
export SOC_MODEL=claude-sonnet-4-6
```

### OpenAI-Compatible

```bash
export SOC_PROVIDER=openai
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://api.openai.com/v1
export SOC_MODEL=gpt-4.1
```

### Ollama

```bash
export SOC_PROVIDER=ollama
export OLLAMA_BASE_URL=http://127.0.0.1:11434
export SOC_MODEL=qwen3:8b
python3 main.py investigate simulated
```

## Configuration

Start from the checked-in example:

```bash
cp .env.example .env
```

Most important settings:

- `SOC_PROVIDER=anthropic|openai|ollama`
- `SOC_MODEL=...`
- `ANTHROPIC_API_KEY=...`
- `OPENAI_API_KEY=...`
- `OPENAI_BASE_URL=...`
- `OLLAMA_BASE_URL=http://127.0.0.1:11434`
- `SOC_DB_PATH=./soc_cases.db`
- `SOC_REPORTS_DIR=./reports`
- `SOC_EVENT_LOG_DIR=./event_logs`
- `SOC_AUTO_REMEDIATE=false`
- `SOC_ENABLE_MEMORY=true`
- `SOC_ENABLE_APPROVAL_QUEUE=true`
- `SOC_WORKER_MODE=local|remote`
- `SOC_STORAGE_BACKEND=sqlite|postgres`
- `SOC_CONTROLPLANE_BACKEND=sqlite|postgres`

## Execution Safety

Containment and write-capable integrations are fail-closed by default.

Important controls:

- `SOC_ALLOW_INTEGRATION_EXECUTION=true`
- `SOC_ALLOWED_ACTIONS=isolate_host,disable_account,...`
- `SOC_AUTO_REMEDIATE=true|false`
- `SOC_APPROVER_IDENTITIES=analyst1,analyst2`
- `SOC_API_APPROVER_TOKEN=...`
- `SOC_ALLOW_LIVE_INTEGRATIONS=true`
- `SOC_ALLOW_WRITE_INTEGRATIONS=false`

In `--dry-run`, the integration registry is disabled and external write paths are not exercised.

## Architecture at a Glance

```text
Normalized Alert
  -> Planner
  -> Scheduler
  -> Specialist Agents
       -> Recon
       -> Threat Intel
       -> Forensics
       -> Remediation
       -> Reporter
  -> Shared State
       -> Case Graph
       -> Event Log
       -> Memory Store
       -> Approval Queue
       -> Worker Queue
  -> Outputs
       -> Incident Report
       -> Replayable Run Metadata
       -> Metrics
       -> Optional API Responses
```

## Integrations

Current first-wave integrations:

- Sentinel
- Defender
- Entra
- Threat intel

These adapters support normalized evidence collection and, where enabled by policy, gated remediation execution.

## Storage and State

### Case Storage

- `SOC_STORAGE_BACKEND=sqlite|postgres`
- `SOC_POSTGRES_DSN=postgresql://...`
- `SOC_POSTGRES_SCHEMA=public`

### Control Plane

- `SOC_CONTROLPLANE_BACKEND=sqlite|postgres`
- `SOC_CONTROLPLANE_POSTGRES_DSN=postgresql://...`
- `SOC_CONTROLPLANE_POSTGRES_SCHEMA=soc_control`

### Additional Files

- `SOC_MEMORY_DB_PATH=./soc_memory.db`
- `SOC_APPROVAL_DB_PATH=./soc_approvals.db`
- `SOC_WORKER_DB_PATH=./soc_workers.db`
- `SOC_EVENT_LOG_DIR=./event_logs`

SQLite is the default and is the easiest way to run locally.

## Testing

Run the main local suite with:

```bash
python3 -m pytest
```

Optional live or environment-specific checks:

```bash
python3 -m pytest tests/test_integration.py -v -s
```

PostgreSQL-specific tests are enabled when `SOC_TEST_POSTGRES_DSN` is set.

## Proof and Design Notes

If you want the formal repository-level correctness statement, read [soc_agent.pdf](soc_agent.pdf).

That document covers the implemented control plane properties, including deterministic planning, dependency-safe scheduling, fail-closed remediation authorization, persistence, and replay boundaries.
