# SOC Agent

Terminal-first autonomous SOC investigation and response platform.

`soc-agent` is built to ingest normalized security alerts, plan and run specialist investigations, correlate against prior incidents, propose or gate containment actions, and preserve a replayable evidence trail. The product stance is deliberate: capability depth first, terminal UX first, web UI optional later.

## Read This First

If you want the formal argument for what this repository actually proves about itself, read
[`proof`](soc_agent.pdf) first.

That document is the mathematical and logical correctness statement for the implemented control
plane. It proves deterministic planning, dependency-safe scheduling, fail-closed remediation
authorization, memory/correlation persistence properties, and replay correctness. It also states
the boundary clearly: the repository does not and cannot formally prove universal real-world SOC
detection accuracy from source code alone.

## Contents

- [Read This First](#read-this-first)
- [Overview](#overview)
- [Platform Capabilities](#platform-capabilities)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Workflows](#cli-workflows)
- [API Mode](#api-mode)
- [Execution Controls](#execution-controls)
- [Integrations](#integrations)
- [Worker Model](#worker-model)
- [Storage and State](#storage-and-state)
- [Testing](#testing)
- [Status](#status)

## Overview

`soc-agent` is a defensive security platform for:

- SOC automation
- alert triage
- investigation orchestration
- cross-incident correlation
- approval-gated containment
- replay and post-incident analysis

It is not a pentesting framework and it is not trying to be a generic chat wrapper around security tools. The target is a serious operator platform for security investigations, with explicit control over memory, policy, approvals, workers, and evidence.

## Platform Capabilities

- Multi-provider model runtime:
  - Anthropic
  - OpenAI-compatible APIs
  - Ollama
- Deterministic planning:
  - alert-type-specific task DAGs
  - planner + scheduler execution
  - retries, early-stop behavior, task dependency handling
- Specialist agents:
  - recon
  - threat intel
  - forensics
  - remediation
  - reporting
- Shared investigation state:
  - case graph
  - append-only event log
  - cross-incident memory
  - approval queue
  - worker queue
- Terminal operations:
  - investigate
  - watch
  - recall
  - replay
  - approve / reject / rollback
  - worker management
  - API server mode
- Execution governance:
  - allowlisted actions
  - approval gating
  - approver identity constraints
  - rollback tracking
- Observability:
  - JSONL event logs
  - Prometheus-style metrics endpoint
  - JSON metrics endpoint
- Remote worker support:
  - delegated task execution
  - lease timeout handling
  - heartbeat tracking
  - stale-task requeue helpers

## Architecture

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

At runtime, the planner maps an alert into a task graph. The scheduler executes that graph locally or through remote workers. Agents write findings, evidence, and actions into shared storage. The report layer summarizes what actually happened in the graph, while memory and replay preserve the run for later analysis.

## Quick Start

### Requirements

- Python 3.11+
- `pip`
- At least one model provider:
  - Anthropic
  - OpenAI-compatible endpoint
  - Ollama

### Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Create configuration:

```bash
cp .env.example .env
```

3. Configure one provider:

- `SOC_PROVIDER=anthropic` with `ANTHROPIC_API_KEY`
- `SOC_PROVIDER=openai` with `OPENAI_API_KEY`
- `SOC_PROVIDER=ollama` with a running Ollama server

4. Run a dry investigation:

```bash
python3 main.py investigate simulated --dry-run
```

### Local Ollama Example

If you want fully local inference:

```bash
export SOC_PROVIDER=ollama
export SOC_MODEL=llama3:latest
python3 main.py investigate simulated --dry-run
```

## CLI Workflows

### Investigate

```bash
python3 main.py investigate simulated --dry-run
python3 main.py investigate alerts/sample_intrusion.json
python3 main.py investigate alerts/sample_brute_force.json
```

### Watch a Folder

```bash
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

### Legacy Entry Points

The older flag-based interface remains available:

```bash
python3 main.py --alert simulated --dry-run
python3 main.py --watch alerts/incoming
```

## API Mode

`soc-agent` can run as a lightweight authenticated API service using the same runtime configuration as the terminal workflows.

### Start the API

```bash
python3 main.py api serve
```

### Core Settings

- `SOC_API_HOST=127.0.0.1`
- `SOC_API_PORT=8080`
- `SOC_API_TOKEN=...`
- `SOC_API_APPROVER_TOKEN=...`
- `SOC_APPROVER_IDENTITIES=analyst1,analyst2`
- `SOC_ENABLE_METRICS=true`

### Available Surfaces

- `GET /health`
- `GET /metrics`
- `GET /api/metrics`
- `GET /api/approvals`
- `POST /api/investigations`

`GET /health` is intended for simple liveness checks. The authenticated surfaces use bearer-token gating.

## Execution Controls

Containment is controlled through explicit policy flags rather than hidden agent behavior.

### Core Controls

- `SOC_ALLOW_INTEGRATION_EXECUTION=true`
  - enables execution policy evaluation
- `SOC_ALLOWED_ACTIONS=isolate_host,disable_account,...`
  - allowlists write-capable actions
- `SOC_AUTO_REMEDIATE=true|false`
  - controls whether approved actions auto-execute or wait for review
- `SOC_APPROVER_IDENTITIES=...`
  - constrains who may approve, reject, or roll back actions
- `SOC_API_APPROVER_TOKEN=...`
  - adds a second gate for approval-changing CLI and API operations

### Expected Action States

- `proposed`
- `awaiting_approval`
- `approved`
- `executing`
- `executed`
- `rejected`
- `failed`
- `rolled_back`

The default operational posture is conservative: propose actions broadly, require explicit approval where policy says so, and only execute when the runtime, allowlist, and adapter support all line up.

## Integrations

Current first-wave integrations:

- Sentinel
- Defender
- Entra
- Threat intel

These adapters support normalized evidence collection, and where applicable, gated write execution through the remediation path.

### Notes

- In `--dry-run`, the integration registry is disabled and external write paths are not exercised.
- Approval queue items appear only when an action is:
  - supported by policy
  - allowlisted
  - backed by a write-capable adapter
  - not auto-executed immediately

## Worker Model

Remote workers allow investigations to dispatch planned tasks into a separate queue-backed execution path.

### Worker Controls

- `SOC_WORKER_MODE=local|remote`
- `SOC_WORKER_POLL_INTERVAL=1.0`
- `SOC_WORKER_LEASE_TIMEOUT=600`
- `SOC_WORKER_HEARTBEAT_INTERVAL=15.0`

### Operational Behavior

- queued tasks can be claimed by a worker
- workers emit heartbeats while active
- stale claimed or running tasks can be requeued
- inspection surfaces expose queue state and age

This is intended to support a more distributed execution model without changing the operator workflow.

## Storage and State

### Case Storage

- `SOC_STORAGE_BACKEND=sqlite|postgres`
- `SOC_POSTGRES_DSN=postgresql://...`
- `SOC_POSTGRES_SCHEMA=public`

### Control Plane

Memory, approvals, and worker queues can use either SQLite or PostgreSQL:

- `SOC_CONTROLPLANE_BACKEND=sqlite|postgres`
- `SOC_CONTROLPLANE_POSTGRES_DSN=postgresql://...`
- `SOC_CONTROLPLANE_POSTGRES_SCHEMA=soc_control`

### Additional State

- `SOC_EVENT_LOG_DIR=...`
- `SOC_MEMORY_DB_PATH=...`
- `SOC_APPROVAL_DB_PATH=...`
- `SOC_WORKER_DB_PATH=...`

SQLite remains the default for simple local use. PostgreSQL support exists both for the investigation store and the stateful control-plane services.

## Testing

Run the main local suite with:

```bash
pytest tests/ -q
```

Optional live or environment-specific checks:

```bash
pytest tests/test_integration.py -v -s
```

PostgreSQL-specific tests are enabled when `SOC_TEST_POSTGRES_DSN` is set.

## Status

`soc-agent` is materially beyond an MVP. It now has a real model abstraction layer, planning and scheduling, shared state, memory and replay, remote worker support, approval gating, API mode, and metrics.

It is still not at finished enterprise-production maturity. The biggest remaining gaps are:

- stronger secret-management posture
- deeper isolated execution and sandboxing
- broader deployment hardening
- richer enterprise auth and policy depth
- broader integration surface

That said, the platform is now operational enough to run real terminal-first investigations, exercise policy-gated actions, and validate the control plane end to end.
