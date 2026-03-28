# Gate 3: Real Integrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `soc-agent` from a well-structured internal SOC platform into a system that can collect evidence from real security systems and execute tightly scoped remediation actions through real vendor APIs, while remaining terminal-first and human-gated by default.

**Architecture:** Gate 2 established the stable seams for this work: `core/app.py` owns composition, `core/providers.py` owns model selection, `core/storage.py` abstracts persistence, and `core/planner.py` + `core/scheduler.py` own investigation flow. Gate 3 must attach real external systems to that architecture rather than introducing a parallel path. The guiding rule is normalized integration data in, normalized action execution out.

**Tech Stack:** Python 3.11+, existing `httpx`, `pytest`, `pytest-asyncio`, current storage/event-log stack, and provider abstraction from Gate 2. New dependencies are allowed only where required for Microsoft authentication or fixture capture, and must be justified by a concrete integration need.

---

## Scope note

This plan covers Gate 3 only:
- standard read/write integration adapter contracts
- first-wave read integrations
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
  - Entra ID sign-in and audit data
  - threat intel feeds
- evidence normalization from vendor payloads into typed internal records
- real remediation execution for a limited first-wave action set
- fixture recording and replay for deterministic offline tests

It does **not** cover:
- cross-incident memory or asset baselining
- analyst approval queues or rich approval UX
- ServiceNow, Teams, Slack, Jira, or ticketing workflows
- remote workers or multi-host execution
- public API surfaces

Those remain later gates.

---

## Why Gate 3 exists

After Gate 2, `soc-agent` has a stronger internal platform:
- provider abstraction
- storage abstraction
- deterministic planner
- scheduler with retries and early stop

But the system still reasons mostly over:
- inbound alert payloads
- locally generated context
- lightweight tools such as `tools/threat_feed.py`
- non-operational remediation through `tools/action_executor.py`

Gate 3 exists to change that. It is the gate where the system gains real operational reach into external SOC systems and starts behaving like a serious SOC investigation platform instead of only an internal orchestration framework.

---

## Design decisions locked for this gate

- `core/app.py` remains the internal composition root.
- `main.py` remains a thin CLI wrapper.
- The planner and scheduler remain authoritative for investigation flow. Integrations supply evidence and actions; they do not bypass the planner.
- Terminal-first remains the product stance. No web UI is introduced in this gate.
- Default operating mode remains safe:
  - read integrations are enabled when configured
  - write integrations are **propose-only by default**
  - actual execution requires explicit config and action-level allowlisting
- Integration code must be adapter-based and vendor-specific logic must not be scattered across agents.
- Agents consume normalized evidence and normalized action results, not raw vendor payloads directly.
- Raw vendor responses may be stored only as sanitized references or redacted snapshots. Secrets and access tokens must never be written to the event log or persisted evidence.
- Every integration added in this gate must support replayable fixtures so tests remain deterministic without live vendor dependencies.
- Microsoft-heavy first wave is intentional:
  - Sentinel
  - Defender
  - Entra
- Threat intel remains part of Gate 3, but it must move behind the same adapter and normalization layer rather than remain a one-off tool.

---

## Current repo grounding

This plan is anchored to the current post-Gate 2 codebase:

- `core/app.py` already composes provider, storage, planner, scheduler, and event log.
- `agents/commander.py` now delegates sequencing to the planner and scheduler rather than hardcoding the old phase pipeline.
- `agents/recon.py`, `agents/threat_intel.py`, and `agents/remediation.py` still rely on tool-level logic rather than a true integration plane.
- `tools/threat_feed.py` is a direct point integration and should become an adapter-backed implementation in this gate.
- `tools/action_executor.py` is still a local stub and must be replaced by real execution adapters plus policy gating.
- `core/schemas.py` already contains typed investigation and scheduling contracts; Gate 3 should extend those schemas rather than invent new ad hoc payloads.

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `core/config.py` | **Modify** | Add integration config, fixture mode, execution safety config |
| `core/app.py` | **Modify** | Build integration registry and execution policy into the app composition |
| `core/schemas.py` | **Modify** | Add normalized evidence and action execution contracts |
| `core/integrations.py` | **Create** | Adapter interfaces, registry, and factory helpers |
| `core/execution_policy.py` | **Create** | Gating for propose-only vs allowlisted execution |
| `integrations/__init__.py` | **Create** | Package marker |
| `integrations/base.py` | **Create** | Shared adapter base classes/helpers |
| `integrations/registry.py` | **Create** | Runtime adapter registry |
| `integrations/fixtures.py` | **Create** | Fixture record/replay helpers and sanitization |
| `integrations/sentinel.py` | **Create** | Sentinel read adapter |
| `integrations/defender.py` | **Create** | Defender read/write adapter |
| `integrations/entra.py` | **Create** | Entra read/write adapter |
| `integrations/threat_intel.py` | **Create** | AbuseIPDB/VirusTotal adapter behind common contract |
| `tools/threat_feed.py` | **Refactor or deprecate** | Compatibility shim to new threat-intel adapter |
| `tools/action_executor.py` | **Refactor or deprecate** | Compatibility shim to real execution layer |
| `agents/recon.py` | **Modify** | Use integration registry for external enrichment and normalized evidence writes |
| `agents/threat_intel.py` | **Modify** | Consume threat-intel adapter and normalized evidence records |
| `agents/forensics.py` | **Modify** | Pull timeline and host/user context from external adapters where available |
| `agents/remediation.py` | **Modify** | Convert proposals into gated execution requests through real adapters |
| `agents/reporter.py` | **Modify** | Surface external evidence provenance and action execution details in reports |
| `tests/test_config.py` | **Modify** | Cover integration/env config parsing |
| `tests/test_integration_registry.py` | **Create** | Adapter registration and selection tests |
| `tests/test_normalization.py` | **Create** | Vendor payload to normalized evidence tests |
| `tests/test_execution_policy.py` | **Create** | Safety gating tests |
| `tests/test_sentinel_integration.py` | **Create** | Sentinel adapter tests with replay fixtures |
| `tests/test_defender_integration.py` | **Create** | Defender adapter tests with replay fixtures |
| `tests/test_entra_integration.py` | **Create** | Entra adapter tests with replay fixtures |
| `tests/test_threat_intel_integration.py` | **Create** | Threat intel adapter tests |
| `tests/test_agents.py` | **Modify** | Agent behavior with normalized evidence and execution outcomes |
| `tests/test_app.py` | **Modify** | App wiring with integration registry and execution policy |
| `tests/test_dry_run_smoke.py` | **Modify** | Confirm dry-run remains offline and does not require integrations |
| `tests/fixtures/integrations/...` | **Create** | Recorded and replayable vendor response fixtures |

The exact module split may vary, but the responsibilities must remain intact.

---

## Contracts introduced in Gate 3

Gate 3 must add typed contracts for normalized evidence and action execution. These may live in `core/schemas.py` or a closely related module, but the split of responsibility must stay the same.

### Integration query contract

```python
@dataclass
class IntegrationQuery:
    alert_id: str
    alert_type: str
    entity_type: str
    entity_value: str
    time_range_hours: int = 24
    context: dict[str, Any] = field(default_factory=dict)
```

### Normalized evidence contract

```python
@dataclass
class NormalizedEvidence:
    source: str
    source_type: str
    entity_type: str
    entity_value: str
    title: str
    summary: str
    severity: str | None = None
    confidence: float | None = None
    observed_at: datetime | None = None
    raw_ref: str | None = None
    tags: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
```

### Evidence batch contract

```python
@dataclass
class EvidenceBatch:
    adapter_name: str
    query: IntegrationQuery
    records: list[NormalizedEvidence]
    partial: bool = False
    error: str | None = None
```

### Action execution request contract

```python
@dataclass
class ActionExecutionRequest:
    action_type: str
    target: str
    reason: str
    urgency: str
    requested_by: str
    allow_execution: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
```

### Action execution result contract

```python
@dataclass
class ActionExecutionResult:
    adapter_name: str
    action_type: str
    target: str
    status: str
    executed: bool
    external_id: str | None = None
    rollback_supported: bool = False
    message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

### Integration adapter contract

```python
class IntegrationAdapter(Protocol):
    name: str
    supports_read: bool
    supports_write: bool

    async def healthcheck(self) -> dict[str, Any]: ...
    async def collect(self, query: IntegrationQuery) -> EvidenceBatch: ...
    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult: ...
```

These exact names may vary, but the design intent must remain:
- reads return normalized evidence batches
- writes return normalized execution results
- adapters declare their capabilities

---

## Configuration introduced in Gate 3

Gate 3 should extend `core/config.py` with explicit integration and safety settings.

### Integration selection

- `SOC_ENABLED_INTEGRATIONS=sentinel,defender,entra,threat_intel`
- `SOC_FIXTURE_MODE=off|record|replay`
- `SOC_FIXTURE_DIR=./tests/fixtures/integrations`

### Microsoft auth

- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_SUBSCRIPTION_ID`

### Sentinel targeting

- `SOC_SENTINEL_WORKSPACE_ID`
- `SOC_SENTINEL_RESOURCE_GROUP`
- `SOC_SENTINEL_SUBSCRIPTION_ID`

### Defender / Entra targeting

- `SOC_DEFENDER_BASE_URL` if non-default
- `SOC_GRAPH_BASE_URL` if non-default

### Threat intel

- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY`

### Execution safety

- `SOC_EXECUTION_MODE=propose_only|allowlisted_execute`
- `SOC_ALLOWED_ACTIONS=isolate_host,disable_account,revoke_sessions`

Backward compatibility:
- `auto_remediate` may remain in config for CLI continuity, but Gate 3 should route the actual decision through `SOC_EXECUTION_MODE` and allowlisted action types.

---

## Task 1: Add integration contracts, registry, and config

**Files:**
- Create: `core/integrations.py`
- Create: `integrations/base.py`
- Create: `integrations/registry.py`
- Modify: `core/config.py`
- Modify: `core/schemas.py`
- Create: `tests/test_integration_registry.py`
- Modify: `tests/test_config.py`

Gate 3 starts by creating one place where integrations are registered, built, and discovered. Agents should never import vendor-specific adapters directly.

- [ ] **Step 1: Write registry and config tests**

Create tests that assert:
- integrations are selected from config
- unknown integration names fail clearly
- execution mode defaults to safe propose-only
- fixture mode parses correctly
- registry can return read and write capable adapters by capability

- [ ] **Step 2: Add typed contracts**

Add the `IntegrationQuery`, `NormalizedEvidence`, `EvidenceBatch`, `ActionExecutionRequest`, and `ActionExecutionResult` contracts.

- [ ] **Step 3: Add integration config**

Extend `Config` with:
- enabled integrations
- fixture mode and fixture directory
- Microsoft auth settings
- execution mode and allowlisted action types

- [ ] **Step 4: Implement registry/factory**

The registry must:
- build enabled adapters from config
- expose read-capable and write-capable subsets
- support no-integration mode cleanly for dry-run and lightweight local runs

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_integration_registry.py tests/test_config.py -v
```

Expected: registry and config wiring is green before vendor-specific work starts.

---

## Task 2: Add fixture record/replay support

**Files:**
- Create: `integrations/fixtures.py`
- Create: `tests/fixtures/integrations/...`
- Create: adapter fixture tests as needed

This gate depends on deterministic offline tests. Fixture recording and replay must land before the heavier integrations so each adapter can target the same harness.

- [ ] **Step 1: Define fixture format**

Requirements:
- JSON fixture files
- request fingerprinting by adapter + operation + query key
- optional sanitized response snapshots
- support for both recorded success and recorded failure cases

- [ ] **Step 2: Implement replay mode**

Requirements:
- replay should not require network access
- missing fixtures should fail clearly
- adapters should be able to run fully under replay mode in tests

- [ ] **Step 3: Implement record mode**

Requirements:
- record only when explicitly enabled
- sanitize tokens, bearer headers, cookies, and secrets before writing fixtures
- never write raw API keys or OAuth tokens to disk

- [ ] **Step 4: Add harness tests**

Add tests for:
- recording metadata shape
- replay lookup
- missing fixture failures
- sanitization

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_integration_registry.py tests/test_config.py -v
```

Expected: fixture infrastructure is ready for vendor adapters.

---

## Task 3: Implement normalized threat intel adapter

**Files:**
- Create: `integrations/threat_intel.py`
- Refactor or deprecate: `tools/threat_feed.py`
- Modify: `agents/threat_intel.py`
- Create: `tests/test_threat_intel_integration.py`
- Create: `tests/test_normalization.py`

Threat intel is the easiest existing external integration to normalize first. It establishes the evidence shape before the Microsoft adapters land.

- [ ] **Step 1: Wrap AbuseIPDB and VirusTotal behind the adapter contract**

Requirements:
- preserve current API-key based access
- convert current response logic into normalized evidence batches
- return partial batches cleanly when one upstream source is unavailable

- [ ] **Step 2: Normalize vendor responses**

Examples:
- IP reputation findings become evidence records with source attribution and confidence
- hash analysis findings become evidence records with maliciousness indicators and tags

- [ ] **Step 3: Update the Threat Intel agent**

Requirements:
- agent writes normalized evidence records to storage
- agent no longer depends on raw merged dicts
- event log records adapter source and record counts, not secret-bearing payloads

- [ ] **Step 4: Add normalization tests**

Cover:
- IP lookup normalization
- hash lookup normalization
- partial upstream failure
- missing API keys behavior

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_threat_intel_integration.py tests/test_normalization.py tests/test_agents.py -v
```

Expected: the first real adapter is normalized end-to-end.

---

## Task 4: Implement Microsoft read adapters

**Files:**
- Create: `integrations/sentinel.py`
- Create: `integrations/defender.py`
- Create: `integrations/entra.py`
- Modify: `agents/recon.py`
- Modify: `agents/forensics.py`
- Create: `tests/test_sentinel_integration.py`
- Create: `tests/test_defender_integration.py`
- Create: `tests/test_entra_integration.py`
- Modify: `tests/test_normalization.py`

This task delivers the first SOC-native real evidence collection. The adapters should be thin vendor clients that return normalized batches; agents decide how to use those batches.

- [ ] **Step 1: Implement shared Microsoft auth helper**

Requirements:
- one auth path for Sentinel, Defender, and Entra
- no token leakage to event log or fixtures
- clear error messages for missing tenant/client config

- [ ] **Step 2: Implement Sentinel read adapter**

Read scope for this gate:
- alert or incident context by entity
- basic incident or log lookup for IP, host, or account
- normalized findings that can feed recon or forensics

- [ ] **Step 3: Implement Defender read adapter**

Read scope for this gate:
- machine/device lookup
- basic machine action history or investigation context
- normalized findings for host and file indicators

- [ ] **Step 4: Implement Entra read adapter**

Read scope for this gate:
- sign-in activity by user/IP
- audit context for account changes
- normalized identity findings

- [ ] **Step 5: Wire Recon and Forensics agents**

Requirements:
- `ReconAgent` should collect relevant external evidence when IP, host, or user context exists
- `ForensicsAgent` should incorporate timeline-like evidence from supported adapters
- missing integrations must degrade gracefully without breaking the investigation

- [ ] **Step 6: Add replay-based tests**

Cover:
- each adapter normalizes representative vendor responses
- each adapter handles auth/config errors cleanly
- each adapter handles empty result sets cleanly
- agents can consume the normalized outputs

- [ ] **Step 7: Optional live-smoke tests**

Add opt-in live tests that run only when the relevant env vars are present. These tests must be skipped by default and must never run in CI unless explicitly enabled.

- [ ] **Step 8: Run tests**

```bash
pytest tests/test_sentinel_integration.py tests/test_defender_integration.py tests/test_entra_integration.py tests/test_normalization.py tests/test_agents.py -v
```

Expected: real read integrations are available without making the base test suite depend on live vendor access.

---

## Task 5: Replace stub remediation with real execution adapters

**Files:**
- Modify: `agents/remediation.py`
- Refactor or deprecate: `tools/action_executor.py`
- Modify: `integrations/defender.py`
- Modify: `integrations/entra.py`
- Create: `core/execution_policy.py`
- Create: `tests/test_execution_policy.py`
- Modify: `tests/test_agents.py`

This task replaces the current local action stub with real vendor-backed action execution for a tightly scoped first wave.

- [ ] **Step 1: Define the allowed first-wave action set**

Gate 3 write scope is intentionally narrow:
- `isolate_host` via Defender where supported
- `disable_account` via Entra where supported
- `revoke_sessions` via Entra where supported

Anything else remains proposed-only in this gate.

- [ ] **Step 2: Implement execution policy**

Requirements:
- default mode is `propose_only`
- execution requires:
  - explicit execution mode
  - allowlisted action type
  - adapter support for the target action
- policy decisions must be visible in logs and persisted action metadata

- [ ] **Step 3: Implement adapter-backed execute methods**

Requirements:
- Defender execute returns a normalized execution result
- Entra execute returns a normalized execution result
- execution failures are captured as structured results, not raised as opaque strings unless truly fatal

- [ ] **Step 4: Update Remediation agent**

Requirements:
- schema-validated action proposals from Gate 1 remain the input
- each proposal is converted into an `ActionExecutionRequest`
- the agent routes the request through policy first, then to the right adapter if execution is permitted
- if execution is not permitted, the action remains proposed with a clear reason

- [ ] **Step 5: Add tests**

Cover:
- propose-only default behavior
- allowlisted execution path
- unsupported action handling
- adapter execution failure handling
- persisted action status and result metadata

- [ ] **Step 6: Run tests**

```bash
pytest tests/test_execution_policy.py tests/test_agents.py -v
```

Expected: remediation is real but still constrained and safe by default.

---

## Task 6: Wire integrations into app composition and reporting

**Files:**
- Modify: `core/app.py`
- Modify: `agents/commander.py`
- Modify: `agents/reporter.py`
- Modify: `tests/test_app.py`
- Modify: `tests/test_agents.py`

Once the adapters exist, the runtime must compose them centrally and the final report must reflect where evidence and actions came from.

- [ ] **Step 1: Build integrations in `core/app.py`**

Requirements:
- build registry from config
- attach fixture mode
- attach execution policy
- pass registry/policy to the agents that need them

- [ ] **Step 2: Keep dry-run fully offline**

Requirements:
- dry-run must not require live integration config
- replay mode may be supported in dry-run if fixtures exist
- default dry-run path remains safe and local

- [ ] **Step 3: Update reporting**

Reports should now include:
- normalized evidence grouped by source
- action proposals vs executed actions
- external references where available
- degraded-mode notes when configured integrations were unavailable

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_app.py tests/test_agents.py -v
```

Expected: integration wiring is centralized and visible in the final output.

---

## Task 7: Add regression and smoke coverage

**Files:**
- Modify: `tests/test_dry_run_smoke.py`
- Add optional live-smoke tests if needed
- Add or update fixture-backed integration smoke coverage

Gate 3 changes real-world behavior significantly, so regression and smoke coverage must confirm both safe offline mode and real integration paths.

- [ ] **Step 1: Keep dry-run smoke safe**

Extend the existing dry-run smoke test to assert:
- no live integration config is required
- reports and event logs still land in temp paths
- missing integration env vars do not break dry-run

- [ ] **Step 2: Add replay-backed integration smoke**

Requirements:
- use sample alerts
- run with `SOC_FIXTURE_MODE=replay`
- assert external evidence is produced from fixtures
- assert no network access is required

- [ ] **Step 3: Add optional live smoke**

Add small opt-in tests for one read path and one write path per vendor family where practical. These tests must:
- be clearly marked
- skip cleanly without credentials
- never run by default in the main unit suite

- [ ] **Step 4: Run tests**

```bash
pytest tests/ -v --ignore=tests/test_integration_live.py
```

Expected: Gate 3 remains deterministic locally while supporting real live validation when credentials are present.

---

## Validation and merge gates

- **After Task 1:** run
  - `pytest tests/test_integration_registry.py tests/test_config.py -v`

- **After Task 2:** run
  - fixture harness tests
  - `pytest tests/test_integration_registry.py tests/test_config.py -v`

- **After Task 3:** run
  - `pytest tests/test_threat_intel_integration.py tests/test_normalization.py tests/test_agents.py -v`

- **After Task 4:** run
  - `pytest tests/test_sentinel_integration.py tests/test_defender_integration.py tests/test_entra_integration.py tests/test_normalization.py tests/test_agents.py -v`

- **After Task 5:** run
  - `pytest tests/test_execution_policy.py tests/test_agents.py -v`

- **After Task 6:** run
  - `pytest tests/test_app.py tests/test_agents.py -v`

- **After Task 7:** run
  - `pytest tests/ -v --ignore=tests/test_integration_live.py`

Optional live validation after the full gate:
- Sentinel live smoke if Microsoft creds are present
- Defender live smoke if Defender scope is configured
- Entra live smoke if Graph scope is configured

---

## Important implementation details

- Do not let adapters write vendor-specific raw payloads directly into graph nodes. Normalize first.
- Preserve source provenance:
  - every evidence record should carry `source` and a stable `raw_ref` or equivalent external reference
- Event logs must record:
  - adapter name
  - operation
  - query target
  - record counts
  - execution decision
  - execution result status
  They must not record secrets, access tokens, or raw authorization headers.
- Gate 3 should prefer thin `httpx` clients over large vendor SDKs unless the SDK is clearly required.
- `tools/threat_feed.py` and `tools/action_executor.py` may remain as compatibility shims during the gate, but the real logic should move behind adapters and execution policy.
- Missing integrations must degrade gracefully. Investigations should continue with partial evidence rather than failing the whole run.
- `ReporterAgent` should explicitly distinguish:
  - evidence derived from external systems
  - evidence inferred by the model
  - actions proposed but not executed
  - actions actually executed
- Do not add approval queues in this gate. Keep policy gating simple and config-based.

---

## Acceptance criteria

- `soc-agent` can ingest a sample alert and, when configured, collect normalized external evidence from at least:
  - Sentinel
  - Defender
  - Entra
  - threat intel feeds
- The integration layer is centralized behind adapter contracts and registry/factory wiring.
- Agents use normalized evidence instead of vendor-specific raw payload structures.
- The remediation path supports real first-wave vendor-backed actions and defaults to propose-only.
- Fixture replay exists and allows deterministic offline testing of integration behavior.
- Dry-run remains local-safe and does not require live credentials.
- `pytest tests/ -v --ignore=tests/test_integration_live.py` passes at the end of the gate.

---

## Risks and constraints

- Microsoft APIs have non-trivial auth and permission variance across tenants. The plan must assume partial availability and explicit error handling.
- Live integration behavior can drift faster than unit logic. Fixture replay reduces this risk but does not remove the need for optional live-smoke tests.
- Write actions carry real operational risk. Keeping execution allowlisted and propose-only by default is non-negotiable in this gate.
- It is better to ship three clean adapters with consistent normalization than six shallow adapters with inconsistent evidence shapes.

---

## Next: Gate 4

After Gate 3 is merged green, the next plan should be:

`docs/superpowers/plans/2026-03-27-gate-4-correlation-and-memory.md`

Gate 4 scope summary:
- cross-incident memory
- entity and asset correlation
- historical pattern retrieval
- analyst feedback capture
- baseline-aware hypothesis scoring
- replay and evaluation improvements built on top of real integrated evidence
