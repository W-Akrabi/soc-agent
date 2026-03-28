# Gate 3 Execution Plan, Subagent-Driven

## Summary

Implement the approved Gate 3 spec from `docs/superpowers/plans/2026-03-27-gate-3-real-integrations.md` as a **task-by-task, review-between-tasks rollout**, with limited parallelism only where the write sets are meaningfully disjoint. The goal is to add real SOC integrations without letting vendor-specific logic leak into agents or breaking the deterministic offline test story established in earlier gates.

This execution plan is grounded in the current repo state:
- Current non-live baseline is green: `104 passed, 3 skipped` from `pytest soc-agent/tests/ -q --ignore=soc-agent/tests/test_integration.py`
- Gate 2 architecture seams are already in place:
  - `core/app.py` is the composition root
  - `agents/commander.py` delegates to planner and scheduler
  - `core/schemas.py` already carries typed investigation and scheduling contracts
- The main Gate 3 stub points are still present:
  - `tools/threat_feed.py` is still a point integration
  - `tools/action_executor.py` is still a local stub
  - `agents/recon.py`, `agents/threat_intel.py`, `agents/forensics.py`, and `agents/remediation.py` still own too much external-tool logic directly

The sequencing below is designed to land stable primitives first, then normalize read integrations, then add real execution, then wire runtime/reporting, and only then widen smoke coverage.

---

## Execution Sequence

### Phase A: shared primitives and safe seams, strict serial

1. **Task 1: integration contracts, registry, and config**
   - Worker scope:
     - `core/config.py`
     - `core/schemas.py`
     - `core/integrations.py`
     - `integrations/base.py`
     - `integrations/registry.py`
     - `tests/test_config.py`
     - `tests/test_integration_registry.py`
   - Deliverables:
     - typed integration contracts
     - integration registry/factory
     - integration and execution safety config
   - Validation:
     - `pytest tests/test_integration_registry.py tests/test_config.py -v`
   - Review gate:
     - config defaults are safe
     - no vendor-specific code appears in agents
     - dry-run remains supportable with zero integrations configured

2. **Task 2: fixture record/replay harness**
   - Worker scope:
     - `integrations/fixtures.py`
     - `tests/fixtures/integrations/...`
     - fixture harness tests created in a new focused test file or under registry tests
   - Deliverables:
     - record/replay support
     - request fingerprinting
     - fixture sanitization
   - Validation:
     - fixture harness tests
   - Review gate:
     - replay mode is fully offline
     - record mode is opt-in only
     - no tokens, bearer headers, or secrets are written to fixtures

### Phase B: first normalized read path, serial

3. **Task 3: normalized threat-intel adapter**
   - Worker scope:
     - `integrations/threat_intel.py`
     - `tools/threat_feed.py`
     - `agents/threat_intel.py`
     - `tests/test_threat_intel_integration.py`
     - `tests/test_normalization.py`
     - `tests/test_agents.py`
   - Deliverables:
     - adapter-backed AbuseIPDB/VirusTotal integration
     - normalized evidence records
     - threat-intel agent writing normalized evidence instead of raw merged dicts
   - Validation:
     - `pytest tests/test_threat_intel_integration.py tests/test_normalization.py tests/test_agents.py -v`
   - Review gate:
     - partial upstream failure is modeled explicitly
     - missing API keys degrade cleanly
     - event log entries contain counts and source names, not raw secrets or auth details

### Phase C: Microsoft read integrations, limited parallelism after shared auth lands

4. **Task 4A: shared Microsoft auth and Sentinel adapter**
   - Worker scope:
     - `integrations/sentinel.py`
     - shared auth helpers in `integrations/base.py` or equivalent
     - `tests/test_sentinel_integration.py`
     - `tests/test_normalization.py`
   - Deliverables:
     - shared Microsoft auth helper
     - Sentinel read adapter
     - normalized Sentinel evidence
   - Validation:
     - `pytest tests/test_sentinel_integration.py tests/test_normalization.py -v`
   - Review gate:
     - auth helper is reusable for Defender and Entra
     - auth/config failures are clear and non-secret-bearing

5. **Task 4B: Defender adapter and host evidence wiring**
   - Worker scope:
     - `integrations/defender.py`
     - `agents/recon.py`
     - `tests/test_defender_integration.py`
     - `tests/test_normalization.py`
     - relevant `tests/test_agents.py`
   - Deliverables:
     - Defender read adapter
     - host/device evidence path into recon
   - Validation:
     - `pytest tests/test_defender_integration.py tests/test_normalization.py tests/test_agents.py -v`
   - Review gate:
     - recon uses registry-driven evidence collection
     - missing Defender config degrades gracefully

6. **Task 4C: Entra adapter and identity/timeline evidence wiring**
   - Worker scope:
     - `integrations/entra.py`
     - `agents/forensics.py`
     - `tests/test_entra_integration.py`
     - `tests/test_normalization.py`
     - relevant `tests/test_agents.py`
   - Deliverables:
     - Entra read adapter
     - identity and audit evidence path into forensics
   - Validation:
     - `pytest tests/test_entra_integration.py tests/test_normalization.py tests/test_agents.py -v`
   - Review gate:
     - forensics consumes normalized identity/timeline evidence cleanly
     - empty result sets are not treated as failures

Parallelism rule for Phase C:
- `Task 4B` and `Task 4C` may run in parallel **only after** `Task 4A` is merged locally, because both depend on the shared auth seam and normalization conventions.

### Phase D: real execution, strict serial

7. **Task 5: execution policy and real remediation adapters**
   - Worker scope:
     - `core/execution_policy.py`
     - `agents/remediation.py`
     - `tools/action_executor.py`
     - `integrations/defender.py`
     - `integrations/entra.py`
     - `tests/test_execution_policy.py`
     - remediation-focused `tests/test_agents.py`
   - Deliverables:
     - propose-only default policy
     - allowlisted execution policy
     - real first-wave actions:
       - `isolate_host`
       - `disable_account`
       - `revoke_sessions`
   - Validation:
     - `pytest tests/test_execution_policy.py tests/test_agents.py -v`
   - Review gate:
     - no write action executes unless config and allowlist both permit it
     - unsupported actions remain proposed with an explicit reason
     - execution failures are structured and persisted, not opaque

### Phase E: runtime composition and reporting, strict serial

8. **Task 6: app composition, agent wiring, and reporting**
   - Worker scope:
     - `core/app.py`
     - `agents/commander.py`
     - `agents/recon.py`
     - `agents/threat_intel.py`
     - `agents/forensics.py`
     - `agents/reporter.py`
     - `tests/test_app.py`
     - `tests/test_agents.py`
   - Deliverables:
     - integration registry and execution policy built centrally in app composition
     - agents receiving adapters through shared runtime wiring
     - reports grouped by source with explicit executed-vs-proposed actions
   - Validation:
     - `pytest tests/test_app.py tests/test_agents.py -v`
   - Review gate:
     - `core/app.py` remains the only composition root
     - agents no longer construct vendor integrations directly
     - dry-run stays local-safe and may optionally support replay mode

### Phase F: regression and smoke, final serial task

9. **Task 7: replay-backed smoke and offline guarantees**
   - Worker scope:
     - `tests/test_dry_run_smoke.py`
     - replay-backed smoke tests
     - optional live-smoke tests if introduced
   - Deliverables:
     - dry-run smoke still safe without live integrations
     - replay-backed integration smoke using sample alerts
     - opt-in live smoke tests, skipped by default
   - Validation:
     - `pytest tests/ -v --ignore=tests/test_integration_live.py`
   - Review gate:
     - main suite stays deterministic and offline
     - live tests never run by default

---

## Subagent Assignment Rules

- Use a **fresh worker per task**.
- Merge and review after every completed task before starting the next worker.
- Only `Task 4B` and `Task 4C` may run in parallel, and only after `Task 4A` is landed.
- Worker ownership must stay strict:
  - `Task 1` owns contracts, registry, and config only.
  - `Task 2` owns fixture infrastructure only.
  - `Task 3` owns the threat-intel adapter path only.
  - `Task 4A` owns shared Microsoft auth and Sentinel only.
  - `Task 4B` owns Defender plus recon-side host evidence wiring.
  - `Task 4C` owns Entra plus forensics-side identity/timeline wiring.
  - `Task 5` owns execution policy and real write actions.
  - `Task 6` owns app composition and reporting integration.
  - `Task 7` owns smoke coverage only.
- Later workers must not “cleanup refactor” unrelated earlier areas unless the current task explicitly requires it.

---

## Validation and Merge Gates

- **After Task 1:** run
  - `pytest tests/test_integration_registry.py tests/test_config.py -v`

- **After Task 2:** run
  - fixture harness tests
  - `pytest tests/test_integration_registry.py tests/test_config.py -v`

- **After Task 3:** run
  - `pytest tests/test_threat_intel_integration.py tests/test_normalization.py tests/test_agents.py -v`

- **After Task 4A:** run
  - `pytest tests/test_sentinel_integration.py tests/test_normalization.py -v`

- **After Phase C merge:** run
  - `pytest tests/test_sentinel_integration.py tests/test_defender_integration.py tests/test_entra_integration.py tests/test_normalization.py tests/test_agents.py -v`

- **After Task 5:** run
  - `pytest tests/test_execution_policy.py tests/test_agents.py -v`

- **After Task 6:** run
  - `pytest tests/test_app.py tests/test_agents.py -v`

- **After Task 7:** run
  - `pytest tests/ -v --ignore=tests/test_integration_live.py`

Optional live validation after the full gate:
- Sentinel live smoke if Microsoft credentials are present
- Defender live smoke if Defender scope is configured
- Entra live smoke if Graph scope is configured

---

## Important Implementation Details

- `core/app.py` must remain the single place that composes integrations and execution policy.
- `tools/threat_feed.py` and `tools/action_executor.py` may survive as compatibility shims during the gate, but the real logic must move behind adapter and policy layers.
- Agents should consume normalized evidence and normalized execution results. They should not branch on vendor-specific raw response structure.
- Store source provenance on every externally derived record:
  - source adapter name
  - entity type/value
  - stable external reference where available
- Event logging must capture:
  - adapter name
  - operation
  - target entity
  - record counts
  - execution decision
  - execution outcome
  It must never capture tokens, bearer headers, cookies, or raw authorization data.
- Dry-run must remain safe without live credentials. If replay mode is supported in dry-run, it must still avoid network calls.
- Write execution must remain config-gated and allowlist-gated even if `auto_remediate` still exists for compatibility.
- Prefer thin `httpx` clients over heavy vendor SDKs unless a specific SDK is clearly required for auth or request correctness.

---

## Acceptance Criteria

- All Gate 3 tasks are merged green in the order above.
- The runtime can collect normalized external evidence from at least:
  - Sentinel
  - Defender
  - Entra
  - threat intel feeds
- The integration layer is centralized behind registry and adapter contracts.
- Threat-intel, recon, and forensics paths use normalized evidence instead of vendor-specific raw payloads.
- Remediation supports real first-wave write actions and defaults to propose-only.
- Fixture replay enables deterministic offline testing of integration behavior.
- Dry-run remains local-safe with no live credentials required.
- `pytest tests/ -v --ignore=tests/test_integration_live.py` passes at the end of the gate.

---

## Assumptions

- Commit cadence stays **one commit per task**, matching the earlier gate execution style, if the workspace is later attached to git.
- Live integration tests remain opt-in and are not part of the default unit suite.
- This execution plan covers Gate 3 only. Gate 4 should be planned only after Gate 3 is merged green.
