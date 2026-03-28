import pytest
from unittest.mock import AsyncMock, MagicMock
from core.case_graph import CaseGraph
from core.execution_policy import ExecutionPolicy
from core.models import Alert, AlertType, Severity
from datetime import datetime, timezone
from rich.console import Console
from agents.recon import ReconAgent
from agents.threat_intel import ThreatIntelAgent
from agents.forensics import ForensicsAgent
from agents.remediation import RemediationAgent
from agents.reporter import ReporterAgent
from core.schemas import ActionExecutionResult, EvidenceBatch, IntegrationQuery, NormalizedEvidence


@pytest.fixture
def graph(tmp_path):
    return CaseGraph(str(tmp_path / "test.db"))

@pytest.fixture
def console():
    return Console(quiet=True)

@pytest.fixture
def alert():
    return Alert(
        id="test-alert-1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={"rule_name": "TEST", "logs": [{"ts": "2026-01-01T00:00:00Z", "event": "test"}]},
        source_ip="185.220.101.45",
        dest_ip="10.0.1.50",
        dest_port=8080,
        hostname="web-prod-01",
    )

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.call = AsyncMock(return_value='{"tasks": []}')
    return llm


@pytest.mark.asyncio
async def test_recon_agent_writes_ip_nodes(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value="I found geo data for the IP.")
    alert_node_id = graph.write_node("alert", "test-alert-1", {"alert_id": alert.id}, "ingestion")
    task_id = graph.write_node("task", "recon-task", {"agent": "recon", "objective": "Investigate IP"}, "commander")

    agent = ReconAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    ip_nodes = graph.get_nodes_by_type("ip")
    assert len(ip_nodes) >= 1
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
async def test_threat_intel_agent_writes_cve_nodes(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value="CVE-2024-1337 is critical.")
    graph.write_node("ip", "185.220.101.45", {"open_ports": [{"port": 8080}]}, "recon")
    task_id = graph.write_node("task", "intel-task", {"agent": "threat_intel", "objective": "Look up CVEs"}, "commander")

    agent = ThreatIntelAgent(graph, mock_llm, console)
    batch = EvidenceBatch(
        adapter_name="threat_intel",
        query=IntegrationQuery(
            alert_id=alert.id,
            alert_type=alert.type.value,
            entity_type="ip",
            entity_value="185.220.101.45",
        ),
        records=[
            NormalizedEvidence(
                source="abuseipdb",
                source_type="threat_intel",
                entity_type="ip",
                entity_value="185.220.101.45",
                title="AbuseIPDB reputation for 185.220.101.45",
                summary="Known malicious host",
                severity="high",
                confidence=92.0,
            )
        ],
    )
    agent.threat_adapter.collect = AsyncMock(return_value=batch)
    await agent.run(task_id, alert)

    cve_nodes = graph.get_nodes_by_type("cve")
    finding_nodes = graph.get_nodes_by_type("finding")
    evidence_nodes = graph.get_nodes_by_type("evidence")
    assert len(cve_nodes) + len(finding_nodes) >= 1
    assert len(evidence_nodes) >= 1
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
async def test_forensics_agent_writes_timeline_events(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value="Timeline: login then escalation then exfil.")
    task_id = graph.write_node("task", "forensics-task", {"agent": "forensics", "objective": "Build timeline"}, "commander")

    agent = ForensicsAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    timeline_nodes = graph.get_nodes_by_type("timeline_event")
    assert len(timeline_nodes) >= 1
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
async def test_remediation_agent_writes_action_nodes(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value='[{"action_type": "block_ip", "target": "185.220.101.45", "reason": "malicious", "urgency": "immediate"}]')
    task_id = graph.write_node("task", "remediation-task", {"agent": "remediation"}, "commander")

    agent = RemediationAgent(graph, mock_llm, console, auto_remediate=False)
    await agent.run(task_id, alert)

    action_nodes = graph.get_nodes_by_type("action")
    assert len(action_nodes) >= 1
    assert action_nodes[0]["status"] == "proposed"
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action_type,target,expected_adapter",
    [
        ("isolate_host", "web-prod-01", "defender"),
        ("disable_account", "alice@example.com", "entra"),
        ("revoke_sessions", "alice@example.com", "entra"),
    ],
)
async def test_remediation_agent_executes_allowlisted_actions(graph, console, alert, mock_llm, action_type, target, expected_adapter):
    mock_llm.call = AsyncMock(
        return_value=(
            f'[{{"action_type": "{action_type}", "target": "{target}", '
            f'"reason": "containment required", "urgency": "immediate"}}]'
        )
    )
    task_id = graph.write_node("task", "remediation-task", {"agent": "remediation"}, "commander")

    defender = MagicMock()
    defender.supports_write = True
    defender.execute = AsyncMock(
        return_value=ActionExecutionResult(
            adapter_name="defender",
            action_type="isolate_host",
            target=target,
            status="executed",
            executed=True,
            message="ok",
        )
    )

    entra = MagicMock()
    entra.supports_write = True
    entra.execute = AsyncMock(
        return_value=ActionExecutionResult(
            adapter_name="entra",
            action_type=action_type,
            target=target,
            status="executed",
            executed=True,
            message="ok",
        )
    )

    policy = ExecutionPolicy(enabled=True, allowed_actions=("isolate_host", "disable_account", "revoke_sessions"))
    agent = RemediationAgent(
        graph,
        mock_llm,
        console,
        auto_remediate=True,
        execution_policy=policy,
        defender_adapter=defender,
        entra_adapter=entra,
    )
    await agent.run(task_id, alert)

    action_nodes = graph.get_nodes_by_type("action")
    assert len(action_nodes) == 1
    assert action_nodes[0]["status"] == "executed"
    assert action_nodes[0]["data"]["result"]["policy"]["status"] == "approved"
    assert action_nodes[0]["data"]["result"]["adapter_name"] == expected_adapter
    assert graph.get_task_status(task_id) == "completed"
    if expected_adapter == "defender":
        assert defender.execute.await_count == 1
        assert entra.execute.await_count == 0
    else:
        assert defender.execute.await_count == 0
        assert entra.execute.await_count == 1


@pytest.mark.asyncio
async def test_reporter_agent_returns_report_text(graph, console, alert, mock_llm, tmp_path):
    mock_llm.call = AsyncMock(return_value="# Incident Report\n\nSeverity: HIGH\n\nSummary: exploit detected.")
    graph.write_node("alert", "test-alert-1", {"alert_id": alert.id}, "ingestion")
    task_id = graph.write_node("task", "reporter-task", {"agent": "reporter"}, "commander")

    agent = ReporterAgent(graph, mock_llm, console, reports_dir=str(tmp_path))
    await agent.run(task_id, alert)

    report_files = list(tmp_path.glob("*.md"))
    assert len(report_files) == 1
    content = report_files[0].read_text()
    assert "Incident Report" in content
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
async def test_reporter_agent_surfaces_evidence_by_source_and_action_outcomes(graph, console, alert, mock_llm, tmp_path):
    mock_llm.call = AsyncMock(return_value="# Incident Report\n\nSeverity: HIGH\n\nSummary: exploit detected.")
    graph.write_node(
        "evidence",
        "Defender host evidence for web-prod-01",
        {
            "source": "defender",
            "source_type": "edr",
            "entity_type": "host",
            "entity_value": "web-prod-01",
            "title": "Defender host evidence for web-prod-01",
            "summary": "Device healthy",
            "severity": "medium",
            "confidence": 72.0,
        },
        "recon",
    )
    graph.write_node(
        "evidence",
        "Entra sign-in",
        {
            "source": "entra",
            "source_type": "identity",
            "entity_type": "user",
            "entity_value": "alice@example.com",
            "title": "Suspicious sign-in",
            "summary": "Sign-in from unfamiliar IP",
            "severity": "high",
            "confidence": 92.0,
        },
        "forensics",
    )
    graph.write_node(
        "action",
        "block_ip:185.220.101.45",
        {
            "action_type": "block_ip",
            "target": "185.220.101.45",
            "reason": "malicious",
            "urgency": "immediate",
            "result": {"status": "proposed"},
        },
        "remediation",
        status="proposed",
    )
    graph.write_node(
        "action",
        "isolate_host:web-prod-01",
        {
            "action_type": "isolate_host",
            "target": "web-prod-01",
            "reason": "containment",
            "urgency": "immediate",
            "result": {"status": "executed"},
        },
        "remediation",
        status="executed",
    )
    graph.write_node("alert", "test-alert-1", {"alert_id": alert.id}, "ingestion")
    task_id = graph.write_node("task", "reporter-task", {"agent": "reporter"}, "commander")

    agent = ReporterAgent(graph, mock_llm, console, reports_dir=str(tmp_path))
    await agent.run(task_id, alert)

    prompt = mock_llm.call.await_args.kwargs["messages"][0]["content"]
    assert "evidence_by_source" in prompt
    assert "proposed_actions" in prompt
    assert "executed_actions" in prompt
    assert "action_status_counts" in prompt


@pytest.mark.asyncio
async def test_agent_marks_task_failed_on_llm_error(graph, console, alert, mock_llm):
    from core.llm_client import LLMError
    mock_llm.call = AsyncMock(side_effect=LLMError("LLM unavailable"))
    task_id = graph.write_node("task", "recon-task", {"agent": "recon"}, "commander")

    agent = ReconAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    assert graph.get_task_status(task_id) == "failed"
