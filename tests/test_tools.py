import pytest
from tools.ip_lookup import IPLookupTool
from tools.whois_lookup import WHOISTool
from tools.port_scan import PortScanTool
from tools.cve_search import CVESearchTool
from tools.threat_feed import ThreatFeedTool
from tools.log_parser import LogParserTool
from tools.action_executor import ActionExecutorTool


@pytest.mark.asyncio
async def test_ip_lookup_known_ip():
    tool = IPLookupTool()
    result = await tool.run({"ip": "185.220.101.45"})
    assert "geo" in result
    assert "asn" in result


@pytest.mark.asyncio
async def test_ip_lookup_unknown_ip():
    tool = IPLookupTool()
    result = await tool.run({"ip": "1.2.3.4"})
    assert "geo" in result  # returns something even for unknown


@pytest.mark.asyncio
async def test_whois_lookup():
    tool = WHOISTool()
    result = await tool.run({"domain": "google.com"})
    assert "registrar" in result or "error" in result  # real lookup may fail in CI


@pytest.mark.asyncio
async def test_port_scan():
    tool = PortScanTool()
    result = await tool.run({"ip": "185.220.101.45"})
    assert "open_ports" in result
    assert isinstance(result["open_ports"], list)


@pytest.mark.asyncio
async def test_cve_search_by_port():
    tool = CVESearchTool()
    result = await tool.run({"port": 22, "service": "openssh"})
    assert "cves" in result
    assert isinstance(result["cves"], list)
    # NVD API may be slow or rate-limited — just verify structure
    if result["cves"]:
        assert "id" in result["cves"][0]
        assert "severity" in result["cves"][0]


@pytest.mark.asyncio
async def test_threat_feed_lookup_no_keys():
    # Without API keys, should return gracefully with note fields
    tool = ThreatFeedTool()
    result = await tool.run({"ip": "8.8.8.8"})
    assert "malicious" in result
    assert "categories" in result
    assert "confidence" in result


@pytest.mark.asyncio
async def test_log_parser():
    tool = LogParserTool()
    logs = [
        {"ts": "2026-03-26T03:12:01Z", "event": "connection_established", "src": "1.2.3.4"},
        {"ts": "2026-03-26T03:14:10Z", "event": "privilege_escalation", "user": "root"},
    ]
    result = await tool.run({"logs": logs})
    assert "events" in result
    assert len(result["events"]) == 2


@pytest.mark.asyncio
async def test_action_executor_suggest_mode():
    tool = ActionExecutorTool(auto_remediate=False)
    result = await tool.run({
        "action_type": "block_ip",
        "target": "1.2.3.4",
        "reason": "known malicious IP",
        "urgency": "immediate"
    })
    assert result["status"] == "suggested"
    assert result["executed"] is False


@pytest.mark.asyncio
async def test_action_executor_auto_remediate_immediate():
    tool = ActionExecutorTool(auto_remediate=True)
    result = await tool.run({
        "action_type": "block_ip",
        "target": "1.2.3.4",
        "reason": "known malicious IP",
        "urgency": "immediate"
    })
    assert result["status"] == "executed"
    assert result["executed"] is True


@pytest.mark.asyncio
async def test_action_executor_auto_remediate_non_immediate():
    tool = ActionExecutorTool(auto_remediate=True)
    result = await tool.run({
        "action_type": "patch_recommendation",
        "target": "web-prod-01",
        "reason": "CVE patch required",
        "urgency": "within_24h"
    })
    assert result["status"] == "suggested"
