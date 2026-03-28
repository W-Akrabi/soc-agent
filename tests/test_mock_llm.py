from datetime import datetime, timezone

import pytest

from core.mock_llm import MockLLMClient
from core.models import Alert, AlertType, Severity


def make_alert(alert_type: AlertType, **overrides) -> Alert:
    values = {
        "id": "test-id",
        "type": alert_type,
        "severity": Severity.HIGH,
        "timestamp": datetime.now(timezone.utc),
        "raw_payload": {},
        "source_ip": "10.0.0.5",
        "dest_ip": "10.0.1.50",
        "dest_port": 443,
        "hostname": "host-01",
        "user_account": "jsmith",
        "process": "nginx",
    }
    values.update(overrides)
    return Alert(**values)


@pytest.mark.asyncio
async def test_intrusion_response_is_non_empty_and_keeps_existing_spirit():
    llm = MockLLMClient()
    response = await llm.call(
        system="You are a reconnaissance specialist in a SOC investigation.",
        messages=[{"role": "user", "content": "investigate"}],
    )

    assert response
    assert "Tor exit node" in response
    assert "8080" in response


@pytest.mark.asyncio
async def test_brute_force_response_is_context_aware():
    llm = MockLLMClient()
    llm.set_alert_context(make_alert(AlertType.BRUTE_FORCE, source_ip="203.0.113.99", hostname="bastion-01"))

    response = await llm.call(
        system="You are a threat intelligence analyst in a SOC investigation.",
        messages=[{"role": "user", "content": "investigate"}],
    )

    lower = response.lower()
    assert response
    assert "brute" in lower or "credential" in lower or "ssh" in lower
    assert "203.0.113.99" in response or "bastion-01" in response


@pytest.mark.asyncio
async def test_malware_response_mentions_malware():
    llm = MockLLMClient()
    llm.set_alert_context(make_alert(AlertType.MALWARE, hostname="workstation-99"))

    response = await llm.call(
        system="You are a SOC incident reporter.",
        messages=[{"role": "user", "content": "Investigation data:\n{}"}],
    )

    assert response
    assert "Incident Report" in response
    assert "malware" in response.lower()


@pytest.mark.asyncio
async def test_same_alert_type_is_deterministic():
    llm = MockLLMClient()
    llm.set_alert_context(make_alert(AlertType.DATA_EXFILTRATION, source_ip="10.0.3.14"))

    first = await llm.call(
        system="You are a digital forensics investigator in a SOC investigation.",
        messages=[{"role": "user", "content": "investigate"}],
    )
    second = await llm.call(
        system="You are a digital forensics investigator in a SOC investigation.",
        messages=[{"role": "user", "content": "investigate"}],
    )

    assert first == second


@pytest.mark.asyncio
async def test_without_context_still_works():
    llm = MockLLMClient()
    response = await llm.call(
        system="You are the Commander of a Security Operations Center investigation.",
        messages=[{"role": "user", "content": "{}"}],
    )

    assert response
    assert "objective" in response.lower()


@pytest.mark.asyncio
async def test_reporter_with_string_context_does_not_raise():
    llm = MockLLMClient()
    llm.set_alert_context(make_alert(AlertType.MALWARE, hostname="ws-01"))
    assert isinstance(llm._alert_context["alert_type"], str)

    response = await llm.call(
        system="You are a SOC incident reporter.",
        messages=[{"role": "user", "content": "Investigation data:\n{}"}],
    )

    assert "Incident Report" in response
    assert "malware" in response.lower()
