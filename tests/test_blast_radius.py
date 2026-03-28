from core.blast_radius import ROLLBACK_MAP, estimate_blast_radius, rollback_details


def test_block_ip_description_mentions_target_and_blocking():
    result = estimate_blast_radius("block_ip", "10.0.0.1")
    assert "10.0.0.1" in result
    assert "block" in result.lower() or "traffic" in result.lower()


def test_disable_account_description_mentions_account_access():
    result = estimate_blast_radius("disable_account", "jdoe")
    assert "jdoe" in result
    assert "account" in result.lower() or "access" in result.lower()


def test_isolate_host_description_mentions_isolation():
    result = estimate_blast_radius("isolate_host", "web-prod-01")
    assert "web-prod-01" in result
    assert "isolat" in result.lower() or "network" in result.lower()


def test_patch_recommendation_is_advisory():
    result = estimate_blast_radius("patch_recommendation", "CVE-2024-1234")
    assert "advisory" in result.lower() or "recommend" in result.lower()


def test_unknown_action_returns_generic_text():
    result = estimate_blast_radius("unknown_action_xyz", "some-target")
    assert result


def test_rollback_map_isolate_host():
    rollback_action_type, rollback_supported = ROLLBACK_MAP["isolate_host"]
    assert rollback_supported is True
    assert rollback_action_type == "unisolate_host"


def test_rollback_map_disable_account():
    rollback_action_type, rollback_supported = rollback_details("disable_account")
    assert rollback_supported is True
    assert rollback_action_type == "enable_account"


def test_rollback_map_block_ip_not_supported():
    rollback_action_type, rollback_supported = rollback_details("block_ip")
    assert rollback_supported is False
    assert rollback_action_type == "unblock_ip"
