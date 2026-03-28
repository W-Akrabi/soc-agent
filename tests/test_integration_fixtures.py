import json

import pytest

from core.schemas import IntegrationQuery
from integrations.fixtures import FixtureNotFoundError, FixtureStore


def _query(context: dict | None = None) -> IntegrationQuery:
    return IntegrationQuery(
        alert_id="alert-1",
        alert_type="intrusion",
        entity_type="ip",
        entity_value="185.220.101.45",
        time_range_hours=24,
        context=context or {},
    )


def test_fingerprint_is_stable_for_equivalent_query_keys(tmp_path):
    store = FixtureStore(tmp_path)
    left = _query({"b": 2, "a": 1})
    right = _query({"a": 1, "b": 2})

    assert store.fingerprint("sentinel", "collect", left) == store.fingerprint("sentinel", "collect", right)
    assert store.fingerprint("defender", "collect", left) != store.fingerprint("sentinel", "collect", left)
    assert store.fingerprint("sentinel", "execute", left) != store.fingerprint("sentinel", "collect", left)


def test_record_sanitizes_sensitive_payloads(tmp_path):
    store = FixtureStore(tmp_path)
    query = _query({"note": "contains secrets"})
    request = {
        "headers": {
            "Authorization": "Bearer abc.def.ghi",
            "Cookie": "session=abcd",
            "X-Api-Key": "secret-key",
        },
        "url": "https://example.test/path?access_token=abc123&password=swordfish",
        "nested": {"client_secret": "super-secret"},
    }
    response = {
        "message": "Bearer xyz.token value and token=rawsecret",
        "cookies": ["sid=abcd", "another=value"],
    }

    entry = store.record(
        "sentinel",
        "collect",
        query,
        request=request,
        response=response,
        metadata={"refresh_token": "refresh-secret"},
    )

    path = store.path_for("sentinel", "collect", query)
    payload = json.loads(path.read_text())
    raw = path.read_text()

    assert entry.status == "ok"
    assert payload["adapter"] == "sentinel"
    assert payload["operation"] == "collect"
    assert payload["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert payload["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert payload["request"]["headers"]["X-Api-Key"] == "[REDACTED]"
    assert payload["request"]["url"].endswith("access_token=[REDACTED]&password=[REDACTED]")
    assert payload["request"]["nested"]["client_secret"] == "[REDACTED]"
    assert payload["response"]["message"] == "Bearer [REDACTED] value and token=[REDACTED]"
    assert payload["response"]["cookies"] == "[REDACTED]"
    assert payload["metadata"]["refresh_token"] == "[REDACTED]"
    assert "abc.def.ghi" not in raw
    assert "super-secret" not in raw
    assert "refresh-secret" not in raw


def test_record_and_replay_round_trip_includes_error_cases(tmp_path):
    store = FixtureStore(tmp_path)
    query = _query()

    success = store.record(
        "defender",
        "collect",
        query,
        request={"headers": {"Authorization": "Bearer abc"}},
        response={"records": [{"id": 1}]},
    )
    failure = store.record(
        "defender",
        "execute",
        query,
        request={"headers": {"Authorization": "Bearer abc"}},
        error={"message": "HTTP 500", "access_token": "abc"},
    )

    replayed_success = store.replay("defender", "collect", query)
    replayed_failure = store.replay("defender", "execute", query)

    assert success.fingerprint == replayed_success.fingerprint
    assert replayed_success.status == "ok"
    assert replayed_success.response == {"records": [{"id": 1}]}
    assert failure.fingerprint == replayed_failure.fingerprint
    assert replayed_failure.status == "error"
    assert replayed_failure.error == {"message": "HTTP 500", "access_token": "[REDACTED]"}


def test_missing_fixture_raises_clear_error(tmp_path):
    store = FixtureStore(tmp_path)

    with pytest.raises(FixtureNotFoundError, match="Missing fixture"):
        store.replay("sentinel", "collect", _query())
