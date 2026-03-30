import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from core.config import Config
from core.integrations import FixtureMode
from main import ApproverAuthorizationError, _authorize_approver, _task_is_stale


def test_for_dry_run_uses_env_db_path():
    with patch.dict(os.environ, {"SOC_DB_PATH": "/tmp/mydb.db"}, clear=False):
        config = Config.for_dry_run()
    assert config.db_path == "/tmp/mydb.db"


def test_for_dry_run_uses_env_reports_dir():
    with patch.dict(os.environ, {"SOC_REPORTS_DIR": "/tmp/myreports"}, clear=False):
        config = Config.for_dry_run()
    assert config.reports_dir == "/tmp/myreports"


def test_for_dry_run_uses_env_timeouts():
    with patch.dict(
        os.environ,
        {"SOC_COMMANDER_TIMEOUT": "600", "SOC_AGENT_TIMEOUT": "60"},
        clear=False,
    ):
        config = Config.for_dry_run()
    assert config.commander_timeout == 600
    assert config.agent_timeout == 60


def test_for_dry_run_does_not_require_api_key():
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.anthropic_api_key == ""


def test_for_dry_run_defaults_match_from_env_defaults():
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("SOC_") and k not in {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "OLLAMA_BASE_URL"}
    }
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.db_path == "./soc_cases.db"
    assert config.reports_dir == "./reports"
    assert config.event_log_dir is None
    assert config.memory_db_path == "./soc_memory.db"
    assert config.approval_db_path == "./soc_approvals.db"
    assert config.worker_db_path == "./soc_workers.db"
    assert config.worker_mode == "local"
    assert config.worker_lease_timeout == 600
    assert config.worker_heartbeat_interval == 15.0
    assert config.ollama_base_url == "http://127.0.0.1:11434"


def test_for_dry_run_uses_soc_event_log_dir():
    with patch.dict(os.environ, {"SOC_EVENT_LOG_DIR": "/tmp/logs"}, clear=False):
        config = Config.for_dry_run()
    assert config.event_log_dir == "/tmp/logs"


def test_from_env_uses_soc_event_log_dir():
    with patch.dict(
        os.environ,
        {
            "SOC_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_EVENT_LOG_DIR": "/tmp/prodlogs",
        },
        clear=False,
    ):
        config = Config.from_env()
    assert config.event_log_dir == "/tmp/prodlogs"


def test_for_dry_run_defaults_to_safe_integration_config():
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("SOC_") and k not in {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}
    }
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.enabled_integrations == ()
    assert config.fixture_mode == FixtureMode.OFF
    assert config.fixture_dir is None
    assert config.allow_live_integrations is False
    assert config.allow_write_integrations is False
    assert config.allow_integration_execution is False
    assert config.integration_timeout == 30


def test_from_env_parses_integration_safety_env_vars():
    with patch.dict(
        os.environ,
        {
            "SOC_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_ENABLED_INTEGRATIONS": "sentinel, defender,entra",
            "SOC_FIXTURE_MODE": "record",
            "SOC_FIXTURE_DIR": "/tmp/fixtures",
            "SOC_ALLOW_LIVE_INTEGRATIONS": "true",
            "SOC_ALLOW_WRITE_INTEGRATIONS": "1",
            "SOC_ALLOW_INTEGRATION_EXECUTION": "yes",
            "SOC_INTEGRATION_TIMEOUT": "75",
        },
        clear=False,
    ):
        config = Config.from_env()
    assert config.enabled_integrations == ("sentinel", "defender", "entra")
    assert config.fixture_mode == FixtureMode.RECORD
    assert config.fixture_dir == "/tmp/fixtures"
    assert config.allow_live_integrations is True
    assert config.allow_write_integrations is True
    assert config.allow_integration_execution is True
    assert config.integration_timeout == 75


def test_from_env_parses_allowed_actions():
    with patch.dict(
        os.environ,
        {
            "SOC_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_ALLOWED_ACTIONS": "isolate_host, disable_account, revoke_sessions",
        },
        clear=False,
    ):
        config = Config.from_env()
    assert config.allowed_actions == ("isolate_host", "disable_account", "revoke_sessions")


def test_from_env_defaults_to_anthropic_provider():
    with patch.dict(
        os.environ,
        {"SOC_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-fake"},
        clear=False,
    ):
        config = Config.from_env()
    assert config.provider == "anthropic"


def test_from_env_openai_provider_uses_openai_key():
    with patch.dict(
        os.environ,
        {
            "SOC_PROVIDER": "openai",
            "OPENAI_API_KEY": "openai-key",
            "OPENAI_BASE_URL": "https://example.com/v1",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.provider == "openai"
    assert config.openai_api_key == "openai-key"
    assert config.openai_base_url == "https://example.com/v1"


def test_from_env_openai_provider_requires_openai_key():
    with patch.dict(os.environ, {"SOC_PROVIDER": "openai"}, clear=True):
        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            Config.from_env()


def test_from_env_ollama_provider_uses_default_base_url_without_api_key():
    with patch.dict(
        os.environ,
        {
            "SOC_PROVIDER": "ollama",
            "OLLAMA_BASE_URL": "http://ollama:11434",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.provider == "ollama"
    assert config.ollama_base_url == "http://ollama:11434"


def test_for_dry_run_defaults_to_sqlite_storage():
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOC_") and k not in {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "OLLAMA_BASE_URL"}}
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.storage_backend == "sqlite"
    assert config.postgres_dsn is None
    assert config.postgres_schema == "public"
    assert config.vector_dimensions == 1536
    assert config.controlplane_backend == "sqlite"
    assert config.controlplane_postgres_dsn is None
    assert config.controlplane_postgres_schema == "soc_control"
    assert config.api_host == "127.0.0.1"
    assert config.api_port == 8080
    assert config.api_token is None
    assert config.api_approver_token is None
    assert config.approver_identities == ()


def test_from_env_reads_postgres_storage_settings():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_STORAGE_BACKEND": "postgres",
            "SOC_POSTGRES_DSN": "postgresql://user:pass@localhost:5432/soc",
            "SOC_POSTGRES_SCHEMA": "soc",
            "SOC_VECTOR_DIMENSIONS": "1024",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.storage_backend == "postgres"
    assert config.postgres_dsn == "postgresql://user:pass@localhost:5432/soc"
    assert config.postgres_schema == "soc"
    assert config.vector_dimensions == 1024


def test_from_env_reads_controlplane_postgres_settings():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_CONTROLPLANE_BACKEND": "postgres",
            "SOC_CONTROLPLANE_POSTGRES_DSN": "postgresql://user:pass@localhost:5432/soc_control",
            "SOC_CONTROLPLANE_POSTGRES_SCHEMA": "soc_control",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.controlplane_backend == "postgres"
    assert config.controlplane_postgres_dsn == "postgresql://user:pass@localhost:5432/soc_control"
    assert config.controlplane_postgres_schema == "soc_control"


def test_from_env_reads_api_server_settings():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_API_HOST": "0.0.0.0",
            "SOC_API_PORT": "9090",
            "SOC_API_TOKEN": "api-token",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.api_host == "0.0.0.0"
    assert config.api_port == 9090
    assert config.api_token == "api-token"


def test_from_env_reads_metrics_toggle():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_ENABLE_METRICS": "false",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.enable_metrics is False


def test_for_dry_run_defaults_to_metrics_enabled():
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOC_") and k not in {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}}
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.enable_metrics is True


def test_from_env_reads_approval_identity_settings():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_APPROVER_IDENTITIES": "analyst1, analyst2",
            "SOC_API_APPROVER_TOKEN": "approver-token",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.approver_identities == ("analyst1", "analyst2")
    assert config.api_approver_token == "approver-token"


def test_authorize_approver_allows_listed_identity_and_token():
    config = Config.for_dry_run()
    config.approver_identities = ("analyst1", "analyst2")
    config.api_approver_token = "approver-token"

    _authorize_approver(config, "Analyst1", "approver-token")


def test_authorize_approver_rejects_unlisted_identity():
    config = Config.for_dry_run()
    config.approver_identities = ("analyst1",)

    with pytest.raises(ApproverAuthorizationError, match="not in SOC_APPROVER_IDENTITIES"):
        _authorize_approver(config, "analyst2")


def test_authorize_approver_rejects_missing_token_when_configured():
    config = Config.for_dry_run()
    config.api_approver_token = "approver-token"

    with pytest.raises(ApproverAuthorizationError, match="approval token required"):
        _authorize_approver(config, "analyst1")


def test_from_env_parses_memory_approval_and_worker_settings():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_MEMORY_DB_PATH": "/tmp/memory.db",
            "SOC_MEMORY_CONTEXT_LIMIT": "5",
            "SOC_ENABLE_MEMORY": "false",
            "SOC_APPROVAL_DB_PATH": "/tmp/approvals.db",
            "SOC_ENABLE_APPROVAL_QUEUE": "0",
            "SOC_WORKER_MODE": "remote",
            "SOC_WORKER_DB_PATH": "/tmp/workers.db",
            "SOC_WORKER_POLL_INTERVAL": "0.25",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.memory_db_path == "/tmp/memory.db"
    assert config.memory_context_limit == 5
    assert config.enable_memory is False
    assert config.approval_db_path == "/tmp/approvals.db"
    assert config.enable_approval_queue is False
    assert config.worker_mode == "remote"
    assert config.worker_db_path == "/tmp/workers.db"
    assert config.worker_poll_interval == 0.25


def test_from_env_parses_worker_lease_and_heartbeat_settings():
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "sk-fake",
            "SOC_WORKER_LEASE_TIMEOUT": "900",
            "SOC_WORKER_HEARTBEAT_INTERVAL": "20.5",
        },
        clear=True,
    ):
        config = Config.from_env()
    assert config.worker_lease_timeout == 900
    assert config.worker_heartbeat_interval == 20.5


def test_task_is_stale_uses_lease_timeout():
    task = {
        "status": "claimed",
        "claimed_at": "2026-03-27T00:00:00+00:00",
        "created_at": "2026-03-27T00:00:00+00:00",
    }
    reference_now = datetime(2026, 3, 27, 0, 20, tzinfo=timezone.utc)
    assert _task_is_stale(task, lease_timeout_seconds=600, now=reference_now) is True
    assert _task_is_stale(task, lease_timeout_seconds=0, now=reference_now) is False
