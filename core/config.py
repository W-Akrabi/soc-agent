import os
from dataclasses import dataclass
from dotenv import load_dotenv

from core.integrations import FixtureMode, IntegrationSafetyConfig, parse_bool_flag, parse_csv_names

load_dotenv()


@dataclass
class Config:
    anthropic_api_key: str
    model: str
    db_path: str
    reports_dir: str
    commander_timeout: int
    agent_timeout: int
    auto_remediate: bool
    log_level: str
    event_log_dir: str | None = None
    memory_db_path: str = "./soc_memory.db"
    memory_context_limit: int = 3
    enable_memory: bool = True
    approval_db_path: str = "./soc_approvals.db"
    enable_approval_queue: bool = True
    worker_mode: str = "local"
    worker_db_path: str = "./soc_workers.db"
    worker_poll_interval: float = 1.0
    worker_lease_timeout: int = 600
    worker_heartbeat_interval: float = 15.0
    provider: str = "anthropic"
    openai_api_key: str = ""
    openai_base_url: str | None = None
    ollama_base_url: str = "http://127.0.0.1:11434"
    storage_backend: str = "sqlite"
    postgres_dsn: str | None = None
    postgres_schema: str = "public"
    vector_dimensions: int = 1536
    controlplane_backend: str = "sqlite"
    controlplane_postgres_dsn: str | None = None
    controlplane_postgres_schema: str = "soc_control"
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    api_token: str | None = None
    api_approver_token: str | None = None
    approver_identities: tuple[str, ...] = ()
    enable_metrics: bool = True
    enabled_integrations: tuple[str, ...] = ()
    fixture_mode: FixtureMode = FixtureMode.OFF
    fixture_dir: str | None = None
    allow_live_integrations: bool = False
    allow_write_integrations: bool = False
    allow_integration_execution: bool = False
    integration_timeout: int = 30
    allowed_actions: tuple[str, ...] = ()

    @classmethod
    def _from_env(cls, require_api_key: bool) -> "Config":
        provider = os.getenv("SOC_PROVIDER", "anthropic").strip().lower() or "anthropic"
        key = os.getenv("ANTHROPIC_API_KEY", "")
        openai_key = os.getenv("OPENAI_API_KEY", "")
        if require_api_key:
            if provider == "anthropic" and not key:
                raise ValueError("ANTHROPIC_API_KEY is required. Copy .env.example to .env and fill it in.")
            if provider == "openai" and not openai_key:
                raise ValueError("OPENAI_API_KEY is required when SOC_PROVIDER=openai.")
        return cls(
            anthropic_api_key=key,
            model=os.getenv("SOC_MODEL", "claude-sonnet-4-6"),
            db_path=os.getenv("SOC_DB_PATH", "./soc_cases.db"),
            reports_dir=os.getenv("SOC_REPORTS_DIR", "./reports"),
            commander_timeout=int(os.getenv("SOC_COMMANDER_TIMEOUT", "300")),
            agent_timeout=int(os.getenv("SOC_AGENT_TIMEOUT", "120")),
            auto_remediate=os.getenv("SOC_AUTO_REMEDIATE", "false").lower() == "true",
            log_level=os.getenv("SOC_LOG_LEVEL", "INFO"),
            event_log_dir=os.getenv("SOC_EVENT_LOG_DIR") or None,
            memory_db_path=os.getenv("SOC_MEMORY_DB_PATH", "./soc_memory.db"),
            memory_context_limit=int(os.getenv("SOC_MEMORY_CONTEXT_LIMIT", "3")),
            enable_memory=parse_bool_flag(os.getenv("SOC_ENABLE_MEMORY"), default=True),
            approval_db_path=os.getenv("SOC_APPROVAL_DB_PATH", "./soc_approvals.db"),
            enable_approval_queue=parse_bool_flag(os.getenv("SOC_ENABLE_APPROVAL_QUEUE"), default=True),
            worker_mode=os.getenv("SOC_WORKER_MODE", "local").strip().lower() or "local",
            worker_db_path=os.getenv("SOC_WORKER_DB_PATH", "./soc_workers.db"),
            worker_poll_interval=float(os.getenv("SOC_WORKER_POLL_INTERVAL", "1.0")),
            worker_lease_timeout=int(os.getenv("SOC_WORKER_LEASE_TIMEOUT", "600")),
            worker_heartbeat_interval=float(os.getenv("SOC_WORKER_HEARTBEAT_INTERVAL", "15.0")),
            provider=provider,
            openai_api_key=openai_key,
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            storage_backend=os.getenv("SOC_STORAGE_BACKEND", "sqlite").strip().lower() or "sqlite",
            postgres_dsn=os.getenv("SOC_POSTGRES_DSN") or None,
            postgres_schema=os.getenv("SOC_POSTGRES_SCHEMA", "public"),
            vector_dimensions=int(os.getenv("SOC_VECTOR_DIMENSIONS", "1536")),
            controlplane_backend=os.getenv("SOC_CONTROLPLANE_BACKEND", "sqlite").strip().lower() or "sqlite",
            controlplane_postgres_dsn=os.getenv("SOC_CONTROLPLANE_POSTGRES_DSN") or os.getenv("SOC_POSTGRES_DSN") or None,
            controlplane_postgres_schema=os.getenv("SOC_CONTROLPLANE_POSTGRES_SCHEMA", "soc_control"),
            api_host=os.getenv("SOC_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("SOC_API_PORT", "8080")),
            api_token=os.getenv("SOC_API_TOKEN") or None,
            api_approver_token=os.getenv("SOC_API_APPROVER_TOKEN") or None,
            approver_identities=parse_csv_names(os.getenv("SOC_APPROVER_IDENTITIES")),
            enable_metrics=parse_bool_flag(os.getenv("SOC_ENABLE_METRICS"), default=True),
            enabled_integrations=parse_csv_names(os.getenv("SOC_ENABLED_INTEGRATIONS")),
            fixture_mode=FixtureMode.from_value(os.getenv("SOC_FIXTURE_MODE", FixtureMode.OFF.value)),
            fixture_dir=os.getenv("SOC_FIXTURE_DIR") or None,
            allow_live_integrations=parse_bool_flag(os.getenv("SOC_ALLOW_LIVE_INTEGRATIONS"), default=False),
            allow_write_integrations=parse_bool_flag(os.getenv("SOC_ALLOW_WRITE_INTEGRATIONS"), default=False),
            allow_integration_execution=parse_bool_flag(
                os.getenv("SOC_ALLOW_INTEGRATION_EXECUTION"),
                default=False,
            ),
            integration_timeout=int(os.getenv("SOC_INTEGRATION_TIMEOUT", "30")),
            allowed_actions=parse_csv_names(os.getenv("SOC_ALLOWED_ACTIONS")),
        )

    @classmethod
    def from_env(cls) -> "Config":
        return cls._from_env(require_api_key=True)

    @classmethod
    def for_dry_run(cls) -> "Config":
        return cls._from_env(require_api_key=False)

    def integration_safety_config(self) -> IntegrationSafetyConfig:
        return IntegrationSafetyConfig(
            enabled_integrations=self.enabled_integrations,
            fixture_mode=self.fixture_mode,
            fixture_dir=self.fixture_dir,
            allow_live_integrations=self.allow_live_integrations,
            allow_write_integrations=self.allow_write_integrations,
            allow_integration_execution=self.allow_integration_execution,
            integration_timeout=self.integration_timeout,
        )
