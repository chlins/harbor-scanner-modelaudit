"""Runtime configuration, read from environment variables (SCANNER_* prefix)."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_", extra="ignore")

    # HTTP server
    api_server_addr: str = Field(default="0.0.0.0:8080", description="host:port to listen on")
    api_server_read_timeout: int = 15
    log_level: str = "info"

    # Job store. When redis_url is empty an in-memory store is used (single replica only).
    redis_url: str = ""
    redis_namespace: str = "harbor.scanner.modelaudit:store"
    job_ttl: int = Field(default=3600, description="seconds a finished job is kept")
    job_queue_workers: int = Field(default=1, description="concurrent scans per replica")

    # Registry access
    registry_timeout: int = Field(default=300, description="seconds per blob request")
    scratch_dir: str = "/tmp/scanner"

    # ModelAudit
    modelaudit_timeout: int = Field(default=3600, description="seconds for one scan")
    modelaudit_max_size: int = Field(
        default=0, description="max total bytes downloaded per artifact, 0 means unlimited"
    )
    modelaudit_min_severity: str = Field(
        default="warning",
        description="lowest ModelAudit severity kept in the Harbor report (debug|info|warning|critical)",
    )
    modelaudit_keep_raw: bool = Field(default=True, description="store the raw ModelAudit JSON as well")

    @property
    def host(self) -> str:
        return self.api_server_addr.rsplit(":", 1)[0] or "0.0.0.0"

    @property
    def port(self) -> int:
        return int(self.api_server_addr.rsplit(":", 1)[1])


settings = Settings()
