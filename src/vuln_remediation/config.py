"""Application configuration loaded from environment variables."""

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration is loaded from environment variables or .env file.

    Required:
        DEVIN_API_KEY: Service user API key (starts with cog_)
        DEVIN_ORG_ID: Devin organization ID
        GITHUB_TOKEN: GitHub personal access token
        GITHUB_REPO: Target repository (e.g., "your-org/superset")

    Optional:
        GITHUB_WEBHOOK_SECRET: For verifying webhook payloads
        POLL_INTERVAL_SECONDS: How often to check Devin session status
        LOG_LEVEL: Logging verbosity
    """

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # Devin API
    devin_api_key: str = Field(description="Devin service user API key (cog_...)")
    devin_org_id: str = Field(description="Devin organization ID")
    devin_base_url: str = "https://api.devin.ai/v3"

    # GitHub
    github_token: str = Field(description="GitHub personal access token")
    github_repo: str = Field(description="Target repo, e.g. 'owner/repo'")
    github_webhook_secret: str = ""

    # Orchestrator
    poll_interval_seconds: int = 30
    max_concurrent_sessions: int = 3

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    @property
    def github_owner(self) -> str:
        return self.github_repo.split("/")[0]

    @property
    def github_repo_name(self) -> str:
        return self.github_repo.split("/")[1]


settings = Settings()  # type: ignore[call-arg]
