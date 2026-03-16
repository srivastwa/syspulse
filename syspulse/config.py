from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    tool_version: str = "0.1.0"
    check_timeout: int = 30          # seconds per PowerShell script
    max_interaction_boost: float = 2.0
    top_findings_for_score: int = 10  # use top-N findings for composite score


settings = Settings()
