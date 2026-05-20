"""Configuration loader: YAML file with JKA_ environment variable overrides."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseModel):
    name: str = "jka_antivirus"
    data_dir: Path = Path("./data")
    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper


class DatabaseConfig(BaseModel):
    path: Path = Path("./data/jka.db")


class QuarantineConfig(BaseModel):
    vault_path: Path = Path("./data/quarantine")
    retention_days: int = Field(default=30, ge=1)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="JKA_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    quarantine: QuarantineConfig = Field(default_factory=QuarantineConfig)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load YAML file, returning empty dict if file is missing."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    return data


def _flatten_yaml(data: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten nested YAML dict into JKA_ prefixed environment variable form."""
    result: dict[str, str] = {}
    for key, value in data.items():
        env_key = f"{prefix}{key.upper()}" if prefix else f"JKA_{key.upper()}"
        if isinstance(value, dict):
            result.update(_flatten_yaml(value, prefix=f"{env_key}__"))
        elif value is not None:
            result[env_key] = str(value)
    return result


def load_settings(config_path: Path | None = None) -> Settings:
    """Load settings from YAML, then apply environment variable overrides.

    Environment variables with prefix JKA_ and delimiter __ take precedence
    over YAML values (e.g. JKA_APP__LOG_LEVEL=DEBUG overrides app.log_level).
    """
    resolved = config_path or _default_config_path()
    yaml_data = _load_yaml(resolved)

    # Inject YAML values as env vars so Pydantic picks them up at lower priority
    # than real env vars (real env vars win because os.environ already has them).
    flattened = _flatten_yaml(yaml_data)
    for key, value in flattened.items():
        if key not in os.environ:
            os.environ[key] = value

    return Settings()


def _default_config_path() -> Path:
    """Resolve the default config.yaml location relative to the project root."""
    here = Path(__file__).parent
    # Walk up until we find config/config.yaml or hit the filesystem root.
    candidate = here
    for _ in range(6):
        yaml_path = candidate / "config" / "config.yaml"
        if yaml_path.exists():
            return yaml_path
        candidate = candidate.parent
    return Path("config/config.yaml")
