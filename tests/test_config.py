"""Tests for the config loader (config.py)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from jka_antivirus.config import Settings, load_settings


def test_default_settings_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings load with defaults when no YAML or env vars are set."""
    # Clear any JKA_ vars that may have leaked from prior test runs or load_settings calls.
    for key in list(os.environ):
        if key.startswith("JKA_"):
            monkeypatch.delenv(key, raising=False)

    settings = Settings()
    assert settings.app.name == "jka_antivirus"
    assert settings.app.log_level == "INFO"
    assert settings.database.path == Path("./data/jka.db")
    assert settings.quarantine.retention_days == 30


def test_yaml_config_loaded(tmp_path: Path) -> None:
    """Values from a YAML file are picked up by load_settings."""
    yaml_content = """
app:
  name: test_av
  log_level: DEBUG
  data_dir: /tmp/av_data
database:
  path: /tmp/av_data/test.db
quarantine:
  vault_path: /tmp/av_data/vault
  retention_days: 7
"""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"
    config_file.write_text(yaml_content, encoding="utf-8")

    # Remove any JKA_ vars that might override our YAML.
    env_backup = {k: v for k, v in os.environ.items() if k.startswith("JKA_")}
    for key in env_backup:
        del os.environ[key]

    try:
        settings = load_settings(config_path=config_file)
        assert settings.app.name == "test_av"
        assert settings.app.log_level == "DEBUG"
        assert settings.quarantine.retention_days == 7
        assert settings.database.path == Path("/tmp/av_data/test.db")
    finally:
        for key, value in env_backup.items():
            os.environ[key] = value


def test_env_override_beats_yaml(tmp_path: Path) -> None:
    """JKA_ environment variables override YAML values."""
    yaml_content = "app:\n  log_level: INFO\n"
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"
    config_file.write_text(yaml_content, encoding="utf-8")

    os.environ["JKA_APP__LOG_LEVEL"] = "WARNING"
    try:
        settings = load_settings(config_path=config_file)
        assert settings.app.log_level == "WARNING"
    finally:
        del os.environ["JKA_APP__LOG_LEVEL"]


def test_invalid_log_level_raises() -> None:
    """An invalid log_level value raises a validation error."""
    import pydantic  # noqa: PLC0415

    with pytest.raises(pydantic.ValidationError):
        Settings(app={"log_level": "VERBOSE"})  # type: ignore[arg-type]


def test_retention_days_minimum() -> None:
    """retention_days must be >= 1."""
    import pydantic  # noqa: PLC0415

    with pytest.raises(pydantic.ValidationError):
        Settings(quarantine={"retention_days": 0})  # type: ignore[arg-type]
