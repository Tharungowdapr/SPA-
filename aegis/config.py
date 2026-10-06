"""Central configuration: YAML file + environment overrides. Nothing secret is stored here."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "configs" / "config.yaml"

# Friendly env aliases -> dotted config keys
ENV_ALIASES = {
    "KAFKA_BOOTSTRAP": "bus.kafka_bootstrap",
    "DATABASE_PATH": "app.db_path",
    "MODELS_DIR": "app.models_dir",
    "AGENT_ENABLED": "agent.enabled",
    "LLM_PROVIDER": "agent.provider",
    "LLM_MODEL": "agent.model",
    "APP_ENV": "app.env",
    "AUTH_ENABLED": "app.auth_enabled",
    "SYNC_PROCESSING": "app.sync_processing",
}


def _set(d: dict, dotted: str, value: Any) -> None:
    keys = dotted.lower().split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _parse(v: str) -> Any:
    try:
        return yaml.safe_load(v)
    except yaml.YAMLError:
        return v


class Settings:
    """Dotted-key access: settings.get('risk.levels.high')."""

    def __init__(self, raw: dict):
        self.raw = raw

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.raw
        for k in dotted.split("."):
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    def set(self, dotted: str, value: Any) -> None:
        _set(self.raw, dotted, value)

    def copy(self) -> "Settings":
        return Settings(copy.deepcopy(self.raw))

    # secrets come ONLY from the environment
    @property
    def secret_key(self) -> str:
        return os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")

    @property
    def master_key(self) -> str:
        return os.environ.get("MASTER_KEY", self.secret_key)

    def resolve_path(self, key: str) -> Path:
        p = Path(self.get(key))
        return p if p.is_absolute() else ROOT / p


def load_settings(path: Path | str | None = None, overrides: dict | None = None) -> Settings:
    path = Path(path or os.environ.get("AEGIS_CONFIG", DEFAULT_CONFIG))
    raw = yaml.safe_load(path.read_text()) if path.exists() else {}
    for env, dotted in ENV_ALIASES.items():
        if env in os.environ:
            _set(raw, dotted, _parse(os.environ[env]))
    for k, v in os.environ.items():
        if k.startswith("AEGIS__"):
            _set(raw, k[7:].replace("__", "."), _parse(v))
    for dotted, v in (overrides or {}).items():
        _set(raw, dotted, v)
    return Settings(raw)
