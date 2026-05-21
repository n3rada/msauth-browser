# msauth_browser/configs/__init__.py

# Built-in imports
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class AppConfig:
    """Configuration for a Microsoft application."""

    name: str
    client_id: str
    redirect_uri: str
    default_scopes: List[str]

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "AppConfig":
        """Create an :class:`AppConfig` instance from a mapping."""

        missing = [
            field
            for field in ("name", "client_id", "redirect_uri")
            if field not in payload
        ]
        if missing:
            raise ValueError(
                "Config payload missing required fields: " + ", ".join(missing)
            )

        scopes = cls._parse_scopes(payload.get("default_scopes"))

        return cls(
            name=str(payload["name"]),
            client_id=str(payload["client_id"]),
            redirect_uri=str(payload["redirect_uri"]),
            default_scopes=[str(scope) for scope in scopes],
        )

    @staticmethod
    def _parse_scopes(scopes_payload: Optional[Any]) -> List[str]:
        """Normalize the scope payload, applying sensible defaults when missing."""

        if scopes_payload is None:
            return ["openid", "offline_access"]

        if not isinstance(scopes_payload, Iterable) or isinstance(
            scopes_payload, (str, bytes)
        ):
            raise ValueError("default_scopes must be an iterable of strings")

        scopes = [str(scope).strip() for scope in scopes_payload if str(scope).strip()]
        if not scopes:
            return ["openid", "offline_access"]

        if "openid" not in scopes:
            scopes.insert(0, "openid")

        if "offline_access" not in scopes:
            scopes.append("offline_access")

        return scopes


def _load_predefined_configs() -> Dict[str, AppConfig]:
    """Load JSON configuration files from this package using importlib.resources."""

    configs: Dict[str, AppConfig] = {}
    package_files = files(__package__)

    for resource in package_files.iterdir():
        if not resource.name.endswith(".json"):
            continue

        payload = json.loads(resource.read_text(encoding="utf-8"))
        config = AppConfig.from_dict(payload)
        slug = str(payload.get("slug") or resource.name.removesuffix(".json")).lower()

        if slug in configs:
            raise ValueError(
                f"Duplicate configuration slug '{slug}' in {resource.name}."
            )

        configs[slug] = config

    return configs


PREDEFINED_CONFIGS = _load_predefined_configs()


def get_config(name: str) -> AppConfig:
    """
    Retrieve a predefined application configuration by name.

    Args:
        name: The configuration name (e.g., "teams")

    Returns:
        The AppConfig object

    Raises:
        KeyError: If the configuration name is not found
    """
    if name not in PREDEFINED_CONFIGS:
        available = ", ".join(PREDEFINED_CONFIGS.keys())
        raise KeyError(f"Configuration '{name}' not found. Available: {available}")

    return PREDEFINED_CONFIGS[name]


def list_configs() -> List[str]:
    """Return a sorted list of available configuration names."""

    return sorted(PREDEFINED_CONFIGS.keys())
