

"""Configuration loading for AI_Augmented_SOC.

This module is responsible for reading environment variables from `.env` and
exposing a typed `Settings` object to the rest of the application.

The config layer should stay simple:
    - Load values from environment variables.
    - Convert strings into Python types such as bool and int.
    - Provide defaults for local development.
    - Validate required settings before runtime code uses them.

This module should not:
    - Call Wazuh, Security Onion, OpenRouter, or any external API.
    - Open database connections.
    - Start background jobs.

Typical usage:
    from soc.config import get_settings

    settings = get_settings()
    print(settings.wazuh_host)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from dotenv import load_dotenv


DEFAULT_ENV_FILE: Final[Path] = Path(".env")


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Application settings loaded from environment variables.

    Attributes are grouped by subsystem. Required credentials may still be empty
    immediately after loading so tests and partial local workflows can run. Use
    the `validate_*` methods before calling a subsystem that needs credentials.
    """

    # Core runtime settings
    poll_interval_seconds: int
    alert_lookback_minutes: int
    output_dir: Path
    log_dir: Path

    # Wazuh settings
    wazuh_host: str
    wazuh_user: str
    wazuh_password: str
    wazuh_min_level: int
    wazuh_alert_source: str
    wazuh_alert_json_path: Path

    # Security Onion settings
    securityonion_host: str
    securityonion_user: str
    securityonion_password: str
    securityonion_alert_index: str
    securityonion_zeek_index: str
    so_min_severity: int

    # OpenRouter settings
    openrouter_api_key: str
    openrouter_base_url: str
    openrouter_model: str
    openrouter_report_model: str
    openrouter_site_url: str
    openrouter_app_name: str

    # Threat intelligence settings
    virustotal_api_key: str
    abuseipdb_api_key: str
    shodan_api_key: str
    enrichment_cache_ttl_hours: int

    # Notification settings
    email_enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    email_from: str
    email_to: str
    email_use_tls: bool
    slack_webhook_url: str

    # Storage settings
    dedup_store: str
    sqlite_db_path: Path
    redis_url: str
    dedup_ttl_hours: int

    # Replay/testing settings
    enable_sample_replay: bool
    sample_replay_file: Path
    manual_test_events_dir: Path

    # Later phase: Splunk output
    splunk_hec_url: str
    splunk_hec_token: str
    splunk_hec_index: str
    splunk_hec_sourcetype: str

    # Later phase: OpenBSD firewall integration
    openbsd_pf_enabled: bool
    openbsd_pf_host: str
    openbsd_pf_user: str
    openbsd_pflog_path: Path
    openbsd_pf_block_table: str

    def ensure_directories(self) -> None:
        """Create local runtime directories if they do not already exist.

        Inputs:
            None. Uses `output_dir`, `log_dir`, and `manual_test_events_dir`
            from this settings object.

        Outputs:
            None. Directories are created on disk.
        """

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.manual_test_events_dir.mkdir(parents=True, exist_ok=True)

    def validate_wazuh(self) -> None:
        """Validate that required Wazuh settings are present.

        Inputs:
            None. Uses Wazuh fields from this settings object.

        Outputs:
            None.

        Raises:
            ConfigError: If a required Wazuh setting is missing.
        """

        _require_non_empty("WAZUH_HOST", self.wazuh_host)
        _require_non_empty("WAZUH_USER", self.wazuh_user)
        _require_non_empty("WAZUH_PASSWORD", self.wazuh_password)

    def validate_security_onion(self) -> None:
        """Validate that required Security Onion settings are present.

        Inputs:
            None. Uses Security Onion fields from this settings object.

        Outputs:
            None.

        Raises:
            ConfigError: If a required Security Onion setting is missing.
        """

        _require_non_empty("SECURITYONION_HOST", self.securityonion_host)
        _require_non_empty("SECURITYONION_USER", self.securityonion_user)
        _require_non_empty("SECURITYONION_PASSWORD", self.securityonion_password)

    def validate_openrouter(self) -> None:
        """Validate that required OpenRouter settings are present.

        Inputs:
            None. Uses OpenRouter fields from this settings object.

        Outputs:
            None.

        Raises:
            ConfigError: If a required OpenRouter setting is missing.
        """

        _require_non_empty("OPENROUTER_API_KEY", self.openrouter_api_key)
        _require_non_empty("OPENROUTER_BASE_URL", self.openrouter_base_url)
        _require_non_empty("OPENROUTER_MODEL", self.openrouter_model)

    def validate_email(self) -> None:
        """Validate email settings when email notifications are enabled.

        Inputs:
            None. Uses email fields from this settings object.

        Outputs:
            None.

        Raises:
            ConfigError: If email is enabled but required SMTP fields are
            missing.
        """

        if not self.email_enabled:
            return

        _require_non_empty("SMTP_HOST", self.smtp_host)
        _require_non_empty("SMTP_USERNAME", self.smtp_username)
        _require_non_empty("SMTP_PASSWORD", self.smtp_password)
        _require_non_empty("EMAIL_FROM", self.email_from)
        _require_non_empty("EMAIL_TO", self.email_to)

    def validate_splunk(self) -> None:
        """Validate later-phase Splunk HEC settings.

        Inputs:
            None. Uses Splunk fields from this settings object.

        Outputs:
            None.

        Raises:
            ConfigError: If Splunk URL or token is missing.
        """

        _require_non_empty("SPLUNK_HEC_URL", self.splunk_hec_url)
        _require_non_empty("SPLUNK_HEC_TOKEN", self.splunk_hec_token)

    def validate_openbsd_pf(self) -> None:
        """Validate later-phase OpenBSD pfctl integration settings.

        Inputs:
            None. Uses OpenBSD pf fields from this settings object.

        Outputs:
            None.

        Raises:
            ConfigError: If OpenBSD pf integration is enabled but required
            fields are missing.
        """

        if not self.openbsd_pf_enabled:
            return

        _require_non_empty("OPENBSD_PF_HOST", self.openbsd_pf_host)
        _require_non_empty("OPENBSD_PF_USER", self.openbsd_pf_user)
        _require_non_empty("OPENBSD_PF_BLOCK_TABLE", self.openbsd_pf_block_table)

    @property
    def report_model(self) -> str:
        """Return the configured report model, falling back to triage model.

        Returns:
            OpenRouter model name used for report generation.
        """

        return self.openrouter_report_model or self.openrouter_model


_cached_settings: Settings | None = None


def get_settings(env_file: Path | str = DEFAULT_ENV_FILE, *, reload: bool = False) -> Settings:
    """Load and cache application settings.

    Inputs:
        env_file: Path to a dotenv file. Defaults to `.env`.
        reload: If True, ignore the cached settings and reload from disk/env.

    Outputs:
        A `Settings` object containing typed configuration values.
    """

    global _cached_settings

    if _cached_settings is not None and not reload:
        return _cached_settings

    load_dotenv(env_file)
    _cached_settings = _load_settings_from_env()
    return _cached_settings


def _load_settings_from_env() -> Settings:
    """Build a Settings object from current environment variables.

    Inputs:
        None. Reads from `os.environ`.

    Outputs:
        A populated `Settings` object.

    Raises:
        ConfigError: If numeric or boolean values are invalid.
    """

    return Settings(
        poll_interval_seconds=_get_int("POLL_INTERVAL_SECONDS", 120, minimum=1),
        alert_lookback_minutes=_get_int("ALERT_LOOKBACK_MINUTES", 5, minimum=1),
        output_dir=_get_path("OUTPUT_DIR", "output"),
        log_dir=_get_path("LOG_DIR", "logs"),
        wazuh_host=_get_str("WAZUH_HOST", ""),
        wazuh_user=_get_str("WAZUH_USER", ""),
        wazuh_password=_get_str("WAZUH_PASSWORD", ""),
        wazuh_min_level=_get_int("WAZUH_MIN_LEVEL", 7, minimum=0),
        wazuh_alert_source=_get_str("WAZUH_ALERT_SOURCE", "api"),
        wazuh_alert_json_path=_get_path(
            "WAZUH_ALERT_JSON_PATH",
            "/var/ossec/logs/alerts/alerts.json",
        ),
        securityonion_host=_get_str("SECURITYONION_HOST", ""),
        securityonion_user=_get_str("SECURITYONION_USER", ""),
        securityonion_password=_get_str("SECURITYONION_PASSWORD", ""),
        securityonion_alert_index=_get_str("SECURITYONION_ALERT_INDEX", "so-ids-*"),
        securityonion_zeek_index=_get_str("SECURITYONION_ZEEK_INDEX", "so-zeek-*"),
        so_min_severity=_get_int("SO_MIN_SEVERITY", 2, minimum=0),
        openrouter_api_key=_get_str("OPENROUTER_API_KEY", ""),
        openrouter_base_url=_get_str("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        openrouter_model=_get_str("OPENROUTER_MODEL", "openrouter/free"),
        openrouter_report_model=_get_str("OPENROUTER_REPORT_MODEL", ""),
        openrouter_site_url=_get_str("OPENROUTER_SITE_URL", ""),
        openrouter_app_name=_get_str("OPENROUTER_APP_NAME", "AI_Augmented_SOC"),
        virustotal_api_key=_get_str("VIRUSTOTAL_API_KEY", ""),
        abuseipdb_api_key=_get_str("ABUSEIPDB_API_KEY", ""),
        shodan_api_key=_get_str("SHODAN_API_KEY", ""),
        enrichment_cache_ttl_hours=_get_int("ENRICHMENT_CACHE_TTL_HOURS", 24, minimum=1),
        email_enabled=_get_bool("EMAIL_ENABLED", False),
        smtp_host=_get_str("SMTP_HOST", ""),
        smtp_port=_get_int("SMTP_PORT", 587, minimum=1, maximum=65535),
        smtp_username=_get_str("SMTP_USERNAME", ""),
        smtp_password=_get_str("SMTP_PASSWORD", ""),
        email_from=_get_str("EMAIL_FROM", ""),
        email_to=_get_str("EMAIL_TO", ""),
        email_use_tls=_get_bool("EMAIL_USE_TLS", True),
        slack_webhook_url=_get_str("SLACK_WEBHOOK_URL", ""),
        dedup_store=_get_str("DEDUP_STORE", "sqlite"),
        sqlite_db_path=_get_path("SQLITE_DB_PATH", "ai_soc.db"),
        redis_url=_get_str("REDIS_URL", "redis://localhost:6379/0"),
        dedup_ttl_hours=_get_int("DEDUP_TTL_HOURS", 24, minimum=1),
        enable_sample_replay=_get_bool("ENABLE_SAMPLE_REPLAY", False),
        sample_replay_file=_get_path(
            "SAMPLE_REPLAY_FILE",
            "tests/fixtures/sample_incident_replay.json",
        ),
        manual_test_events_dir=_get_path(
            "MANUAL_TEST_EVENTS_DIR",
            "tests/fixtures/manual_events",
        ),
        splunk_hec_url=_get_str("SPLUNK_HEC_URL", ""),
        splunk_hec_token=_get_str("SPLUNK_HEC_TOKEN", ""),
        splunk_hec_index=_get_str("SPLUNK_HEC_INDEX", ""),
        splunk_hec_sourcetype=_get_str("SPLUNK_HEC_SOURCETYPE", "ai_triage"),
        openbsd_pf_enabled=_get_bool("OPENBSD_PF_ENABLED", False),
        openbsd_pf_host=_get_str("OPENBSD_PF_HOST", ""),
        openbsd_pf_user=_get_str("OPENBSD_PF_USER", ""),
        openbsd_pflog_path=_get_path("OPENBSD_PFLOG_PATH", "/var/log/pflog"),
        openbsd_pf_block_table=_get_str("OPENBSD_PF_BLOCK_TABLE", "ai_soc_blocklist"),
    )


def _get_str(name: str, default: str) -> str:
    """Read a string environment variable.

    Inputs:
        name: Environment variable name.
        default: Default value when variable is missing.

    Outputs:
        The stripped string value.
    """

    return os.getenv(name, default).strip()


def _get_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Read and validate an integer environment variable.

    Inputs:
        name: Environment variable name.
        default: Default value when variable is missing.
        minimum: Optional inclusive minimum.
        maximum: Optional inclusive maximum.

    Outputs:
        Parsed integer value.

    Raises:
        ConfigError: If the value is not an integer or is outside bounds.
    """

    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        value = default
    else:
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise ConfigError(f"{name} must be an integer") from exc

    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be <= {maximum}")

    return value


def _get_bool(name: str, default: bool) -> bool:
    """Read and validate a boolean environment variable.

    Inputs:
        name: Environment variable name.
        default: Default value when variable is missing.

    Outputs:
        Parsed boolean value.

    Raises:
        ConfigError: If the value is not a recognized boolean string.
    """

    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default

    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False

    raise ConfigError(
        f"{name} must be a boolean value such as true/false, yes/no, or 1/0"
    )


def _get_path(name: str, default: str) -> Path:
    """Read a path environment variable.

    Inputs:
        name: Environment variable name.
        default: Default path when variable is missing.

    Outputs:
        Path object. The path is not created by this function.
    """

    return Path(_get_str(name, default)).expanduser()


def _require_non_empty(name: str, value: str) -> None:
    """Require that a configuration value is not empty.

    Inputs:
        name: Environment variable name used in the error message.
        value: Value to validate.

    Outputs:
        None.

    Raises:
        ConfigError: If the value is empty.
    """

    if value.strip() == "":
        raise ConfigError(f"Missing required environment variable: {name}")