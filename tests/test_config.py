"""Tests for environment-backed application configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc.config import ConfigError, get_settings

WAZUH_ENV_KEYS = [
    "WAZUH_HOST",
    "WAZUH_USER",
    "WAZUH_PASSWORD",
    "WAZUH_MANAGER_URL",
    "WAZUH_MANAGER_USER",
    "WAZUH_MANAGER_PASSWORD",
    "WAZUH_MANAGER_VERIFY_TLS",
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_INDEXER_VERIFY_TLS",
    "WAZUH_ALERT_INDEX",
    "WAZUH_ALERT_LIMIT",
    "WAZUH_ALERT_LOOKBACK_MINUTES",
    "WAZUH_MIN_LEVEL",
    "WAZUH_ALERT_SOURCE",
    "WAZUH_ALERT_JSON_PATH",
]


def _write_env_file(tmp_path: Path, content: str) -> Path:
    """Write a temporary .env file."""

    env_file = tmp_path / ".env.test"
    env_file.write_text(content.strip() + "\n", encoding="utf-8")
    return env_file


@pytest.fixture(autouse=True)
def clear_wazuh_env(monkeypatch):
    """Remove Wazuh-specific environment variables for deterministic tests."""

    for key in WAZUH_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_default_settings_do_not_require_wazuh_credentials(tmp_path):
    """Replay mode should load settings without live Wazuh credentials."""

    env_file = _write_env_file(
        tmp_path,
        """
        OUTPUT_DIR=output
        SQLITE_DB_PATH=data/soc.db
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.wazuh_manager_url == ""
    assert settings.wazuh_manager_user == ""
    assert settings.wazuh_manager_password == ""
    assert settings.wazuh_indexer_url == ""
    assert settings.wazuh_indexer_user == ""
    assert settings.wazuh_indexer_password == ""
    assert settings.wazuh_alert_index == "wazuh-alerts-*"
    assert settings.wazuh_alert_limit == 100
    assert settings.wazuh_alert_lookback_minutes == 5
    assert settings.wazuh_min_level == 7
    assert settings.wazuh_alert_source == "json_logs"
    assert settings.wazuh_alert_json_path == Path("/var/ossec/logs/alerts/alerts.json")


def test_new_wazuh_manager_and_json_log_settings_are_loaded(tmp_path):
    """Manager and alerts.json settings should load from the environment."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_MANAGER_URL=https://manager.example:55000
        WAZUH_MANAGER_USER=manager-user
        WAZUH_MANAGER_PASSWORD=manager-pass
        WAZUH_MANAGER_VERIFY_TLS=false
        WAZUH_ALERT_SOURCE=json_logs
        WAZUH_ALERT_JSON_PATH=data/alerts.json
        WAZUH_ALERT_LIMIT=250
        WAZUH_ALERT_LOOKBACK_MINUTES=15
        WAZUH_MIN_LEVEL=10
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.wazuh_manager_url == "https://manager.example:55000"
    assert settings.wazuh_manager_user == "manager-user"
    assert settings.wazuh_manager_password == "manager-pass"
    assert settings.wazuh_manager_verify_tls is False
    assert settings.wazuh_alert_source == "json_logs"
    assert settings.wazuh_alert_json_path == Path("data/alerts.json")
    assert settings.wazuh_alert_limit == 250
    assert settings.wazuh_alert_lookback_minutes == 15
    assert settings.wazuh_min_level == 10


def test_legacy_wazuh_settings_still_populate_manager_aliases(tmp_path):
    """Old WAZUH_HOST/USER/PASSWORD values should still work for Manager settings."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_HOST=https://legacy-manager.example:55000
        WAZUH_USER=legacy-user
        WAZUH_PASSWORD=legacy-pass
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.wazuh_manager_url == "https://legacy-manager.example:55000"
    assert settings.wazuh_manager_user == "legacy-user"
    assert settings.wazuh_manager_password == "legacy-pass"
    assert settings.wazuh_host == "https://legacy-manager.example:55000"
    assert settings.wazuh_user == "legacy-user"
    assert settings.wazuh_password == "legacy-pass"


def test_new_wazuh_manager_values_override_legacy_values(tmp_path):
    """New Manager variables should take priority over legacy aliases."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_HOST=https://legacy-manager.example:55000
        WAZUH_USER=legacy-user
        WAZUH_PASSWORD=legacy-pass
        WAZUH_MANAGER_URL=https://manager.example:55000
        WAZUH_MANAGER_USER=manager-user
        WAZUH_MANAGER_PASSWORD=manager-pass
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.wazuh_manager_url == "https://manager.example:55000"
    assert settings.wazuh_manager_user == "manager-user"
    assert settings.wazuh_manager_password == "manager-pass"
    assert settings.wazuh_host == "https://manager.example:55000"
    assert settings.wazuh_user == "manager-user"
    assert settings.wazuh_password == "manager-pass"


def test_wazuh_lookback_defaults_to_global_alert_lookback(tmp_path):
    """Wazuh lookback should inherit ALERT_LOOKBACK_MINUTES when not set."""

    env_file = _write_env_file(
        tmp_path,
        """
        ALERT_LOOKBACK_MINUTES=30
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.alert_lookback_minutes == 30
    assert settings.wazuh_alert_lookback_minutes == 30


def test_wazuh_lookback_can_override_global_alert_lookback(tmp_path):
    """Wazuh-specific lookback should override the global alert lookback."""

    env_file = _write_env_file(
        tmp_path,
        """
        ALERT_LOOKBACK_MINUTES=30
        WAZUH_ALERT_LOOKBACK_MINUTES=7
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.alert_lookback_minutes == 30
    assert settings.wazuh_alert_lookback_minutes == 7


def test_validate_wazuh_accepts_json_logs_settings(tmp_path):
    """Full Wazuh validation should accept Manager-only json_logs settings."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=json_logs
        WAZUH_ALERT_JSON_PATH=data/alerts.json
        """,
    )

    settings = get_settings(env_file, reload=True)

    settings.validate_wazuh()


def test_validate_wazuh_manager_accepts_only_manager_settings(tmp_path):
    """Manager-only validation should not require Indexer settings."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_MANAGER_URL=https://manager.example:55000
        WAZUH_MANAGER_USER=manager-user
        WAZUH_MANAGER_PASSWORD=manager-pass
        """,
    )

    settings = get_settings(env_file, reload=True)

    settings.validate_wazuh_manager()


def test_validate_wazuh_rejects_an_unsupported_alert_source(tmp_path):
    """Full Wazuh validation should reject alert sources with no reader behind them."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=carrier_pigeon
        WAZUH_ALERT_JSON_PATH=data/alerts.json
        """,
    )

    settings = get_settings(env_file, reload=True)

    with pytest.raises(ConfigError, match="Unsupported Wazuh alert source"):
        settings.validate_wazuh()


def test_validate_wazuh_dispatches_to_the_indexer_validator(tmp_path):
    """`indexer` is a supported source now, so validation must check its settings.

    Left rejecting `indexer`, this method would report a working configuration as
    unsupported — and the ingestion path does not call it, so the staleness would
    stay invisible until someone wired validation in and it failed for no reason.
    """

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=indexer
        """,
    )

    settings = get_settings(env_file, reload=True)

    with pytest.raises(ConfigError, match="WAZUH_INDEXER_URL"):
        settings.validate_wazuh()


def test_validate_wazuh_accepts_a_configured_indexer(tmp_path):
    """A fully configured indexer must pass full Wazuh validation."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=indexer
        WAZUH_INDEXER_URL=https://indexer.example:9200
        WAZUH_INDEXER_USER=soc-reader
        WAZUH_INDEXER_PASSWORD=not-a-real-password
        """,
    )

    settings = get_settings(env_file, reload=True)

    settings.validate_wazuh()


def test_validate_wazuh_json_logs_accepts_alert_json_path(tmp_path):
    """alerts.json validation should accept a configured JSON log path."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=json_logs
        WAZUH_ALERT_JSON_PATH=data/alerts.json
        """,
    )

    settings = get_settings(env_file, reload=True)

    settings.validate_wazuh_json_logs()


def test_invalid_wazuh_alert_limit_raises_config_error(tmp_path):
    """Invalid Wazuh integer settings should raise ConfigError."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_LIMIT=0
        """,
    )

    with pytest.raises(ConfigError, match="WAZUH_ALERT_LIMIT"):
        get_settings(env_file, reload=True)


def test_invalid_wazuh_lookback_raises_config_error(tmp_path):
    """Invalid Wazuh lookback should raise ConfigError."""

    env_file = _write_env_file(
        tmp_path,
        """
        WAZUH_ALERT_LOOKBACK_MINUTES=0
        """,
    )

    with pytest.raises(ConfigError, match="WAZUH_ALERT_LOOKBACK_MINUTES"):
        get_settings(env_file, reload=True)

def test_security_onion_connect_api_settings_are_loaded(tmp_path):
    """Connect API credentials and query bounds must come from the environment.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify the loaded Connect API settings.
    """

    env_file = _write_env_file(
        tmp_path,
        """
        SECURITYONION_HOST=https://securityonion.example
        SECURITYONION_CLIENT_ID=soc-automation
        SECURITYONION_CLIENT_SECRET=super-secret
        SECURITYONION_VERIFY_TLS=false
        SECURITYONION_LOOKBACK_MINUTES=30
        SECURITYONION_ALERT_LIMIT=250
        SECURITYONION_GRID_ID=grid-2
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.securityonion_client_id == "soc-automation"
    assert settings.securityonion_client_secret == "super-secret"
    assert settings.securityonion_verify_tls is False
    assert settings.securityonion_lookback_minutes == 30
    assert settings.securityonion_alert_limit == 250
    assert settings.securityonion_grid_id == "grid-2"


def test_security_onion_lookback_falls_back_to_shared_alert_lookback(tmp_path):
    """A single ALERT_LOOKBACK_MINUTES should drive both ingestion sources.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the fallback.
    """

    env_file = _write_env_file(tmp_path, "ALERT_LOOKBACK_MINUTES=45")

    assert get_settings(env_file, reload=True).securityonion_lookback_minutes == 45


def test_validate_security_onion_requires_connect_api_credentials(tmp_path):
    """The Connect API authenticates with a client ID and secret, not a password.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify each missing credential is reported by name.
    """

    settings = get_settings(_write_env_file(tmp_path, "OUTPUT_DIR=output"), reload=True)

    with pytest.raises(ConfigError, match="SECURITYONION_HOST"):
        settings.validate_security_onion()

    settings = get_settings(
        _write_env_file(tmp_path, "SECURITYONION_HOST=https://securityonion.example"),
        reload=True,
    )

    with pytest.raises(ConfigError, match="SECURITYONION_CLIENT_ID"):
        settings.validate_security_onion()

    settings = get_settings(
        _write_env_file(
            tmp_path,
            """
            SECURITYONION_HOST=https://securityonion.example
            SECURITYONION_CLIENT_ID=soc-automation
            """,
        ),
        reload=True,
    )

    with pytest.raises(ConfigError, match="SECURITYONION_CLIENT_SECRET"):
        settings.validate_security_onion()


def test_asset_inventory_path_is_loaded(tmp_path):
    """Asset context needs a configurable inventory location.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the configured path is loaded.
    """

    env_file = _write_env_file(tmp_path, "ASSET_INVENTORY_PATH=data/assets.csv")

    assert str(get_settings(env_file, reload=True).asset_inventory_path) == "data/assets.csv"


def test_asset_inventory_path_defaults_to_empty(tmp_path):
    """Running without an asset inventory is a normal mode, not an error.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the default is empty.
    """

    env_file = _write_env_file(tmp_path, "OUTPUT_DIR=output")

    assert str(get_settings(env_file, reload=True).asset_inventory_path) == ""


def test_pflog_text_path_is_separate_from_the_binary_pflog_path(tmp_path):
    """The parser reads tcpdump text, not the binary pcap, so they differ.

    `OPENBSD_PFLOG_PATH` points at /var/log/pflog, which is a pcap file the
    ingestion path cannot read directly. Conflating the two would make an
    operator point the reader at binary data and get silent zero results.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify both paths load independently.
    """

    env_file = _write_env_file(
        tmp_path,
        """
        OPENBSD_PFLOG_PATH=/var/log/pflog
        OPENBSD_PFLOG_TEXT_PATH=data/pflog.txt
        """,
    )

    settings = get_settings(env_file, reload=True)

    # Compared as Paths, not as strings: Path normalizes separators per platform,
    # so str(Path("/var/log/pflog")) is "\\var\\log\\pflog" on Windows. The text
    # path is a plain str by design, so it stays literal, which is the difference
    # this test is really about.
    assert settings.openbsd_pflog_path == Path("/var/log/pflog")
    assert settings.openbsd_pflog_text_path == "data/pflog.txt"


def test_pflog_text_path_defaults_to_empty(tmp_path):
    """Running without pflog ingestion is a normal mode.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the default is empty.
    """

    env_file = _write_env_file(tmp_path, "OUTPUT_DIR=output")

    assert get_settings(env_file, reload=True).openbsd_pflog_text_path == ""


def test_response_capabilities_are_all_disabled_by_default(tmp_path):
    """Every response capability is off unless explicitly switched on.

    A default-on response capability means a misconfigured deploy could change a
    firewall or drop a host by itself.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify each capability defaults to False.
    """

    settings = get_settings(_write_env_file(tmp_path, "OUTPUT_DIR=output"), reload=True)

    assert settings.response_pf_block_enabled is False
    assert settings.response_wazuh_firewall_drop_enabled is False
    assert settings.response_wazuh_host_deny_enabled is False


def test_each_response_capability_has_its_own_switch(tmp_path):
    """Enabling one capability must never imply another.

    Blocking an external address at the firewall and dropping an endpoint off the
    network are different risks and need separate decisions.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify the switches are independent.
    """

    settings = get_settings(
        _write_env_file(tmp_path, "RESPONSE_PF_BLOCK_ENABLED=true"), reload=True
    )

    assert settings.response_pf_block_enabled is True
    assert settings.response_wazuh_firewall_drop_enabled is False
    assert settings.response_wazuh_host_deny_enabled is False


def test_response_capability_lookup_matches_action_names(tmp_path):
    """The gate asks by action type, so the mapping must cover every action.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify lookup by action value.
    """

    from soc.response import ResponseActionType

    settings = get_settings(
        _write_env_file(tmp_path, "RESPONSE_WAZUH_HOST_DENY_ENABLED=true"), reload=True
    )

    assert settings.response_capability_enabled(ResponseActionType.WAZUH_HOST_DENY) is True
    assert settings.response_capability_enabled(ResponseActionType.PF_BLOCK_IP) is False


def test_playbook_directory_setting_defaults_to_playbooks(tmp_path):
    """Playbooks live in a known place but must remain overridable.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the default.
    """

    settings = get_settings(_write_env_file(tmp_path, "OUTPUT_DIR=output"), reload=True)

    assert settings.playbook_dir == "playbooks"


def test_splunk_search_settings_are_read_from_the_environment(tmp_path):
    """Milestone 5.2 ingestion needs its keys in Settings, not just via getattr.

    `SplunkSearchClient.from_settings` reads with `getattr` defaults, so absent
    keys do not crash — they make a configured `--splunk-search` run fail as
    though nothing had been set.
    """

    env_file = _write_env_file(
        tmp_path,
        """
        SPLUNK_SEARCH_URL=https://splunk.example:8089
        SPLUNK_SEARCH_TOKEN=not-a-real-token
        SPLUNK_SEARCH_QUERY=search index=soc sourcetype=wazuh
        SPLUNK_SEARCH_EARLIEST=-30m
        SPLUNK_SEARCH_LATEST=now
        SPLUNK_SEARCH_LIMIT=250
        """,
    )

    settings = get_settings(env_file, reload=True)

    assert settings.splunk_search_url == "https://splunk.example:8089"
    assert settings.splunk_search_token == "not-a-real-token"
    assert settings.splunk_search_query == "search index=soc sourcetype=wazuh"
    assert settings.splunk_search_earliest == "-30m"
    assert settings.splunk_search_latest == "now"
    assert settings.splunk_search_limit == 250


def test_splunk_search_tls_verification_defaults_to_on(tmp_path):
    """A read layer holding SOC data must not default to unverified TLS."""

    settings = get_settings(_write_env_file(tmp_path, ""), reload=True)

    assert settings.splunk_search_verify_tls is True


def test_validate_splunk_search_requires_a_url_and_token(tmp_path):
    """Validation must name the missing key rather than failing at request time."""

    settings = get_settings(_write_env_file(tmp_path, ""), reload=True)

    with pytest.raises(ConfigError, match="SPLUNK_SEARCH_URL"):
        settings.validate_splunk_search()


def test_dedup_store_defaults_to_the_only_implemented_store(tmp_path, monkeypatch):
    """With nothing configured, dedup runs on SQLite."""

    monkeypatch.delenv("DEDUP_STORE", raising=False)
    settings = get_settings(_write_env_file(tmp_path, ""), reload=True)

    assert settings.dedup_store == "sqlite"


def test_an_unimplemented_dedup_store_fails_loudly(tmp_path, monkeypatch):
    """Requesting Redis dedup must fail, not silently downgrade to SQLite.

    A key that reads cleanly and does nothing is the worst outcome here: the
    operator believes dedup is shared across processes when it is not.
    """

    monkeypatch.delenv("DEDUP_STORE", raising=False)
    env_file = _write_env_file(tmp_path, "DEDUP_STORE=redis")

    with pytest.raises(ConfigError, match="DEDUP_STORE"):
        get_settings(env_file, reload=True)


def test_the_unsupported_dedup_store_message_names_the_supported_value(tmp_path, monkeypatch):
    """The failure must say what to set instead."""

    monkeypatch.delenv("DEDUP_STORE", raising=False)
    env_file = _write_env_file(tmp_path, "DEDUP_STORE=redis")

    with pytest.raises(ConfigError, match="sqlite"):
        get_settings(env_file, reload=True)


def test_redis_url_is_not_a_setting(tmp_path, monkeypatch):
    """No Redis store exists, so no Redis setting should imply one."""

    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    settings = get_settings(_write_env_file(tmp_path, ""), reload=True)

    assert not hasattr(settings, "redis_url")
