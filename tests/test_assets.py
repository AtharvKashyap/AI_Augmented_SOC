"""Tests for asset inventory lookup.

These tests verify that `soc.assets` can load a CSV asset inventory, match
alert hostnames and IPs against it tolerantly, and degrade rather than fail on
messy or absent inventory data.

Asset context matters for triage because criticality is often the difference
between queueing an alert and paging a human, and a CMDB export is rarely as
clean as the alerts it has to be matched against.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from soc.assets import (
    ASSET_CRITICALITIES,
    AssetContext,
    AssetError,
    AssetInventory,
    load_asset_inventory,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_ASSETS_CSV = FIXTURES_DIR / "sample_assets.csv"


def _write_csv(path: Path, text: str) -> Path:
    """Write CSV test data to disk.

    Inputs:
        path: Path to write.
        text: CSV text content.

    Outputs:
        The path that was written.
    """

    path.write_text(text, encoding="utf-8")
    return path


def test_load_sample_fixture() -> None:
    """The shipped fixture loads and reports its row count."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    assert len(inventory) == 4


def test_module_level_loader_matches_classmethod() -> None:
    """`load_asset_inventory` mirrors `AssetInventory.from_csv`."""

    inventory = load_asset_inventory(SAMPLE_ASSETS_CSV)

    assert isinstance(inventory, AssetInventory)
    assert len(inventory) == 4


def test_lookup_by_exact_hostname() -> None:
    """An exact hostname match returns the full asset context."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="web-01.corp.local")

    assert context is not None
    assert context.hostname == "web-01.corp.local"
    assert context.ip == "203.0.113.10"
    assert context.owner == "platform-team"
    assert context.criticality == "critical"
    assert context.internet_facing is True
    assert context.department == "IT Infrastructure"


def test_lookup_hostname_is_case_insensitive() -> None:
    """Hostname matching ignores case differences."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="WEB-01.CORP.LOCAL")

    assert context is not None
    assert context.hostname == "web-01.corp.local"


def test_lookup_short_name_matches_fqdn_row() -> None:
    """A short alert hostname matches a fully-qualified inventory row."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="web-01")

    assert context is not None
    assert context.hostname == "web-01.corp.local"


def test_lookup_fqdn_matches_short_name_row() -> None:
    """A fully-qualified alert hostname matches a short inventory row."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="wks-104.corp.local")

    assert context is not None
    assert context.hostname == "wks-104"
    assert context.criticality == "low"
    assert context.internet_facing is False


def test_lookup_by_ip() -> None:
    """An IP match is used when no hostname is supplied."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(ip="10.0.5.104")

    assert context is not None
    assert context.hostname == "wks-104"


def test_lookup_falls_back_to_ip_when_hostname_unknown() -> None:
    """An unmatched hostname still allows an IP match."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="not-in-cmdb", ip="10.0.1.5")

    assert context is not None
    assert context.hostname == "dc-01.corp.local"


def test_hostname_match_takes_precedence_over_ip() -> None:
    """When both match different rows, the hostname match wins."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="wks-104", ip="203.0.113.10")

    assert context is not None
    assert context.hostname == "wks-104"


def test_lookup_unknown_host_returns_none() -> None:
    """An unknown hostname and IP produce no context rather than an error."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    assert inventory.lookup(hostname="ghost-01", ip="198.51.100.99") is None


def test_lookup_with_no_arguments_returns_none() -> None:
    """Looking up nothing returns nothing."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    assert inventory.lookup() is None


def test_empty_inventory_is_valid_and_matches_nothing() -> None:
    """An empty inventory is a normal operating mode, not an error."""

    inventory = AssetInventory.empty()

    assert len(inventory) == 0
    assert inventory.lookup(hostname="web-01.corp.local") is None
    assert inventory.lookup(ip="203.0.113.10") is None
    assert inventory.lookup() is None


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("True", True),
        ("yes", True),
        ("YES", True),
        ("1", True),
        ("false", False),
        ("FALSE", False),
        ("no", False),
        ("No", False),
        ("0", False),
        ("", False),
        ("   ", False),
        ("maybe", False),
    ],
)
def test_internet_facing_boolean_spellings(tmp_path: Path, raw_value: str, expected: bool) -> None:
    """Boolean spellings are parsed tolerantly and blanks default to False."""

    csv_path = _write_csv(
        tmp_path / "assets.csv",
        f"hostname,internet_facing\nhost-01,{raw_value}\n",
    )

    context = AssetInventory.from_csv(csv_path).lookup(hostname="host-01")

    assert context is not None
    assert context.internet_facing is expected


@pytest.mark.parametrize("value", sorted(ASSET_CRITICALITIES))
def test_known_criticality_values_are_preserved(tmp_path: Path, value: str) -> None:
    """Every allowed criticality survives loading, case-insensitively."""

    csv_path = _write_csv(
        tmp_path / "assets.csv",
        f"hostname,criticality\nhost-01,{value.upper()}\n",
    )

    context = AssetInventory.from_csv(csv_path).lookup(hostname="host-01")

    assert context is not None
    assert context.criticality == value


@pytest.mark.parametrize("value", ["Tier-0", "business critical", "P1", "", "   "])
def test_unrecognized_criticality_degrades_to_unknown(tmp_path: Path, value: str) -> None:
    """A bad CMDB criticality degrades instead of breaking ingestion."""

    csv_path = _write_csv(
        tmp_path / "assets.csv",
        f'hostname,criticality\nhost-01,"{value}"\n',
    )

    context = AssetInventory.from_csv(csv_path).lookup(hostname="host-01")

    assert context is not None
    assert context.criticality == "unknown"


def test_fixture_messy_criticality_degrades_to_unknown() -> None:
    """The fixture's messy criticality row loads as `unknown`."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="dc-01")

    assert context is not None
    assert context.criticality == "unknown"
    assert context.internet_facing is False


def test_optional_fields_absent_from_csv_become_none(tmp_path: Path) -> None:
    """Every field except hostname tolerates being absent entirely."""

    csv_path = _write_csv(tmp_path / "assets.csv", "hostname\nhost-01\n")

    context = AssetInventory.from_csv(csv_path).lookup(hostname="host-01")

    assert context is not None
    assert context.ip is None
    assert context.owner is None
    assert context.department is None
    assert context.criticality == "unknown"
    assert context.internet_facing is False


def test_blank_optional_columns_become_none() -> None:
    """Blank cells are treated as absent values."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)

    context = inventory.lookup(hostname="legacy-print")

    assert context is not None
    assert context.owner is None
    assert context.criticality == "medium"
    assert context.internet_facing is False
    assert context.department == "Facilities"


def test_extra_csv_columns_are_ignored(tmp_path: Path) -> None:
    """Unknown CMDB export columns are ignored rather than rejected."""

    csv_path = _write_csv(
        tmp_path / "assets.csv",
        "serial,hostname,rack,owner,patch_group\nSN123,host-01,B7,jdoe,weekly\n",
    )

    context = AssetInventory.from_csv(csv_path).lookup(hostname="host-01")

    assert context is not None
    assert context.owner == "jdoe"
    assert not hasattr(context, "rack")


def test_header_only_file_loads_as_empty(tmp_path: Path) -> None:
    """A file with a header but zero data rows is valid and empty."""

    csv_path = _write_csv(tmp_path / "assets.csv", "hostname,ip,owner\n")

    inventory = AssetInventory.from_csv(csv_path)

    assert len(inventory) == 0
    assert inventory.lookup(hostname="host-01") is None


def test_rows_without_a_hostname_value_are_skipped(tmp_path: Path) -> None:
    """Rows with a blank hostname cannot be matched and are dropped."""

    csv_path = _write_csv(
        tmp_path / "assets.csv",
        "hostname,ip\n,10.0.0.1\nhost-01,10.0.0.2\n",
    )

    inventory = AssetInventory.from_csv(csv_path)

    assert len(inventory) == 1
    assert inventory.lookup(ip="10.0.0.1") is None


def test_missing_file_raises_asset_error(tmp_path: Path) -> None:
    """A missing inventory file raises an actionable AssetError."""

    missing = tmp_path / "nope.csv"

    with pytest.raises(AssetError) as exc_info:
        AssetInventory.from_csv(missing)

    assert str(missing) in str(exc_info.value)


def test_directory_path_raises_asset_error(tmp_path: Path) -> None:
    """A directory is not a usable inventory file."""

    with pytest.raises(AssetError):
        AssetInventory.from_csv(tmp_path)


def test_missing_hostname_column_raises_asset_error(tmp_path: Path) -> None:
    """A CSV without a `hostname` column raises AssetError."""

    csv_path = _write_csv(tmp_path / "assets.csv", "host,ip\nhost-01,10.0.0.2\n")

    with pytest.raises(AssetError) as exc_info:
        AssetInventory.from_csv(csv_path)

    assert "hostname" in str(exc_info.value)


def test_completely_empty_file_raises_asset_error(tmp_path: Path) -> None:
    """A file with no header at all has no `hostname` column."""

    csv_path = _write_csv(tmp_path / "assets.csv", "")

    with pytest.raises(AssetError):
        AssetInventory.from_csv(csv_path)


def test_header_whitespace_and_case_are_tolerated(tmp_path: Path) -> None:
    """Column headers are matched case-insensitively and trimmed."""

    csv_path = _write_csv(
        tmp_path / "assets.csv",
        " Hostname , Criticality \nhost-01,High\n",
    )

    context = AssetInventory.from_csv(csv_path).lookup(hostname="host-01")

    assert context is not None
    assert context.criticality == "high"


def test_asset_context_to_dict_is_json_safe() -> None:
    """`to_dict` returns a JSON-safe mapping of every field."""

    inventory = AssetInventory.from_csv(SAMPLE_ASSETS_CSV)
    context = inventory.lookup(hostname="web-01")

    assert context is not None
    assert context.to_dict() == {
        "hostname": "web-01.corp.local",
        "ip": "203.0.113.10",
        "owner": "platform-team",
        "criticality": "critical",
        "internet_facing": True,
        "department": "IT Infrastructure",
    }


def test_asset_context_is_frozen() -> None:
    """AssetContext is immutable so callers cannot mutate shared inventory."""

    context = AssetContext(hostname="host-01")

    with pytest.raises(FrozenInstanceError):
        context.hostname = "other"  # type: ignore[misc]
