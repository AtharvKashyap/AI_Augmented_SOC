"""Asset inventory context lookup for AI_Augmented_SOC.

Triage cannot tell a developer laptop from a domain controller without knowing
what the host *is*. Asset criticality is frequently the difference between
queueing an alert and paging a human, so this module loads a small asset
inventory (typically a CSV export from a CMDB or a hand-maintained
`assets.csv`) and matches alert hostnames and IPs against it.

Expected CSV shape:

    hostname,ip,owner,criticality,internet_facing,department
    web-01.corp.local,203.0.113.10,platform-team,critical,true,IT Infrastructure
    wks-104,10.0.5.104,jdoe,low,no,Sales

Only `hostname` is required. Any other column is optional, and unknown extra
columns are ignored because a real CMDB export always carries more fields than
this pipeline cares about.

Design decisions worth knowing:

- **Matching is deliberately forgiving.** Alerts and inventories disagree about
  fully-qualified names constantly, so `web-01` matches an inventory row of
  `web-01.corp.local` and vice versa, case-insensitively.
- **Bad data degrades, it does not raise.** An unrecognized criticality becomes
  `unknown` and an unparseable boolean becomes False, because one strange CMDB
  cell must not stop alert ingestion. Only genuinely unusable input — a missing
  file, or a file with no `hostname` column — raises `AssetError`.
- **No inventory is a normal mode.** `AssetInventory.empty()` matches nothing
  and is not an error, so callers can run without any inventory configured.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

JsonDict = dict[str, Any]

HOSTNAME_COLUMN = "hostname"

OPTIONAL_COLUMNS: tuple[str, ...] = (
    "ip",
    "owner",
    "criticality",
    "internet_facing",
    "department",
)

ASSET_CRITICALITIES: frozenset[str] = frozenset(
    {
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
    }
)

UNKNOWN_CRITICALITY = "unknown"

TRUE_VALUES: frozenset[str] = frozenset({"true", "yes", "y", "1"})
FALSE_VALUES: frozenset[str] = frozenset({"false", "no", "n", "0"})


class AssetError(ValueError):
    """Raised when asset inventory input is missing, unreadable, or invalid."""


@dataclass(frozen=True, slots=True)
class AssetContext:
    """Asset inventory context for a single host.

    Attributes:
        hostname: Hostname as recorded in the inventory.
        ip: Primary IP address, if the inventory records one.
        owner: Owning person or team, if known.
        criticality: One of `ASSET_CRITICALITIES`; `unknown` when absent or
            unrecognized.
        internet_facing: True when the inventory marks the host as reachable
            from the internet. Defaults to False when absent or unparseable.
        department: Owning department or business unit, if known.
    """

    hostname: str
    ip: str | None = None
    owner: str | None = None
    criticality: str = UNKNOWN_CRITICALITY
    internet_facing: bool = False
    department: str | None = None

    def to_dict(self) -> JsonDict:
        """Serialize the asset context into a JSON-safe dictionary.

        Inputs:
            None.

        Outputs:
            Dictionary of every field, containing only strings, booleans, and
            None values.
        """

        return dict(asdict(self))


class AssetInventory:
    """In-memory asset inventory with tolerant hostname and IP matching.

    The inventory is built once (usually at startup) and queried per alert, so
    lookups are served from precomputed dictionaries rather than by scanning.
    """

    def __init__(self, assets: list[AssetContext] | None = None) -> None:
        """Build an inventory from asset contexts.

        Inputs:
            assets: Asset contexts to index. None or an empty list produces an
                inventory that matches nothing.

        Outputs:
            None.
        """

        self._assets: list[AssetContext] = list(assets or [])
        self._by_hostname: dict[str, AssetContext] = {}
        self._by_short_name: dict[str, AssetContext] = {}
        self._by_ip: dict[str, AssetContext] = {}

        for asset in self._assets:
            hostname_key = asset.hostname.strip().lower()
            if hostname_key == "":
                continue

            # First row wins on every key, so a duplicated hostname or shared
            # short name resolves deterministically to the earlier CSV row.
            self._by_hostname.setdefault(hostname_key, asset)
            self._by_short_name.setdefault(_short_name(hostname_key), asset)

            if asset.ip:
                self._by_ip.setdefault(asset.ip.strip().lower(), asset)

    @classmethod
    def from_csv(cls, path: str | Path) -> AssetInventory:
        """Load an asset inventory from a CSV file.

        The `hostname` column is required. `ip`, `owner`, `criticality`,
        `internet_facing`, and `department` are optional, and any other column
        is ignored.

        Inputs:
            path: Path to the inventory CSV file.

        Outputs:
            AssetInventory containing one AssetContext per usable data row. A
            header-only file yields a valid, empty inventory.

        Raises:
            AssetError: If the file is missing, is not a file, cannot be read,
                or has no `hostname` column.
        """

        csv_path = Path(path).expanduser()
        if not csv_path.exists():
            raise AssetError(
                f"Asset inventory file does not exist: {csv_path}. "
                "Create the CSV with a 'hostname' column or run without an asset inventory."
            )
        if not csv_path.is_file():
            raise AssetError(f"Asset inventory path is not a file: {csv_path}")

        try:
            # utf-8-sig so a BOM from an Excel-exported CMDB file does not end
            # up glued to the first column name.
            with csv_path.open("r", encoding="utf-8-sig", newline="") as file_obj:
                reader = csv.reader(file_obj)
                rows = list(reader)
        except OSError as exc:
            raise AssetError(f"Could not read asset inventory {csv_path}: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise AssetError(f"Asset inventory {csv_path} is not valid UTF-8 text: {exc}") from exc

        if not rows:
            raise AssetError(
                f"Asset inventory {csv_path} is empty and has no header row; a '{HOSTNAME_COLUMN}' column is required"
            )

        column_index = _build_column_index(rows[0])
        if HOSTNAME_COLUMN not in column_index:
            found = ", ".join(sorted(column_index)) or "no columns"
            raise AssetError(
                f"Asset inventory {csv_path} has no '{HOSTNAME_COLUMN}' column (found: {found}); "
                f"add a '{HOSTNAME_COLUMN}' column to the CSV header"
            )

        assets = [
            asset for row in rows[1:] if (asset := _asset_from_row(row, column_index)) is not None
        ]
        return cls(assets)

    @classmethod
    def empty(cls) -> AssetInventory:
        """Return an inventory with no assets.

        This is the normal state when no inventory is configured, not an error
        condition: every lookup simply returns None.

        Inputs:
            None.

        Outputs:
            Empty AssetInventory.
        """

        return cls([])

    def lookup(self, hostname: str | None = None, ip: str | None = None) -> AssetContext | None:
        """Find the asset context for an alert's hostname or IP.

        Hostname matching is tried first and is case-insensitive; it also
        matches a short name against a fully-qualified inventory name in either
        direction. IP matching is only consulted when the hostname does not
        match anything.

        Inputs:
            hostname: Hostname from the alert, if any.
            ip: IP address from the alert, if any.

        Outputs:
            The matching AssetContext, or None when nothing matches or neither
            value was supplied.
        """

        match = self._lookup_hostname(hostname)
        if match is not None:
            return match

        return self._lookup_ip(ip)

    def assets(self) -> list[AssetContext]:
        """Return every loaded asset context.

        Inputs:
            None.

        Outputs:
            New list of AssetContext objects in CSV order.
        """

        return list(self._assets)

    def __len__(self) -> int:
        """Return how many assets were loaded.

        Inputs:
            None.

        Outputs:
            Number of asset rows, so callers can distinguish an empty inventory
            from a loaded one.
        """

        return len(self._assets)

    def _lookup_hostname(self, hostname: str | None) -> AssetContext | None:
        """Match a hostname exactly, then by short name.

        Inputs:
            hostname: Hostname from the alert, or None.

        Outputs:
            Matching AssetContext, or None.
        """

        if hostname is None:
            return None

        hostname_key = hostname.strip().lower()
        if hostname_key == "":
            return None

        exact = self._by_hostname.get(hostname_key)
        if exact is not None:
            return exact

        # `web-01` should find `web-01.corp.local`, and `wks-104.corp.local`
        # should find `wks-104`. Both reduce to comparing first labels.
        return self._by_short_name.get(_short_name(hostname_key))

    def _lookup_ip(self, ip: str | None) -> AssetContext | None:
        """Match an IP address.

        Inputs:
            ip: IP address from the alert, or None.

        Outputs:
            Matching AssetContext, or None.
        """

        if ip is None:
            return None

        ip_key = ip.strip().lower()
        if ip_key == "":
            return None

        return self._by_ip.get(ip_key)


def load_asset_inventory(path: str | Path) -> AssetInventory:
    """Load an asset inventory from a CSV path.

    Module-level counterpart to `AssetInventory.from_csv`, matching the
    class-plus-function pattern used across this codebase.

    Inputs:
        path: Path to the inventory CSV file.

    Outputs:
        AssetInventory loaded from the file.

    Raises:
        AssetError: If the file is missing, unreadable, or has no `hostname`
            column.
    """

    return AssetInventory.from_csv(path)


def normalize_criticality(value: Any) -> str:
    """Normalize an inventory criticality value.

    Inputs:
        value: Raw criticality cell, which may be None, blank, or an
            unrecognized label from a CMDB export.

    Outputs:
        Lowercased criticality from `ASSET_CRITICALITIES`. Anything
        unrecognized becomes `unknown` rather than raising, so one bad cell
        cannot block ingestion.
    """

    if value is None:
        return UNKNOWN_CRITICALITY

    text = str(value).strip().lower()
    if text in ASSET_CRITICALITIES:
        return text

    return UNKNOWN_CRITICALITY


def parse_internet_facing(value: Any) -> bool:
    """Parse an inventory boolean tolerantly.

    Accepts `true`/`false`, `yes`/`no`, `y`/`n`, and `1`/`0` in any case.

    Inputs:
        value: Raw cell value, which may be None or blank.

    Outputs:
        True only for a recognized truthy spelling; False for a recognized
        falsy spelling, a blank cell, or an unrecognized value.
    """

    if value is None:
        return False

    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False

    return False


def _build_column_index(header_row: list[str]) -> dict[str, int]:
    """Map recognized column names to their position in the header row.

    Inputs:
        header_row: First row of the CSV file.

    Outputs:
        Dictionary of normalized column name to column index. Unknown columns
        are omitted, which is how extra CMDB export columns get ignored.
    """

    recognized = {HOSTNAME_COLUMN, *OPTIONAL_COLUMNS}
    column_index: dict[str, int] = {}

    for index, raw_name in enumerate(header_row):
        name = raw_name.strip().lower()
        if name in recognized:
            column_index.setdefault(name, index)

    return column_index


def _asset_from_row(row: list[str], column_index: dict[str, int]) -> AssetContext | None:
    """Convert one CSV data row into an AssetContext.

    Inputs:
        row: CSV data row.
        column_index: Mapping of recognized column names to indexes.

    Outputs:
        AssetContext, or None when the row has no usable hostname (a blank
        hostname cannot be matched, and a fully blank line is padding).
    """

    hostname = _cell(row, column_index, HOSTNAME_COLUMN)
    if hostname is None:
        return None

    return AssetContext(
        hostname=hostname,
        ip=_cell(row, column_index, "ip"),
        owner=_cell(row, column_index, "owner"),
        criticality=normalize_criticality(_cell(row, column_index, "criticality")),
        internet_facing=parse_internet_facing(_cell(row, column_index, "internet_facing")),
        department=_cell(row, column_index, "department"),
    )


def _cell(row: list[str], column_index: dict[str, int], name: str) -> str | None:
    """Read one trimmed cell from a CSV row.

    Inputs:
        row: CSV data row.
        column_index: Mapping of recognized column names to indexes.
        name: Normalized column name to read.

    Outputs:
        Trimmed cell text, or None when the column is absent from the file, the
        row is short, or the cell is blank.
    """

    index = column_index.get(name)
    if index is None or index >= len(row):
        return None

    text = row[index].strip()
    if text == "":
        return None

    return text


def _short_name(hostname: str) -> str:
    """Return the first DNS label of a hostname.

    Inputs:
        hostname: Already-lowercased hostname, qualified or not.

    Outputs:
        Text before the first dot, which is the hostname itself when it is not
        fully qualified.
    """

    return hostname.split(".", 1)[0]
