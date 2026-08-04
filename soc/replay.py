"""Replay fixture loading for AI_Augmented_SOC.

This module supports testing the SOC pipeline in low-alert environments by
loading sample/manual JSON events from disk and converting them into `RawEvent`
objects.

Replay mode is important because a real lab SOC may not generate enough live
Wazuh or Security Onion alerts to test triage, clustering, routing, and report
writing reliably.

Expected replay file formats:

1. List format:
    [
        {
            "id": "raw-wazuh-001",
            "source": "wazuh",
            "timestamp": "2026-06-10T12:00:00+00:00",
            "payload": {...}
        }
    ]

2. Object format:
    {
        "events": [
            {
                "id": "raw-so-001",
                "source": "security_onion",
                "timestamp": "2026-06-10T12:01:00+00:00",
                "payload": {...}
            }
        ]
    }

Manual event directories may contain one or more `.json` files. Each file may
use either format above.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc.models import EventSource, RawEvent

JsonDict = dict[str, Any]


class ReplayError(ValueError):
    """Raised when replay input files are missing, invalid, or malformed."""


@dataclass(frozen=True, slots=True)
class ReplayLoadResult:
    """Result returned after loading replay events from disk.

    Attributes:
        events: RawEvent objects loaded from replay files.
        files_loaded: JSON files that were successfully read.
        files_skipped: Files skipped because they were not JSON files.
    """

    events: list[RawEvent]
    files_loaded: list[Path]
    files_skipped: list[Path]


REPLAY_SOURCE_ALIASES: dict[str, EventSource] = {
    "wazuh": EventSource.WAZUH,
    "security_onion": EventSource.SECURITY_ONION,
    "security-onion": EventSource.SECURITY_ONION,
    "so": EventSource.SECURITY_ONION,
    "openbsd_pf": EventSource.OPENBSD_PF,
    "openbsd-pf": EventSource.OPENBSD_PF,
    "pf": EventSource.OPENBSD_PF,
    "splunk": EventSource.SPLUNK,
    "replay": EventSource.REPLAY,
    "unknown": EventSource.UNKNOWN,
}


def load_replay_file(path: str | Path) -> list[RawEvent]:
    """Load RawEvent objects from one replay JSON file.

    Inputs:
        path: Path to a replay JSON file.

    Outputs:
        List of RawEvent objects.

    Raises:
        ReplayError: If the file does not exist, is invalid JSON, or has an
        unsupported shape.
    """

    replay_path = Path(path).expanduser()
    if not replay_path.exists():
        raise ReplayError(f"Replay file does not exist: {replay_path}")
    if not replay_path.is_file():
        raise ReplayError(f"Replay path is not a file: {replay_path}")

    payload = _read_json_file(replay_path)
    event_dicts = _extract_event_dicts(payload, replay_path)
    return [raw_event_from_dict(event_dict, index=index, file_path=replay_path) for index, event_dict in enumerate(event_dicts)]


def load_replay_directory(path: str | Path) -> ReplayLoadResult:
    """Load RawEvent objects from all JSON files in a directory.

    Inputs:
        path: Directory containing replay/manual event JSON files.

    Outputs:
        ReplayLoadResult containing events, loaded files, and skipped files.

    Raises:
        ReplayError: If the path does not exist or is not a directory.
    """

    directory = Path(path).expanduser()
    if not directory.exists():
        raise ReplayError(f"Replay directory does not exist: {directory}")
    if not directory.is_dir():
        raise ReplayError(f"Replay path is not a directory: {directory}")

    events: list[RawEvent] = []
    files_loaded: list[Path] = []
    files_skipped: list[Path] = []

    for file_path in sorted(directory.iterdir()):
        if not file_path.is_file() or file_path.suffix.lower() != ".json":
            files_skipped.append(file_path)
            continue

        events.extend(load_replay_file(file_path))
        files_loaded.append(file_path)

    return ReplayLoadResult(
        events=events,
        files_loaded=files_loaded,
        files_skipped=files_skipped,
    )


def raw_event_from_dict(
    event_data: JsonDict,
    *,
    index: int = 0,
    file_path: Path | None = None,
) -> RawEvent:
    """Convert one replay event dictionary into a RawEvent.

    Inputs:
        event_data: Dictionary with `source` and `payload` fields. `id` and
            `timestamp` are recommended but optional.
        index: Event position inside the replay file, used to create fallback
            IDs.
        file_path: Optional replay file path, used for better fallback IDs and
            error messages.

    Outputs:
        RawEvent object.

    Raises:
        ReplayError: If required fields are missing or invalid.
    """

    if not isinstance(event_data, dict):
        raise ReplayError("Replay event must be a JSON object")

    source = parse_event_source(event_data.get("source", "replay"))
    payload = event_data.get("payload")
    if not isinstance(payload, dict):
        raise ReplayError("Replay event must include a JSON object payload")

    event_id = event_data.get("id")
    if event_id is None or str(event_id).strip() == "":
        event_id = _fallback_event_id(source=source, index=index, file_path=file_path)

    timestamp = parse_timestamp(event_data.get("timestamp"))

    return RawEvent(
        id=str(event_id),
        source=source,
        timestamp=timestamp,
        payload=payload,
    )


def parse_event_source(value: Any) -> EventSource:
    """Parse a replay source value into an EventSource enum.

    Inputs:
        value: Source string such as `wazuh`, `security_onion`, or `replay`.

    Outputs:
        EventSource enum value.

    Raises:
        ReplayError: If the source is empty or unsupported.
    """

    source_text = str(value).strip().lower()
    if source_text == "":
        raise ReplayError("Replay event source cannot be empty")

    try:
        return REPLAY_SOURCE_ALIASES[source_text]
    except KeyError as exc:
        allowed = ", ".join(sorted(REPLAY_SOURCE_ALIASES))
        raise ReplayError(f"Unsupported replay source '{value}'. Allowed: {allowed}") from exc


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an optional ISO-8601 timestamp.

    Inputs:
        value: Timestamp string, None, or empty string.

    Outputs:
        Timezone-aware datetime, or None if no timestamp was provided.

    Raises:
        ReplayError: If the timestamp is present but invalid.
    """

    if value is None:
        return None

    timestamp_text = str(value).strip()
    if timestamp_text == "":
        return None

    if timestamp_text.endswith("Z"):
        timestamp_text = f"{timestamp_text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(timestamp_text)
    except ValueError as exc:
        raise ReplayError(f"Invalid replay timestamp: {value}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed


def _read_json_file(path: Path) -> Any:
    """Read and parse a JSON file.

    Inputs:
        path: JSON file path.

    Outputs:
        Parsed JSON value.

    Raises:
        ReplayError: If the file cannot be read or parsed.
    """

    try:
        with path.open("r", encoding="utf-8") as file_obj:
            return json.load(file_obj)
    except OSError as exc:
        raise ReplayError(f"Could not read replay file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReplayError(f"Invalid JSON in replay file {path}: {exc}") from exc


def _extract_event_dicts(payload: Any, path: Path) -> list[JsonDict]:
    """Extract replay event dictionaries from a parsed JSON value.

    Inputs:
        payload: Parsed JSON value from a replay file.
        path: Replay file path for error messages.

    Outputs:
        List of event dictionaries.

    Raises:
        ReplayError: If the replay file shape is unsupported.
    """

    if isinstance(payload, list):
        event_dicts = payload
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        event_dicts = payload["events"]
    elif isinstance(payload, dict):
        # A bare object is one event. Manual test events are written by hand and
        # should not need a one-element list wrapper.
        event_dicts = [payload]
    else:
        raise ReplayError(
            f"Replay file {path} must be an event object, a list of events, "
            "or an object with an 'events' list"
        )

    for event_dict in event_dicts:
        if not isinstance(event_dict, dict):
            raise ReplayError(f"Replay file {path} contains a non-object event")

    return event_dicts


def _fallback_event_id(source: EventSource, index: int, file_path: Path | None) -> str:
    """Build a deterministic fallback replay event ID.

    Inputs:
        source: Parsed event source.
        index: Event index in replay file.
        file_path: Optional replay file path.

    Outputs:
        Deterministic fallback ID string.
    """

    file_stem = file_path.stem if file_path is not None else "manual"
    return f"replay-{source.value}-{file_stem}-{index + 1:04d}"
