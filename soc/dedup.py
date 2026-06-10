

"""Deduplication helpers for AI_Augmented_SOC.

This module prevents the pipeline from processing the same event or alert more
than once during repeated polling cycles.

The dedup layer is intentionally thin:
    - It builds stable deduplication keys.
    - It checks whether a key has already been seen.
    - It marks keys as seen using the SQLite store.

The database table itself lives in `soc.store.SQLiteStore`. This file exists so
higher-level code does not need to know how dedup keys are stored.

Typical usage:
    dedup = DeduplicationService(store, ttl_hours=24)

    if dedup.has_seen_alert("wazuh", "12345"):
        return

    process_alert(...)
    dedup.mark_alert_seen("wazuh", "12345")
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from soc.models import Alert, EventSource, RawEvent
from soc.store import SQLiteStore


class DeduplicationError(ValueError):
    """Raised when a deduplication key cannot be created or used."""


@dataclass(frozen=True, slots=True)
class DeduplicationService:
    """Service for checking and recording processed events.

    Args:
        store: SQLiteStore instance used to persist dedup keys.
        ttl_hours: Number of hours a dedup key remains valid.
    """

    store: SQLiteStore
    ttl_hours: int = 24

    def has_seen_key(self, key: str) -> bool:
        """Return whether a raw deduplication key has already been seen.

        Inputs:
            key: Stable deduplication key.

        Outputs:
            True if the key exists and has not expired, otherwise False.

        Raises:
            DeduplicationError: If the key is empty.
        """

        key = _normalize_key_part(key)
        return self.store.has_dedup_key(key)

    def mark_key_seen(self, key: str) -> None:
        """Persist a raw deduplication key as seen.

        Inputs:
            key: Stable deduplication key.

        Outputs:
            None. Key is stored in the database.

        Raises:
            DeduplicationError: If the key is empty.
        """

        key = _normalize_key_part(key)
        self.store.add_dedup_key(key, ttl_hours=self.ttl_hours)

    def has_seen_raw_event(self, event: RawEvent) -> bool:
        """Return whether a RawEvent has already been processed.

        Inputs:
            event: RawEvent instance.

        Outputs:
            True if the event has already been seen, otherwise False.
        """

        return self.has_seen_key(build_raw_event_key(event))

    def mark_raw_event_seen(self, event: RawEvent) -> None:
        """Mark a RawEvent as processed.

        Inputs:
            event: RawEvent instance.

        Outputs:
            None. Dedup key is stored in the database.
        """

        self.mark_key_seen(build_raw_event_key(event))

    def has_seen_alert(self, alert: Alert) -> bool:
        """Return whether an Alert has already been processed.

        Inputs:
            alert: Alert instance.

        Outputs:
            True if the alert has already been seen, otherwise False.
        """

        return self.has_seen_key(build_alert_key(alert))

    def mark_alert_seen(self, alert: Alert) -> None:
        """Mark an Alert as processed.

        Inputs:
            alert: Alert instance.

        Outputs:
            None. Dedup key is stored in the database.
        """

        self.mark_key_seen(build_alert_key(alert))

    def has_seen_source_id(self, source: EventSource | str, source_id: str) -> bool:
        """Return whether a source/id pair has already been processed.

        Inputs:
            source: Event source name or EventSource enum.
            source_id: Source-specific event or alert identifier.

        Outputs:
            True if the source/id pair has already been seen, otherwise False.
        """

        return self.has_seen_key(build_source_id_key(source, source_id))

    def mark_source_id_seen(self, source: EventSource | str, source_id: str) -> None:
        """Mark a source/id pair as processed.

        Inputs:
            source: Event source name or EventSource enum.
            source_id: Source-specific event or alert identifier.

        Outputs:
            None. Dedup key is stored in the database.
        """

        self.mark_key_seen(build_source_id_key(source, source_id))

    def cleanup_expired(self) -> int:
        """Delete expired dedup keys from the store.

        Inputs:
            None.

        Outputs:
            Number of expired keys deleted.
        """

        return self.store.delete_expired_dedup_keys()


def build_raw_event_key(event: RawEvent) -> str:
    """Build a stable dedup key for a RawEvent.

    Inputs:
        event: RawEvent instance.

    Outputs:
        Deduplication key in the form `raw:<source>:<id>`.
    """

    return build_source_id_key(f"raw:{event.source.value}", event.id)


def build_alert_key(alert: Alert) -> str:
    """Build a stable dedup key for an Alert.

    Inputs:
        alert: Alert instance.

    Outputs:
        Deduplication key in the form `alert:<source>:<id>`.
    """

    return build_source_id_key(f"alert:{alert.source.value}", alert.id)


def build_source_id_key(source: EventSource | str, source_id: str) -> str:
    """Build a stable dedup key from a source and source-specific ID.

    Inputs:
        source: Event source enum or string.
        source_id: Source-specific event or alert ID.

    Outputs:
        Deduplication key in the form `<source>:<source_id>`.

    Raises:
        DeduplicationError: If source or source_id is empty.
    """

    source_text = source.value if isinstance(source, EventSource) else str(source)
    source_text = _normalize_key_part(source_text)
    source_id_text = _normalize_key_part(source_id)
    return f"{source_text}:{source_id_text}"


def build_payload_fingerprint_key(source: EventSource | str, payload: Any) -> str:
    """Build a dedup key from a payload when no source ID is available.

    This should be a fallback only. Prefer source-provided alert/event IDs when
    possible because they are easier to audit.

    Inputs:
        source: Event source enum or string.
        payload: Any payload that can be represented as a string.

    Outputs:
        Deduplication key containing a SHA-256 fingerprint.
    """

    source_text = source.value if isinstance(source, EventSource) else str(source)
    source_text = _normalize_key_part(source_text)
    fingerprint = hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()
    return f"fingerprint:{source_text}:{fingerprint}"


def _normalize_key_part(value: str) -> str:
    """Normalize one part of a deduplication key.

    Inputs:
        value: Raw key part.

    Outputs:
        Trimmed key part.

    Raises:
        DeduplicationError: If the value is empty after trimming.
    """

    normalized = str(value).strip()
    if normalized == "":
        raise DeduplicationError("Deduplication key parts cannot be empty")
    return normalized