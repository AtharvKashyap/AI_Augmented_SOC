

"""SQLite persistence layer for AI_Augmented_SOC.

This module stores the local SOC pipeline state in SQLite. It is intentionally
simple and dependency-free so the MVP can run anywhere Python runs.

The store is responsible for:
    - Creating database tables.
    - Saving Wazuh agent inventory.
    - Saving raw telemetry events.
    - Saving normalized alerts.
    - Saving incident candidates.
    - Saving triage results.
    - Saving routing decisions.
    - Tracking deduplication keys.

Design notes:
    - Important searchable fields get their own columns.
    - Full model payloads are also stored as JSON for auditability.
    - SQLite is enough for the MVP and low-alert SOC environments.
    - Redis or PostgreSQL can be added later without changing the models.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc.models import (
    Alert,
    AnalysisSource,
    AnalystVerdict,
    IncidentCandidate,
    RawEvent,
    ReviewQueueItem,
    RoutingDecision,
    TriageAction,
    TriageResult,
    WazuhAgent,
    utc_now,
)


JsonDict = dict[str, Any]


class StoreError(RuntimeError):
    """Raised when a database operation fails."""


@dataclass(frozen=True, slots=True)
class StoreStats:
    """Basic database record counts for debugging and health checks.

    Attributes:
        wazuh_agents: Number of Wazuh agent records.
        raw_events: Number of raw event records.
        alerts: Number of normalized alert records.
        incident_candidates: Number of incident candidate records.
        triage_results: Number of triage result records.
        routing_decisions: Number of routing decision records.
        dedup_keys: Number of deduplication keys.
    """

    wazuh_agents: int
    raw_events: int
    alerts: int
    incident_candidates: int
    triage_results: int
    routing_decisions: int
    dedup_keys: int


@dataclass(frozen=True, slots=True)
class IngestCursor:
    """Persistent read position for one append-only ingestion source.

    A cursor lets an unattended reader resume where the previous cycle stopped
    instead of re-reading a whole file. The inode and device fields exist so
    log rotation can be detected: when either changes, the file behind the path
    is a different file and the offset is meaningless.

    Attributes:
        source: Logical source name, for example wazuh_alerts_json.
        path: Absolute path of the file being read.
        byte_offset: Byte position just past the last fully consumed record.
        inode: Filesystem inode of the file when the offset was recorded.
        device: Filesystem device ID of the file when the offset was recorded.
        content_fingerprint: Digest of the file's leading bytes, formatted as
            "<length>:<sha256 hex>". Inode and size cannot detect a log that was
            truncated in place and refilled to a similar length, which is what
            copytruncate-style rotation does; comparing the leading bytes can.
            The length is stored with the digest so a file that later grows past
            the sampled window is still recognized as the same file.
        updated_at: Time the cursor was last written, set by the store on load.
    """

    source: str
    path: str
    byte_offset: int
    inode: int | None = None
    device: int | None = None
    content_fingerprint: str | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate cursor fields.

        Inputs:
            None.

        Outputs:
            None.

        Raises:
            StoreError: If the source, path, or byte_offset is invalid.
        """

        if self.source.strip() == "":
            raise StoreError("IngestCursor source is required")
        if self.path.strip() == "":
            raise StoreError("IngestCursor path is required")
        if self.byte_offset < 0:
            raise StoreError("IngestCursor byte_offset cannot be negative")


class SQLiteStore:
    """SQLite-backed persistence layer for the SOC pipeline.

    Args:
        db_path: Path to the SQLite database file.

    Usage:
        store = SQLiteStore("ai_soc.db")
        store.initialize()
        store.upsert_wazuh_agent(agent)
    """

    def __init__(self, db_path: str | Path) -> None:
        """Initialize the store object without opening a long-lived connection.

        Inputs:
            db_path: SQLite database path.

        Outputs:
            None. Connections are opened per operation.
        """

        self.db_path = Path(db_path).expanduser()

    def initialize(self) -> None:
        """Create all database tables and indexes if they do not exist.

        Inputs:
            None.

        Outputs:
            None. Tables and indexes are created in SQLite.
        """

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            self._apply_column_migrations(conn)
            conn.executescript(_SCHEMA_SQL)

    def _apply_column_migrations(self, conn: sqlite3.Connection) -> None:
        """Add columns that are missing from an already-created database.

        `CREATE TABLE IF NOT EXISTS` silently leaves older databases on their
        original schema, so columns added after a database was first created
        must be applied explicitly. Adding a nullable column is cheap and safe
        to run on every initialize.

        This runs before the schema script so that indexes defined on newly
        added columns can be created in the same pass. Tables that do not exist
        yet are skipped; the schema script creates those complete.

        Inputs:
            conn: Open SQLite connection.

        Outputs:
            None. Missing columns are added in place.
        """

        for table, columns in _ADDED_COLUMNS.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if not existing:
                continue
            for column, column_type in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")

    def upsert_wazuh_agent(self, agent: WazuhAgent) -> None:
        """Insert or update a Wazuh agent inventory record.

        Inputs:
            agent: WazuhAgent model from Wazuh inventory.

        Outputs:
            None. Agent record is persisted.
        """

        payload = _to_json(agent.to_dict())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO wazuh_agents (
                    agent_id, hostname, ip, os_name, os_version, status,
                    groups_json, labels_json, last_seen, raw_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    ip = excluded.ip,
                    os_name = excluded.os_name,
                    os_version = excluded.os_version,
                    status = excluded.status,
                    groups_json = excluded.groups_json,
                    labels_json = excluded.labels_json,
                    last_seen = excluded.last_seen,
                    raw_json = excluded.raw_json,
                    updated_at = excluded.updated_at
                """,
                (
                    agent.agent_id,
                    agent.hostname,
                    agent.ip,
                    agent.os_name,
                    agent.os_version,
                    agent.status,
                    _to_json(agent.groups),
                    _to_json(agent.labels),
                    _dt_to_text(agent.last_seen),
                    payload,
                    _dt_to_text(utc_now()),
                ),
            )

    def upsert_wazuh_agents(self, agents: Iterable[WazuhAgent]) -> None:
        """Insert or update multiple Wazuh agent records.

        Inputs:
            agents: Iterable of WazuhAgent models.

        Outputs:
            None. All records are persisted in individual upserts.
        """

        for agent in agents:
            self.upsert_wazuh_agent(agent)

    def get_wazuh_agent(self, agent_id: str) -> WazuhAgent | None:
        """Fetch a Wazuh agent by ID.

        Inputs:
            agent_id: Wazuh agent ID.

        Outputs:
            WazuhAgent if found, otherwise None.
        """

        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_json FROM wazuh_agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()

        if row is None:
            return None
        return _wazuh_agent_from_dict(_from_json(row["raw_json"]))

    def save_raw_event(self, event: RawEvent) -> None:
        """Persist a raw source event before normalization.

        Inputs:
            event: RawEvent collected from Wazuh, Security Onion, or replay.

        Outputs:
            None. Raw event is inserted or replaced.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO raw_events (
                    id, source, event_timestamp, received_at, payload_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.source.value,
                    _dt_to_text(event.timestamp),
                    _dt_to_text(event.received_at),
                    _to_json(event.payload),
                ),
            )

    def save_alert(self, alert: Alert) -> None:
        """Persist a normalized alert.

        Inputs:
            alert: Alert produced by the normalizer.

        Outputs:
            None. Alert is inserted or replaced.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    id, source, event_timestamp, severity, source_severity,
                    rule_name, src_ip, dst_ip, hostname, agent_id, user,
                    process_name, command_line, raw_event_id, payload_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.source.value,
                    _dt_to_text(alert.timestamp),
                    alert.severity.value,
                    str(alert.source_severity) if alert.source_severity is not None else None,
                    alert.rule_name,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.hostname,
                    alert.agent_id,
                    alert.user,
                    alert.process_name,
                    alert.command_line,
                    alert.raw_event_id,
                    _to_json(alert.to_dict()),
                    _dt_to_text(utc_now()),
                ),
            )

    def save_alerts(self, alerts: Iterable[Alert]) -> None:
        """Persist multiple normalized alerts.

        Inputs:
            alerts: Iterable of Alert models.

        Outputs:
            None. Alerts are inserted or replaced.
        """

        for alert in alerts:
            self.save_alert(alert)

    def get_alert(self, alert_id: str) -> JsonDict | None:
        """Fetch a normalized alert payload by ID.

        Inputs:
            alert_id: Normalized alert ID.

        Outputs:
            Alert payload dictionary if found, otherwise None.
        """

        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()

        if row is None:
            return None
        return _from_json(row["payload_json"])

    def list_recent_alerts(self, limit: int = 100) -> list[JsonDict]:
        """Return recent normalized alerts as dictionaries.

        Inputs:
            limit: Maximum number of alerts to return.

        Outputs:
            List of alert payload dictionaries, newest first.
        """

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_json
                FROM alerts
                ORDER BY COALESCE(event_timestamp, created_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [_from_json(row["payload_json"]) for row in rows]

    def save_incident_candidate(self, candidate: IncidentCandidate) -> None:
        """Persist an incident candidate and its alert relationships.

        Inputs:
            candidate: IncidentCandidate produced by clustering.

        Outputs:
            None. Candidate and candidate-alert links are persisted.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incident_candidates (
                    id, first_seen, last_seen, primary_host, primary_user,
                    src_ips_json, dst_ips_json, payload_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.id,
                    _dt_to_text(candidate.first_seen),
                    _dt_to_text(candidate.last_seen),
                    candidate.primary_host,
                    candidate.primary_user,
                    _to_json(candidate.src_ips),
                    _to_json(candidate.dst_ips),
                    _to_json(candidate.to_dict()),
                    _dt_to_text(candidate.created_at),
                ),
            )
            conn.execute(
                "DELETE FROM candidate_alerts WHERE candidate_id = ?",
                (candidate.id,),
            )
            conn.executemany(
                """
                INSERT OR IGNORE INTO candidate_alerts (candidate_id, alert_id)
                VALUES (?, ?)
                """,
                [(candidate.id, alert.id) for alert in candidate.alerts],
            )

    def get_incident_candidate(self, candidate_id: str) -> JsonDict | None:
        """Fetch an incident candidate payload by ID.

        Inputs:
            candidate_id: Incident candidate ID.

        Outputs:
            Candidate payload dictionary if found, otherwise None.
        """

        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM incident_candidates WHERE id = ?",
                (candidate_id,),
            ).fetchone()

        if row is None:
            return None
        return _from_json(row["payload_json"])

    def save_triage_result(self, result: TriageResult) -> None:
        """Persist an AI triage result.

        Inputs:
            result: TriageResult from the triage engine.

        Outputs:
            None. Triage result is inserted or replaced.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO triage_results (
                    id, target_id, target_type, score, fp_likelihood,
                    classification, action, summary, model, latency_ms,
                    analysis_source, prompt_version, payload_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.id,
                    result.target_id,
                    result.target_type,
                    result.score,
                    result.fp_likelihood.value,
                    result.classification,
                    result.action.value,
                    result.summary,
                    result.model,
                    result.latency_ms,
                    result.analysis_source.value,
                    result.prompt_version,
                    _to_json(result.to_dict()),
                    _dt_to_text(result.created_at),
                ),
            )

    def save_routing_decision(self, decision: RoutingDecision) -> None:
        """Persist a routing decision.

        Inputs:
            decision: RoutingDecision created by the router.

        Outputs:
            None. Routing decision is inserted or replaced.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO routing_decisions (
                    id, triage_result_id, target_id, action, status,
                    destination, message, error, payload_json, created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.id,
                    decision.triage_result_id,
                    decision.target_id,
                    decision.action.value,
                    decision.status.value,
                    decision.destination,
                    decision.message,
                    decision.error,
                    _to_json(decision.to_dict()),
                    _dt_to_text(decision.created_at),
                    _dt_to_text(decision.updated_at),
                ),
            )

    def get_triage_result(self, triage_result_id: str) -> JsonDict | None:
        """Fetch one stored triage result as its full serialized payload.

        Reviewing a queued decision needs the summary, IOCs, evidence and
        recommended actions, not just the score, so this returns the stored
        payload rather than the indexed columns.

        Inputs:
            triage_result_id: Triage result ID.

        Outputs:
            Triage result dictionary, or None when not stored.
        """

        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM triage_results WHERE id = ?",
                (triage_result_id,),
            ).fetchone()

        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        return payload if isinstance(payload, dict) else None

    def enqueue_for_review(self, result: TriageResult) -> None:
        """Add a triage result to the analyst review queue.

        Keyed on the triage result ID, which is itself a deterministic content
        fingerprint, so re-running the pipeline over the same input updates the
        existing row instead of queueing duplicate work. An already-reviewed item
        keeps its verdict.

        Inputs:
            result: TriageResult routed for analyst review.

        Outputs:
            None. The item is queued if it was not already present.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO analyst_queue (
                    triage_result_id, target_id, target_type, score, action,
                    analysis_source, queued_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(triage_result_id) DO NOTHING
                """,
                (
                    result.id,
                    result.target_id,
                    result.target_type,
                    result.score,
                    result.action.value,
                    result.analysis_source.value,
                    _dt_to_text(utc_now()),
                ),
            )

    def list_open_queue_items(self, limit: int | None = None) -> list[ReviewQueueItem]:
        """Return queue items still awaiting an analyst verdict, oldest first.

        Inputs:
            limit: Optional maximum number of items to return.

        Outputs:
            List of open ReviewQueueItem objects.
        """

        sql = """
            SELECT * FROM analyst_queue
            WHERE reviewed_at IS NULL
            ORDER BY queued_at ASC, triage_result_id ASC
        """
        params: tuple[Any, ...] = ()
        if limit is not None:
            sql += " LIMIT ?"
            params = (limit,)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_queue_item_from_row(row) for row in rows]

    def list_reviewed_queue_items(self, limit: int | None = None) -> list[ReviewQueueItem]:
        """Return queue items an analyst has judged, most recent first.

        These verdicts are the ground truth an evaluation set is built from.

        Inputs:
            limit: Optional maximum number of items to return.

        Outputs:
            List of reviewed ReviewQueueItem objects.
        """

        sql = """
            SELECT * FROM analyst_queue
            WHERE reviewed_at IS NOT NULL
            ORDER BY reviewed_at DESC, triage_result_id ASC
        """
        params: tuple[Any, ...] = ()
        if limit is not None:
            sql += " LIMIT ?"
            params = (limit,)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_queue_item_from_row(row) for row in rows]

    def get_queue_item(self, triage_result_id: str) -> ReviewQueueItem | None:
        """Return one queue item by triage result ID.

        Inputs:
            triage_result_id: Triage result identifying the queue item.

        Outputs:
            ReviewQueueItem, or None when not queued.
        """

        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM analyst_queue WHERE triage_result_id = ?",
                (triage_result_id,),
            ).fetchone()
        return None if row is None else _queue_item_from_row(row)

    def record_analyst_verdict(
        self,
        triage_result_id: str,
        *,
        verdict: AnalystVerdict,
        analyst_score: int | None = None,
        notes: str | None = None,
    ) -> None:
        """Record an analyst's judgment and close the queue item.

        Inputs:
            triage_result_id: Queue item to close.
            verdict: The analyst's judgment.
            analyst_score: Optional score the analyst would have given, 1-10.
            notes: Optional free-text notes.

        Outputs:
            None. The item is marked reviewed.

        Raises:
            StoreError: If the item is not queued or the score is out of range.
        """

        if analyst_score is not None and not 1 <= analyst_score <= 10:
            raise StoreError("analyst_score must be between 1 and 10")

        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE analyst_queue
                SET reviewed_at = ?, analyst_verdict = ?, analyst_score = ?, notes = ?
                WHERE triage_result_id = ?
                """,
                (
                    _dt_to_text(utc_now()),
                    verdict.value,
                    analyst_score,
                    notes,
                    triage_result_id,
                ),
            )
            if cursor.rowcount == 0:
                raise StoreError(f"{triage_result_id} is not in the review queue")

    def has_dedup_key(self, key: str) -> bool:
        """Check whether a deduplication key already exists and is unexpired.

        Inputs:
            key: Deduplication key, usually based on source and alert ID.

        Outputs:
            True if key exists and is not expired, otherwise False.
        """

        now_text = _dt_to_text(utc_now())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM dedup_keys
                WHERE key = ? AND expires_at > ?
                """,
                (key, now_text),
            ).fetchone()

        return row is not None

    def add_dedup_key(self, key: str, ttl_hours: int = 24) -> None:
        """Store or refresh a deduplication key.

        Inputs:
            key: Deduplication key.
            ttl_hours: Number of hours until the key expires.

        Outputs:
            None. Key is persisted.
        """

        now = utc_now()
        expires_at = now + timedelta(hours=ttl_hours)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dedup_keys (key, created_at, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    expires_at = excluded.expires_at
                """,
                (key, _dt_to_text(now), _dt_to_text(expires_at)),
            )

    def delete_expired_dedup_keys(self) -> int:
        """Delete expired deduplication keys.

        Inputs:
            None.

        Outputs:
            Number of deleted keys.
        """

        now_text = _dt_to_text(utc_now())
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM dedup_keys WHERE expires_at <= ?",
                (now_text,),
            )
            return cursor.rowcount

    def get_ingest_cursor(self, source: str, path: str) -> IngestCursor | None:
        """Fetch the stored read position for one ingestion source and path.

        Inputs:
            source: Logical source name, for example wazuh_alerts_json.
            path: Absolute path of the file being read.

        Outputs:
            IngestCursor if a cursor was stored, otherwise None.
        """

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT source, path, byte_offset, inode, device,
                       content_fingerprint, updated_at
                FROM ingest_cursors
                WHERE source = ? AND path = ?
                """,
                (source, path),
            ).fetchone()

        if row is None:
            return None

        return IngestCursor(
            source=row["source"],
            path=row["path"],
            byte_offset=int(row["byte_offset"]),
            inode=None if row["inode"] is None else int(row["inode"]),
            device=None if row["device"] is None else int(row["device"]),
            content_fingerprint=row["content_fingerprint"],
            updated_at=_text_to_dt(row["updated_at"]),
        )

    def upsert_ingest_cursor(self, cursor: IngestCursor) -> None:
        """Insert or update the read position for one ingestion source and path.

        Inputs:
            cursor: IngestCursor describing the new read position.

        Outputs:
            None. The cursor is persisted, keyed by source and path.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ingest_cursors (
                    source, path, byte_offset, inode, device,
                    content_fingerprint, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, path) DO UPDATE SET
                    byte_offset = excluded.byte_offset,
                    inode = excluded.inode,
                    device = excluded.device,
                    content_fingerprint = excluded.content_fingerprint,
                    updated_at = excluded.updated_at
                """,
                (
                    cursor.source,
                    cursor.path,
                    cursor.byte_offset,
                    cursor.inode,
                    cursor.device,
                    cursor.content_fingerprint,
                    _dt_to_text(cursor.updated_at or utc_now()),
                ),
            )

    def stats(self) -> StoreStats:
        """Return basic row counts for core tables.

        Inputs:
            None.

        Outputs:
            StoreStats object with table counts.
        """

        with self._connect() as conn:
            return StoreStats(
                wazuh_agents=_count_rows(conn, "wazuh_agents"),
                raw_events=_count_rows(conn, "raw_events"),
                alerts=_count_rows(conn, "alerts"),
                incident_candidates=_count_rows(conn, "incident_candidates"),
                triage_results=_count_rows(conn, "triage_results"),
                routing_decisions=_count_rows(conn, "routing_decisions"),
                dedup_keys=_count_rows(conn, "dedup_keys"),
            )

    @contextmanager
    def _connect(self) -> Iterable[sqlite3.Connection]:
        """Open a SQLite connection with project defaults.

        Inputs:
            None.

        Outputs:
            Context manager yielding a sqlite3.Connection.

        Raises:
            StoreError: If SQLite reports an error.
        """

        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            if conn is not None:
                conn.rollback()
            raise StoreError(str(exc)) from exc
        finally:
            if conn is not None:
                conn.close()


_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "ingest_cursors": {
        "content_fingerprint": "TEXT",
    },
    "triage_results": {
        "latency_ms": "INTEGER",
        "analysis_source": "TEXT",
        "prompt_version": "TEXT",
    },
}


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS wazuh_agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    os_name TEXT,
    os_version TEXT,
    status TEXT,
    groups_json TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    last_seen TEXT,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wazuh_agents_hostname
    ON wazuh_agents(hostname);

CREATE INDEX IF NOT EXISTS idx_wazuh_agents_ip
    ON wazuh_agents(ip);

CREATE TABLE IF NOT EXISTS raw_events (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_timestamp TEXT,
    received_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_events_source_time
    ON raw_events(source, event_timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_timestamp TEXT,
    severity TEXT NOT NULL,
    source_severity TEXT,
    rule_name TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    hostname TEXT,
    agent_id TEXT,
    user TEXT,
    process_name TEXT,
    command_line TEXT,
    raw_event_id TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(raw_event_id) REFERENCES raw_events(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_source_time
    ON alerts(source, event_timestamp);

CREATE INDEX IF NOT EXISTS idx_alerts_hostname
    ON alerts(hostname);

CREATE INDEX IF NOT EXISTS idx_alerts_agent_id
    ON alerts(agent_id);

CREATE INDEX IF NOT EXISTS idx_alerts_src_ip
    ON alerts(src_ip);

CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip
    ON alerts(dst_ip);

CREATE TABLE IF NOT EXISTS incident_candidates (
    id TEXT PRIMARY KEY,
    first_seen TEXT,
    last_seen TEXT,
    primary_host TEXT,
    primary_user TEXT,
    src_ips_json TEXT NOT NULL,
    dst_ips_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incident_candidates_time
    ON incident_candidates(first_seen, last_seen);

CREATE INDEX IF NOT EXISTS idx_incident_candidates_host
    ON incident_candidates(primary_host);

CREATE TABLE IF NOT EXISTS candidate_alerts (
    candidate_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    PRIMARY KEY(candidate_id, alert_id),
    FOREIGN KEY(candidate_id) REFERENCES incident_candidates(id) ON DELETE CASCADE,
    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS triage_results (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    fp_likelihood TEXT NOT NULL,
    classification TEXT NOT NULL,
    action TEXT NOT NULL,
    summary TEXT NOT NULL,
    model TEXT,
    latency_ms INTEGER,
    analysis_source TEXT,
    prompt_version TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_triage_results_analysis_source
    ON triage_results(analysis_source);

CREATE INDEX IF NOT EXISTS idx_triage_results_target
    ON triage_results(target_id, target_type);

CREATE INDEX IF NOT EXISTS idx_triage_results_score
    ON triage_results(score);

CREATE TABLE IF NOT EXISTS routing_decisions (
    id TEXT PRIMARY KEY,
    triage_result_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    destination TEXT,
    message TEXT,
    error TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(triage_result_id) REFERENCES triage_results(id)
);

CREATE INDEX IF NOT EXISTS idx_routing_decisions_target
    ON routing_decisions(target_id);

CREATE INDEX IF NOT EXISTS idx_routing_decisions_status
    ON routing_decisions(status);

CREATE TABLE IF NOT EXISTS dedup_keys (
    key TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dedup_keys_expires_at
    ON dedup_keys(expires_at);

CREATE TABLE IF NOT EXISTS analyst_queue (
    triage_result_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    action TEXT NOT NULL,
    analysis_source TEXT,
    queued_at TEXT NOT NULL,
    reviewed_at TEXT,
    analyst_verdict TEXT,
    analyst_score INTEGER,
    notes TEXT,
    FOREIGN KEY(triage_result_id) REFERENCES triage_results(id)
);

CREATE INDEX IF NOT EXISTS idx_analyst_queue_open
    ON analyst_queue(reviewed_at, queued_at);

CREATE TABLE IF NOT EXISTS ingest_cursors (
    source TEXT NOT NULL,
    path TEXT NOT NULL,
    byte_offset INTEGER NOT NULL,
    inode INTEGER,
    device INTEGER,
    content_fingerprint TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source, path)
);
"""


def _queue_item_from_row(row: Any) -> ReviewQueueItem:
    """Build a ReviewQueueItem from a database row.

    Inputs:
        row: SQLite row from the analyst_queue table.

    Outputs:
        ReviewQueueItem instance.
    """

    verdict = row["analyst_verdict"]
    source = row["analysis_source"]
    return ReviewQueueItem(
        triage_result_id=row["triage_result_id"],
        target_id=row["target_id"],
        target_type=row["target_type"],
        score=int(row["score"]),
        action=TriageAction(row["action"]),
        analysis_source=AnalysisSource(source) if source else AnalysisSource.LOCAL,
        queued_at=_text_to_dt(row["queued_at"]) or utc_now(),
        reviewed_at=_text_to_dt(row["reviewed_at"]),
        analyst_verdict=AnalystVerdict(verdict) if verdict else None,
        analyst_score=None if row["analyst_score"] is None else int(row["analyst_score"]),
        notes=row["notes"],
    )


def _to_json(value: Any) -> str:
    """Serialize a Python value into stable JSON text.

    Inputs:
        value: JSON-compatible Python value.

    Outputs:
        JSON string.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _from_json(value: str) -> JsonDict:
    """Deserialize JSON text into a dictionary.

    Inputs:
        value: JSON string.

    Outputs:
        Parsed dictionary.
    """

    loaded = json.loads(value)
    if not isinstance(loaded, dict):
        raise StoreError("Expected JSON object from database")
    return loaded


def _dt_to_text(value: datetime | None) -> str | None:
    """Convert a datetime to ISO-8601 text.

    Inputs:
        value: Datetime or None.

    Outputs:
        ISO-8601 string or None.
    """

    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _text_to_dt(value: str | None) -> datetime | None:
    """Convert ISO-8601 text from the database into a datetime.

    Inputs:
        value: ISO-8601 string or None.

    Outputs:
        Timezone-aware UTC datetime, or None when the value is missing or
        unparseable.
    """

    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _count_rows(conn: sqlite3.Connection, table: str) -> int:
    """Count rows in a table.

    Inputs:
        conn: Active SQLite connection.
        table: Table name. Must be an internal constant, not user input.

    Outputs:
        Number of rows in the table.
    """

    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"])


def _wazuh_agent_from_dict(payload: JsonDict) -> WazuhAgent:
    """Rebuild a WazuhAgent from its serialized dictionary.

    Inputs:
        payload: Dictionary previously produced by WazuhAgent.to_dict().

    Outputs:
        WazuhAgent instance.
    """

    last_seen = payload.get("last_seen")
    return WazuhAgent(
        agent_id=str(payload["agent_id"]),
        hostname=payload.get("hostname"),
        ip=payload.get("ip"),
        os_name=payload.get("os_name"),
        os_version=payload.get("os_version"),
        status=payload.get("status"),
        groups=list(payload.get("groups", [])),
        labels=dict(payload.get("labels", {})),
        last_seen=datetime.fromisoformat(last_seen) if last_seen else None,
        raw=dict(payload.get("raw", {})),
    )