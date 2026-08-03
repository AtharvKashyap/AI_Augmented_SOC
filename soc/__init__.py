"""AI_Augmented_SOC package.

This package contains the core components for an AI-assisted SOC triage
pipeline built around Wazuh, Security Onion, SQLite, replay fixtures, and
OpenRouter-based analysis.

The package exports the stable foundation objects that other modules and run
scripts are expected to use directly.
"""

from __future__ import annotations

from soc.config import ConfigError, Settings, get_settings
from soc.dedup import DeduplicationError, DeduplicationService
from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    EnrichmentResult,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    IncidentCandidate,
    IncidentReport,
    RawEvent,
    RoutingDecision,
    RoutingStatus,
    TriageAction,
    TriageResult,
    WazuhAgent,
    utc_now,
)
from soc.normalizer import NormalizationError, Normalizer
from soc.replay import ReplayError, ReplayLoadResult, load_replay_directory, load_replay_file
from soc.store import IngestCursor, SQLiteStore, StoreError, StoreStats


__version__ = "0.1.0"

__all__ = [
    "Alert",
    "AlertSeverity",
    "AnalysisSource",
    "ConfigError",
    "DeduplicationError",
    "DeduplicationService",
    "EnrichmentResult",
    "EventSource",
    "EvidenceItem",
    "FalsePositiveLikelihood",
    "IncidentCandidate",
    "IncidentReport",
    "IngestCursor",
    "NormalizationError",
    "Normalizer",
    "RawEvent",
    "ReplayError",
    "ReplayLoadResult",
    "RoutingDecision",
    "RoutingStatus",
    "SQLiteStore",
    "Settings",
    "StoreError",
    "StoreStats",
    "TriageAction",
    "TriageResult",
    "WazuhAgent",
    "__version__",
    "get_settings",
    "load_replay_directory",
    "load_replay_file",
    "utc_now",
]
