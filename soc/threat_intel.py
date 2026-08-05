

"""Threat-intelligence provider layer.

External reputation lookups sit behind this interface rather than being mixed
into the pipeline, so a provider can be added, removed, rate limited, or fail
without any other stage noticing.

Four rules shape this module, and each exists for a reason:

    - **Internal addresses are never sent upstream.** Querying 10.0.1.50 at a
      third party discloses internal addressing, returns nothing useful, and
      burns free-tier quota. Non-global addresses are dropped before any call.
    - **A provider failure is contained.** A rate-limited or broken provider is
      logged and skipped so the rest of enrichment, and the run, survive. Losing
      one reputation lookup is not worth losing the alert.
    - **Answers are cached with a TTL.** Free tiers are measured in requests per
      minute, and the same indicator recurs constantly. Failures are deliberately
      not cached, since caching one would suppress retries for the whole TTL.
    - **The verdict must live in the summary.** `soc.triage` deliberately
      withholds enrichment `raw` payloads from the model, so a verdict recorded
      only in the details would never reach triage at all.

Providers implement `ThreatIntelProvider`. `IntelLookup` and `IntelVerdict` stay
local to this layer on purpose: what gets persisted and passed onward is still
the shared `EnrichmentResult` contract from `soc.models`.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from soc.enrichment import extract_alert_indicators, extract_candidate_indicators
from soc.models import Alert, EnrichmentResult, IncidentCandidate, utc_now

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

IP_INDICATOR_TYPE = "ip"

DEFAULT_CACHE_TTL_HOURS = 24


class ThreatIntelError(RuntimeError):
    """Raised when a threat-intel lookup or its input is invalid."""


class IntelVerdict(str, Enum):
    """A provider's judgment about one indicator.

    Values:
        MALICIOUS: The provider asserts this indicator is bad.
        SUSPICIOUS: Some signal, not enough to call it malicious.
        BENIGN: The provider has data and considers it clean.
        UNKNOWN: The provider has nothing useful to say.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


_ESCALATING_VERDICTS = {IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS}

_SEVERITY_HINTS = {
    IntelVerdict.MALICIOUS: "high",
    IntelVerdict.SUSPICIOUS: "medium",
    IntelVerdict.BENIGN: "info",
    IntelVerdict.UNKNOWN: "info",
}


@dataclass(frozen=True, slots=True)
class IntelLookup:
    """One provider's answer about one indicator.

    Attributes:
        provider: Provider name, for example virustotal.
        indicator_type: Indicator type, for example ip or domain.
        indicator: Indicator value.
        verdict: The provider's judgment.
        summary: Human-readable one-liner. This is the field that reaches the
            model, so it must carry the verdict rather than burying it in details.
        risk_factors: Short machine-readable factors that justify the verdict.
            Only present for escalating verdicts, since a clean result is
            information rather than evidence of compromise.
        details: Provider-specific payload, kept for auditability and cached, but
            withheld from the model by the triage context allowlist.
    """

    provider: str
    indicator_type: str
    indicator: str
    verdict: IntelVerdict
    summary: str
    risk_factors: tuple[str, ...] = ()
    details: JsonDict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the lookup.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            ThreatIntelError: If the provider or indicator is missing.
        """

        if not self.provider.strip():
            raise ThreatIntelError("IntelLookup provider is required")
        if not self.indicator.strip():
            raise ThreatIntelError("IntelLookup indicator is required")
        if not self.indicator_type.strip():
            raise ThreatIntelError("IntelLookup indicator_type is required")

    @property
    def is_escalating(self) -> bool:
        """Return whether this verdict should raise a triage score."""

        return self.verdict in _ESCALATING_VERDICTS

    @property
    def severity_hint(self) -> str:
        """Return the severity hint local scoring reads."""

        return _SEVERITY_HINTS[self.verdict]

    def to_payload(self) -> JsonDict:
        """Serialize into a cacheable JSON-safe payload.

        Inputs:
            None.

        Outputs:
            Payload dictionary.
        """

        return {
            "provider": self.provider,
            "indicator_type": self.indicator_type,
            "indicator": self.indicator,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "risk_factors": list(self.risk_factors),
            "details": dict(self.details),
        }

    @classmethod
    def from_payload(cls, payload: JsonDict) -> IntelLookup:
        """Rebuild a lookup from a cached payload.

        Inputs:
            payload: Payload previously produced by to_payload.

        Outputs:
            IntelLookup instance.

        Raises:
            ThreatIntelError: If the payload cannot be interpreted.
        """

        try:
            verdict = IntelVerdict(str(payload.get("verdict", "unknown")))
        except ValueError as exc:
            raise ThreatIntelError(f"Unknown cached verdict: {exc}") from exc

        risk_factors = payload.get("risk_factors") or []
        details = payload.get("details") or {}
        return cls(
            provider=str(payload.get("provider", "")),
            indicator_type=str(payload.get("indicator_type", "")),
            indicator=str(payload.get("indicator", "")),
            verdict=verdict,
            summary=str(payload.get("summary", "")),
            risk_factors=tuple(str(item) for item in risk_factors),
            details=dict(details) if isinstance(details, dict) else {},
        )

    def to_enrichment_result(self, *, target_id: str | None = None) -> EnrichmentResult:
        """Convert into the shared EnrichmentResult contract.

        `raw` carries the risk factors and severity hint that local scoring
        reads, alongside the provider details for auditability.

        Inputs:
            target_id: Optional alert or candidate ID that produced the indicator.

        Outputs:
            EnrichmentResult instance.
        """

        now = utc_now()
        # Risk factors are dropped for non-escalating verdicts rather than
        # trusted to be absent. Local scoring boosts on any risk factor, so a
        # provider that reported one alongside a clean verdict would silently
        # inflate scores. Enforcing the invariant here means no provider has to
        # remember it.
        risk_factors = list(self.risk_factors) if self.is_escalating else []
        return EnrichmentResult(
            indicator=self.indicator,
            indicator_type=self.indicator_type,
            provider=self.provider,
            summary=self.summary,
            raw={
                "provider": self.provider,
                "verdict": self.verdict.value,
                "risk_factors": risk_factors,
                "severity_hint": self.severity_hint,
                "target_id": target_id,
                "details": dict(self.details),
                "looked_up_at": now.isoformat(),
            },
            looked_up_at=now,
        )


class ThreatIntelProvider(Protocol):
    """Contract every reputation provider implements.

    Attributes:
        name: Short provider name used for caching and attribution.
        supported_indicator_types: Indicator types this provider can answer.
        min_seconds_between_calls: Minimum spacing between calls, so free-tier
            request limits are respected. Zero means no limit.
    """

    name: str
    supported_indicator_types: tuple[str, ...]
    min_seconds_between_calls: float

    def lookup(self, indicator_type: str, indicator: str) -> IntelLookup:
        """Return this provider's verdict for one indicator."""


class ThreatIntelEnricher:
    """Run reputation providers over indicators, with caching and rate limits."""

    def __init__(
        self,
        providers: Sequence[ThreatIntelProvider] = (),
        *,
        cache: Any | None = None,
        ttl_hours: int = DEFAULT_CACHE_TTL_HOURS,
        sleep: Callable[[float], None] | None = None,
        monotonic: Callable[[], float] | None = None,
        skip_non_global_ips: bool = True,
    ) -> None:
        """Initialize the enricher.

        Inputs:
            providers: Providers to query, in order.
            cache: Optional store exposing get_cached_enrichment and
                put_cached_enrichment. Without one, every lookup is live.
            ttl_hours: How long cached answers stay valid.
            sleep: Optional sleep callable for rate limiting. Defaults to
                time.sleep; tests inject a recorder so no real time passes.
            monotonic: Optional monotonic clock, for the same reason.
            skip_non_global_ips: Whether to withhold non-public addresses from
                providers. Leave enabled outside tests.

        Outputs:
            None.
        """

        self.providers = list(providers)
        self.cache = cache
        self.ttl_hours = ttl_hours
        self.skip_non_global_ips = skip_non_global_ips
        self._sleep = sleep or time.sleep
        self._monotonic = monotonic or time.monotonic
        self._last_call_at: dict[str, float] = {}

    def enrich_alert(self, alert: Alert, *, include_local: bool = False) -> list[EnrichmentResult]:
        """Look up the indicators found on one alert.

        Inputs:
            alert: Normalized Alert object.
            include_local: Unused placeholder kept for symmetry with
                LocalEnricher; external providers never produce local context.

        Outputs:
            EnrichmentResult list.
        """

        del include_local
        return self.enrich_indicators(extract_alert_indicators(alert), target_id=alert.id)

    def enrich_candidate(self, candidate: IncidentCandidate) -> list[EnrichmentResult]:
        """Look up the indicators found across an incident candidate.

        Inputs:
            candidate: IncidentCandidate object.

        Outputs:
            EnrichmentResult list.
        """

        return self.enrich_indicators(
            extract_candidate_indicators(candidate), target_id=candidate.id
        )

    def enrich_indicators(
        self,
        indicators: Iterable[tuple[str, str]],
        *,
        target_id: str | None = None,
    ) -> list[EnrichmentResult]:
        """Look up indicators across every configured provider.

        Inputs:
            indicators: (indicator_type, value) pairs.
            target_id: Optional alert or candidate ID that produced them.

        Outputs:
            EnrichmentResult list, empty when no provider had anything to say.
        """

        if not self.providers:
            return []

        results: list[EnrichmentResult] = []
        for indicator_type, value in self._eligible_indicators(indicators):
            for provider in self.providers:
                if indicator_type not in provider.supported_indicator_types:
                    continue
                lookup = self._lookup_with_cache(provider, indicator_type, value)
                if lookup is not None:
                    results.append(lookup.to_enrichment_result(target_id=target_id))
        return results

    def _eligible_indicators(
        self,
        indicators: Iterable[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        """Filter indicators down to those worth sending upstream.

        Duplicates are collapsed so the same value is never paid for twice, and
        non-global addresses are withheld entirely.

        Inputs:
            indicators: (indicator_type, value) pairs.

        Outputs:
            Deduplicated eligible pairs, in first-seen order.
        """

        eligible: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for indicator_type, value in indicators:
            key = (indicator_type, value)
            if key in seen:
                continue
            seen.add(key)
            if (
                indicator_type == IP_INDICATOR_TYPE
                and self.skip_non_global_ips
                and not _is_global_ip(value)
            ):
                logger.debug("Withholding non-global address %s from providers", value)
                continue
            eligible.append(key)
        return eligible

    def _lookup_with_cache(
        self,
        provider: ThreatIntelProvider,
        indicator_type: str,
        indicator: str,
    ) -> IntelLookup | None:
        """Return a cached or freshly fetched lookup, or None on failure.

        Inputs:
            provider: Provider to query.
            indicator_type: Indicator type.
            indicator: Indicator value.

        Outputs:
            IntelLookup, or None when the provider could not answer.
        """

        cached = self._read_cache(provider.name, indicator_type, indicator)
        if cached is not None:
            return cached

        self._respect_rate_limit(provider)
        try:
            lookup = provider.lookup(indicator_type, indicator)
        except Exception as exc:
            # Contained on purpose: a rate-limited or broken provider must not
            # cost us the rest of enrichment, or the run.
            logger.warning(
                "Threat-intel provider %s failed for %s %s: %s",
                provider.name,
                indicator_type,
                indicator,
                exc,
            )
            return None

        # Only successes are cached. Caching a failure would suppress retries for
        # the whole TTL.
        self._write_cache(provider.name, indicator_type, indicator, lookup)
        return lookup

    def _read_cache(
        self,
        provider_name: str,
        indicator_type: str,
        indicator: str,
    ) -> IntelLookup | None:
        """Read one cached lookup, tolerating an unusable cache.

        Inputs:
            provider_name: Provider name.
            indicator_type: Indicator type.
            indicator: Indicator value.

        Outputs:
            Cached IntelLookup, or None.
        """

        if self.cache is None:
            return None
        try:
            payload = self.cache.get_cached_enrichment(provider_name, indicator_type, indicator)
            return None if payload is None else IntelLookup.from_payload(payload)
        except Exception as exc:
            logger.warning("Threat-intel cache read failed for %s: %s", provider_name, exc)
            return None

    def _write_cache(
        self,
        provider_name: str,
        indicator_type: str,
        indicator: str,
        lookup: IntelLookup,
    ) -> None:
        """Cache one lookup, tolerating an unusable cache.

        Inputs:
            provider_name: Provider name.
            indicator_type: Indicator type.
            indicator: Indicator value.
            lookup: Lookup to cache.

        Outputs:
            None.
        """

        if self.cache is None:
            return
        try:
            self.cache.put_cached_enrichment(
                provider_name,
                indicator_type,
                indicator,
                lookup.to_payload(),
                ttl_hours=self.ttl_hours,
            )
        except Exception as exc:
            logger.warning("Threat-intel cache write failed for %s: %s", provider_name, exc)

    def _respect_rate_limit(self, provider: ThreatIntelProvider) -> None:
        """Wait if this provider was called too recently.

        Inputs:
            provider: Provider about to be called.

        Outputs:
            None.
        """

        min_interval = float(getattr(provider, "min_seconds_between_calls", 0.0) or 0.0)
        if min_interval <= 0:
            return

        last_call = self._last_call_at.get(provider.name)
        now = self._monotonic()
        if last_call is not None:
            wait = min_interval - (now - last_call)
            if wait > 0:
                self._sleep(wait)
                now = self._monotonic()
        self._last_call_at[provider.name] = now


def _is_global_ip(value: str) -> bool:
    """Return whether an address is publicly routable.

    Anything not globally routable, and anything unparseable, is treated as not
    eligible: withholding an address costs one lookup, while leaking internal
    addressing to a third party cannot be undone.

    Inputs:
        value: Candidate IP address.

    Outputs:
        True when the address is global.
    """

    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False
