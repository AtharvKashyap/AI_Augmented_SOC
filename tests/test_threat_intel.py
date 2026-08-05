

"""Tests for the threat-intelligence provider layer.

No test performs a network call. Providers are fakes implementing the protocol,
which is also how the real provider clients are tested.

These tests deliberately use genuinely routable addresses such as 8.8.8.8 rather
than the usual RFC 5737 documentation ranges. Documentation ranges report
`is_global == False`, so the enricher correctly withholds them from providers,
which would make every lookup here a no-op for the wrong reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from soc.models import Alert, AlertSeverity, EventSource
from soc.store import SQLiteStore
from soc.threat_intel import (
    IntelLookup,
    IntelVerdict,
    ThreatIntelEnricher,
    ThreatIntelError,
)


@dataclass
class FakeProvider:
    """Fake threat-intel provider recording its calls."""

    name: str = "fakeintel"
    supported_indicator_types: tuple[str, ...] = ("ip", "domain")
    min_seconds_between_calls: float = 0.0
    verdict: IntelVerdict = IntelVerdict.MALICIOUS
    raise_error: Exception | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)

    def lookup(self, indicator_type: str, indicator: str) -> IntelLookup:
        """Record the call and return a configured verdict."""

        self.calls.append((indicator_type, indicator))
        if self.raise_error is not None:
            raise self.raise_error
        return IntelLookup(
            provider=self.name,
            indicator_type=indicator_type,
            indicator=indicator,
            verdict=self.verdict,
            summary=f"{self.name}: {self.verdict.value} for {indicator}",
            risk_factors=("flagged_by_fakeintel",),
            details={"engine_hits": 7},
        )


def _store(tmp_path) -> SQLiteStore:
    """Return an initialized store for cache tests."""

    store = SQLiteStore(tmp_path / "intel.db")
    store.initialize()
    return store


def _alert() -> Alert:
    """Return an alert with one public and one private address."""

    return Alert(
        id="alert-intel-001",
        source=EventSource.WAZUH,
        timestamp=None,
        severity=AlertSeverity.HIGH,
        rule_name="Outbound connection",
        src_ip="10.0.1.50",
        dst_ip="8.8.8.8",
    )


def test_enricher_returns_nothing_without_providers():
    """No configured providers is a normal mode, not an error."""

    assert ThreatIntelEnricher().enrich_indicators([("ip", "8.8.8.8")]) == []


def test_enricher_queries_a_provider_and_builds_an_enrichment_result():
    """A provider verdict must become a normal EnrichmentResult."""

    provider = FakeProvider()

    results = ThreatIntelEnricher([provider]).enrich_indicators(
        [("ip", "8.8.8.8")], target_id="alert-1"
    )

    assert provider.calls == [("ip", "8.8.8.8")]
    assert len(results) == 1
    assert results[0].provider == "fakeintel"
    assert results[0].indicator == "8.8.8.8"
    assert "malicious" in results[0].summary


def test_verdict_reaches_the_llm_through_the_summary():
    """The triage context allowlist excludes raw, so the summary must carry it.

    Provider payloads are deliberately withheld from the model. If the verdict
    lived only in the raw details it would never reach triage at all.
    """

    from soc.triage import build_enrichment_context

    results = ThreatIntelEnricher([FakeProvider()]).enrich_indicators([("ip", "8.8.8.8")])
    context = build_enrichment_context(results[0])

    assert "malicious" in context["summary"]
    assert "raw" not in context


def test_risk_factors_and_severity_hint_reach_local_scoring():
    """Intel must be able to raise a local score, or it changes nothing."""

    from soc.triage import score_alert_locally

    alert = _alert()
    results = ThreatIntelEnricher([FakeProvider()]).enrich_indicators([("ip", "8.8.8.8")])

    assert score_alert_locally(alert, results) > score_alert_locally(alert, [])


def test_benign_intel_does_not_raise_the_score():
    """A clean verdict is information, not evidence of compromise."""

    from soc.triage import score_alert_locally

    alert = _alert()
    results = ThreatIntelEnricher([FakeProvider(verdict=IntelVerdict.BENIGN)]).enrich_indicators(
        [("ip", "8.8.8.8")]
    )

    assert score_alert_locally(alert, results) == score_alert_locally(alert, [])


def test_non_global_addresses_are_never_sent_to_a_provider():
    """Internal addresses must not be leaked to a third party.

    Querying 10.0.1.50 upstream tells the provider about our internal addressing,
    returns nothing useful, and burns free-tier quota.
    """

    provider = FakeProvider()

    results = ThreatIntelEnricher([provider]).enrich_indicators(
        [("ip", "10.0.1.50"), ("ip", "127.0.0.1"), ("ip", "8.8.8.8")]
    )

    assert provider.calls == [("ip", "8.8.8.8")]
    assert len(results) == 1


def test_unsupported_indicator_types_are_skipped():
    """A provider must only be asked what it can answer."""

    provider = FakeProvider(supported_indicator_types=("domain",))

    ThreatIntelEnricher([provider]).enrich_indicators([("ip", "8.8.8.8")])

    assert provider.calls == []


def test_a_failing_provider_does_not_stop_the_others():
    """One rate-limited or broken provider must not lose all enrichment."""

    broken = FakeProvider(name="broken", raise_error=ThreatIntelError("rate limited"))
    working = FakeProvider(name="working")

    results = ThreatIntelEnricher([broken, working]).enrich_indicators([("ip", "8.8.8.8")])

    assert [result.provider for result in results] == ["working"]


def test_an_unexpected_provider_error_is_also_contained():
    """A provider raising something unexpected must not break the pipeline."""

    broken = FakeProvider(name="broken", raise_error=RuntimeError("boom"))
    working = FakeProvider(name="working")

    results = ThreatIntelEnricher([broken, working]).enrich_indicators([("ip", "8.8.8.8")])

    assert [result.provider for result in results] == ["working"]


def test_cached_lookups_do_not_call_the_provider_again(tmp_path):
    """Caching is what keeps free-tier quotas usable."""

    provider = FakeProvider()
    store = _store(tmp_path)
    enricher = ThreatIntelEnricher([provider], cache=store, ttl_hours=24)

    first = enricher.enrich_indicators([("ip", "8.8.8.8")])
    second = enricher.enrich_indicators([("ip", "8.8.8.8")])

    assert len(provider.calls) == 1
    assert first[0].summary == second[0].summary


def test_expired_cache_entries_cause_a_refetch(tmp_path):
    """Stale intel must be refreshed rather than trusted indefinitely."""

    provider = FakeProvider()
    store = _store(tmp_path)
    enricher = ThreatIntelEnricher([provider], cache=store, ttl_hours=24)

    enricher.enrich_indicators([("ip", "8.8.8.8")])
    with store._connect() as conn:
        conn.execute("UPDATE enrichment_cache SET expires_at = ?", ("2020-01-01T00:00:00+00:00",))
    enricher.enrich_indicators([("ip", "8.8.8.8")])

    assert len(provider.calls) == 2


def test_failed_lookups_are_not_cached(tmp_path):
    """Caching a failure would suppress retries for the whole TTL."""

    provider = FakeProvider(raise_error=ThreatIntelError("rate limited"))
    store = _store(tmp_path)
    enricher = ThreatIntelEnricher([provider], cache=store, ttl_hours=24)

    enricher.enrich_indicators([("ip", "8.8.8.8")])
    enricher.enrich_indicators([("ip", "8.8.8.8")])

    assert len(provider.calls) == 2


def test_rate_limit_waits_between_calls_to_the_same_provider():
    """Free tiers cap requests per minute, so calls must be spaced."""

    sleeps: list[float] = []
    clock = {"now": 0.0}

    def _sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["now"] += seconds

    provider = FakeProvider(min_seconds_between_calls=15.0)
    enricher = ThreatIntelEnricher(
        [provider],
        sleep=_sleep,
        monotonic=lambda: clock["now"],
    )

    enricher.enrich_indicators([("ip", "8.8.8.8"), ("ip", "1.1.1.1")])

    assert len(provider.calls) == 2
    assert sleeps and sleeps[0] == pytest.approx(15.0)


def test_rate_limit_does_not_wait_before_the_first_call():
    """Nothing has been sent yet, so there is nothing to wait for."""

    sleeps: list[float] = []
    provider = FakeProvider(min_seconds_between_calls=15.0)
    enricher = ThreatIntelEnricher([provider], sleep=lambda s: sleeps.append(s), monotonic=lambda: 0.0)

    enricher.enrich_indicators([("ip", "8.8.8.8")])

    assert sleeps == []


def test_enrich_alert_uses_the_alerts_own_indicators():
    """The enricher must accept an Alert directly, like LocalEnricher does."""

    provider = FakeProvider()

    results = ThreatIntelEnricher([provider]).enrich_alert(_alert())

    assert ("ip", "8.8.8.8") in provider.calls
    assert ("ip", "10.0.1.50") not in provider.calls
    assert results


def test_intel_lookup_payload_round_trips():
    """Cached payloads must reconstruct an equivalent lookup."""

    lookup = IntelLookup(
        provider="vt",
        indicator_type="ip",
        indicator="8.8.8.8",
        verdict=IntelVerdict.SUSPICIOUS,
        summary="two engines flagged this",
        risk_factors=("vt_suspicious",),
        details={"hits": 2},
    )

    restored = IntelLookup.from_payload(lookup.to_payload())

    assert restored == lookup


def test_intel_lookup_rejects_an_empty_indicator():
    """An empty indicator is a caller bug and must fail loudly."""

    with pytest.raises(ThreatIntelError, match="indicator"):
        IntelLookup(
            provider="vt",
            indicator_type="ip",
            indicator="   ",
            verdict=IntelVerdict.UNKNOWN,
            summary="nothing",
        )


def test_duplicate_indicators_are_queried_once():
    """The same indicator appearing twice must not double the API spend."""

    provider = FakeProvider()

    ThreatIntelEnricher([provider]).enrich_indicators(
        [("ip", "8.8.8.8"), ("ip", "8.8.8.8")]
    )

    assert len(provider.calls) == 1


def test_non_ip_indicator_types_are_not_subject_to_the_ip_guard():
    """The private-address guard must not suppress domains or hashes."""

    provider = FakeProvider(supported_indicator_types=("ip", "domain"))

    ThreatIntelEnricher([provider]).enrich_indicators([("domain", "evil.example")])

    assert provider.calls == [("domain", "evil.example")]


def test_enricher_tolerates_a_broken_cache(tmp_path: Any) -> None:
    """A cache failure must degrade to a live lookup, not lose enrichment."""

    class _BrokenCache:
        """Cache whose reads and writes both fail."""

        def get_cached_enrichment(self, provider: str, indicator_type: str, indicator: str) -> None:
            raise RuntimeError("cache read failed")

        def put_cached_enrichment(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("cache write failed")

    provider = FakeProvider()

    results = ThreatIntelEnricher([provider], cache=_BrokenCache()).enrich_indicators(
        [("ip", "8.8.8.8")]
    )

    assert len(results) == 1
    assert len(provider.calls) == 1
