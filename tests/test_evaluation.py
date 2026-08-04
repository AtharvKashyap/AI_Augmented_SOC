

"""Tests for the triage evaluation harness.

The metric arithmetic is tested against hand-built cases so the numbers are
verified exactly, and one end-to-end test runs the shipped labeled set through
real local triage.
"""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path

import pytest

from soc.evaluation import (
    LABELED_SET_DIR,
    EvaluationError,
    EvaluationThresholds,
    LabeledCase,
    LabelProvenance,
    evaluate_cases,
    load_labeled_cases,
)
from soc.models import TriageAction


def _case(
    case_id: str = "case-001",
    *,
    fixture: str = "tests/fixtures/sample_wazuh_benign_alert.json",
    score_min: int = 1,
    score_max: int = 3,
    actions: tuple[str, ...] = ("mark_likely_benign",),
    provenance: str = "synthetic",
) -> LabeledCase:
    """Build a labeled case without touching disk."""

    return LabeledCase(
        id=case_id,
        provenance=LabelProvenance(provenance),
        fixture=Path(fixture),
        expected_score_min=score_min,
        expected_score_max=score_max,
        expected_actions=tuple(TriageAction(action) for action in actions),
        expected_classification=None,
        rationale="test case",
    )


def test_labeled_case_rejects_an_inverted_band():
    """A band whose floor exceeds its ceiling is a labeling mistake."""

    with pytest.raises(EvaluationError, match="expected_score_min"):
        _case(score_min=8, score_max=3)


def test_labeled_case_rejects_an_out_of_scale_band():
    """Bands must live on the same 1-10 scale as triage scores."""

    with pytest.raises(EvaluationError, match="between 1 and 10"):
        _case(score_min=0, score_max=3)


def test_labeled_case_requires_a_rationale():
    """A label without a stated reason cannot be reviewed or trusted."""

    with pytest.raises(EvaluationError, match="rationale"):
        LabeledCase(
            id="no-rationale",
            provenance=LabelProvenance.SYNTHETIC,
            fixture=Path("tests/fixtures/sample_wazuh_benign_alert.json"),
            expected_score_min=1,
            expected_score_max=3,
            expected_actions=(TriageAction.MARK_LIKELY_BENIGN,),
            expected_classification=None,
            rationale="  ",
        )


def test_evaluation_reports_action_agreement_and_band_accuracy():
    """Agreement and in-band rates must be computed over every case."""

    report = evaluate_cases(
        [_case("a"), _case("b"), _case("c")],
        score_action_source=lambda case: {
            "a": (2, TriageAction.MARK_LIKELY_BENIGN),
            "b": (5, TriageAction.QUEUE_REVIEW),
            "c": (1, TriageAction.MARK_LIKELY_BENIGN),
        }[case.id],
    )

    assert report.cases_evaluated == 3
    assert report.action_agreement_rate == pytest.approx(2 / 3)
    assert report.in_band_rate == pytest.approx(2 / 3)


def test_evaluation_scores_error_as_distance_outside_the_band():
    """An in-band score is not an error; only the distance outside one counts."""

    report = evaluate_cases(
        [_case("in-band", score_min=4, score_max=6), _case("over", score_min=1, score_max=3)],
        score_action_source=lambda case: {
            "in-band": (5, TriageAction.QUEUE_REVIEW),
            "over": (7, TriageAction.QUEUE_REVIEW),
        }[case.id],
    )

    outcomes = {outcome.case.id: outcome for outcome in report.outcomes}
    assert outcomes["in-band"].score_error == 0
    assert outcomes["over"].score_error == 4
    assert report.mean_score_error == pytest.approx(2.0)


def test_evaluation_reports_missed_true_positives_separately():
    """Missing a real threat is not interchangeable with being noisy."""

    report = evaluate_cases(
        [_case("serious", score_min=8, score_max=10, actions=("page_now",))],
        score_action_source=lambda case: (2, TriageAction.MARK_LIKELY_BENIGN),
    )

    assert [outcome.case.id for outcome in report.missed_true_positives] == ["serious"]
    assert report.noise_cases == []


def test_evaluation_reports_noise_separately():
    """Over-paging on benign activity is the other, distinct failure mode."""

    report = evaluate_cases(
        [_case("benign", score_min=1, score_max=3)],
        score_action_source=lambda case: (9, TriageAction.PAGE_NOW),
    )

    assert [outcome.case.id for outcome in report.noise_cases] == ["benign"]
    assert report.missed_true_positives == []
    assert report.benign_caught_rate == pytest.approx(0.0)


def test_evaluation_computes_benign_caught_rate():
    """The benign-suppression rate is one of Phase 2's exit thresholds."""

    report = evaluate_cases(
        [_case("b1"), _case("b2"), _case("b3"), _case("serious", score_min=8, score_max=10)],
        score_action_source=lambda case: {
            "b1": (2, TriageAction.MARK_LIKELY_BENIGN),
            "b2": (3, TriageAction.MARK_LIKELY_BENIGN),
            "b3": (6, TriageAction.QUEUE_REVIEW),
            "serious": (9, TriageAction.PAGE_NOW),
        }[case.id],
    )

    assert report.benign_caught_rate == pytest.approx(2 / 3)


def test_evaluation_builds_an_action_confusion_matrix():
    """Which way the actions are wrong matters, not just how often."""

    report = evaluate_cases(
        [_case("a"), _case("b", score_min=8, score_max=10, actions=("page_now",))],
        score_action_source=lambda case: {
            "a": (2, TriageAction.MARK_LIKELY_BENIGN),
            "b": (5, TriageAction.QUEUE_REVIEW),
        }[case.id],
    )

    assert report.action_confusion[("mark_likely_benign", "mark_likely_benign")] == 1
    assert report.action_confusion[("page_now", "queue_review")] == 1


def test_evaluation_counts_label_provenance():
    """A run over synthetic labels must never look like a validated run."""

    report = evaluate_cases(
        [_case("s1"), _case("a1", provenance="analyst_reviewed")],
        score_action_source=lambda case: (2, TriageAction.MARK_LIKELY_BENIGN),
    )

    assert report.provenance_counts == {"synthetic": 1, "analyst_reviewed": 1}
    assert report.is_analyst_validated is False


def test_evaluation_is_analyst_validated_only_with_analyst_labels():
    """Only analyst-reviewed labels can support an accuracy claim."""

    report = evaluate_cases(
        [_case("a1", provenance="analyst_reviewed")],
        score_action_source=lambda case: (2, TriageAction.MARK_LIKELY_BENIGN),
    )

    assert report.is_analyst_validated is True


def test_evaluation_rejects_an_empty_case_set():
    """An empty run would report a perfect score over nothing."""

    with pytest.raises(EvaluationError, match="at least one"):
        evaluate_cases([], score_action_source=lambda case: (1, TriageAction.MARK_LIKELY_BENIGN))


def test_thresholds_report_each_unmet_criterion():
    """Phase 2's exit criteria must be executable, not prose."""

    report = evaluate_cases(
        [
            _case("benign"),
            _case("serious", score_min=8, score_max=10, actions=("page_now",)),
        ],
        score_action_source=lambda case: {
            "benign": (9, TriageAction.PAGE_NOW),
            "serious": (2, TriageAction.MARK_LIKELY_BENIGN),
        }[case.id],
    )

    failures = EvaluationThresholds().check(report)

    assert any("missed" in failure for failure in failures)
    assert any("benign" in failure for failure in failures)
    assert any("agreement" in failure for failure in failures)


def test_thresholds_pass_on_a_clean_run():
    """A run meeting every criterion reports no failures."""

    report = evaluate_cases(
        [
            _case("benign"),
            _case("serious", score_min=8, score_max=10, actions=("page_now",)),
        ],
        score_action_source=lambda case: {
            "benign": (2, TriageAction.MARK_LIKELY_BENIGN),
            "serious": (9, TriageAction.PAGE_NOW),
        }[case.id],
    )

    assert EvaluationThresholds().check(report) == []


def test_load_labeled_cases_reads_the_shipped_set():
    """The labeled set on disk must load and be non-empty."""

    cases = load_labeled_cases(LABELED_SET_DIR)

    assert cases
    assert all(case.rationale.strip() for case in cases)
    assert all(case.fixture.exists() for case in cases)


def test_load_labeled_cases_rejects_a_missing_fixture(tmp_path):
    """A label pointing at a fixture that does not exist is unusable."""

    label_file = tmp_path / "bad.json"
    label_file.write_text(
        json.dumps(
            {
                "id": "broken",
                "provenance": "synthetic",
                "fixture": "tests/fixtures/does_not_exist.json",
                "expected_score_min": 1,
                "expected_score_max": 3,
                "expected_actions": ["mark_likely_benign"],
                "rationale": "points nowhere",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(EvaluationError, match="fixture"):
        load_labeled_cases(tmp_path)


def test_shipped_labeled_set_runs_through_real_local_triage():
    """The harness must work end to end against real fixtures and real triage.

    This asserts the harness runs and reports, not that local scoring is good.
    Quality is reported, never asserted, because the labels are still synthetic.
    """

    report = evaluate_cases(load_labeled_cases(LABELED_SET_DIR))

    assert report.cases_evaluated == len(load_labeled_cases(LABELED_SET_DIR))
    assert 0.0 <= report.action_agreement_rate <= 1.0
    assert report.is_analyst_validated is False
    summary = report.to_summary()
    assert json.loads(json.dumps(summary))["cases_evaluated"] == report.cases_evaluated


def _seed_reviewed_item(
    tmp_path: Path,
    *,
    verdict: str,
    triage_score: int = 6,
    analyst_score: int | None = None,
    notes: str | None = "analyst note",
):
    """Seed a store with one reviewed queue item and its source raw event."""

    from datetime import datetime

    from soc.models import (
        Alert,
        AlertSeverity,
        AnalystVerdict,
        EventSource,
        FalsePositiveLikelihood,
        IncidentCandidate,
        RawEvent,
        TriageAction,
        TriageResult,
    )
    from soc.store import SQLiteStore

    moment = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
    store = SQLiteStore(tmp_path / "soc.db")
    store.initialize()

    raw = RawEvent(
        id="raw-review-001",
        source=EventSource.WAZUH,
        received_at=moment,
        timestamp=moment,
        payload={"rule": {"level": 10, "description": "Reviewed rule"}, "agent": {"id": "001"}},
    )
    alert = Alert(
        id="alert-review-001",
        source=EventSource.WAZUH,
        timestamp=moment,
        severity=AlertSeverity.HIGH,
        rule_name="Reviewed rule",
        raw_event_id=raw.id,
    )
    candidate = IncidentCandidate(
        id="CAND-review-001", first_seen=moment, last_seen=moment, alerts=[alert]
    )
    triage = TriageResult(
        id="triage-review-001",
        target_id=candidate.id,
        target_type="incident_candidate",
        score=triage_score,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="needs_analyst_review",
        action=TriageAction.QUEUE_REVIEW,
        summary="Needs a human decision.",
    )
    store.save_raw_event(raw)
    store.save_alert(alert)
    store.save_incident_candidate(candidate)
    store.save_triage_result(triage)
    store.enqueue_for_review(triage)
    store.record_analyst_verdict(
        triage.id,
        verdict=AnalystVerdict(verdict),
        analyst_score=analyst_score,
        notes=notes,
    )
    return store


def test_promote_reviews_writes_a_loadable_labeled_case(tmp_path):
    """A reviewed verdict must become a labeled case the harness can load.

    This is the whole point of building the review queue before the harness: if
    analyst judgment cannot reach the labeled set, the set stays synthetic and
    the system can never be shown to improve.
    """

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="too_high", analyst_score=2)
    labels_path = tmp_path / "labels" / "analyst.json"

    records = promote_reviews_to_labels(
        store,
        labels_path=labels_path,
        fixtures_dir=tmp_path / "labels" / "fixtures",
    )

    assert len(records) == 1
    cases = load_labeled_cases(labels_path)
    assert len(cases) == 1
    assert cases[0].provenance is LabelProvenance.ANALYST_REVIEWED
    assert cases[0].fixture.exists()


def test_promoted_case_is_scoreable_end_to_end(tmp_path):
    """The reconstructed fixture must actually replay through triage."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="agree")
    labels_path = tmp_path / "labels.json"
    promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    report = evaluate_cases(load_labeled_cases(labels_path))

    assert report.cases_evaluated == 1
    assert report.is_analyst_validated is True


def test_analyst_score_takes_precedence_over_inference(tmp_path):
    """An explicit analyst score is better evidence than any inference."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="too_low", triage_score=3, analyst_score=9)
    labels_path = tmp_path / "labels.json"

    records = promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    assert records[0]["expected_score_min"] <= 9 <= records[0]["expected_score_max"]
    assert records[0]["expected_score_min"] >= 8


def test_too_high_without_a_score_shifts_the_band_down(tmp_path):
    """A directional verdict alone still constrains the expected band."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="too_high", triage_score=8, analyst_score=None)
    labels_path = tmp_path / "labels.json"

    records = promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    assert records[0]["expected_score_max"] < 8
    assert records[0]["expected_score_min"] == 1


def test_too_low_without_a_score_shifts_the_band_up(tmp_path):
    """The mirror case must shift the other way."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="too_low", triage_score=4, analyst_score=None)
    labels_path = tmp_path / "labels.json"

    records = promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    assert records[0]["expected_score_min"] > 4
    assert records[0]["expected_score_max"] == 10


def test_agree_narrows_the_band_around_the_triage_score(tmp_path):
    """Agreement means the score triage gave was about right."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="agree", triage_score=6)
    labels_path = tmp_path / "labels.json"

    records = promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    assert records[0]["expected_score_min"] <= 6 <= records[0]["expected_score_max"]
    assert records[0]["expected_score_max"] - records[0]["expected_score_min"] <= 2


def test_analyst_notes_become_the_rationale(tmp_path):
    """The analyst's own words are the best available rationale."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="too_high", notes="Known nightly backup job.")
    labels_path = tmp_path / "labels.json"

    records = promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    assert "Known nightly backup job." in records[0]["rationale"]


def test_promotion_still_produces_a_rationale_without_notes(tmp_path):
    """A rationale is required, so one must be synthesized when notes are absent."""

    from soc.evaluation import promote_reviews_to_labels

    store = _seed_reviewed_item(tmp_path, verdict="wrong_class", notes=None)
    labels_path = tmp_path / "labels.json"

    records = promote_reviews_to_labels(
        store, labels_path=labels_path, fixtures_dir=tmp_path / "fixtures"
    )

    assert records[0]["rationale"].strip()
    assert load_labeled_cases(labels_path)


def test_promotion_skips_targets_with_no_recoverable_events(tmp_path):
    """A verdict whose source events are gone cannot become a labeled case."""

    from soc.evaluation import promote_reviews_to_labels
    from soc.models import AnalystVerdict, FalsePositiveLikelihood, TriageAction, TriageResult
    from soc.store import SQLiteStore

    store = SQLiteStore(tmp_path / "soc.db")
    store.initialize()
    triage = TriageResult(
        id="triage-orphan",
        target_id="CAND-gone",
        target_type="incident_candidate",
        score=5,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="needs_analyst_review",
        action=TriageAction.QUEUE_REVIEW,
        summary="Orphaned.",
    )
    store.save_triage_result(triage)
    store.enqueue_for_review(triage)
    store.record_analyst_verdict(triage.id, verdict=AnalystVerdict.AGREE)

    records = promote_reviews_to_labels(
        store, labels_path=tmp_path / "labels.json", fixtures_dir=tmp_path / "fixtures"
    )

    assert records == []
