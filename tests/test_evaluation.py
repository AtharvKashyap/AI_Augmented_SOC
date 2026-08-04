

"""Tests for the triage evaluation harness.

The metric arithmetic is tested against hand-built cases so the numbers are
verified exactly, and one end-to-end test runs the shipped labeled set through
real local triage.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc.evaluation import (
    LABELED_SET_DIR,
    EvaluationError,
    EvaluationThresholds,
    LabelProvenance,
    LabeledCase,
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
