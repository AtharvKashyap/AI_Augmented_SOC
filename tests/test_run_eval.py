

"""Tests for the evaluation CLI."""

from __future__ import annotations

import copy
import json
from datetime import UTC
from pathlib import Path

import pytest

from run_eval import EvalCliError, build_parser, main, run_from_args


def _args(**overrides: object):
    """Build a default argparse namespace for run_from_args tests."""

    parser = build_parser()
    args = parser.parse_args([])
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_parser_defaults_to_local_triage_and_the_shipped_labels():
    """Evaluation must work with no arguments and no API key."""

    args = build_parser().parse_args([])

    assert args.llm is False
    assert args.labels == Path("tests/fixtures/labeled")


def test_run_from_args_evaluates_local_triage():
    """A default run scores the shipped labeled set locally."""

    summary, failures = run_from_args(_args())

    assert summary["triage_mode"] == "local"
    assert summary["cases_evaluated"] > 0
    assert isinstance(failures, list)


def test_run_from_args_marks_synthetic_runs_as_not_validated():
    """A synthetic-label run must never claim to be validated."""

    summary, _ = run_from_args(_args())

    assert summary["is_analyst_validated"] is False


def test_run_from_args_writes_a_report_file(tmp_path):
    """The report must be persistable so runs can be compared over time."""

    output = tmp_path / "reports" / "eval.json"

    run_from_args(_args(output=output))

    assert json.loads(output.read_text(encoding="utf-8"))["cases_evaluated"] > 0


def test_llm_mode_requires_a_configured_key(tmp_path):
    """Requesting an LLM run without a key must fail clearly, not silently."""

    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=\n", encoding="utf-8")

    with pytest.raises(EvalCliError, match="OPENROUTER_API_KEY"):
        run_from_args(_args(llm=True, env_file=env_file))


def test_main_returns_zero_on_a_passing_run(capsys):
    """A run meeting every threshold exits zero and prints JSON."""

    exit_code = main([])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["cases_evaluated"] > 0


def test_main_warns_that_synthetic_runs_are_not_accuracy(capsys):
    """The synthetic-label caveat must reach the operator, not just the docs."""

    main([])

    assert "self-consistency" in capsys.readouterr().err


def test_main_can_gate_a_build_on_thresholds(tmp_path, capsys):
    """--fail-under-thresholds makes the exit criteria enforceable in CI."""

    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            [
                {
                    "id": "impossible",
                    "provenance": "synthetic",
                    "fixture": "tests/fixtures/sample_wazuh_benign_alert.json",
                    "expected_score_min": 9,
                    "expected_score_max": 10,
                    "expected_actions": ["page_now"],
                    "rationale": "Deliberately unsatisfiable, to prove the gate fires.",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(["--labels", str(labels), "--fail-under-thresholds"])

    assert exit_code == 1
    assert "threshold unmet" in capsys.readouterr().err


def test_main_reports_thresholds_without_failing_by_default(tmp_path, capsys):
    """Reporting a shortfall must not break a build unless asked."""

    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            [
                {
                    "id": "impossible",
                    "provenance": "synthetic",
                    "fixture": "tests/fixtures/sample_wazuh_benign_alert.json",
                    "expected_score_min": 9,
                    "expected_score_max": 10,
                    "expected_actions": ["page_now"],
                    "rationale": "Deliberately unsatisfiable, to prove reporting is non-fatal.",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(["--labels", str(labels)])

    assert exit_code == 0
    assert "threshold unmet" in capsys.readouterr().err


def test_promote_command_writes_a_loadable_labeled_set(tmp_path, capsys):
    """`run_review.py promote` must produce a set the eval CLI can consume.

    This is the seam between the two CLIs: if it breaks, analyst judgment stops
    reaching the evaluation harness and the labeled set stays synthetic.
    """

    from datetime import datetime

    import run_review
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
    db_path = tmp_path / "soc.db"
    store = SQLiteStore(db_path)
    store.initialize()

    raw = RawEvent(
        id="raw-cli-001",
        source=EventSource.WAZUH,
        received_at=moment,
        timestamp=moment,
        payload={"rule": {"level": 9, "description": "CLI seam rule"}},
    )
    alert = Alert(
        id="alert-cli-001",
        source=EventSource.WAZUH,
        timestamp=moment,
        severity=AlertSeverity.HIGH,
        rule_name="CLI seam rule",
        raw_event_id=raw.id,
    )
    candidate = IncidentCandidate(
        id="CAND-cli-001", first_seen=moment, last_seen=moment, alerts=[alert]
    )
    triage = TriageResult(
        id="triage-cli-001",
        target_id=candidate.id,
        target_type="incident_candidate",
        score=5,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="needs_analyst_review",
        action=TriageAction.QUEUE_REVIEW,
        summary="Seam test.",
    )
    for save in (
        lambda: store.save_raw_event(raw),
        lambda: store.save_alert(alert),
        lambda: store.save_incident_candidate(candidate),
        lambda: store.save_triage_result(triage),
        lambda: store.enqueue_for_review(triage),
    ):
        save()
    store.record_analyst_verdict(
        triage.id, verdict=AnalystVerdict.AGREE, notes="Correctly queued."
    )

    labels_path = tmp_path / "labels" / "analyst.json"
    exit_code = run_review.main(
        [
            "promote",
            "--labels",
            str(labels_path),
            "--db",
            str(db_path),
            "--env-file",
            str(tmp_path / "missing.env"),
        ]
    )
    capsys.readouterr()

    assert exit_code == 0
    assert main(["--labels", str(labels_path)]) == 0
    assert json.loads(capsys.readouterr().out)["is_analyst_validated"] is True


def test_report_records_prompt_version_and_model_for_comparability():
    """Eval runs must be attributable, or results cannot be compared over time.

    A score without the prompt version and model that produced it is not a data
    point: a later run cannot tell whether a change helped, hurt, or was simply
    measured against a different prompt.
    """

    summary, _ = run_from_args(_args())

    assert summary["prompt_version"]
    assert "model" in summary
    assert summary["evaluated_at"]


def test_local_runs_report_no_model():
    """A local run has no model, and must say so rather than imply one."""

    summary, _ = run_from_args(_args())

    assert summary["triage_mode"] == "local"
    assert summary["model"] is None


def test_main_warns_when_a_case_spans_more_than_one_clustering_window(tmp_path, capsys):
    """A case scored on fragments must say so on the terminal, not only in JSON.

    "We evaluated half of it" and "we evaluated it" must never look the same.
    """

    events_dir = Path("tests/fixtures/labeled/events")
    benign = json.loads((events_dir / "benign_av_definition_update.json").read_text())[0]
    serious = json.loads((events_dir / "serious_lsass_credential_dump.json").read_text())[0]

    def _at(event: dict, stamp: str) -> dict:
        event = copy.deepcopy(event)
        event["timestamp"] = stamp
        event["payload"]["timestamp"] = stamp
        return event

    fixture = tmp_path / "split_events.json"
    fixture.write_text(
        json.dumps([_at(benign, "2026-08-05T02:10:00Z"), _at(serious, "2026-08-05T03:47:09Z")]),
        encoding="utf-8",
    )
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            [
                {
                    "id": "spans-two-windows",
                    "provenance": "synthetic",
                    "fixture": str(fixture),
                    "expected_score_min": 8,
                    "expected_score_max": 10,
                    "expected_actions": ["page_now"],
                    "rationale": "Deliberately spans two clustering windows.",
                }
            ]
        ),
        encoding="utf-8",
    )

    main(["--labels", str(labels)])

    captured = capsys.readouterr()
    assert json.loads(captured.out)["split_cases"] == {"spans-two-windows": 2}
    assert "spans-two-windows" in captured.err
    assert "clustering window" in captured.err
