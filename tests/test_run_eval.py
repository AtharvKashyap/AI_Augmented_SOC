

"""Tests for the evaluation CLI."""

from __future__ import annotations

import json
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
