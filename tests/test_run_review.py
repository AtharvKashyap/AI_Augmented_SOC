"""Tests for the run_review analyst CLI.

Unlike `tests/test_run_pipeline.py`, these tests drive a real `SQLiteStore` on a
`tmp_path` database seeded through the real persistence API. The review CLI is
persistence-facing: its entire job is reading and writing the analyst queue, so a
fake store would hide the SQL that actually has to work.

`--db` and `--env-file` are always passed explicitly. `get_settings` uses
`load_dotenv`, which writes into `os.environ` permanently and does not override
already-set variables, so relying on ambient configuration makes tests
order-dependent.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    AnalystVerdict,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    IncidentCandidate,
    TriageAction,
    TriageResult,
)
from soc.store import SQLiteStore

from run_review import build_parser, main, run_from_args


def _env_file(tmp_path: Path, db_path: Path) -> Path:
    """Write a real .env file pointing at a throwaway database.

    Inputs:
        tmp_path: Pytest temporary directory.
        db_path: Database path to record as SQLITE_DB_PATH.

    Outputs:
        Path to the written env file.
    """

    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(
            [
                f"SQLITE_DB_PATH={db_path}",
                f"OUTPUT_DIR={tmp_path / 'out'}",
                f"LOG_DIR={tmp_path / 'logs'}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return env_file


def _advancing_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every store timestamp strictly increasing.

    Queue ordering is by `queued_at` and `reviewed_at`. Real calls made inside one
    test can land on the same instant, which would make ordering assertions depend
    on the ID tie-breaker instead of on time.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.

    Outputs:
        None. `soc.store.utc_now` is replaced for the test.
    """

    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    counter = {"n": 0}

    def _next() -> datetime:
        """Return a timestamp one minute later than the previous call."""

        counter["n"] += 1
        return base + timedelta(minutes=counter["n"])

    monkeypatch.setattr("soc.store.utc_now", _next)


def _store(db_path: Path) -> SQLiteStore:
    """Build and initialize a real store.

    Inputs:
        db_path: SQLite database path.

    Outputs:
        Initialized SQLiteStore.
    """

    store = SQLiteStore(db_path)
    store.initialize()
    return store


def _seed_queue_item(
    store: SQLiteStore,
    *,
    triage_id: str,
    target_id: str = "CAND-20260101-001-abc",
    target_type: str = "incident_candidate",
    score: int = 5,
    analysis_source: AnalysisSource = AnalysisSource.LLM,
    summary: str = "Repeated failed SSH logins followed by a success.",
) -> TriageResult:
    """Seed one queued triage result plus its target through the real API.

    Inputs:
        store: Initialized store.
        triage_id: Triage result ID to use.
        target_id: Alert or candidate ID under triage.
        target_type: Either incident_candidate or alert.
        score: Triage score.
        analysis_source: Whether the score came from a model or local rules.
        summary: Triage summary text.

    Outputs:
        The seeded TriageResult.
    """

    timestamp = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    alert_id = target_id if target_type == "alert" else f"ALERT-{triage_id}"
    alert = Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=timestamp,
        severity=AlertSeverity.HIGH,
        rule_name="sshd brute force",
        src_ip="203.0.113.10",
        hostname="endpoint-01",
        user="root",
    )
    store.save_alert(alert)
    if target_type == "incident_candidate":
        store.save_incident_candidate(
            IncidentCandidate(
                id=target_id,
                first_seen=timestamp,
                last_seen=timestamp,
                alerts=[alert],
                primary_host="endpoint-01",
                primary_user="root",
                src_ips=["203.0.113.10"],
            )
        )
    result = TriageResult(
        id=triage_id,
        target_id=target_id,
        target_type=target_type,
        score=score,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="credential_access",
        action=TriageAction.QUEUE_REVIEW,
        summary=summary,
        iocs={"ipv4": ["203.0.113.10"]},
        recommended_actions=["Confirm the successful login with the account owner"],
        reasoning="Score reflects a successful login after many failures.",
        evidence=[
            EvidenceItem(
                source=EventSource.WAZUH,
                field="data.srcip",
                value="203.0.113.10",
                alert_id=alert_id,
            )
        ],
        analysis_source=analysis_source,
        model="vendor/model-x" if analysis_source is AnalysisSource.LLM else None,
        prompt_version="triage-v1" if analysis_source is AnalysisSource.LLM else None,
    )
    store.save_triage_result(result)
    store.enqueue_for_review(result)
    return result


def _cli(command: str, tmp_path: Path, db_path: Path, *extra: str) -> list[str]:
    """Build an argv list with explicit db and env-file arguments.

    Inputs:
        command: Subcommand name.
        tmp_path: Pytest temporary directory.
        db_path: Database path to pass via --db.
        extra: Further arguments.

    Outputs:
        argv list.
    """

    return [
        command,
        *extra,
        "--db",
        str(db_path),
        "--env-file",
        str(_env_file(tmp_path, db_path)),
    ]


def test_build_parser_requires_a_command():
    """An analyst invoking the CLI bare must be told which verbs exist."""

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_build_parser_accepts_list_options(tmp_path):
    """list must expose a limit and a reviewed-items mode."""

    args = build_parser().parse_args(
        ["list", "--limit", "5", "--reviewed", "--db", str(tmp_path / "soc.db")]
    )

    assert args.command == "list"
    assert args.limit == 5
    assert args.reviewed is True
    assert args.db == tmp_path / "soc.db"
    assert args.env_file == Path(".env")


def test_list_reports_an_empty_queue_clearly(tmp_path, capsys):
    """An empty queue must say so rather than print an empty table."""

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("list", tmp_path, db_path))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no open review queue items" in captured.out.lower()


def test_list_shows_open_items_oldest_first_with_analysis_source(monkeypatch, tmp_path, capsys):
    """Every row must name its analysis source, in queue order.

    An analyst who cannot tell a model score from a heuristic one is being asked
    to review provenance-free numbers.
    """

    _advancing_clock(monkeypatch)
    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-OLD", analysis_source=AnalysisSource.LLM, score=6)
    _seed_queue_item(
        store,
        triage_id="TRIAGE-NEW",
        target_id="ALERT-STANDALONE",
        target_type="alert",
        analysis_source=AnalysisSource.LOCAL,
        score=4,
    )

    exit_code = main(_cli("list", tmp_path, db_path))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.index("TRIAGE-OLD") < captured.out.index("TRIAGE-NEW")
    old_row = next(line for line in captured.out.splitlines() if "TRIAGE-OLD" in line)
    new_row = next(line for line in captured.out.splitlines() if "TRIAGE-NEW" in line)
    assert "llm" in old_row
    assert "local" in new_row
    assert "queue_review" in old_row
    assert "6" in old_row


def test_list_limit_caps_the_number_of_rows(monkeypatch, tmp_path, capsys):
    """--limit must reach the store, not be silently ignored."""

    _advancing_clock(monkeypatch)
    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-001")
    _seed_queue_item(store, triage_id="TRIAGE-002", target_id="CAND-002")

    exit_code = main(_cli("list", tmp_path, db_path, "--limit", "1"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "TRIAGE-001" in captured.out
    assert "TRIAGE-002" not in captured.out


def test_list_reviewed_shows_judged_items_and_their_verdicts(monkeypatch, tmp_path, capsys):
    """--reviewed must list judged items instead of open ones."""

    _advancing_clock(monkeypatch)
    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-OPEN")
    _seed_queue_item(store, triage_id="TRIAGE-DONE", target_id="CAND-002")
    store.record_analyst_verdict(
        "TRIAGE-DONE",
        verdict=AnalystVerdict.TOO_HIGH,
        analyst_score=3,
        notes="Known scanner",
    )

    exit_code = main(_cli("list", tmp_path, db_path, "--reviewed"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "TRIAGE-DONE" in captured.out
    assert "TRIAGE-OPEN" not in captured.out
    assert "too_high" in captured.out


def test_list_reports_no_reviewed_items_clearly(tmp_path, capsys):
    """An empty reviewed listing must say so too."""

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("list", tmp_path, db_path, "--reviewed"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no reviewed queue items" in captured.out.lower()


def test_show_prints_full_triage_detail_and_target(tmp_path, capsys):
    """show must print everything needed to judge the score, not just the score."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-SHOW")

    exit_code = main(_cli("show", tmp_path, db_path, "TRIAGE-SHOW"))

    captured = capsys.readouterr()
    out = captured.out
    assert exit_code == 0
    assert "TRIAGE-SHOW" in out
    assert "Repeated failed SSH logins followed by a success." in out
    assert "credential_access" in out
    assert "203.0.113.10" in out
    assert "Confirm the successful login with the account owner" in out
    assert "data.srcip" in out
    assert "llm" in out
    assert "vendor/model-x" in out
    # The candidate target itself must be visible, not only its ID.
    assert "endpoint-01" in out


def test_show_prints_alert_target_when_target_is_an_alert(tmp_path, capsys):
    """An alert-targeted result must resolve through get_alert, not get_incident_candidate."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(
        store,
        triage_id="TRIAGE-ALERT",
        target_id="ALERT-STANDALONE",
        target_type="alert",
        analysis_source=AnalysisSource.LOCAL,
    )

    exit_code = main(_cli("show", tmp_path, db_path, "TRIAGE-ALERT"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ALERT-STANDALONE" in captured.out
    assert "sshd brute force" in captured.out
    assert "local" in captured.out


def test_show_reports_a_reviewed_items_verdict(tmp_path, capsys):
    """Showing an already-judged item must display the verdict already recorded."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-DONE")
    store.record_analyst_verdict(
        "TRIAGE-DONE", verdict=AnalystVerdict.TOO_LOW, analyst_score=8, notes="Lateral movement"
    )

    exit_code = main(_cli("show", tmp_path, db_path, "TRIAGE-DONE"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "too_low" in captured.out
    assert "Lateral movement" in captured.out


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ("--agree", AnalystVerdict.AGREE),
        ("--too-high", AnalystVerdict.TOO_HIGH),
        ("--too-low", AnalystVerdict.TOO_LOW),
        ("--wrong-class", AnalystVerdict.WRONG_CLASS),
    ],
)
def test_verdict_flags_map_to_the_right_enum_value(tmp_path, capsys, flag, expected):
    """Each flag must persist exactly the verdict it names."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-V")

    exit_code = main(_cli("verdict", tmp_path, db_path, "TRIAGE-V", flag))

    capsys.readouterr()
    assert exit_code == 0
    item = _store(db_path).get_queue_item("TRIAGE-V")
    assert item is not None
    assert item.analyst_verdict is expected
    assert item.is_open is False


def test_verdict_records_score_and_notes(tmp_path, capsys):
    """The analyst's own score and notes are the label 2.5 will consume."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-V")

    exit_code = main(
        _cli(
            "verdict",
            tmp_path,
            db_path,
            "TRIAGE-V",
            "--too-low",
            "--score",
            "9",
            "--notes",
            "Confirmed lateral movement",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "TRIAGE-V" in captured.out
    item = _store(db_path).get_queue_item("TRIAGE-V")
    assert item is not None
    assert item.analyst_verdict is AnalystVerdict.TOO_LOW
    assert item.analyst_score == 9
    assert item.notes == "Confirmed lateral movement"


def test_verdict_requires_a_verdict_flag(tmp_path):
    """A verdict with no judgment is not a verdict."""

    with pytest.raises(SystemExit):
        build_parser().parse_args(["verdict", "TRIAGE-V", "--db", str(tmp_path / "soc.db")])


def test_verdict_rejects_two_verdict_flags(tmp_path):
    """The four verdicts are mutually exclusive."""

    with pytest.raises(SystemExit):
        build_parser().parse_args(["verdict", "TRIAGE-V", "--agree", "--too-high"])


def test_verdict_out_of_range_score_is_a_cli_error_not_a_traceback(tmp_path, capsys):
    """A StoreError must surface as a message and exit 1, never as a traceback."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-V")

    exit_code = main(
        _cli("verdict", tmp_path, db_path, "TRIAGE-V", "--too-high", "--score", "42")
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err
    assert "between 1 and 10" in captured.err
    assert "Traceback" not in captured.err
    item = _store(db_path).get_queue_item("TRIAGE-V")
    assert item is not None
    assert item.is_open is True


def test_verdict_on_an_unqueued_id_exits_one(tmp_path, capsys):
    """Recording a verdict for something never queued must fail cleanly."""

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("verdict", tmp_path, db_path, "TRIAGE-MISSING", "--agree"))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "TRIAGE-MISSING" in captured.err
    assert "Traceback" not in captured.err


def test_show_exits_non_zero_for_unknown_id(tmp_path, capsys):
    """An unknown ID must be a clear error, not an empty success."""

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("show", tmp_path, db_path, "TRIAGE-MISSING"))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "TRIAGE-MISSING" in captured.err
    assert captured.out == ""


def test_export_writes_reviewed_verdicts_as_json(monkeypatch, tmp_path, capsys):
    """The exported file is the label set 2.5 consumes, so its shape is a contract."""

    _advancing_clock(monkeypatch)
    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-DONE", score=7, analysis_source=AnalysisSource.LLM)
    _seed_queue_item(store, triage_id="TRIAGE-OPEN", target_id="CAND-002")
    store.record_analyst_verdict(
        "TRIAGE-DONE",
        verdict=AnalystVerdict.TOO_HIGH,
        analyst_score=3,
        notes="Authorized scanner",
    )
    output = tmp_path / "labels" / "verdicts.json"

    exit_code = main(_cli("export", tmp_path, db_path, "--output", str(output)))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "1" in captured.out
    assert str(output) in captured.out
    records = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(records, list)
    assert len(records) == 1
    record = records[0]
    assert record["triage_result_id"] == "TRIAGE-DONE"
    assert record["target_id"] == "CAND-20260101-001-abc"
    assert record["target_type"] == "incident_candidate"
    assert record["triage_score"] == 7
    assert record["analyst_verdict"] == "too_high"
    assert record["analyst_score"] == 3
    assert record["notes"] == "Authorized scanner"
    assert record["analysis_source"] == "llm"
    assert record["reviewed_at"]


def test_export_marks_records_as_analyst_reviewed(tmp_path, capsys):
    """Analyst labels must never be confusable with synthetic ones."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-DONE")
    store.record_analyst_verdict("TRIAGE-DONE", verdict=AnalystVerdict.AGREE)
    output = tmp_path / "verdicts.json"

    exit_code = main(_cli("export", tmp_path, db_path, "--output", str(output)))

    capsys.readouterr()
    assert exit_code == 0
    records = json.loads(output.read_text(encoding="utf-8"))
    assert records
    assert all(record["label_provenance"] == "analyst_reviewed" for record in records)
    # `provenance` is the key the Milestone 2.5 labeled-set loader reads.
    assert all(record["provenance"] == "analyst_reviewed" for record in records)


def test_export_pretty_prints_when_asked(tmp_path, capsys):
    """--pretty must make the label file reviewable by a human in a diff."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-DONE")
    store.record_analyst_verdict("TRIAGE-DONE", verdict=AnalystVerdict.AGREE)
    output = tmp_path / "verdicts.json"

    exit_code = main(_cli("export", tmp_path, db_path, "--output", str(output), "--pretty"))

    capsys.readouterr()
    assert exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert "\n  " in text
    assert json.loads(text)


def test_export_writes_an_empty_array_when_nothing_is_reviewed(tmp_path, capsys):
    """An empty label set is a valid, honest answer; a missing file is not."""

    db_path = tmp_path / "soc.db"
    _store(db_path)
    output = tmp_path / "verdicts.json"

    exit_code = main(_cli("export", tmp_path, db_path, "--output", str(output)))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8")) == []
    assert "0" in captured.out


def test_db_argument_overrides_the_settings_default(tmp_path, capsys):
    """--db must win over SQLITE_DB_PATH, or reviews land in the wrong database."""

    settings_db = tmp_path / "settings.db"
    override_db = tmp_path / "override.db"
    settings_store = _store(settings_db)
    _seed_queue_item(settings_store, triage_id="TRIAGE-IN-SETTINGS-DB")
    override_store = _store(override_db)
    _seed_queue_item(override_store, triage_id="TRIAGE-IN-OVERRIDE-DB")
    env_file = _env_file(tmp_path, settings_db)

    exit_code = main(["list", "--db", str(override_db), "--env-file", str(env_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "TRIAGE-IN-OVERRIDE-DB" in captured.out
    assert "TRIAGE-IN-SETTINGS-DB" not in captured.out


def test_settings_default_is_used_when_db_is_omitted(tmp_path, capsys):
    """Without --db the CLI must read SQLITE_DB_PATH from the env file."""

    settings_db = tmp_path / "settings.db"
    store = _store(settings_db)
    _seed_queue_item(store, triage_id="TRIAGE-IN-SETTINGS-DB")
    env_file = _env_file(tmp_path, settings_db)

    exit_code = main(["list", "--env-file", str(env_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "TRIAGE-IN-SETTINGS-DB" in captured.out


def test_run_from_args_returns_a_summary(tmp_path, capsys):
    """run_from_args is the callable surface; it must report what it did."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    _seed_queue_item(store, triage_id="TRIAGE-001")
    args = build_parser().parse_args(_cli("list", tmp_path, db_path))

    summary = run_from_args(args)

    capsys.readouterr()
    assert summary["command"] == "list"
    assert summary["db_path"] == str(db_path)
    assert summary["count"] == 1
    assert summary["mode"] == "open"


def test_main_returns_130_for_keyboard_interrupt(monkeypatch, tmp_path, capsys):
    """Interrupting a review loop must exit 130, like the pipeline CLI."""

    db_path = tmp_path / "soc.db"
    _store(db_path)
    monkeypatch.setattr(
        "run_review.run_from_args",
        lambda args: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    exit_code = main(_cli("list", tmp_path, db_path))

    captured = capsys.readouterr()
    assert exit_code == 130
    assert "error: interrupted" in captured.err


def test_list_rejects_a_non_positive_limit(tmp_path, capsys):
    """A zero or negative limit is a mistake worth naming."""

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("list", tmp_path, db_path, "--limit", "0"))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--limit must be a positive integer" in captured.err
