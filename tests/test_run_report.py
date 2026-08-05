"""Tests for the run_report incident reporting CLI.

Like `tests/test_run_review.py`, these tests drive a real `SQLiteStore` on a
`tmp_path` database seeded through the real persistence API. The report CLI reads
incidents, candidates, and triage results back out of SQLite, so a fake store
would hide the queries that actually have to work.

`--db` and `--env-file` are always passed explicitly. `get_settings` uses
`load_dotenv`, which writes into `os.environ` permanently and does not override
already-set variables, so relying on ambient configuration makes tests
order-dependent.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import run_report
from run_report import CliError, build_parser, main, run_from_args
from soc.incidents import Incident
from soc.models import (
    Alert,
    AlertSeverity,
    EventSource,
    FalsePositiveLikelihood,
    IncidentCandidate,
    TriageAction,
    TriageResult,
)
from soc.store import SQLiteStore

BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _env_file(tmp_path: Path, db_path: Path, *, extra: list[str] | None = None) -> Path:
    """Write a real .env file pointing at a throwaway database.

    Inputs:
        tmp_path: Pytest temporary directory.
        db_path: Database path to record as SQLITE_DB_PATH.
        extra: Optional additional KEY=VALUE lines.

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
                "OPENROUTER_API_KEY=",
                "EMAIL_ENABLED=false",
                *(extra or []),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return env_file


def _alert(alert_id: str, *, timestamp: datetime) -> Alert:
    """Build one normalized alert.

    Inputs:
        alert_id: Alert ID.
        timestamp: Alert time.

    Outputs:
        Alert object.
    """

    return Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=timestamp,
        severity=AlertSeverity.HIGH,
        rule_name="Suspicious PowerShell download",
        rule_groups=["windows", "powershell"],
        src_ip="10.0.1.50",
        dst_ip="203.0.113.10",
        hostname="WIN-FIN-01",
        user="jdoe",
        process_name="powershell.exe",
        command_line="powershell -enc SQBFAFgA",
        raw={"rule": {"level": 12}},
    )


def _candidate(candidate_id: str, *, timestamp: datetime) -> IncidentCandidate:
    """Build one incident candidate holding a single alert.

    Inputs:
        candidate_id: Candidate ID.
        timestamp: Candidate activity time.

    Outputs:
        IncidentCandidate object.
    """

    alert = _alert(f"ALERT-{candidate_id}", timestamp=timestamp)
    return IncidentCandidate(
        id=candidate_id,
        first_seen=timestamp,
        last_seen=timestamp,
        alerts=[alert],
        primary_host="WIN-FIN-01",
        primary_user="jdoe",
        src_ips=["10.0.1.50"],
        dst_ips=["203.0.113.10"],
        created_at=timestamp,
    )


def _triage(triage_id: str, candidate_id: str, *, score: int = 9) -> TriageResult:
    """Build one triage result for a candidate.

    Inputs:
        triage_id: Triage result ID.
        candidate_id: Candidate the result scores.
        score: Triage score.

    Outputs:
        TriageResult object.
    """

    return TriageResult(
        id=triage_id,
        target_id=candidate_id,
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive_high_priority",
        action=TriageAction.PAGE_NOW,
        summary="Encoded PowerShell reached a public address.",
        reasoning="Encoded command line plus external destination.",
        recommended_actions=["Isolate the host", "Collect the PowerShell log"],
        created_at=BASE_TIME,
    )


def _seed_incident(
    store: SQLiteStore,
    incident_id: str,
    *,
    candidate_id: str,
    created_at: datetime,
    score: int = 9,
    host: str = "WIN-FIN-01",
) -> Incident:
    """Seed one incident with its candidate and triage result.

    Inputs:
        store: Initialized store.
        incident_id: Incident ID to save.
        candidate_id: Candidate ID belonging to the incident.
        created_at: Incident creation time, which also orders `list`.
        score: Maximum triage score in the incident.
        host: Primary host.

    Outputs:
        The saved Incident object.
    """

    candidate = _candidate(candidate_id, timestamp=created_at)
    triage = _triage(f"TRI-{candidate_id}", candidate_id, score=score)
    store.save_alert(candidate.alerts[0])
    store.save_incident_candidate(candidate)
    store.save_triage_result(triage)

    incident = Incident(
        id=incident_id,
        candidate_ids=[candidate_id],
        alert_ids=[candidate.alerts[0].id],
        triage_result_ids=[triage.id],
        first_seen=created_at,
        last_seen=created_at + timedelta(minutes=5),
        primary_host=host,
        primary_user="jdoe",
        src_ips=["10.0.1.50"],
        dst_ips=["203.0.113.10"],
        max_score=score,
        created_at=created_at,
    )
    store.save_incident(incident)
    return incident


def _store(tmp_path: Path) -> tuple[SQLiteStore, Path, Path]:
    """Create an initialized store plus its database and env file paths.

    Inputs:
        tmp_path: Pytest temporary directory.

    Outputs:
        Tuple of store, database path, and env file path.
    """

    db_path = tmp_path / "soc.db"
    store = SQLiteStore(db_path)
    store.initialize()
    return store, db_path, _env_file(tmp_path, db_path)


class FakeNotifierResult:
    """Minimal stand-in for a NotificationResult."""

    def __init__(self, *, success: bool = True) -> None:
        """Initialize the fake result.

        Inputs:
            success: Whether delivery should be reported as successful.

        Outputs:
            None.
        """

        self.success = success

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation.

        Inputs:
            None.

        Outputs:
            Result dictionary.
        """

        return {"channel": "email", "success": self.success, "destination": "analyst@example.com"}


class FakeDispatcher:
    """Dispatcher that records the messages the CLI tried to send."""

    instances: list[FakeDispatcher] = []

    def __init__(self) -> None:
        """Initialize the fake dispatcher.

        Inputs:
            None.

        Outputs:
            None.
        """

        self.messages: list[object] = []
        FakeDispatcher.instances.append(self)

    @classmethod
    def from_settings(cls, settings: object, *, dry_run: bool = False) -> FakeDispatcher:
        """Build a fake dispatcher the way the CLI builds the real one.

        Inputs:
            settings: Ignored settings object.
            dry_run: Ignored dry-run flag.

        Outputs:
            FakeDispatcher instance.
        """

        del settings, dry_run
        return cls()

    def send(self, message: object) -> list[FakeNotifierResult]:
        """Record one message.

        Inputs:
            message: NotificationMessage the CLI built.

        Outputs:
            List with one successful result.
        """

        self.messages.append(message)
        return [FakeNotifierResult()]


def test_list_with_empty_database_says_so(tmp_path, capsys):
    """An empty incident table must print a clear message, not a blank table."""

    _store_obj, db_path, env_file = _store(tmp_path)

    exit_code = main(["list", "--db", str(db_path), "--env-file", str(env_file)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "No incidents" in output
    assert "INC-" not in output


def test_list_shows_incidents_newest_first(tmp_path, capsys):
    """`list` must order incidents newest first with their key facts."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
        score=6,
        host="WIN-FIN-01",
    )
    _seed_incident(
        store,
        "INC-20260611-001-bbbb",
        candidate_id="CAND-20260611-001-bbbb",
        created_at=BASE_TIME + timedelta(days=1),
        score=9,
        host="WIN-HR-02",
    )

    summary = run_from_args(
        build_parser().parse_args(["list", "--db", str(db_path), "--env-file", str(env_file)])
    )

    assert summary["count"] == 2
    output = capsys.readouterr().out
    first = output.index("INC-20260611-001-bbbb")
    second = output.index("INC-20260610-001-aaaa")
    assert first < second
    assert "WIN-HR-02" in output
    assert "9" in output


def test_list_respects_limit(tmp_path, capsys):
    """`--limit` must bound how many incidents are listed."""

    store, db_path, env_file = _store(tmp_path)
    for index in range(3):
        _seed_incident(
            store,
            f"INC-2026061{index}-001-cccc",
            candidate_id=f"CAND-2026061{index}-001-cccc",
            created_at=BASE_TIME + timedelta(days=index),
        )

    summary = run_from_args(
        build_parser().parse_args(
            ["list", "--limit", "2", "--db", str(db_path), "--env-file", str(env_file)]
        )
    )

    assert summary["count"] == 2
    assert capsys.readouterr().out.count("INC-") >= 2


def test_show_prints_incident_candidates_and_triage(tmp_path, capsys):
    """`show` must print the incident plus the evidence behind it."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )

    summary = run_from_args(
        build_parser().parse_args(
            ["show", "INC-20260610-001-aaaa", "--db", str(db_path), "--env-file", str(env_file)]
        )
    )

    assert summary["incident_id"] == "INC-20260610-001-aaaa"
    assert summary["candidates"] == 1
    assert summary["triage_results"] == 1
    output = capsys.readouterr().out
    assert "INC-20260610-001-aaaa" in output
    assert "CAND-20260610-001-aaaa" in output
    assert "TRI-CAND-20260610-001-aaaa" in output
    assert "Encoded PowerShell reached a public address." in output
    assert "WIN-FIN-01" in output


def test_show_unknown_incident_exits_one(tmp_path, capsys):
    """An unknown incident ID must be a handled error, not a traceback."""

    _store_obj, db_path, env_file = _store(tmp_path)

    exit_code = main(["show", "INC-does-not-exist", "--db", str(db_path), "--env-file", str(env_file)])

    assert exit_code == 1
    assert "INC-does-not-exist" in capsys.readouterr().err


def test_generate_writes_report_file_and_reports_path(tmp_path, capsys):
    """`generate` must write the Markdown report and name the file it wrote."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    output_path = tmp_path / "reports" / "incident.md"

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--output",
                str(output_path),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert summary["output_path"] == str(output_path)
    assert output_path.exists()
    report_text = output_path.read_text(encoding="utf-8")
    assert "INC-20260610-001-aaaa" in report_text
    assert str(output_path) in capsys.readouterr().out


def test_generate_defaults_output_path_to_output_dir(tmp_path):
    """Without --output the report lands in OUTPUT_DIR as <incident-id>.md."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    expected = tmp_path / "out" / "INC-20260610-001-aaaa.md"
    assert summary["output_path"] == str(expected)
    assert expected.exists()


def test_generate_no_llm_states_templated_provenance(tmp_path, capsys):
    """A templated report must never be mistakable for a model-drafted one."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    output_path = tmp_path / "incident.md"

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--output",
                str(output_path),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert summary["narrative_mode"] == "templated"
    assert summary["narrative_model"] is None
    assert summary["narrative_requested"] == "templated"
    assert "templated" in output_path.read_text(encoding="utf-8").lower()
    assert "templated" in capsys.readouterr().out.lower()


def test_generate_without_api_key_falls_back_to_templated(tmp_path):
    """No OPENROUTER_API_KEY means a templated report, and the summary says so."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--output",
                str(tmp_path / "incident.md"),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert summary["narrative_requested"] == "templated"
    assert summary["narrative_mode"] == "templated"


def test_generate_notes_reach_the_report(tmp_path):
    """Analyst notes passed with --notes must appear in the written report."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    output_path = tmp_path / "incident.md"

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--notes",
                "Host was already isolated by the on-call analyst.",
                "--output",
                str(output_path),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert summary["analyst_notes"] is True
    assert "Host was already isolated by the on-call analyst." in output_path.read_text(encoding="utf-8")


def test_generate_notes_file_reaches_the_report(tmp_path):
    """Analyst notes read from --notes-file must appear in the written report."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    notes_file = tmp_path / "notes.txt"
    notes_file.write_text("Ticket SOC-4412 tracks the containment.\n", encoding="utf-8")
    output_path = tmp_path / "incident.md"

    run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--notes-file",
                str(notes_file),
                "--output",
                str(output_path),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert "Ticket SOC-4412 tracks the containment." in output_path.read_text(encoding="utf-8")


def test_notes_and_notes_file_are_mutually_exclusive():
    """Two sources of notes would silently drop one, so argparse must refuse."""

    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--notes",
                "inline",
                "--notes-file",
                "notes.txt",
            ]
        )

    assert exc_info.value.code == 2


def test_missing_notes_file_is_a_cli_error(tmp_path):
    """A missing notes file must raise CliError rather than a traceback."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    args = build_parser().parse_args(
        [
            "generate",
            "INC-20260610-001-aaaa",
            "--no-llm",
            "--notes-file",
            str(tmp_path / "absent.txt"),
            "--db",
            str(db_path),
            "--env-file",
            str(env_file),
        ]
    )

    with pytest.raises(CliError, match="notes file"):
        run_from_args(args)


def test_generate_unknown_incident_exits_one(tmp_path, capsys):
    """An unknown incident ID on generate must exit 1 with a clear message."""

    _store_obj, db_path, env_file = _store(tmp_path)

    exit_code = main(
        [
            "generate",
            "INC-nope",
            "--no-llm",
            "--db",
            str(db_path),
            "--env-file",
            str(env_file),
        ]
    )

    assert exit_code == 1
    assert "INC-nope" in capsys.readouterr().err


def test_generate_email_sends_report_as_attachment(tmp_path, monkeypatch):
    """--email must deliver the report as an attachment, not only in the body."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    FakeDispatcher.instances.clear()
    monkeypatch.setattr(run_report, "NotificationDispatcher", FakeDispatcher)
    output_path = tmp_path / "incident.md"

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--email",
                "--output",
                str(output_path),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert summary["email"] is True
    assert summary["notifications"] == [
        {"channel": "email", "success": True, "destination": "analyst@example.com"}
    ]
    message = FakeDispatcher.instances[0].messages[0]
    assert len(message.attachments) == 1
    attachment = message.attachments[0]
    assert attachment.filename == "incident.md"
    assert attachment.subtype == "markdown"
    assert attachment.content == output_path.read_text(encoding="utf-8")
    assert "INC-20260610-001-aaaa" in message.subject
    # The body must stand alone for a client that cannot render the attachment.
    assert "INC-20260610-001-aaaa" in message.body
    assert "templated" in message.body.lower()


def test_generate_without_email_flag_sends_nothing(tmp_path, monkeypatch):
    """Absent --email the CLI writes the file and contacts no channel."""

    store, db_path, env_file = _store(tmp_path)
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    FakeDispatcher.instances.clear()
    monkeypatch.setattr(run_report, "NotificationDispatcher", FakeDispatcher)

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--no-llm",
                "--output",
                str(tmp_path / "incident.md"),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert summary["email"] is False
    assert FakeDispatcher.instances == []


def test_db_flag_overrides_settings_default(tmp_path, capsys):
    """--db must win over SQLITE_DB_PATH from the env file."""

    settings_db = tmp_path / "settings.db"
    settings_store = SQLiteStore(settings_db)
    settings_store.initialize()
    _seed_incident(
        settings_store,
        "INC-20260610-999-eeee",
        candidate_id="CAND-20260610-999-eeee",
        created_at=BASE_TIME,
    )
    env_file = _env_file(tmp_path, settings_db)

    override_db = tmp_path / "override.db"
    override_store = SQLiteStore(override_db)
    override_store.initialize()
    _seed_incident(
        override_store,
        "INC-20260610-777-ffff",
        candidate_id="CAND-20260610-777-ffff",
        created_at=BASE_TIME,
    )

    summary = run_from_args(
        build_parser().parse_args(["list", "--db", str(override_db), "--env-file", str(env_file)])
    )

    assert summary["db_path"] == str(override_db)
    output = capsys.readouterr().out
    assert "INC-20260610-777-ffff" in output
    assert "INC-20260610-999-eeee" not in output


def test_narrative_provenance_never_claims_a_model_without_evidence():
    """A requested draft that fell back to the template must read as templated.

    Mislabeling a templated narrative as model-drafted is the failure this
    project refuses, so only a recorded model counts as evidence.
    """

    class ReportWithoutModel:
        """Report whose narrative was produced by the deterministic renderer."""

        generated_by_model = None

    mode, model = run_report.narrative_provenance(
        ReportWithoutModel(),
        requested_model="vendor/model-x",
    )

    assert mode == "templated"
    assert model is None


def test_narrative_provenance_reports_model_recorded_on_the_report():
    """When the report records a drafting model, the CLI reports it."""

    class ReportWithModel:
        """Report whose narrative a model genuinely drafted."""

        generated_by_model = "vendor/model-x"

    mode, model = run_report.narrative_provenance(
        ReportWithModel(),
        requested_model="vendor/model-x",
    )

    assert mode == "model_drafted"
    assert model == "vendor/model-x"


class FakeNarrativeClient:
    """Narrative client that returns usable JSON prose without any network."""

    instances: list[FakeNarrativeClient] = []

    def __init__(self, model: str | None) -> None:
        """Initialize the fake client.

        Inputs:
            model: Model the CLI asked for.

        Outputs:
            None.
        """

        self.model = model
        self.prompts: list[str] = []
        FakeNarrativeClient.instances.append(self)

    @classmethod
    def from_settings(cls, settings: object, *, model: str | None = None, **kwargs: object) -> FakeNarrativeClient:
        """Build the fake client the way the CLI builds the real one.

        Inputs:
            settings: Ignored settings object.
            model: Model override the CLI selected.
            kwargs: Ignored extra keyword arguments.

        Outputs:
            FakeNarrativeClient instance.
        """

        del settings, kwargs
        return cls(model)

    def complete_text(self, prompt: str, **kwargs: object) -> str:
        """Return drafted narrative sections as JSON.

        Inputs:
            prompt: Report prompt.
            kwargs: Ignored generation parameters.

        Outputs:
            JSON text holding the four prose sections.
        """

        del kwargs
        self.prompts.append(prompt)
        return (
            '{"executive_summary": "A model wrote this summary.",'
            ' "attack_narrative": "A model wrote this narrative.",'
            ' "remediation": "A model wrote this remediation.",'
            ' "detection_gaps": "A model wrote this gap analysis."}'
        )


def test_generate_prefers_report_model_and_states_model_provenance(tmp_path, monkeypatch, capsys):
    """A model-drafted report must name its model, and use the report model.

    `OPENROUTER_REPORT_MODEL` exists so reports can use a better model than
    triage, so the CLI must prefer it over `OPENROUTER_MODEL`.
    """

    db_path = tmp_path / "soc.db"
    store = SQLiteStore(db_path)
    store.initialize()
    env_file = _env_file(
        tmp_path,
        db_path,
        extra=[
            "OPENROUTER_API_KEY=fake-key-do-not-report",
            "OPENROUTER_MODEL=vendor/triage-model",
            "OPENROUTER_REPORT_MODEL=vendor/report-model",
        ],
    )
    _seed_incident(
        store,
        "INC-20260610-001-aaaa",
        candidate_id="CAND-20260610-001-aaaa",
        created_at=BASE_TIME,
    )
    FakeNarrativeClient.instances.clear()
    monkeypatch.setattr(run_report, "OpenRouterClient", FakeNarrativeClient)
    output_path = tmp_path / "incident.md"

    summary = run_from_args(
        build_parser().parse_args(
            [
                "generate",
                "INC-20260610-001-aaaa",
                "--output",
                str(output_path),
                "--db",
                str(db_path),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert FakeNarrativeClient.instances[0].model == "vendor/report-model"
    assert summary["narrative_requested"] == "model_drafted"
    assert summary["narrative_mode"] == "model_drafted"
    assert summary["narrative_model"] == "vendor/report-model"
    assert summary["narrative_fallback"] is False
    report_text = output_path.read_text(encoding="utf-8")
    assert "A model wrote this summary." in report_text
    assert "vendor/report-model" in report_text
    assert "model-drafted" in capsys.readouterr().out
