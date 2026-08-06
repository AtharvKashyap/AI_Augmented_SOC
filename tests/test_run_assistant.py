"""Tests for the run_assistant read-only analyst CLI.

Like `tests/test_run_review.py`, these tests drive a real `SQLiteStore` on a
`tmp_path` database seeded through the real persistence API: the assistant is
purely persistence-facing, so a fake store would hide the SQL that has to work.

Every test uses `--ask`, the single-question path. The REPL is a thin loop over
that same code, so testing the loop would only test `input()`.

`--db` and `--env-file` are always passed explicitly, because `get_settings`
uses `load_dotenv`, which writes into `os.environ` permanently and does not
override already-set variables.
"""

from __future__ import annotations

import ast
import inspect
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import run_assistant
from run_assistant import build_parser, main, run_from_args
from soc.incidents import Incident
from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    EventSource,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
)
from soc.store import SQLiteStore

BASE_TIME = datetime(2026, 6, 10, 9, 30, 0, tzinfo=UTC)


def _env_file(tmp_path: Path, db_path: Path, *, extra: list[str] | None = None) -> Path:
    """Write a real .env file pointing at a throwaway database.

    Inputs:
        tmp_path: Pytest temporary directory.
        db_path: Database path to record as SQLITE_DB_PATH.
        extra: Optional extra KEY=VALUE lines.

    Outputs:
        Path to the written env file.
    """

    lines = [
        f"SQLITE_DB_PATH={db_path}",
        f"OUTPUT_DIR={tmp_path / 'out'}",
        f"LOG_DIR={tmp_path / 'logs'}",
    ]
    lines.extend(extra or [])
    env_file = tmp_path / ".env.test"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_file


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


def _alert(
    alert_id: str,
    *,
    severity: AlertSeverity = AlertSeverity.HIGH,
    src_ip: str | None = "8.8.8.8",
    hostname: str | None = "endpoint-01",
    timestamp: datetime = BASE_TIME,
    rule_name: str = "sshd brute force",
    raw: dict | None = None,
) -> Alert:
    """Build one alert for seeding.

    Inputs:
        alert_id: Alert ID.
        severity: Normalized severity.
        src_ip: Source address.
        hostname: Hostname.
        timestamp: Event time.
        rule_name: Rule name.
        raw: Original source payload.

    Outputs:
        Alert instance.
    """

    return Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=timestamp,
        severity=severity,
        rule_name=rule_name,
        src_ip=src_ip,
        hostname=hostname,
        user="root",
        raw=raw if raw is not None else {"rule": {"level": 10}},
    )


def _ask(tmp_path: Path, db_path: Path, question: str, *extra_argv: str, env_file: Path | None = None):
    """Run one `--ask` invocation and return its summary.

    Inputs:
        tmp_path: Pytest temporary directory.
        db_path: Database path.
        question: Question to ask.
        extra_argv: Extra command-line arguments.
        env_file: Optional pre-written env file.

    Outputs:
        JSON-safe summary dictionary from `run_from_args`.
    """

    env = env_file or _env_file(tmp_path, db_path)
    argv = ["--ask", question, "--db", str(db_path), "--env-file", str(env), *extra_argv]
    return run_from_args(build_parser().parse_args(argv))


def _triage(triage_id: str, target_id: str, *, score: int = 5) -> TriageResult:
    """Build one triage result for seeding the review queue.

    Inputs:
        triage_id: Triage result ID.
        target_id: Alert or candidate ID under triage.
        score: Triage score.

    Outputs:
        TriageResult instance.
    """

    return TriageResult(
        id=triage_id,
        target_id=target_id,
        target_type="alert",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="brute_force",
        action=TriageAction.QUEUE_REVIEW,
        summary="Repeated failed SSH logins followed by a success.",
        analysis_source=AnalysisSource.LLM,
    )


def _incident_payload(incident_id: str, *, primary_host: str, src_ip: str) -> object:
    """Build a minimal object the store can persist as an incident.

    `SQLiteStore.save_incident` takes anything exposing the incident attributes
    plus `to_dict()`, so a small stand-in keeps the seeding readable.

    Inputs:
        incident_id: Incident ID.
        primary_host: Host the incident centres on.
        src_ip: Source address involved.

    Outputs:
        Object suitable for `save_incident`.
    """

    return Incident(
        id=incident_id,
        candidate_ids=["CAND-20260610-001-aaaa"],
        alert_ids=["ALERT-1"],
        triage_result_ids=["TRIAGE-1"],
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        primary_host=primary_host,
        primary_user="root",
        src_ips=[src_ip],
        max_score=9,
        created_at=BASE_TIME,
    )


class FakeProposal:
    """Minimal stand-in for a recorded response proposal.

    The assistant must be able to *display* recorded actions without importing
    anything that can approve or execute one, so the test seeds the audit row
    directly rather than driving `soc.response`.
    """

    def __init__(self, proposal_id: str) -> None:
        """Initialize the fake proposal.

        Inputs:
            proposal_id: Proposal ID to record.

        Outputs:
            None.
        """

        self.id = proposal_id
        self.playbook_name = "block-external-brute-force"
        self.action = SimpleNamespace(value="pf_block_ip")
        self.target = "8.8.8.8"
        self.triage_result_id = "TRIAGE-1"
        self.triage_score = 9
        self.analysis_source = SimpleNamespace(value="llm")
        self.status = SimpleNamespace(value="executed")
        self.approved_by = "alice"
        self.command = "pfctl -t soc_block -T add 8.8.8.8"
        self.rollback_command = "pfctl -t soc_block -T delete 8.8.8.8"
        self.dry_run = False
        self.created_at = BASE_TIME

    def to_dict(self) -> dict:
        """Return the audit payload the store persists.

        Inputs:
            None.

        Outputs:
            JSON-safe dictionary.
        """

        return {
            "id": self.id,
            "playbook_name": self.playbook_name,
            "action": self.action.value,
            "target": self.target,
            "triage_result_id": self.triage_result_id,
            "triage_score": self.triage_score,
            "analysis_source": self.analysis_source.value,
            "status": self.status.value,
            "reason": "score 9 from a model result",
            "approved_by": self.approved_by,
            "command": self.command,
            "rollback_command": self.rollback_command,
            "dry_run": self.dry_run,
            "created_at": self.created_at.isoformat(),
        }


def test_ask_against_empty_database_answers_gracefully(tmp_path, capsys):
    """An empty store is a normal state, not an error.

    A brand-new deployment has no alerts. The assistant must say so and exit
    zero rather than raising or inventing activity.
    """

    db_path = tmp_path / "soc.db"
    _store(db_path)

    summary = _ask(tmp_path, db_path, "summarize today's high alerts")

    assert summary["answer_mode"] == "deterministic"
    output = capsys.readouterr().out
    assert "no" in output.lower()
    assert summary["context"]["alert_count"] == 0


def test_high_alerts_question_summarizes_only_serious_alerts(tmp_path, capsys):
    """"Today's high alerts" must not quietly include low-severity noise."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-HIGH-1", severity=AlertSeverity.HIGH))
    store.save_alert(_alert("ALERT-CRIT-1", severity=AlertSeverity.CRITICAL, hostname="db-01"))
    store.save_alert(_alert("ALERT-LOW-1", severity=AlertSeverity.LOW, hostname="printer-01"))

    summary = _ask(tmp_path, db_path, "summarize today's high alerts")

    output = capsys.readouterr().out
    assert "ALERT-HIGH-1" in output
    assert "ALERT-CRIT-1" in output
    assert "ALERT-LOW-1" not in output
    assert summary["context"]["alert_count"] == 3


def test_queue_question_lists_open_queue_items(tmp_path, capsys):
    """The review queue is the analyst's actual workload, so it must be askable."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-Q-1"))
    result = _triage("TRIAGE-Q-1", "ALERT-Q-1", score=6)
    store.save_triage_result(result)
    store.enqueue_for_review(result)

    summary = _ask(tmp_path, db_path, "what is in the review queue")

    output = capsys.readouterr().out
    assert "TRIAGE-Q-1" in output
    assert "ALERT-Q-1" in output
    assert summary["context"]["queue_count"] == 1
    assert summary["answer_mode"] == "deterministic"


def test_incidents_question_lists_recorded_incidents(tmp_path, capsys):
    """An incident is what a human opens a case for, so it must be askable."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_incident(_incident_payload("INC-20260610-001-aaaa", primary_host="db-01", src_ip="8.8.8.8"))

    summary = _ask(tmp_path, db_path, "what incidents are open")

    output = capsys.readouterr().out
    assert "INC-20260610-001-aaaa" in output
    assert "db-01" in output
    assert summary["context"]["incident_count"] == 1


def test_alerts_from_ip_question_lists_only_matching_alerts(tmp_path, capsys):
    """"Show all alerts from this IP" must filter, not dump the whole store."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-IP-MATCH", src_ip="8.8.8.8"))
    store.save_alert(_alert("ALERT-IP-OTHER", src_ip="1.1.1.1", hostname="web-01"))

    _ask(tmp_path, db_path, "show all alerts from 8.8.8.8 in the last 24h")

    output = capsys.readouterr().out
    assert "ALERT-IP-MATCH" in output
    assert "ALERT-IP-OTHER" not in output


def test_blast_radius_names_asset_criticality_from_the_inventory(tmp_path, capsys):
    """Blast radius without criticality is reach without impact.

    Asset criticality is usually what turns "this host had alerts" into "this
    matters", so a configured inventory must be reflected in the answer.
    """

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-BR-1", hostname="db-01", src_ip="10.0.1.42"))
    store.save_alert(_alert("ALERT-BR-OTHER", hostname="printer-01", src_ip="10.0.9.9"))
    store.save_incident(_incident_payload("INC-20260610-002-bbbb", primary_host="db-01", src_ip="10.0.1.42"))

    inventory = tmp_path / "assets.csv"
    inventory.write_text(
        "hostname,ip,owner,criticality,internet_facing\ndb-01,10.0.1.42,dba-team,critical,false\n",
        encoding="utf-8",
    )
    env_file = _env_file(tmp_path, db_path, extra=[f"ASSET_INVENTORY_PATH={inventory}"])

    summary = _ask(
        tmp_path,
        db_path,
        "what is the blast radius if 10.0.1.42 is compromised",
        env_file=env_file,
    )

    output = capsys.readouterr().out
    assert "critical" in output
    assert "ALERT-BR-1" in output
    assert "INC-20260610-002-bbbb" in output
    assert "ALERT-BR-OTHER" not in output
    assert summary["asset_inventory_configured"] is True
    assert summary["context"]["asset_count"] == 1


def test_unrecognized_question_explains_what_it_can_answer(tmp_path, capsys):
    """An unmatched question is normal input, not an error, and must not be guessed at."""

    db_path = tmp_path / "soc.db"
    _store(db_path)

    summary = _ask(tmp_path, db_path, "who won the football on saturday")

    output = capsys.readouterr().out
    assert "could not match" in output.lower()
    assert "blast radius" in output.lower()
    assert summary["answer_mode"] == "deterministic"


def test_response_actions_are_displayable_but_only_as_history(tmp_path, capsys):
    """Reading response history is safe; the answer must say it cannot act."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(FakeProposal("RESP-0001"))

    summary = _ask(tmp_path, db_path, "what response actions were recorded")

    output = capsys.readouterr().out
    assert "RESP-0001" in output
    assert "pf_block_ip" in output
    assert "alice" in output
    assert "separate response CLI" in output
    assert summary["context"]["response_action_count"] == 1


def test_no_llm_marks_the_answer_deterministic_even_with_a_key(tmp_path, capsys, monkeypatch):
    """`--no-llm` must force stored-data answers and say so, like run_pipeline.py."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-NOLLM-1"))
    env_file = _env_file(tmp_path, db_path, extra=["OPENROUTER_API_KEY=fake-key-do-not-report"])

    def _explode(*args: object, **kwargs: object) -> None:
        """Fail loudly if a client is built despite --no-llm."""

        del args, kwargs
        raise AssertionError("--no-llm must not build a model client")

    monkeypatch.setattr(run_assistant.OpenRouterClient, "from_settings", _explode)

    summary = _ask(tmp_path, db_path, "summarize today's high alerts", "--no-llm", env_file=env_file)

    output = capsys.readouterr().out
    assert summary["answer_mode"] == "deterministic"
    assert summary["model"] is None
    assert "deterministic" in output.lower()


class FakeAssistantClient:
    """Chat client that answers without any network."""

    instances: list[FakeAssistantClient] = []

    def __init__(self, model: str | None) -> None:
        """Initialize the fake client.

        Inputs:
            model: Model the CLI asked for.

        Outputs:
            None.
        """

        self.model = model
        self.prompts: list[str] = []
        FakeAssistantClient.instances.append(self)

    @classmethod
    def from_settings(cls, settings: object, *, model: str | None = None, **kwargs: object) -> FakeAssistantClient:
        """Build the fake client the way the CLI builds the real one.

        Inputs:
            settings: Ignored settings object.
            model: Model override the CLI selected.
            kwargs: Ignored extra keyword arguments.

        Outputs:
            FakeAssistantClient instance.
        """

        del settings, kwargs
        return cls(model)

    def chat_completion(self, messages: list[dict], **kwargs: object) -> SimpleNamespace:
        """Return one canned assistant answer.

        Inputs:
            messages: Chat messages, whose last entry is the prompt.
            kwargs: Ignored generation parameters.

        Outputs:
            Object exposing content and model, like ChatCompletionResult.
        """

        del kwargs
        self.prompts.append(str(messages[-1]["content"]))
        return SimpleNamespace(
            content="One high alert on endpoint-01 (ALERT-LLM-1).",
            model=self.model,
            usage={},
            raw={},
        )


def test_model_backed_answer_is_marked_as_such_and_names_the_model(tmp_path, capsys, monkeypatch):
    """A model answer must be labelled a model answer and name the model."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-LLM-1"))
    env_file = _env_file(
        tmp_path,
        db_path,
        extra=[
            "OPENROUTER_API_KEY=fake-key-do-not-report",
            "OPENROUTER_MODEL=vendor/assistant-model",
        ],
    )
    FakeAssistantClient.instances.clear()
    monkeypatch.setattr(run_assistant, "OpenRouterClient", FakeAssistantClient)

    summary = _ask(tmp_path, db_path, "summarize today's high alerts", env_file=env_file)

    output = capsys.readouterr().out
    assert summary["answer_mode"] == "model"
    assert summary["model"] == "vendor/assistant-model"
    assert summary["prompt_version"] == run_assistant.ASSISTANT_PROMPT_VERSION
    assert "vendor/assistant-model" in output
    assert "One high alert on endpoint-01 (ALERT-LLM-1)." in output


def test_prompt_never_contains_the_raw_alert_payload(tmp_path, monkeypatch):
    """Raw alert payloads are attacker-controlled and must not reach the model.

    The assistant reuses the triage context allowlist, so a field nobody
    allowlisted cannot leak into the prompt no matter what the source recorded.
    """

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    canary = "CANARY-RAW-PAYLOAD-MUST-NOT-LEAK"
    store.save_alert(
        _alert(
            "ALERT-CANARY-1",
            raw={
                "rule": {"level": 12, "description": canary},
                "data": {"secret_field": canary},
                "previous_output": canary,
            },
        )
    )
    env_file = _env_file(
        tmp_path,
        db_path,
        extra=["OPENROUTER_API_KEY=fake-key-do-not-report", "OPENROUTER_MODEL=vendor/assistant-model"],
    )
    FakeAssistantClient.instances.clear()
    monkeypatch.setattr(run_assistant, "OpenRouterClient", FakeAssistantClient)

    _ask(tmp_path, db_path, "summarize today's high alerts", env_file=env_file)

    assert FakeAssistantClient.instances, "the fake client should have been used"
    prompts = FakeAssistantClient.instances[-1].prompts
    assert prompts, "a prompt should have been sent"
    assert canary not in prompts[0]
    # The allowlisted fields still got through, so this is filtering rather than
    # an empty context.
    assert "ALERT-CANARY-1" in prompts[0]


def test_module_cannot_approve_or_execute_a_response_action():
    """The assistant must be structurally unable to act.

    Alert content reaches this module's context and is attacker-controlled, so an
    assistant that could approve or execute would be a remote-code-execution path
    wearing a chat interface. This inspects the module source rather than trusting
    review, so the property cannot regress silently.
    """

    source = inspect.getsource(run_assistant)
    tree = ast.parse(source)

    # Executable code only: the module docstring explains the read-only rule and
    # necessarily names the things it refuses to use.
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if isinstance(node, ast.ImportFrom):
            assert node.module != "soc.response", "the assistant must not import the response layer"
        if isinstance(node, ast.Import):
            assert all(alias.name != "soc.response" for alias in node.names)
        if isinstance(node, ast.Call):
            called = node.func
            name = called.attr if isinstance(called, ast.Attribute) else getattr(called, "id", "")
            assert name not in {"approve", "execute", "ResponseGate"}, f"assistant must not call {name}()"

    assert not re.search(r"\bResponseGate\b", _strip_docstrings(source))
    # Reading recorded history is the only response-related capability.
    assert "list_response_actions" in code


def _strip_docstrings(source: str) -> str:
    """Return module source with every docstring removed.

    The read-only property is about what the code does, not about what the prose
    explaining that property is allowed to mention.

    Inputs:
        source: Python module source.

    Outputs:
        Source text with docstring expressions blanked out.
    """

    tree = ast.parse(source)
    lines = source.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, str):
            continue
        for index in range(node.lineno - 1, (node.end_lineno or node.lineno)):
            lines[index] = ""
    return "\n".join(lines)


def test_db_flag_overrides_the_settings_default(tmp_path, capsys):
    """`--db` must win over SQLITE_DB_PATH, or a test could read the real database."""

    settings_db = tmp_path / "settings.db"
    chosen_db = tmp_path / "chosen.db"
    _store(settings_db)
    store = _store(chosen_db)
    store.save_alert(_alert("ALERT-CHOSEN-1"))
    env_file = _env_file(tmp_path, settings_db)

    summary = run_from_args(
        build_parser().parse_args(
            [
                "--ask",
                "summarize today's high alerts",
                "--db",
                str(chosen_db),
                "--env-file",
                str(env_file),
            ]
        )
    )

    assert Path(summary["db_path"]) == chosen_db
    assert "ALERT-CHOSEN-1" in capsys.readouterr().out


def test_main_returns_130_on_keyboard_interrupt(tmp_path, monkeypatch, capsys):
    """Ctrl-C in an interactive tool is an interrupt, not a crash."""

    db_path = tmp_path / "soc.db"
    _store(db_path)
    env_file = _env_file(tmp_path, db_path)

    def _interrupt(args: object) -> dict:
        """Raise KeyboardInterrupt the way an interrupted REPL would."""

        del args
        raise KeyboardInterrupt

    monkeypatch.setattr(run_assistant, "run_from_args", _interrupt)

    exit_code = main(["--ask", "anything", "--db", str(db_path), "--env-file", str(env_file)])

    assert exit_code == 130
    assert "interrupted" in capsys.readouterr().err


def test_bad_alert_limit_is_a_cli_error(tmp_path, capsys):
    """A non-positive context bound is a user error, reported as exit 1."""

    db_path = tmp_path / "soc.db"
    _store(db_path)
    env_file = _env_file(tmp_path, db_path)

    exit_code = main(
        ["--ask", "queue", "--alert-limit", "0", "--db", str(db_path), "--env-file", str(env_file)]
    )

    assert exit_code == 1
    assert "--alert-limit" in capsys.readouterr().err


def test_repl_answers_until_eof(tmp_path, monkeypatch, capsys):
    """The REPL is thin, but it must actually reach the single-question path."""

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_alert(_alert("ALERT-REPL-1"))
    env_file = _env_file(tmp_path, db_path)
    questions = iter(["what is in the review queue", "exit"])

    monkeypatch.setattr("builtins.input", lambda _prompt="": next(questions))

    summary = run_from_args(
        build_parser().parse_args(["--db", str(db_path), "--env-file", str(env_file)])
    )

    assert summary["mode"] == "interactive"
    assert summary["questions_answered"] == 1
    assert "review queue is empty" in capsys.readouterr().out


def test_pretty_prints_the_json_summary(tmp_path, capsys):
    """The JSON summary must report provenance for machine consumers too."""

    db_path = tmp_path / "soc.db"
    _store(db_path)
    env_file = _env_file(tmp_path, db_path)

    run_from_args(
        build_parser().parse_args(
            ["--ask", "queue", "--pretty", "--db", str(db_path), "--env-file", str(env_file)]
        )
    )

    output = capsys.readouterr().out
    assert '"answer_mode": "deterministic"' in output


def test_unreadable_configured_asset_inventory_fails_loudly(tmp_path, capsys):
    """A configured-but-missing inventory must not degrade into a silent empty one."""

    db_path = tmp_path / "soc.db"
    _store(db_path)
    env_file = _env_file(tmp_path, db_path, extra=[f"ASSET_INVENTORY_PATH={tmp_path / 'missing.csv'}"])

    exit_code = main(
        ["--ask", "queue", "--db", str(db_path), "--env-file", str(env_file)]
    )

    assert exit_code == 1
    assert "asset inventory" in capsys.readouterr().err.lower()


def test_parser_exposes_no_action_verb():
    """No flag or subcommand may exist that could approve or execute anything."""

    parser = build_parser()
    flags = {option for action in parser._actions for option in action.option_strings}

    assert "--ask" in flags
    assert not any(word in flag for flag in flags for word in ("approve", "execute", "block", "isolate"))
    with pytest.raises(SystemExit):
        parser.parse_args(["approve", "RESP-0001"])
