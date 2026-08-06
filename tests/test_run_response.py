"""Tests for the run_response approval CLI.

Like `tests/test_run_review.py`, these tests drive a real `SQLiteStore` on a
`tmp_path` database seeded through the real persistence API: the response CLI is
persistence-facing and the store is also the audit sink the gate refuses to act
without, so a fake store would hide the SQL that has to work.

No test is allowed to open SSH or HTTP. Executors are injected by monkeypatching
the module-level `build_executor` seam with a recording fake, which also lets a
test assert that a command was *not* performed.

`--db` and `--env-file` are always passed explicitly. `get_settings` uses
`load_dotenv`, which writes into `os.environ` and does not override variables
that are already set, so relying on ambient configuration would make these tests
order-dependent.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc.models import (
    AnalysisSource,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
)
from soc.response import (
    ResponseActionType,
    ResponseProposal,
    ResponseStatus,
)
from soc.store import SQLiteStore
from soc.wazuh_response import WAZUH_ROLLBACK_UNAVAILABLE

WAZUH_SECRET = "sup3r-secret-manager-password"
"""Credential planted in settings so output can be checked for leaks."""

PF_PLAYBOOK = {
    "name": "pf-block-malicious-ip",
    "action": "pf_block_ip",
    "required_confidence": 9,
    "requires_confirmation": True,
    "enabled": True,
    "trigger_actions": ["page_now"],
    "description": "Block a model-confirmed malicious external address.",
}

WAZUH_PLAYBOOK = {
    "name": "wazuh-host-deny",
    "action": "wazuh_host_deny",
    "required_confidence": 9,
    "requires_confirmation": True,
    "enabled": True,
    "trigger_actions": ["page_now"],
    "description": "Deny a confirmed malicious source on one Wazuh agent.",
}


def _playbook_dir(tmp_path: Path, *records: dict) -> Path:
    """Write playbook JSON files into a throwaway directory.

    Inputs:
        tmp_path: Pytest temporary directory.
        records: Playbook records to write, one file each.

    Outputs:
        Path to the playbook directory.
    """

    directory = tmp_path / "playbooks"
    directory.mkdir(exist_ok=True)
    for record in records:
        (directory / f"{record['name']}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
    return directory


def _env_file(tmp_path: Path, db_path: Path, **overrides: str) -> Path:
    """Write a real .env file pointing at a throwaway database.

    Inputs:
        tmp_path: Pytest temporary directory.
        db_path: Database path to record as SQLITE_DB_PATH.
        overrides: Settings to add or replace.

    Outputs:
        Path to the written env file.
    """

    values = {
        "SQLITE_DB_PATH": str(db_path),
        "OUTPUT_DIR": str(tmp_path / "out"),
        "LOG_DIR": str(tmp_path / "logs"),
        "PLAYBOOK_DIR": str(tmp_path / "playbooks"),
        "RESPONSE_PF_BLOCK_ENABLED": "true",
        "RESPONSE_WAZUH_HOST_DENY_ENABLED": "true",
        "OPENBSD_PF_HOST": "fw.example.net",
        "OPENBSD_PF_USER": "socbot",
        "OPENBSD_PF_BLOCK_TABLE": "soc_blocklist",
        "WAZUH_MANAGER_URL": "https://wazuh.example.net:55000",
        "WAZUH_MANAGER_USER": "soc-api",
        "WAZUH_MANAGER_PASSWORD": WAZUH_SECRET,
    }
    values.update(overrides)

    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )
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


def _triage(
    *,
    triage_id: str = "TRIAGE-RESP",
    score: int = 9,
    action: TriageAction = TriageAction.PAGE_NOW,
    analysis_source: AnalysisSource = AnalysisSource.LLM,
) -> TriageResult:
    """Build one triage result suitable for a response proposal.

    Inputs:
        triage_id: Triage result ID.
        score: Triage score.
        action: Routed triage action.
        analysis_source: Whether the score came from a model or local rules.

    Outputs:
        The TriageResult.
    """

    return TriageResult(
        id=triage_id,
        target_id="CAND-20260101-001-abc",
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="command_and_control",
        action=action,
        summary="Beaconing to a known malicious address.",
        iocs={"ipv4": ["8.8.8.8"]},
        recommended_actions=["Block the destination at the perimeter"],
        reasoning="Repeated fixed-interval callbacks to a flagged address.",
        evidence=[
            EvidenceItem(
                source=EventSource.WAZUH,
                field="data.dstip",
                value="8.8.8.8",
                timestamp=datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC),
                alert_id="ALERT-1",
            )
        ],
        analysis_source=analysis_source,
        model="vendor/model-x" if analysis_source is AnalysisSource.LLM else None,
        prompt_version="triage-v1" if analysis_source is AnalysisSource.LLM else None,
    )


def _proposal(
    *,
    proposal_id: str = "RESP-aaaaaaaaaaaa",
    action: ResponseActionType = ResponseActionType.PF_BLOCK_IP,
    playbook_name: str = "pf-block-malicious-ip",
    target: str = "8.8.8.8",
    status: ResponseStatus = ResponseStatus.SUGGESTED,
    analysis_source: AnalysisSource = AnalysisSource.LLM,
    score: int = 9,
    approved_by: str | None = None,
    denial_reason: str = "",
    command: str = "",
    rollback_command: str = "",
    dry_run: bool = True,
) -> ResponseProposal:
    """Build one response proposal for seeding the audit table.

    Inputs:
        proposal_id: Proposal ID.
        action: Response action type.
        playbook_name: Proposing playbook.
        target: Action target.
        status: Lifecycle status.
        analysis_source: Provenance of the score.
        score: Triage score at proposal time.
        approved_by: Approving analyst, when approved.
        denial_reason: Refusal reason, when denied.
        command: Recorded command.
        rollback_command: Recorded rollback command.
        dry_run: Whether the recorded execution was a dry run.

    Outputs:
        The ResponseProposal.
    """

    return ResponseProposal(
        id=proposal_id,
        playbook_name=playbook_name,
        action=action,
        target=target,
        triage_result_id="TRIAGE-RESP",
        triage_score=score,
        analysis_source=analysis_source,
        status=status,
        reason=f"{playbook_name}: score {score} met required confidence 9",
        denial_reason=denial_reason,
        approved_by=approved_by,
        command=command,
        rollback_command=rollback_command,
        dry_run=dry_run,
    )


def _cli(command: str, tmp_path: Path, db_path: Path, *extra: str, **env: str) -> list[str]:
    """Build an argv list with explicit db and env-file arguments.

    Inputs:
        command: Subcommand name.
        tmp_path: Pytest temporary directory.
        db_path: Database path to pass via --db.
        extra: Further arguments.
        env: Settings overrides for the generated env file.

    Outputs:
        argv list.
    """

    return [
        command,
        *extra,
        "--db",
        str(db_path),
        "--env-file",
        str(_env_file(tmp_path, db_path, **env)),
    ]


class FakePfExecutor:
    """Recording stand-in for the pf block executor.

    Attributes:
        action: The action this executor handles.
        executed: Recorded (target, dry_run) execute calls.
        rolled_back: Recorded (target, dry_run) rollback calls.
    """

    action = ResponseActionType.PF_BLOCK_IP

    def __init__(self, *, fail: bool = False) -> None:
        """Initialize the fake.

        Inputs:
            fail: Whether a live execute should raise.

        Outputs:
            None.
        """

        self.executed: list[tuple[str, bool]] = []
        self.rolled_back: list[tuple[str, bool]] = []
        self.fail = fail

    def describe(self, target: str) -> tuple[str, str]:
        """Return the add and delete command text.

        Inputs:
            target: Address to describe.

        Outputs:
            Tuple of (add command, delete command).
        """

        return (
            f"pfctl -t soc_blocklist -T add {target}",
            f"pfctl -t soc_blocklist -T delete {target}",
        )

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Record an execute call.

        Inputs:
            target: Address to block.
            dry_run: Whether this was a dry run.

        Outputs:
            Result text.

        Raises:
            RuntimeError: When constructed with fail=True and not a dry run.
        """

        self.executed.append((target, dry_run))
        if self.fail and not dry_run:
            raise RuntimeError("firewall unreachable")
        if dry_run:
            return f"DRY RUN: would block {target}. No action taken."
        return f"blocked {target}"

    def rollback(self, target: str, *, dry_run: bool) -> str:
        """Record a rollback call.

        Inputs:
            target: Address to unblock.
            dry_run: Whether this was a dry run.

        Outputs:
            Result text.
        """

        self.rolled_back.append((target, dry_run))
        if dry_run:
            return f"DRY RUN: would unblock {target}. No action taken."
        return f"unblocked {target}"


class FakeWazuhExecutor:
    """Recording stand-in for the Wazuh host-deny executor.

    Attributes:
        action: The action this executor handles.
        executed: Recorded (target, dry_run) execute calls.
    """

    action = ResponseActionType.WAZUH_HOST_DENY

    def __init__(self) -> None:
        """Initialize the fake.

        Inputs:
            None.

        Outputs:
            None.
        """

        self.executed: list[tuple[str, bool]] = []

    def describe(self, target: str) -> tuple[str, str]:
        """Return the request text and the honest rollback text.

        Inputs:
            target: Target string.

        Outputs:
            Tuple of (request text, rollback text).
        """

        return (f"PUT /active-response {target}", WAZUH_ROLLBACK_UNAVAILABLE)

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Record an execute call.

        Inputs:
            target: Target string.
            dry_run: Whether this was a dry run.

        Outputs:
            Result text.
        """

        self.executed.append((target, dry_run))
        return f"host-deny accepted for {target}"


def _install_executor(monkeypatch: pytest.MonkeyPatch, executor: object) -> None:
    """Replace the module-level executor seam with a fake.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.
        executor: Fake executor to return for every action.

    Outputs:
        None.
    """

    import run_response

    monkeypatch.setattr(
        run_response,
        "build_executor",
        lambda action, settings: executor,
    )


def test_build_parser_requires_a_command():
    """An operator invoking the CLI bare must be told which verbs exist."""

    from run_response import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_build_parser_defaults_execute_to_inert():
    """Neither safeguard flag may default to true.

    A live firewall change must require both `--confirm` and `--force-live` to be
    typed. If either defaulted to true, running the command by mistake would
    change a firewall.
    """

    from run_response import build_parser

    args = build_parser().parse_args(["execute", "RESP-1", "--analyst", "alice"])

    assert args.confirm is False
    assert args.force_live is False
    assert args.env_file == Path(".env")


def test_list_reports_no_recorded_actions_clearly(tmp_path, capsys):
    """An empty audit table must say so rather than print an empty table."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("list", tmp_path, db_path))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no recorded response actions" in captured.out.lower()


def test_list_shows_analysis_source_on_every_row(tmp_path, capsys):
    """Every row must name its analysis source, approver, and dry-run state.

    An operator has to be able to see at a glance whether a model or a heuristic
    produced the score behind a proposed action.
    """

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(proposal_id="RESP-modelscored", analysis_source=AnalysisSource.LLM)
    )
    store.record_response_action(
        _proposal(
            proposal_id="RESP-localscored",
            analysis_source=AnalysisSource.LOCAL,
            status=ResponseStatus.DENIED,
            denial_reason="triage score was not model-produced",
        )
    )

    exit_code = main(_cli("list", tmp_path, db_path))

    captured = capsys.readouterr()
    assert exit_code == 0
    model_row = next(line for line in captured.out.splitlines() if "RESP-modelscored" in line)
    local_row = next(line for line in captured.out.splitlines() if "RESP-localscored" in line)
    assert "llm" in model_row
    assert "local" in local_row
    assert "denied" in local_row
    assert "pf_block_ip" in model_row
    assert "8.8.8.8" in model_row


def test_list_filters_by_status_and_limit(tmp_path, capsys):
    """--status and --limit must actually narrow the listing."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(_proposal(proposal_id="RESP-suggested"))
    store.record_response_action(
        _proposal(
            proposal_id="RESP-approved",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )

    exit_code = main(_cli("list", tmp_path, db_path, "--status", "approved"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "RESP-approved" in captured.out
    assert "RESP-suggested" not in captured.out
    assert "alice" in captured.out


def test_list_rejects_an_unknown_status(tmp_path, capsys):
    """An unknown --status must be refused rather than silently matching nothing."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("list", tmp_path, db_path, "--status", "probably-fine"))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "probably-fine" in captured.err


def test_show_prints_command_rollback_and_denial_reason(tmp_path, capsys):
    """show must print the command, the rollback, and why a refusal happened."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-detail",
            status=ResponseStatus.DENIED,
            denial_reason="score 6 is below required confidence 9",
            command="pfctl -t soc_blocklist -T add 8.8.8.8",
            rollback_command="pfctl -t soc_blocklist -T delete 8.8.8.8",
        )
    )

    exit_code = main(_cli("show", tmp_path, db_path, "RESP-detail"))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "pfctl -t soc_blocklist -T add 8.8.8.8" in captured.out
    assert "pfctl -t soc_blocklist -T delete 8.8.8.8" in captured.out
    assert "score 6 is below required confidence 9" in captured.out
    assert "llm" in captured.out


def test_show_unknown_proposal_exits_one(tmp_path, capsys):
    """An unknown proposal ID must exit 1, not print an empty record."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    _store(db_path)

    exit_code = main(_cli("show", tmp_path, db_path, "RESP-nope"))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "RESP-nope" in captured.err


def _forbid_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make building any executor a test failure.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.

    Outputs:
        None.
    """

    import run_response

    def _explode(action: object, settings: object) -> object:
        """Fail the test if an executor is built at all."""

        raise AssertionError(f"build_executor must not be called, got {action}")

    monkeypatch.setattr(run_response, "build_executor", _explode)


def test_propose_prints_every_matching_proposal(monkeypatch, tmp_path, capsys):
    """propose must report each playbook that matched and record it."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_triage_result(_triage())
    _playbook_dir(tmp_path, PF_PLAYBOOK, WAZUH_PLAYBOOK)
    _forbid_executor(monkeypatch)

    exit_code = main(
        _cli(
            "propose",
            tmp_path,
            db_path,
            "--triage-result-id",
            "TRIAGE-RESP",
            "--target",
            "8.8.8.8",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "pf-block-malicious-ip" in captured.out
    assert "wazuh-host-deny" in captured.out
    assert "suggested" in captured.out
    recorded = store.list_response_actions()
    assert {action["playbook_name"] for action in recorded} == {
        "pf-block-malicious-ip",
        "wazuh-host-deny",
    }
    assert {action["status"] for action in recorded} == {"suggested"}


def test_propose_prints_refusals_with_their_reasons(monkeypatch, tmp_path, capsys):
    """A refusal must be printed with its reason, not omitted."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_triage_result(_triage(score=7))
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    _forbid_executor(monkeypatch)

    exit_code = main(
        _cli(
            "propose",
            tmp_path,
            db_path,
            "--triage-result-id",
            "TRIAGE-RESP",
            "--target",
            "8.8.8.8",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "denied" in captured.out
    assert "below required confidence 9" in captured.out
    assert store.list_response_actions()[0]["status"] == "denied"


def test_propose_denies_a_locally_scored_result_after_a_database_round_trip(
    monkeypatch, tmp_path, capsys
):
    """A locally scored result must still be refused once reloaded from SQLite.

    The model-score guard is the gate that cannot be configured away. If
    rebuilding a stored triage result lost `analysis_source`, a round trip
    through the database would silently defeat it, so this asserts the refusal
    survives persistence rather than only holding in memory.
    """

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_triage_result(_triage(score=10, analysis_source=AnalysisSource.LOCAL))
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    _forbid_executor(monkeypatch)

    exit_code = main(
        _cli(
            "propose",
            tmp_path,
            db_path,
            "--triage-result-id",
            "TRIAGE-RESP",
            "--target",
            "8.8.8.8",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "not model-produced" in captured.out
    recorded = store.list_response_actions()[0]
    assert recorded["status"] == "denied"
    assert recorded["analysis_source"] == "local"


def test_propose_unknown_triage_result_exits_one(monkeypatch, tmp_path, capsys):
    """A proposal against a triage result nobody stored must fail loudly."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    _store(db_path)
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    _forbid_executor(monkeypatch)

    exit_code = main(
        _cli(
            "propose",
            tmp_path,
            db_path,
            "--triage-result-id",
            "TRIAGE-MISSING",
            "--target",
            "8.8.8.8",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "TRIAGE-MISSING" in captured.err


def test_approve_records_the_named_analyst(tmp_path, capsys):
    """approve must persist the approver, because accountability is the point."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(_proposal(proposal_id="RESP-approveme"))
    _playbook_dir(tmp_path, PF_PLAYBOOK)

    exit_code = main(
        _cli("approve", tmp_path, db_path, "RESP-approveme", "--analyst", "alice")
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "alice" in captured.out
    recorded = store.list_response_actions()[0]
    assert recorded["status"] == "approved"
    assert recorded["approved_by"] == "alice"


def test_approve_rejects_a_blank_analyst_name(tmp_path, capsys):
    """A blank --analyst must be refused and nothing recorded."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(_proposal(proposal_id="RESP-noname"))
    _playbook_dir(tmp_path, PF_PLAYBOOK)

    exit_code = main(
        _cli("approve", tmp_path, db_path, "RESP-noname", "--analyst", "   ")
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "analyst" in captured.err.lower()
    assert store.list_response_actions()[0]["status"] == "suggested"


def test_approve_refuses_a_denied_proposal(tmp_path, capsys):
    """An approval must never resurrect a proposal an earlier gate refused."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-denied",
            status=ResponseStatus.DENIED,
            denial_reason="target 10.0.0.1 is not a publicly routable address",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)

    exit_code = main(
        _cli("approve", tmp_path, db_path, "RESP-denied", "--analyst", "alice")
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "denied" in captured.err
    recorded = store.list_response_actions()[0]
    assert recorded["status"] == "denied"
    assert recorded["approved_by"] is None


def test_approve_unknown_proposal_exits_one(tmp_path, capsys):
    """Approving an ID nobody proposed must exit 1."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    _store(db_path)
    _playbook_dir(tmp_path, PF_PLAYBOOK)

    exit_code = main(
        _cli("approve", tmp_path, db_path, "RESP-ghost", "--analyst", "alice")
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "RESP-ghost" in captured.err


class FakeLeakyWazuhExecutor(FakeWazuhExecutor):
    """Wazuh fake whose result text carries a credential.

    A real client can echo a URL or header into an error string. Every string
    this CLI prints ends up on an operator's screen and in their scrollback, so
    the CLI must scrub configured secrets out of executor text rather than trust
    the executor not to include them.
    """

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Return a result string that leaks the Manager password.

        Inputs:
            target: Target string.
            dry_run: Whether this was a dry run.

        Outputs:
            Result text containing the configured credential.
        """

        self.executed.append((target, dry_run))
        return f"accepted for {target} via https://soc-api:{WAZUH_SECRET}@wazuh.example.net"


def test_execute_without_confirm_refuses_and_explains(monkeypatch, tmp_path, capsys):
    """The first safeguard: with no --confirm the command must not act at all."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-approved",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli("execute", tmp_path, db_path, "RESP-approved", "--analyst", "alice")
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert executor.executed == []
    assert "pfctl -t soc_blocklist -T add 8.8.8.8" in captured.out
    assert "--confirm" in captured.out + captured.err
    assert store.list_response_actions()[0]["status"] == "approved"


def test_execute_with_confirm_only_performs_a_dry_run(monkeypatch, tmp_path, capsys):
    """The second safeguard: without --force-live the execution must be a dry run."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-dry",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli(
            "execute",
            tmp_path,
            db_path,
            "RESP-dry",
            "--analyst",
            "alice",
            "--confirm",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert executor.executed == [("8.8.8.8", True)]
    assert "dry run" in captured.out.lower()
    recorded = store.list_response_actions()[0]
    assert recorded["status"] == "executed"
    assert recorded["dry_run"] is True


def test_execute_with_both_flags_reaches_the_executor(monkeypatch, tmp_path, capsys):
    """Both safeguards together, and only together, permit a live change."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-live",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli(
            "execute",
            tmp_path,
            db_path,
            "RESP-live",
            "--analyst",
            "alice",
            "--confirm",
            "--force-live",
        )
    )

    captured = capsys.readouterr()
    out = captured.out
    assert exit_code == 0
    assert executor.executed == [("8.8.8.8", False)]
    # The command must be visible before the action and the rollback after it, so
    # an operator can see what ran and how to undo it.
    assert out.index("pfctl -t soc_blocklist -T add 8.8.8.8") < out.index(
        "pfctl -t soc_blocklist -T delete 8.8.8.8"
    )
    recorded = store.list_response_actions()[0]
    assert recorded["status"] == "executed"
    assert recorded["dry_run"] is False
    assert recorded["rollback_command"] == "pfctl -t soc_blocklist -T delete 8.8.8.8"


def test_execute_of_an_unapproved_proposal_exits_one(monkeypatch, tmp_path, capsys):
    """An unapproved proposal must be refused by the gate, flags notwithstanding."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(_proposal(proposal_id="RESP-unapproved"))
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli(
            "execute",
            tmp_path,
            db_path,
            "RESP-unapproved",
            "--analyst",
            "alice",
            "--confirm",
            "--force-live",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not approved" in captured.err
    assert executor.executed == []
    assert store.list_response_actions()[0]["status"] == "suggested"


def test_execute_requires_a_named_analyst(monkeypatch, tmp_path, capsys):
    """Performing an action anonymously must be refused."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-anon",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli(
            "execute",
            tmp_path,
            db_path,
            "RESP-anon",
            "--confirm",
            "--force-live",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "analyst" in captured.err.lower()
    assert executor.executed == []


def test_execute_refuses_an_incompletely_configured_capability(tmp_path, capsys):
    """A capability with missing settings is an error, never a silent skip."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-misconfigured",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)

    exit_code = main(
        _cli(
            "execute",
            tmp_path,
            db_path,
            "RESP-misconfigured",
            "--analyst",
            "alice",
            "--confirm",
            OPENBSD_PF_HOST="",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "OPENBSD_PF_HOST" in captured.err
    assert store.list_response_actions()[0]["status"] == "approved"


def test_build_executor_refuses_incomplete_wazuh_settings(tmp_path):
    """The Wazuh capability must refuse to build without Manager credentials."""

    import run_response
    from soc.config import get_settings

    db_path = tmp_path / "soc.db"
    settings = get_settings(
        _env_file(tmp_path, db_path, WAZUH_MANAGER_PASSWORD=""),
        reload=True,
    )

    with pytest.raises(run_response.CliError) as excinfo:
        run_response.build_executor(ResponseActionType.WAZUH_HOST_DENY, settings)

    assert "WAZUH_MANAGER_PASSWORD" in str(excinfo.value)


def test_rollback_of_a_pf_block_calls_the_executor_rollback(monkeypatch, tmp_path, capsys):
    """A pf block must be undoable, for real, through the executor."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-undo",
            status=ResponseStatus.EXECUTED,
            approved_by="alice",
            command="pfctl -t soc_blocklist -T add 8.8.8.8",
            rollback_command="pfctl -t soc_blocklist -T delete 8.8.8.8",
            dry_run=False,
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli(
            "rollback",
            tmp_path,
            db_path,
            "RESP-undo",
            "--analyst",
            "alice",
            "--confirm",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert executor.rolled_back == [("8.8.8.8", False)]
    assert "pfctl -t soc_blocklist -T delete 8.8.8.8" in captured.out
    assert store.list_response_actions()[0]["status"] == "rolled_back"


def test_rollback_without_confirm_is_a_dry_run(monkeypatch, tmp_path, capsys):
    """An unconfirmed rollback must touch nothing and leave the status alone."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-undodry",
            status=ResponseStatus.EXECUTED,
            approved_by="alice",
            command="pfctl -t soc_blocklist -T add 8.8.8.8",
            rollback_command="pfctl -t soc_blocklist -T delete 8.8.8.8",
            dry_run=False,
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    executor = FakePfExecutor()
    _install_executor(monkeypatch, executor)

    exit_code = main(
        _cli("rollback", tmp_path, db_path, "RESP-undodry", "--analyst", "alice")
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert executor.rolled_back == [("8.8.8.8", True)]
    assert "dry run" in captured.out.lower()
    assert store.list_response_actions()[0]["status"] == "executed"


def test_rollback_of_a_wazuh_action_exits_nonzero_and_admits_it_cannot_undo(
    monkeypatch, tmp_path, capsys
):
    """A Wazuh action has no rollback path, so the CLI must say so and fail.

    Pretending to undo an active response would put a false record in the audit
    trail and leave an operator believing an endpoint had been restored.
    """

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-nowayback",
            action=ResponseActionType.WAZUH_HOST_DENY,
            playbook_name="wazuh-host-deny",
            target="001/8.8.8.8",
            status=ResponseStatus.EXECUTED,
            approved_by="alice",
            command="PUT /active-response 001/8.8.8.8",
            rollback_command=WAZUH_ROLLBACK_UNAVAILABLE,
            dry_run=False,
        )
    )
    _playbook_dir(tmp_path, WAZUH_PLAYBOOK)
    _install_executor(monkeypatch, FakeWazuhExecutor())

    exit_code = main(
        _cli(
            "rollback",
            tmp_path,
            db_path,
            "RESP-nowayback",
            "--analyst",
            "alice",
            "--confirm",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "NO ROLLBACK AVAILABLE" in captured.out + captured.err
    assert store.list_response_actions()[0]["status"] == "executed"


def test_no_credential_appears_in_any_output(monkeypatch, tmp_path, capsys):
    """No configured secret may reach the screen, even via executor text."""

    from run_response import main

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.save_triage_result(_triage())
    store.record_response_action(
        _proposal(
            proposal_id="RESP-secret",
            action=ResponseActionType.WAZUH_HOST_DENY,
            playbook_name="wazuh-host-deny",
            target="001/8.8.8.8",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, WAZUH_PLAYBOOK)
    _install_executor(monkeypatch, FakeLeakyWazuhExecutor())

    exit_codes = [
        main(_cli("list", tmp_path, db_path)),
        main(_cli("show", tmp_path, db_path, "RESP-secret")),
        main(
            _cli(
                "propose",
                tmp_path,
                db_path,
                "--triage-result-id",
                "TRIAGE-RESP",
                "--target",
                "001/8.8.8.8",
            )
        ),
        main(
            _cli(
                "execute",
                tmp_path,
                db_path,
                "RESP-secret",
                "--analyst",
                "alice",
                "--confirm",
                "--force-live",
            )
        ),
    ]

    captured = capsys.readouterr()
    assert exit_codes == [0, 0, 0, 0]
    assert WAZUH_SECRET not in captured.out
    assert WAZUH_SECRET not in captured.err
    assert "<redacted>" in captured.out


def test_a_leaky_executor_cannot_persist_a_secret_into_the_audit_trail(monkeypatch, tmp_path):
    """Scrubbing must happen before the audit row is written, not just on output.

    Redacting only on the way to the terminal would leave the credential sitting
    in SQLite, which is a worse place to find it.
    """

    from run_response import main

    secret = "wazuh-manager-password-value"

    class _LeakyExecutor:
        """Executor that returns a configured secret in its output."""

        action = ResponseActionType.PF_BLOCK_IP

        def describe(self, target: str) -> tuple[str, str]:
            """Return clean commands."""

            return ("pfctl -t soc_blocklist -T add x", "pfctl -t soc_blocklist -T delete x")

        def execute(self, target: str, *, dry_run: bool) -> str:
            """Leak the configured secret in returned output."""

            return f"authenticated with {secret}"

    db_path = tmp_path / "soc.db"
    store = _store(db_path)
    store.record_response_action(
        _proposal(
            proposal_id="RESP-leak",
            status=ResponseStatus.APPROVED,
            approved_by="alice",
        )
    )
    _playbook_dir(tmp_path, PF_PLAYBOOK)
    _install_executor(monkeypatch, _LeakyExecutor())

    main(
        _cli(
            "execute",
            tmp_path,
            db_path,
            "RESP-leak",
            "--analyst",
            "alice",
            "--confirm",
            "--force-live",
            WAZUH_MANAGER_PASSWORD=secret,
        )
    )

    stored = json.dumps(_store(db_path).list_response_actions())
    assert secret not in stored
    assert "<redacted>" in stored
