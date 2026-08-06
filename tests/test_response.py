

"""Tests for the controlled response framework.

These tests are mostly about what the framework REFUSES to do. Response actions
take hosts off networks and change firewalls, so every guard here is the point of
the module rather than incidental validation.

Targets that must be accepted use genuinely routable addresses such as 8.8.8.8,
not the RFC 5737 documentation ranges. Documentation space reports
`is_global == False`, so the firewall guard correctly refuses it, which would make
these tests pass or fail for the wrong reason.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from soc.models import (
    AnalysisSource,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
)
from soc.playbooks import Playbook, PlaybookError, load_playbooks
from soc.response import (
    ResponseActionType,
    ResponseError,
    ResponseGate,
    ResponseStatus,
)

BASE_TIME = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _triage(
    score: int = 9,
    *,
    source: AnalysisSource = AnalysisSource.LLM,
    action: TriageAction = TriageAction.PAGE_NOW,
) -> TriageResult:
    """Build a triage result eligible for response by default."""

    return TriageResult(
        id="triage-1",
        target_id="CAND-1",
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive",
        action=action,
        summary="Confirmed compromise",
        model="vendor/model-x",
        analysis_source=source,
        prompt_version="triage-v1",
    )


def _playbook(**overrides: Any) -> Playbook:
    """Build a pf block playbook."""

    values: dict[str, Any] = {
        "name": "block-malicious-ip",
        "action": ResponseActionType.PF_BLOCK_IP,
        "required_confidence": 9,
        "requires_confirmation": True,
        "enabled": True,
        "trigger_actions": (TriageAction.PAGE_NOW,),
        "description": "Add a confirmed malicious address to the pf block table.",
    }
    values.update(overrides)
    return Playbook(**values)


def _gate(*playbooks: Playbook, enabled: bool = True, audit: Any = None) -> ResponseGate:
    """Build a gate with the given playbooks and capability state."""

    return ResponseGate(
        playbooks or (_playbook(),),
        capability_enabled=lambda action: enabled,
        audit=audit,
    )


def test_nothing_is_proposed_when_the_capability_is_disabled():
    """Response capabilities are off unless explicitly enabled.

    Defaulting to enabled would mean a misconfigured deploy could change a
    firewall on its own.
    """

    proposals = _gate(enabled=False).propose(triage=_triage(), target="8.8.8.8")

    assert [proposal.status for proposal in proposals] == [ResponseStatus.DENIED]
    assert "not enabled" in proposals[0].denial_reason


def test_a_locally_scored_result_can_never_trigger_a_response():
    """A regex heuristic must not be able to take a host off the network.

    This is the hardest rule in the module and is deliberately not configurable.
    Local scoring exists so the pipeline runs without an API key; it is not
    evidence strong enough to justify an endpoint or firewall change.
    """

    proposals = _gate().propose(
        triage=_triage(source=AnalysisSource.LOCAL), target="8.8.8.8"
    )

    assert proposals[0].status is ResponseStatus.DENIED
    assert "not model" in proposals[0].denial_reason.lower()


def test_a_score_below_required_confidence_is_denied():
    """Playbooks state the confidence they need, and it is enforced."""

    proposals = _gate(_playbook(required_confidence=9)).propose(
        triage=_triage(score=8), target="8.8.8.8"
    )

    assert proposals[0].status is ResponseStatus.DENIED
    assert "confidence" in proposals[0].denial_reason


def test_a_triage_action_outside_the_trigger_set_proposes_nothing():
    """A queued result is not a paged one, so the playbook is simply silent.

    Applicability and safety are different questions. A playbook that does not
    concern this action produces no record at all, whereas one that does concern
    it but fails a confidence or safety check produces an audited refusal. If
    non-applicability were recorded as a denial, the audit trail would fill with
    entries for every alert every playbook ignored.
    """

    proposals = _gate().propose(
        triage=_triage(action=TriageAction.QUEUE_REVIEW), target="8.8.8.8"
    )

    assert proposals == []


def test_a_qualifying_result_is_only_ever_suggested_not_executed():
    """Proposing is not doing. Nothing runs without a separate approval step."""

    proposals = _gate().propose(triage=_triage(), target="8.8.8.8")

    assert proposals[0].status is ResponseStatus.SUGGESTED
    assert proposals[0].approved_by is None


def test_execution_without_approval_is_refused():
    """An unapproved proposal must not be executable, even by mistake."""

    gate = _gate()
    proposal = gate.propose(triage=_triage(), target="8.8.8.8")[0]

    with pytest.raises(ResponseError, match="not approved"):
        gate.execute(proposal, executor=_RecordingExecutor())


def test_a_denied_proposal_cannot_be_approved():
    """Approval must not be able to override a guard that already refused."""

    gate = _gate(enabled=False)
    proposal = gate.propose(triage=_triage(), target="8.8.8.8")[0]

    with pytest.raises(ResponseError, match="denied"):
        gate.approve(proposal, analyst="alice")


def test_approval_records_who_approved():
    """Accountability: an executed action must name a person."""

    gate = _gate()
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )

    assert proposal.status is ResponseStatus.APPROVED
    assert proposal.approved_by == "alice"


def test_approval_requires_a_named_analyst():
    """An empty approver defeats the purpose of recording one."""

    gate = _gate()
    proposal = gate.propose(triage=_triage(), target="8.8.8.8")[0]

    with pytest.raises(ResponseError, match="analyst"):
        gate.approve(proposal, analyst="   ")


class _RecordingExecutor:
    """Executor recording what it was asked to do."""

    action = ResponseActionType.PF_BLOCK_IP

    def __init__(self, *, fail: bool = False) -> None:
        """Initialize the recorder."""

        self.calls: list[tuple[str, bool]] = []
        self.fail = fail

    def describe(self, target: str) -> tuple[str, str]:
        """Return the command and its rollback."""

        return (f"pfctl -t blocklist -T add {target}", f"pfctl -t blocklist -T delete {target}")

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Record the execution and return output."""

        self.calls.append((target, dry_run))
        if self.fail:
            raise RuntimeError("ssh failed")
        return "1 table created."


def test_execution_is_a_dry_run_by_default():
    """The safe default for a destructive action is to not do it."""

    gate = _gate()
    executor = _RecordingExecutor()
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )

    executed = gate.execute(proposal, executor=executor)

    assert executor.calls == [("8.8.8.8", True)]
    assert executed.dry_run is True
    assert executed.status is ResponseStatus.EXECUTED


def test_execution_records_the_command_and_its_rollback():
    """An action nobody can undo is not a controlled action."""

    gate = _gate()
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )

    executed = gate.execute(proposal, executor=_RecordingExecutor(), dry_run=False)

    assert "T add 8.8.8.8" in executed.command
    assert "T delete 8.8.8.8" in executed.rollback_command


def test_a_failed_execution_is_recorded_as_failed():
    """A failure must be visible, not silently swallowed."""

    gate = _gate()
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )

    executed = gate.execute(proposal, executor=_RecordingExecutor(fail=True), dry_run=False)

    assert executed.status is ResponseStatus.FAILED
    assert "ssh failed" in executed.error


def test_an_executor_for_a_different_action_is_refused():
    """Handing a pf proposal to a Wazuh executor is a programming error."""

    class _Other:
        action = ResponseActionType.WAZUH_HOST_DENY

        def describe(self, target: str) -> tuple[str, str]:
            """Unused."""

            return ("", "")

        def execute(self, target: str, *, dry_run: bool) -> str:
            """Unused."""

            return ""

    gate = _gate()
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )

    with pytest.raises(ResponseError, match="cannot execute"):
        gate.execute(proposal, executor=_Other())


def test_a_non_public_target_is_refused_for_a_firewall_block():
    """Blocking internal or reserved space could cut off the network itself."""

    for target in ("10.0.1.5", "127.0.0.1", "not-an-ip", "0.0.0.0"):
        proposals = _gate().propose(triage=_triage(), target=target)
        assert proposals[0].status is ResponseStatus.DENIED, target
        assert "target" in proposals[0].denial_reason.lower(), target


def test_every_outcome_is_audited():
    """Suggested, denied, approved and executed must all leave a record."""

    records: list[Any] = []

    class _Audit:
        def record_response_action(self, proposal: Any) -> None:
            """Record one audit entry."""

            records.append((proposal.status, proposal.approved_by))

    gate = _gate(audit=_Audit())
    denied = gate.propose(triage=_triage(source=AnalysisSource.LOCAL), target="8.8.8.8")
    proposal = gate.propose(triage=_triage(), target="8.8.8.8")[0]
    approved = gate.approve(proposal, analyst="alice")
    gate.execute(approved, executor=_RecordingExecutor(), dry_run=False)

    statuses = [status for status, _ in records]
    assert denied[0].status is ResponseStatus.DENIED
    assert ResponseStatus.DENIED in statuses
    assert ResponseStatus.SUGGESTED in statuses
    assert ResponseStatus.APPROVED in statuses
    assert ResponseStatus.EXECUTED in statuses


def test_an_audit_failure_does_not_execute_anything_silently():
    """If the action cannot be recorded, it must not be performed.

    An unlogged firewall change is worse than a missed one: nobody can review or
    roll back what was never written down.
    """

    class _BrokenAudit:
        def record_response_action(self, proposal: Any) -> None:
            """Always fail."""

            raise RuntimeError("audit unavailable")

    gate = _gate(audit=_BrokenAudit())
    executor = _RecordingExecutor()

    with pytest.raises(ResponseError, match="audit"):
        proposal = gate.propose(triage=_triage(), target="8.8.8.8")[0]
        approved = gate.approve(proposal, analyst="alice")
        gate.execute(approved, executor=executor, dry_run=False)

    assert executor.calls == []


def test_proposal_ids_are_deterministic():
    """A rerun over the same decision must not create a second audit trail."""

    first = _gate().propose(triage=_triage(), target="8.8.8.8")[0]
    second = _gate().propose(triage=_triage(), target="8.8.8.8")[0]

    assert first.id == second.id


def test_playbook_rejects_an_out_of_range_confidence():
    """A playbook that can never fire, or always fires, is a mistake."""

    with pytest.raises(PlaybookError, match="required_confidence"):
        _playbook(required_confidence=0)

    with pytest.raises(PlaybookError, match="required_confidence"):
        _playbook(required_confidence=11)


def test_playbook_requires_a_name_and_description():
    """An unexplained response playbook cannot be reviewed."""

    with pytest.raises(PlaybookError, match="name"):
        _playbook(name="  ")

    with pytest.raises(PlaybookError, match="description"):
        _playbook(description="")


def test_load_playbooks_reads_the_shipped_directory():
    """The shipped playbooks must load and validate."""

    playbooks = load_playbooks(Path("playbooks"))

    assert playbooks
    assert all(playbook.description.strip() for playbook in playbooks)


def test_shipped_playbooks_all_require_confirmation():
    """Nothing shipped may act without a human, whatever else it says."""

    assert all(playbook.requires_confirmation for playbook in load_playbooks(Path("playbooks")))


def test_load_playbooks_rejects_an_unknown_action(tmp_path):
    """A typo in an action name must fail loudly, not be ignored."""

    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "name": "typo",
                "action": "delete_everything",
                "required_confidence": 9,
                "description": "Not a real action.",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PlaybookError, match="action"):
        load_playbooks(tmp_path)


def test_load_playbooks_defaults_requires_confirmation_to_true(tmp_path):
    """Omitting the field must not silently mean unattended execution."""

    path = tmp_path / "pb.json"
    path.write_text(
        json.dumps(
            {
                "name": "block",
                "action": "pf_block_ip",
                "required_confidence": 9,
                "description": "Block an address.",
            }
        ),
        encoding="utf-8",
    )

    assert load_playbooks(tmp_path)[0].requires_confirmation is True


def test_missing_playbook_directory_is_not_an_error(tmp_path):
    """Running with no playbooks means no response, which is a valid mode."""

    assert load_playbooks(tmp_path / "absent") == []


def test_executor_output_is_scrubbed_before_it_is_audited():
    """A leaky executor must not persist a secret into the audit trail.

    Executors are required not to return credentials, but the audit row is
    written from whatever they do return, and a database is a bad place to
    discover a leak. The scrub runs before recording, so a mistake in an executor
    cannot become a stored secret.
    """

    secret = "super-secret-token"
    recorded: list[str] = []

    class _Audit:
        def record_response_action(self, proposal: Any) -> None:
            """Capture what would be persisted."""

            recorded.append(f"{proposal.output}|{proposal.error}")

    class _LeakyExecutor:
        action = ResponseActionType.PF_BLOCK_IP

        def describe(self, target: str) -> tuple[str, str]:
            """Return clean commands."""

            return ("pfctl add", "pfctl delete")

        def execute(self, target: str, *, dry_run: bool) -> str:
            """Leak a secret in the returned output."""

            return f"connected using {secret}"

    gate = ResponseGate(
        (_playbook(),),
        capability_enabled=lambda action: True,
        audit=_Audit(),
        scrub=lambda text: text.replace(secret, "<redacted>"),
    )
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )
    executed = gate.execute(proposal, executor=_LeakyExecutor(), dry_run=False)

    assert secret not in executed.output
    assert "<redacted>" in executed.output
    assert all(secret not in entry for entry in recorded)


def test_a_leaky_error_message_is_also_scrubbed():
    """Failures quote transport errors, which is where secrets usually appear."""

    secret = "super-secret-token"

    class _FailingExecutor:
        action = ResponseActionType.PF_BLOCK_IP

        def describe(self, target: str) -> tuple[str, str]:
            """Return clean commands."""

            return ("pfctl add", "pfctl delete")

        def execute(self, target: str, *, dry_run: bool) -> str:
            """Fail with a secret in the message."""

            raise RuntimeError(f"ssh -i {secret} failed")

    gate = ResponseGate(
        (_playbook(),),
        capability_enabled=lambda action: True,
        scrub=lambda text: text.replace(secret, "<redacted>"),
    )
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )
    executed = gate.execute(proposal, executor=_FailingExecutor(), dry_run=False)

    assert executed.status is ResponseStatus.FAILED
    assert secret not in executed.error


def test_no_scrub_configured_leaves_output_unchanged():
    """The hook is optional and must not alter output when absent."""

    gate = _gate()
    proposal = gate.approve(
        gate.propose(triage=_triage(), target="8.8.8.8")[0], analyst="alice"
    )

    executed = gate.execute(proposal, executor=_RecordingExecutor(), dry_run=False)

    assert executed.output == "1 table created."
