
"""Controlled response framework.

This module exists to say no. Response actions change firewalls and take hosts
off networks, so the default answer to "may this run" is no, and every yes has to
clear several independent gates.

The gates, in order, and why each one is here:

    1. **The capability must be explicitly enabled** in settings. Defaulting to
       enabled would let a misconfigured deploy change a firewall by itself.
    2. **The score must have come from a model.** A locally-scored result can
       never trigger a response, and this is deliberately not configurable. Local
       scoring exists so the pipeline runs without an API key; a regex heuristic
       is not evidence strong enough to drop a host off the network. Note the
       consequence: with no model configured, nothing here can fire at all. That
       is the intended ordering, not an oversight.
    3. **A playbook must apply** to the triage action, and the score must meet
       the confidence the playbook demands. Applicability is silent when it does
       not match; a confidence shortfall is an audited refusal, because that is
       the record needed to tune the bar.
    4. **The target must be valid** for the action. A firewall block against
       internal or reserved space could cut off the network it protects.
    5. **A named analyst must approve.** Accountability is not optional, and an
       approval cannot resurrect a proposal an earlier gate already denied.
    6. **The action must be auditable before it is performed.** If the audit
       write fails, execution does not happen: an unlogged firewall change is
       worse than a missed one, because nobody can review or roll it back.

Execution is a dry run unless explicitly told otherwise, and every executed
action records both the exact command and the command that undoes it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol

from soc.models import AnalysisSource, TriageAction, TriageResult, utc_now
from soc.playbooks import Playbook

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


class ResponseError(RuntimeError):
    """Raised when a response action is misused or cannot be recorded."""


class ResponseActionType(str, Enum):
    """Response actions this project knows how to propose.

    Values:
        PF_BLOCK_IP: Add an address to a controlled OpenBSD pf block table.
        WAZUH_FIREWALL_DROP: Trigger Wazuh firewall-drop on one agent.
        WAZUH_HOST_DENY: Trigger Wazuh host-deny on one agent.
    """

    PF_BLOCK_IP = "pf_block_ip"
    WAZUH_FIREWALL_DROP = "wazuh_firewall_drop"
    WAZUH_HOST_DENY = "wazuh_host_deny"


class ResponseStatus(str, Enum):
    """Lifecycle of a response proposal.

    Every one of these is written to the audit trail, including the refusals,
    because "why did nothing happen" is as important a question as "what ran".
    """

    SUGGESTED = "suggested"
    DENIED = "denied"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


IP_TARGET_ACTIONS = frozenset({ResponseActionType.PF_BLOCK_IP})
"""Actions whose target must be a publicly routable address."""

MODEL_SCORE_REQUIRED = True
"""Whether a model-produced score is required. Not configurable on purpose."""


@dataclass(slots=True)
class ResponseProposal:
    """One proposed response action and its lifecycle state.

    Attributes:
        id: Deterministic proposal ID, so a rerun over the same decision does not
            create a second audit trail.
        playbook_name: Playbook that proposed this.
        action: Response action type.
        target: Address, host, or agent the action applies to.
        triage_result_id: Triage result that justified it.
        triage_score: Score at proposal time.
        analysis_source: Whether that score came from a model or local rules.
        status: Current lifecycle status.
        reason: Human-readable justification.
        denial_reason: Why it was refused, when it was.
        requires_confirmation: Whether a named analyst must approve.
        approved_by: Analyst who approved, when approved.
        command: Exact command performed, once known.
        rollback_command: Command that undoes it.
        output: Executor output.
        error: Failure text, when execution failed.
        dry_run: Whether the execution was a dry run.
        created_at: Proposal time.
        decided_at: Time of the last status change.
    """

    id: str
    playbook_name: str
    action: ResponseActionType
    target: str
    triage_result_id: str
    triage_score: int
    analysis_source: AnalysisSource
    status: ResponseStatus
    reason: str
    denial_reason: str = ""
    requires_confirmation: bool = True
    approved_by: str | None = None
    command: str = ""
    rollback_command: str = ""
    output: str = ""
    error: str = ""
    dry_run: bool = True
    created_at: datetime = field(default_factory=utc_now)
    decided_at: datetime | None = None

    def to_dict(self) -> JsonDict:
        """Return a JSON-safe representation for auditing.

        Inputs:
            None.

        Outputs:
            Dictionary representation of the proposal.
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
            "reason": self.reason,
            "denial_reason": self.denial_reason,
            "requires_confirmation": self.requires_confirmation,
            "approved_by": self.approved_by,
            "command": self.command,
            "rollback_command": self.rollback_command,
            "output": self.output,
            "error": self.error,
            "dry_run": self.dry_run,
            "created_at": self.created_at.isoformat(),
            "decided_at": None if self.decided_at is None else self.decided_at.isoformat(),
        }


class ResponseExecutor(Protocol):
    """Contract for something that can perform one response action.

    Attributes:
        action: The single action type this executor handles.
    """

    action: ResponseActionType

    def describe(self, target: str) -> tuple[str, str]:
        """Return the command that would run and the command that undoes it."""

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Perform the action, or describe it without acting when dry_run."""


class ResponseGate:
    """Decide whether a response may be proposed, approved, and performed."""

    def __init__(
        self,
        playbooks: Any,
        *,
        capability_enabled: Any,
        audit: Any | None = None,
        require_model_score: bool = MODEL_SCORE_REQUIRED,
        scrub: Any | None = None,
    ) -> None:
        """Initialize the gate.

        Inputs:
            playbooks: Playbooks to consider.
            capability_enabled: Callable taking a ResponseActionType and returning
                whether that capability is switched on in settings.
            audit: Optional object exposing `record_response_action(proposal)`.
                When present, a failure to record prevents execution.
            scrub: Optional callable redacting secrets from executor output and
                error text **before** it is audited. Executors are required not to
                return credentials, but the audit row is written from whatever
                they return, and a database is a bad place to discover a leak.
            require_model_score: Left as a parameter only so the guard itself can
                be tested. Production must never pass False; a locally-scored
                result is not grounds for a firewall or endpoint change.

        Outputs:
            None.
        """

        self.playbooks = list(playbooks)
        self.capability_enabled = capability_enabled
        self.audit = audit
        self.require_model_score = require_model_score
        self.scrub = scrub

    def propose(
        self,
        *,
        triage: TriageResult,
        target: str,
        action_override: TriageAction | None = None,
    ) -> list[ResponseProposal]:
        """Evaluate playbooks and return proposals, including refusals.

        A refusal is returned rather than omitted, so the reason nothing happened
        is recorded and reviewable.

        Inputs:
            triage: TriageResult under consideration.
            target: Address, host, or agent the action would apply to.
            action_override: Applied action when the router's decision differs
                from the triage suggestion.

        Outputs:
            One proposal per matching or refusing playbook.
        """

        effective_action = action_override or triage.action
        proposals: list[ResponseProposal] = []

        for playbook in self.playbooks:
            if not playbook.applies_to(effective_action):
                continue
            proposal = self._evaluate(playbook, triage, target)
            self._record(proposal)
            proposals.append(proposal)

        return proposals

    def _evaluate(
        self,
        playbook: Playbook,
        triage: TriageResult,
        target: str,
    ) -> ResponseProposal:
        """Apply every gate to one playbook match.

        Inputs:
            playbook: Matching playbook.
            triage: TriageResult under consideration.
            target: Action target.

        Outputs:
            A suggested or denied proposal.
        """

        action: ResponseActionType = playbook.action
        base = ResponseProposal(
            id=_proposal_id(playbook.name, action, target, triage.id),
            playbook_name=playbook.name,
            action=action,
            target=target,
            triage_result_id=triage.id,
            triage_score=triage.score,
            analysis_source=triage.analysis_source,
            status=ResponseStatus.SUGGESTED,
            reason=(
                f"{playbook.name}: score {triage.score} met required confidence "
                f"{playbook.required_confidence}"
            ),
            requires_confirmation=playbook.requires_confirmation,
        )

        denial = self._denial_reason(playbook, triage, target, action)
        if denial:
            base.status = ResponseStatus.DENIED
            base.denial_reason = denial
            base.decided_at = utc_now()
            logger.warning(
                "Response %s for %s denied: %s", playbook.name, target, denial
            )
            return base

        command, rollback = "", ""
        base.command, base.rollback_command = command, rollback
        return base

    def _denial_reason(
        self,
        playbook: Playbook,
        triage: TriageResult,
        target: str,
        action: ResponseActionType,
    ) -> str:
        """Return why this proposal must be refused, or an empty string.

        Inputs:
            playbook: Matching playbook.
            triage: TriageResult under consideration.
            target: Action target.
            action: Response action type.

        Outputs:
            Denial reason, empty when every gate passes.
        """

        if not self.capability_enabled(action):
            return f"response capability {action.value} is not enabled in settings"

        if self.require_model_score and triage.analysis_source is not AnalysisSource.LLM:
            return (
                "triage score was not model-produced "
                f"(analysis_source={triage.analysis_source.value}); "
                "local scoring cannot authorize a response"
            )

        if triage.score < playbook.required_confidence:
            return (
                f"score {triage.score} is below required confidence "
                f"{playbook.required_confidence}"
            )

        if action in IP_TARGET_ACTIONS and not _is_blockable_ip(target):
            return (
                f"target {target!r} is not a publicly routable address; "
                "blocking internal or reserved space could cut off the network"
            )

        if not str(target).strip():
            return "target is empty"

        return ""

    def approve(self, proposal: ResponseProposal, *, analyst: str) -> ResponseProposal:
        """Record a named analyst's approval.

        Inputs:
            proposal: Suggested proposal.
            analyst: Name of the approving analyst.

        Outputs:
            The approved proposal.

        Raises:
            ResponseError: If the proposal was denied or the analyst is unnamed.
        """

        if proposal.status is ResponseStatus.DENIED:
            raise ResponseError(
                f"proposal {proposal.id} was denied and cannot be approved: "
                f"{proposal.denial_reason}"
            )
        if proposal.status is not ResponseStatus.SUGGESTED:
            raise ResponseError(f"proposal {proposal.id} is not awaiting approval")
        if not str(analyst).strip():
            raise ResponseError("an approving analyst name is required")

        proposal.status = ResponseStatus.APPROVED
        proposal.approved_by = analyst.strip()
        proposal.decided_at = utc_now()
        self._record(proposal)
        return proposal

    def execute(
        self,
        proposal: ResponseProposal,
        *,
        executor: ResponseExecutor,
        dry_run: bool = True,
    ) -> ResponseProposal:
        """Perform an approved action, recording it before it happens.

        Inputs:
            proposal: Approved proposal.
            executor: Executor for this action type.
            dry_run: Whether to describe rather than perform. Defaults to True,
                because the safe default for a destructive action is not doing it.

        Outputs:
            The executed or failed proposal.

        Raises:
            ResponseError: If the proposal is unapproved, the executor handles a
            different action, or the action could not be audited.
        """

        if proposal.status is not ResponseStatus.APPROVED:
            raise ResponseError(
                f"proposal {proposal.id} is not approved and will not be executed"
            )
        if executor.action is not proposal.action:
            raise ResponseError(
                f"executor for {executor.action.value} cannot execute "
                f"{proposal.action.value}"
            )

        command, rollback = executor.describe(proposal.target)
        proposal.command = command
        proposal.rollback_command = rollback
        proposal.dry_run = dry_run

        # Recorded before the action runs. An unlogged firewall change cannot be
        # reviewed or rolled back, so a failure to audit must stop execution.
        self._record(proposal, stage="pre-execution")

        try:
            proposal.output = self._scrubbed(executor.execute(proposal.target, dry_run=dry_run))
            proposal.status = ResponseStatus.EXECUTED
        except Exception as exc:
            proposal.status = ResponseStatus.FAILED
            proposal.error = self._scrubbed(str(exc))
            logger.warning("Response %s for %s failed: %s", proposal.id, proposal.target, exc)

        proposal.decided_at = utc_now()
        self._record(proposal)
        return proposal

    def _scrubbed(self, text: str) -> str:
        """Redact secrets from executor text before it is stored or shown.

        Applied to output and error text on the way out of an executor, so a
        leaky executor cannot turn into a stored credential.

        Inputs:
            text: Raw executor output or error text.

        Outputs:
            Redacted text, or the original when no scrub is configured.
        """

        if self.scrub is None:
            return text
        try:
            return str(self.scrub(text))
        except Exception:
            # A failing scrub must not be a reason to store unredacted text.
            logger.warning("Response output scrub failed; withholding executor text")
            return "<withheld: scrub failed>"

    def _record(self, proposal: ResponseProposal, *, stage: str = "decision") -> None:
        """Write one audit entry.

        Inputs:
            proposal: Proposal to record.
            stage: Label used in the error message when recording fails.

        Outputs:
            None.

        Raises:
            ResponseError: If the audit write fails.
        """

        if self.audit is None:
            return
        try:
            self.audit.record_response_action(proposal)
        except Exception as exc:
            raise ResponseError(
                f"cannot audit response {proposal.id} at {stage}: {exc}; "
                "refusing to act on an unrecordable action"
            ) from exc


def _is_blockable_ip(value: str) -> bool:
    """Return whether an address may be added to a firewall block table.

    Only globally routable addresses qualify. Blocking private, loopback,
    link-local, multicast or reserved space risks cutting off the very network the
    firewall protects, and `0.0.0.0` would be catastrophic.

    Inputs:
        value: Candidate address.

    Outputs:
        True when the address is safe to block.
    """

    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return address.is_global


def _proposal_id(
    playbook_name: str,
    action: ResponseActionType,
    target: str,
    triage_result_id: str,
) -> str:
    """Build a deterministic proposal ID.

    Content-addressed like the project's other identifiers, so re-evaluating the
    same decision updates one audit record instead of creating a second.

    Inputs:
        playbook_name: Playbook name.
        action: Response action type.
        target: Action target.
        triage_result_id: Triage result that justified it.

    Outputs:
        Proposal ID string.
    """

    material = f"{playbook_name}|{action.value}|{target}|{triage_result_id}"
    fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"RESP-{fingerprint}"
