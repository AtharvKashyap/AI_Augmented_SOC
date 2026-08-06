"""Command-line response approval tool for AI_Augmented_SOC.

`soc.response` says no by default. This CLI is where a named human says yes, and
nothing about it is conversational: it takes an explicit proposal ID and an
explicit analyst name, and it has no natural-language input and no model in the
loop. That separation is the point. The analyst assistant ingests alert text an
attacker can influence, so it must be structurally unable to act; approving a
firewall change is a deliberate human decision and lives here instead.

What this file does *not* do matters as much as what it does:

    - It never calls an executor's `execute`. Every execution goes through
      `ResponseGate.execute`, so the approval check, the executor/action match,
      and the audit-before-action rule all still apply.
    - It passes the store as the gate's audit sink. If the audit write fails the
      gate refuses to act, and that refusal is propagated rather than swallowed.
    - It never treats an incompletely configured capability as "skip". Missing
      firewall or Manager settings are an error, because silently doing nothing
      when an analyst asked for a block is its own kind of failure.

Two independent safeguards protect `execute`, and both must be typed for a live
change:

    --confirm     the operator states they mean to run this at all.
    --force-live  the operator states it must not be a dry run.

Neither defaults to true, so the inert outcome is the one you get by accident:
with neither flag the command refuses and explains what it would have done, and
with `--confirm` alone it performs a dry run that touches nothing.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from soc.config import ConfigError, Settings, get_settings
from soc.models import (
    AnalysisSource,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
)
from soc.playbooks import PlaybookError, load_playbooks
from soc.response import (
    ResponseActionType,
    ResponseError,
    ResponseGate,
    ResponseProposal,
    ResponseStatus,
)
from soc.store import SQLiteStore, StoreError
from soc.wazuh_response import WAZUH_ROLLBACK_UNAVAILABLE

JsonDict = dict[str, Any]

REDACTED = "<redacted>"
"""Placeholder substituted for any configured secret found in printed text."""


class CliError(RuntimeError):
    """Raised when CLI input or execution is invalid."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Every verb is a subcommand carrying the shared `--db` / `--env-file`
    arguments, mirroring `run_review.py`. The two `execute` safeguards are plain
    store-true flags so that neither can default to enabled.

    Inputs:
        None.

    Outputs:
        Configured ArgumentParser.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Review, approve, and perform gated SOC response actions. "
            "Non-conversational by design: proposal IDs and analyst names only."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List recorded response actions.")
    list_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of actions to list. Defaults to all.",
    )
    list_parser.add_argument(
        "--status",
        default=None,
        help=(
            "Only list actions in this lifecycle status: "
            + ", ".join(status.value for status in ResponseStatus)
            + "."
        ),
    )
    _add_shared_arguments(list_parser)

    show_parser = subparsers.add_parser(
        "show",
        help="Show one response action in full, including its rollback command.",
    )
    show_parser.add_argument("proposal_id", help="Response proposal ID.")
    _add_shared_arguments(show_parser)

    propose_parser = subparsers.add_parser(
        "propose",
        help="Evaluate playbooks against a stored triage result. Executes nothing.",
    )
    propose_parser.add_argument(
        "--triage-result-id",
        required=True,
        help="Stored triage result the proposal would be based on.",
    )
    propose_parser.add_argument(
        "--target",
        required=True,
        help="Address, or '<agent_id>/<ip>' for a Wazuh action, the action applies to.",
    )
    _add_shared_arguments(propose_parser)

    approve_parser = subparsers.add_parser(
        "approve",
        help="Record a named analyst's approval of one proposal.",
    )
    approve_parser.add_argument("proposal_id", help="Response proposal ID.")
    approve_parser.add_argument(
        "--analyst",
        default="",
        help="Name of the approving analyst. Required; accountability is not optional.",
    )
    _add_shared_arguments(approve_parser)

    execute_parser = subparsers.add_parser(
        "execute",
        help="Perform an approved action. Inert unless --confirm and --force-live.",
    )
    execute_parser.add_argument("proposal_id", help="Response proposal ID.")
    execute_parser.add_argument(
        "--analyst",
        default="",
        help="Name of the analyst performing the action. Required.",
    )
    execute_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm this invocation. Without it the command refuses entirely.",
    )
    execute_parser.add_argument(
        "--force-live",
        action="store_true",
        help="Perform the action for real. Without it the execution is a dry run.",
    )
    _add_shared_arguments(execute_parser)

    rollback_parser = subparsers.add_parser(
        "rollback",
        help="Undo a performed pf block. Wazuh actions have no rollback path.",
    )
    rollback_parser.add_argument("proposal_id", help="Response proposal ID.")
    rollback_parser.add_argument(
        "--analyst",
        default="",
        help="Name of the analyst performing the rollback. Required.",
    )
    rollback_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Perform the rollback for real. Without it the rollback is a dry run.",
    )
    _add_shared_arguments(rollback_parser)

    return parser


def _add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the arguments every subcommand accepts.

    Inputs:
        parser: Subcommand parser to extend.

    Outputs:
        None. Arguments are added in place.
    """

    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to .env file. Defaults to .env.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="SQLite database path. Defaults to SQLITE_DB_PATH from .env.",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the response approval CLI.

    Inputs:
        argv: Optional argument list. Defaults to sys.argv.

    Outputs:
        Process exit code: 0 on success, 1 on handled errors, 130 on interrupt.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        run_from_args(args)
    except (CliError, ConfigError, StoreError, ResponseError, PlaybookError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130

    return 0


def run_from_args(args: argparse.Namespace) -> JsonDict:
    """Dispatch one response subcommand.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        JSON-safe summary dictionary describing what the command did.

    Raises:
        CliError: If the command is unknown or its input is invalid.
        ConfigError: If settings cannot be loaded.
        StoreError: If the store rejects the operation.
        ResponseError: If the response gate refused the operation.
    """

    store, db_path, settings = _build_store(args)
    summary: JsonDict = {"command": args.command, "db_path": str(db_path)}

    if args.command == "list":
        summary.update(_run_list(store, args))
    elif args.command == "show":
        summary.update(_run_show(store, args))
    elif args.command == "propose":
        summary.update(_run_propose(store, settings, args))
    elif args.command == "approve":
        summary.update(_run_approve(store, settings, args))
    elif args.command == "execute":
        summary.update(_run_execute(store, settings, args))
    elif args.command == "rollback":
        summary.update(_run_rollback(store, settings, args))
    else:
        raise CliError(f"unknown command: {args.command}")

    return summary


def _build_store(args: argparse.Namespace) -> tuple[SQLiteStore, Path, Settings]:
    """Open the store the command should read and audit into.

    Inputs:
        args: Parsed argparse namespace carrying --db and --env-file.

    Outputs:
        Tuple of initialized store, resolved database path, and settings.

    Raises:
        CliError: If the database cannot be opened or initialized.
    """

    settings = get_settings(args.env_file, reload=True)
    db_path = Path(args.db or settings.sqlite_db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(db_path)
    try:
        store.initialize()
    except Exception as exc:
        raise CliError(f"cannot initialize database: {exc}") from exc
    return store, db_path, settings


def _run_list(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """List recorded response actions as a compact table.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying --limit and --status.

    Outputs:
        Summary dictionary with the row count and applied filter.

    Raises:
        CliError: If --limit is not positive or --status is unknown.
    """

    limit = _validate_limit(args.limit)
    status = _validate_status(args.status)

    # Filtering happens here rather than in SQL, so a --status filter combined
    # with --limit returns N matching rows instead of N rows that may not match.
    actions = store.list_response_actions()
    if status is not None:
        actions = [action for action in actions if action.get("status") == status.value]
    if limit is not None:
        actions = actions[:limit]

    if not actions:
        scope = "" if status is None else f" with status {status.value}"
        print(f"No recorded response actions{scope}.")
        return {"count": 0, "status": None if status is None else status.value}

    print(_format_table(actions))
    return {"count": len(actions), "status": None if status is None else status.value}


def _run_show(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """Print one recorded response action in full.

    The command, the rollback command and the denial reason are all printed:
    an operator reviewing an action needs to know what ran, how to undo it, and
    why a refusal happened.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying proposal_id.

    Outputs:
        Summary dictionary naming the action shown.

    Raises:
        CliError: If the proposal ID is not recorded.
    """

    payload = _load_action(store, args.proposal_id)
    print(_format_detail(payload))
    return {"proposal_id": payload["id"], "status": payload.get("status")}


def _run_propose(
    store: SQLiteStore,
    settings: Settings,
    args: argparse.Namespace,
) -> JsonDict:
    """Evaluate playbooks against a stored triage result and print the outcome.

    This command performs nothing. It builds no executor at all, so there is no
    code path from here to a firewall or an endpoint, and every proposal it
    produces still has to be approved by a named analyst before anything can run.
    Refusals are printed with their reasons, because "why did nothing happen" is
    as important a question as "what ran".

    Inputs:
        store: Initialized store, also used as the gate's audit sink.
        settings: Loaded settings supplying playbooks and capability switches.
        args: Parsed argparse namespace carrying --triage-result-id and --target.

    Outputs:
        Summary dictionary listing every proposal and its status.

    Raises:
        CliError: If the triage result is not stored or the target is blank.
        PlaybookError: If a playbook file is unusable.
        ResponseError: If a proposal could not be audited.
    """

    target = str(args.target).strip()
    if not target:
        raise CliError("--target cannot be blank")

    payload = store.get_triage_result(args.triage_result_id)
    if payload is None:
        raise CliError(f"{args.triage_result_id} is not a stored triage result")

    triage = _triage_from_payload(payload)
    gate = _build_gate(store, settings)
    proposals = gate.propose(triage=triage, target=target)

    print(
        f"Evaluated {len(gate.playbooks)} playbook(s) for triage {triage.id} "
        f"(score {triage.score}, source {triage.analysis_source.value}, "
        f"action {triage.action.value}) against target {target}."
    )
    if not proposals:
        print("No playbook applies to this triage action. Nothing proposed.")
    for proposal in proposals:
        print("")
        print(_format_proposal(proposal))
    print("")
    print("Nothing was executed. A named analyst must approve first.")

    return {
        "triage_result_id": triage.id,
        "target": target,
        "proposals": [
            {
                "id": proposal.id,
                "playbook_name": proposal.playbook_name,
                "status": proposal.status.value,
                "denial_reason": proposal.denial_reason,
            }
            for proposal in proposals
        ],
    }


def _run_approve(
    store: SQLiteStore,
    settings: Settings,
    args: argparse.Namespace,
) -> JsonDict:
    """Record a named analyst's approval of one recorded proposal.

    The approval itself is delegated to `ResponseGate.approve`, so a denied
    proposal cannot be resurrected here and the approval is audited by the same
    code path the pipeline uses.

    Inputs:
        store: Initialized store, also used as the gate's audit sink.
        settings: Loaded settings.
        args: Parsed argparse namespace carrying proposal_id and --analyst.

    Outputs:
        Summary dictionary describing the approval.

    Raises:
        CliError: If the proposal is unknown or the analyst name is blank.
        ResponseError: If the gate refuses the approval.
    """

    analyst = _require_analyst(args.analyst)
    proposal = _proposal_from_payload(_load_action(store, args.proposal_id))
    gate = _build_gate(store, settings)
    gate.approve(proposal, analyst=analyst)

    print(f"Approved {proposal.id} ({proposal.action.value} on {proposal.target}) as {analyst}.")
    print(
        "Nothing has run yet. Perform it with 'execute "
        f"{proposal.id} --analyst {analyst} --confirm', which is a dry run, and "
        "add --force-live only when the change is meant to be real."
    )
    return {
        "proposal_id": proposal.id,
        "status": proposal.status.value,
        "approved_by": proposal.approved_by,
    }


def _run_execute(
    store: SQLiteStore,
    settings: Settings,
    args: argparse.Namespace,
) -> JsonDict:
    """Perform an approved action behind two independent safeguards.

    The safeguards are separate questions and both must be answered in the
    affirmative for anything to change on a real system:

        `--confirm` means "I meant to run this command at all". Without it this
        function prints the command and the rollback and then refuses, so an
        accidental invocation is inert.

        `--force-live` means "and it must not be a dry run". Without it the
        execution goes ahead as a dry run, which reaches the executor but
        performs no SSH, no HTTP, and no side effect.

    Execution itself always goes through `ResponseGate.execute`, never the
    executor directly, so the approval check, the executor/action match and the
    audit-before-action rule still apply.

    Inputs:
        store: Initialized store, also used as the gate's audit sink.
        settings: Loaded settings supplying executor configuration.
        args: Parsed argparse namespace carrying proposal_id, --analyst,
            --confirm and --force-live.

    Outputs:
        Summary dictionary describing what was performed.

    Raises:
        CliError: If the analyst is unnamed, the proposal is unknown, the
        capability is misconfigured, or --confirm was not given.
        ResponseError: If the gate refuses the execution or cannot audit it.
    """

    analyst = _require_analyst(args.analyst)
    proposal = _proposal_from_payload(_load_action(store, args.proposal_id))
    executor = build_executor(proposal.action, settings)

    # describe() is pure on every executor: it performs no SSH and no HTTP, so
    # the command can be shown before any decision to act is taken.
    command, rollback = executor.describe(proposal.target)
    dry_run = not bool(args.force_live)

    print(f"Proposal:  {proposal.id} ({proposal.action.value}, status {proposal.status.value})")
    print(f"Target:    {proposal.target}")
    print(f"Approved:  {_text(proposal.approved_by)}")
    print(f"Analyst:   {analyst}")
    print(f"Mode:      {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"Command:   {_scrub(command, settings)}")
    print(f"Rollback:  {_scrub(rollback, settings)}")

    if not args.confirm:
        print(
            "Refusing to proceed without --confirm. With --confirm this would "
            + (
                "perform a DRY RUN of the command above and change nothing."
                if dry_run
                else "perform the command above for real."
            )
        )
        raise CliError(
            f"{proposal.id} not performed: --confirm is required. Add --confirm for a "
            "dry run, and --confirm --force-live to make the change live."
        )

    if proposal.approved_by and proposal.approved_by != analyst:
        print(
            f"Note: approved by {proposal.approved_by}, being performed by {analyst}."
        )

    performed = _execute_through_gate(
        store, settings, proposal, executor=executor, dry_run=dry_run
    )

    print(f"Status:    {performed.status.value}")
    print(f"Output:    {_scrub(performed.output, settings)}")
    if performed.error:
        print(f"Error:     {_scrub(performed.error, settings)}")
    print(f"Rollback with: rollback {performed.id} --analyst {analyst} --confirm")

    if performed.status is ResponseStatus.FAILED:
        raise CliError(
            f"{performed.id} failed: {_scrub(performed.error, settings)}"
        )

    return {
        "proposal_id": performed.id,
        "status": performed.status.value,
        "dry_run": performed.dry_run,
        "analyst": analyst,
        "command": _scrub(performed.command, settings),
        "rollback_command": _scrub(performed.rollback_command, settings),
    }


def _execute_through_gate(
    store: SQLiteStore,
    settings: Settings,
    proposal: ResponseProposal,
    *,
    executor: Any,
    dry_run: bool,
) -> ResponseProposal:
    """Run one execution through the response gate.

    Exists as its own function so there is a single place in this file where an
    action is performed, and so that place demonstrably goes through the gate
    rather than calling `executor.execute` itself.

    Inputs:
        store: Initialized store used as the gate's audit sink.
        settings: Loaded settings supplying playbooks and capability switches.
        proposal: Approved proposal to perform.
        executor: Executor for this action type.
        dry_run: Whether to describe rather than perform.

    Outputs:
        The executed or failed proposal.

    Raises:
        ResponseError: If the gate refuses the execution or cannot audit it.
    """

    gate = _build_gate(store, settings)
    return gate.execute(proposal, executor=executor, dry_run=dry_run)


def _run_rollback(
    store: SQLiteStore,
    settings: Settings,
    args: argparse.Namespace,
) -> JsonDict:
    """Undo a performed pf block, or admit that a Wazuh action cannot be undone.

    Only `pf_block_ip` has a real inverse, and only its executor exposes
    `rollback`. For a Wazuh active response the recorded rollback text says in
    plain words that no rollback exists, so this prints that text and exits
    non-zero. Printing a success here would leave an operator believing an
    endpoint had been restored when nothing had changed.

    Inputs:
        store: Initialized store, also used as the audit sink.
        settings: Loaded settings supplying executor configuration.
        args: Parsed argparse namespace carrying proposal_id, --analyst and
            --confirm.

    Outputs:
        Summary dictionary describing the rollback.

    Raises:
        CliError: If the analyst is unnamed, the proposal is unknown, the action
        has no rollback path, the action was never performed, or the rollback
        failed.
    """

    analyst = _require_analyst(args.analyst)
    proposal = _proposal_from_payload(_load_action(store, args.proposal_id))
    confirm = bool(args.confirm)

    print(f"Proposal:  {proposal.id} ({proposal.action.value}, status {proposal.status.value})")
    print(f"Target:    {proposal.target}")
    print(f"Analyst:   {analyst}")

    if proposal.action is not ResponseActionType.PF_BLOCK_IP:
        recorded = proposal.rollback_command or WAZUH_ROLLBACK_UNAVAILABLE
        print(f"Rollback:  {_scrub(recorded, settings)}")
        raise CliError(
            f"{proposal.id} cannot be rolled back: {proposal.action.value} has no "
            "rollback path, and this tool will not pretend otherwise"
        )

    if confirm and proposal.status not in {
        ResponseStatus.EXECUTED,
        ResponseStatus.FAILED,
        ResponseStatus.ROLLED_BACK,
    }:
        raise CliError(
            f"{proposal.id} was never performed (status {proposal.status.value}); "
            "there is nothing to roll back"
        )

    executor = build_executor(proposal.action, settings)
    if not hasattr(executor, "rollback"):
        raise CliError(
            f"the executor for {proposal.action.value} exposes no rollback operation"
        )

    _, rollback_command = executor.describe(proposal.target)
    print(f"Mode:      {'LIVE' if confirm else 'DRY RUN'}")
    print(f"Command:   {_scrub(rollback_command, settings)}")

    if not confirm:
        output = executor.rollback(proposal.target, dry_run=True)
        print(f"Output:    {_scrub(output, settings)}")
        print("Nothing was changed. Add --confirm to perform the rollback.")
        return {
            "proposal_id": proposal.id,
            "status": proposal.status.value,
            "dry_run": True,
            "analyst": analyst,
        }

    # Recorded before the rollback runs, for the same reason the gate records
    # before an execution: an unlogged firewall change cannot be reviewed.
    proposal.status = ResponseStatus.ROLLED_BACK
    proposal.dry_run = False
    proposal.rollback_command = rollback_command
    proposal.decided_at = _now()
    _audit(store, proposal, stage="pre-rollback")

    try:
        output = executor.rollback(proposal.target, dry_run=False)
    except Exception as exc:
        proposal.status = ResponseStatus.FAILED
        proposal.error = f"rollback failed: {exc}"
        proposal.decided_at = _now()
        _audit(store, proposal, stage="rollback failure")
        raise CliError(
            f"rollback of {proposal.id} failed: {_scrub(str(exc), settings)}"
        ) from exc

    proposal.output = f"rolled back by {analyst}: {output}"
    proposal.decided_at = _now()
    _audit(store, proposal, stage="rollback")

    print(f"Output:    {_scrub(output, settings)}")
    print(f"Rolled back {proposal.id} as {analyst}.")
    return {
        "proposal_id": proposal.id,
        "status": proposal.status.value,
        "dry_run": False,
        "analyst": analyst,
    }


def _audit(store: SQLiteStore, proposal: ResponseProposal, *, stage: str) -> None:
    """Write one audit entry for an action this CLI performs itself.

    Mirrors `ResponseGate._record`: a rollback that cannot be recorded is not a
    controlled action, so a failure here raises rather than being logged and
    ignored.

    Inputs:
        store: Initialized store used as the audit sink.
        proposal: Proposal to record.
        stage: Label used in the error message when recording fails.

    Outputs:
        None.

    Raises:
        CliError: If the audit write fails.
    """

    try:
        store.record_response_action(proposal)
    except Exception as exc:
        raise CliError(
            f"cannot audit response {proposal.id} at {stage}: {exc}; "
            "refusing to act on an unrecordable action"
        ) from exc


def _scrub(text: Any, settings: Settings) -> str:
    """Remove any configured secret from text about to be printed.

    Executors and the clients underneath them can echo a URL, a header, or a key
    path into their own result and error strings. Everything this CLI prints ends
    up on an operator's screen and in their scrollback, so configured secrets are
    replaced here rather than trusting each executor not to include them.

    Inputs:
        text: Text to scrub.
        settings: Loaded settings holding the secret values.

    Outputs:
        Scrubbed text.
    """

    rendered = _text(text)
    for secret in _secret_values(settings):
        rendered = rendered.replace(secret, REDACTED)
    return rendered


def _secret_values(settings: Settings) -> list[str]:
    """Return every configured secret value, longest first.

    Longest first so a secret that contains another as a substring is replaced
    whole rather than being left partially readable.

    Inputs:
        settings: Loaded settings.

    Outputs:
        Non-empty secret values.
    """

    candidates = [
        settings.wazuh_manager_password,
        settings.wazuh_indexer_password,
        settings.securityonion_password,
        settings.securityonion_client_secret,
        settings.openrouter_api_key,
        settings.virustotal_api_key,
        settings.abuseipdb_api_key,
        settings.shodan_api_key,
        settings.smtp_password,
        settings.splunk_hec_token,
    ]
    values = {str(value) for value in candidates if str(value or "").strip()}
    return sorted(values, key=len, reverse=True)


def _build_gate(store: SQLiteStore, settings: Settings) -> ResponseGate:
    """Build the response gate every command must go through.

    The store is passed as the audit sink on purpose: the gate refuses to act
    when it cannot record what it is about to do, and this CLI must not weaken
    that. `require_model_score` is left at its default, so a locally scored
    result can never authorize a response from here.

    Inputs:
        store: Initialized store used as the audit sink.
        settings: Loaded settings supplying playbooks and capability switches.

    Outputs:
        Configured ResponseGate.

    Raises:
        PlaybookError: If a playbook file is unusable.
    """

    return ResponseGate(
        load_playbooks(settings.playbook_dir),
        capability_enabled=settings.response_capability_enabled,
        audit=store,
        # Redaction happens inside the gate, before the audit row is written.
        # Scrubbing only on the way to the terminal would still let a leaky
        # executor persist a credential into SQLite.
        scrub=lambda text: _scrub(text, settings),
    )


def build_executor(action: ResponseActionType, settings: Settings) -> Any:
    """Build the executor for one response action from settings.

    This is the seam tests replace, so no test opens SSH or HTTP. Imports are
    local so that `propose`, `list` and `show` never touch a transport module.

    An incompletely configured capability raises rather than returning None. A
    silent skip would tell an analyst nothing while quietly declining to carry
    out the action they approved.

    Inputs:
        action: Response action the executor must handle.
        settings: Loaded settings supplying connection details.

    Outputs:
        Executor exposing `describe` and `execute` for that action.

    Raises:
        CliError: If the action is unknown or its settings are incomplete.
    """

    if action is ResponseActionType.PF_BLOCK_IP:
        from soc.pfctl_client import PfctlBlockExecutor, PfctlConfig, PfctlError

        _require_settings(
            action,
            {
                "OPENBSD_PF_HOST": settings.openbsd_pf_host,
                "OPENBSD_PF_USER": settings.openbsd_pf_user,
                "OPENBSD_PF_BLOCK_TABLE": settings.openbsd_pf_block_table,
            },
        )
        try:
            config = PfctlConfig(
                host=settings.openbsd_pf_host,
                user=settings.openbsd_pf_user,
                block_table=settings.openbsd_pf_block_table,
            )
        except PfctlError as exc:
            raise CliError(f"pf firewall settings are unusable: {exc}") from exc
        return PfctlBlockExecutor(config)

    if action in {
        ResponseActionType.WAZUH_FIREWALL_DROP,
        ResponseActionType.WAZUH_HOST_DENY,
    }:
        from soc.wazuh_client import (
            WazuhError,
            WazuhManagerClient,
            WazuhManagerConfig,
        )
        from soc.wazuh_response import (
            WazuhFirewallDropExecutor,
            WazuhHostDenyExecutor,
        )

        _require_settings(
            action,
            {
                "WAZUH_MANAGER_URL": settings.wazuh_manager_url,
                "WAZUH_MANAGER_USER": settings.wazuh_manager_user,
                "WAZUH_MANAGER_PASSWORD": settings.wazuh_manager_password,
            },
        )
        try:
            client = WazuhManagerClient(
                WazuhManagerConfig(
                    url=settings.wazuh_manager_url,
                    username=settings.wazuh_manager_user,
                    password=settings.wazuh_manager_password,
                    verify_tls=settings.wazuh_manager_verify_tls,
                )
            )
        except WazuhError as exc:
            raise CliError(f"Wazuh Manager settings are unusable: {exc}") from exc
        if action is ResponseActionType.WAZUH_FIREWALL_DROP:
            return WazuhFirewallDropExecutor(client)
        return WazuhHostDenyExecutor(client)

    raise CliError(f"no executor is configured for action {action.value}")


def _require_settings(action: ResponseActionType, required: dict[str, str]) -> None:
    """Refuse an action whose transport settings are incomplete.

    Inputs:
        action: Response action being prepared.
        required: Mapping of environment variable name to configured value.

    Outputs:
        None.

    Raises:
        CliError: If any required value is blank.
    """

    missing = sorted(name for name, value in required.items() if not str(value).strip())
    if missing:
        raise CliError(
            f"response capability {action.value} is not fully configured; "
            f"missing: {', '.join(missing)}"
        )


def _require_analyst(analyst: Any) -> str:
    """Validate that a named analyst was given.

    Inputs:
        analyst: Value of --analyst.

    Outputs:
        The trimmed analyst name.

    Raises:
        CliError: If the name is missing or blank.
    """

    name = str(analyst or "").strip()
    if not name:
        raise CliError("--analyst is required: a response action needs a named human behind it")
    return name


def _triage_from_payload(payload: JsonDict) -> TriageResult:
    """Rebuild a stored triage result.

    `analysis_source` is carried through deliberately and defaults to LOCAL when
    absent. The gate refuses any response whose score did not come from a model,
    so losing or defaulting this field the other way would let a round trip
    through SQLite launder a heuristic score into an authorization.

    Inputs:
        payload: Stored triage result payload.

    Outputs:
        Rebuilt TriageResult.

    Raises:
        CliError: If the stored payload cannot be rebuilt.
    """

    try:
        return TriageResult(
            id=str(payload["id"]),
            target_id=str(payload.get("target_id", "")),
            target_type=str(payload.get("target_type", "")),
            score=int(payload["score"]),
            fp_likelihood=FalsePositiveLikelihood(payload["fp_likelihood"]),
            classification=str(payload.get("classification", "")),
            action=TriageAction(payload["action"]),
            summary=str(payload.get("summary", "")),
            iocs=payload.get("iocs") or {},
            recommended_actions=list(payload.get("recommended_actions") or []),
            reasoning=payload.get("reasoning"),
            evidence=[_evidence_from_payload(item) for item in payload.get("evidence") or []],
            model=payload.get("model"),
            latency_ms=payload.get("latency_ms"),
            token_usage=payload.get("token_usage") or {},
            analysis_source=AnalysisSource(payload.get("analysis_source", AnalysisSource.LOCAL)),
            prompt_version=payload.get("prompt_version"),
            created_at=_parse_datetime(payload.get("created_at")) or _now(),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CliError(
            f"stored triage result {payload.get('id')!r} cannot be rebuilt: {exc}"
        ) from exc


def _evidence_from_payload(payload: Any) -> EvidenceItem:
    """Rebuild one stored evidence item.

    Inputs:
        payload: Stored evidence dictionary.

    Outputs:
        Rebuilt EvidenceItem.

    Raises:
        ValueError: If the source is not a known event source.
    """

    record = payload if isinstance(payload, dict) else {}
    return EvidenceItem(
        source=EventSource(record.get("source", EventSource.UNKNOWN)),
        field=str(record.get("field", "")),
        value=record.get("value"),
        timestamp=_parse_datetime(record.get("timestamp")),
        alert_id=record.get("alert_id"),
        raw_event_id=record.get("raw_event_id"),
    )


def _proposal_from_payload(payload: JsonDict) -> ResponseProposal:
    """Rebuild a recorded response proposal.

    Rebuilding rather than trusting the caller keeps the lifecycle status
    authoritative in the audit table: an unapproved proposal reloaded here is
    still unapproved, and the gate will refuse to execute it.

    Inputs:
        payload: Stored response action payload.

    Outputs:
        Rebuilt ResponseProposal.

    Raises:
        CliError: If the stored payload cannot be rebuilt.
    """

    try:
        return ResponseProposal(
            id=str(payload["id"]),
            playbook_name=str(payload.get("playbook_name", "")),
            action=ResponseActionType(payload["action"]),
            target=str(payload.get("target", "")),
            triage_result_id=str(payload.get("triage_result_id", "")),
            triage_score=int(payload.get("triage_score", 0)),
            analysis_source=AnalysisSource(payload.get("analysis_source", AnalysisSource.LOCAL)),
            status=ResponseStatus(payload["status"]),
            reason=str(payload.get("reason", "")),
            denial_reason=str(payload.get("denial_reason", "")),
            requires_confirmation=bool(payload.get("requires_confirmation", True)),
            approved_by=payload.get("approved_by"),
            command=str(payload.get("command", "")),
            rollback_command=str(payload.get("rollback_command", "")),
            output=str(payload.get("output", "")),
            error=str(payload.get("error", "")),
            dry_run=bool(payload.get("dry_run", True)),
            created_at=_parse_datetime(payload.get("created_at")) or _now(),
            decided_at=_parse_datetime(payload.get("decided_at")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CliError(
            f"recorded response action {payload.get('id')!r} cannot be rebuilt: {exc}"
        ) from exc


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a stored ISO-8601 timestamp.

    Inputs:
        value: ISO-8601 text, or None.

    Outputs:
        Parsed datetime, or None when absent or unparseable.
    """

    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _now() -> datetime:
    """Return the current UTC time.

    Inputs:
        None.

    Outputs:
        Timezone-aware current time.
    """

    from soc.models import utc_now

    return utc_now()


def _format_proposal(proposal: ResponseProposal) -> str:
    """Render one freshly evaluated proposal for an operator.

    Inputs:
        proposal: Proposal to render.

    Outputs:
        Text block without a trailing newline.
    """

    lines = [
        f"Proposal {proposal.id} [{proposal.status.value}]",
        f"  Playbook:        {proposal.playbook_name}",
        f"  Action:          {proposal.action.value}",
        f"  Target:          {proposal.target}",
        f"  Score:           {proposal.triage_score} ({proposal.analysis_source.value})",
        f"  Reason:          {_text(proposal.reason)}",
    ]
    if proposal.status is ResponseStatus.DENIED:
        lines.append(f"  Denial reason:   {_text(proposal.denial_reason)}")
    return "\n".join(lines)


def _load_action(store: SQLiteStore, proposal_id: str) -> JsonDict:
    """Load one recorded response action by ID.

    Inputs:
        store: Initialized store.
        proposal_id: Response proposal ID.

    Outputs:
        The stored action payload.

    Raises:
        CliError: If no action with that ID is recorded.
    """

    wanted = str(proposal_id).strip()
    for action in store.list_response_actions():
        if action.get("id") == wanted:
            return action
    raise CliError(f"{proposal_id} is not a recorded response action")


def _format_detail(payload: JsonDict) -> str:
    """Render one response action as an aligned detail block.

    Inputs:
        payload: Stored action payload.

    Outputs:
        Detail text without a trailing newline.
    """

    fields = [
        ("Proposal", payload.get("id")),
        ("Playbook", payload.get("playbook_name")),
        ("Action", payload.get("action")),
        ("Target", payload.get("target")),
        ("Status", payload.get("status")),
        ("Triage result", payload.get("triage_result_id")),
        ("Triage score", payload.get("triage_score")),
        ("Analysis source", payload.get("analysis_source")),
        ("Requires confirmation", payload.get("requires_confirmation")),
        ("Approved by", payload.get("approved_by")),
        ("Dry run", payload.get("dry_run")),
        ("Created at", payload.get("created_at")),
        ("Decided at", payload.get("decided_at")),
        ("Reason", payload.get("reason")),
        ("Denial reason", payload.get("denial_reason")),
        ("Command", payload.get("command")),
        ("Rollback command", payload.get("rollback_command")),
        ("Output", payload.get("output")),
        ("Error", payload.get("error")),
    ]
    width = max(len(label) for label, _ in fields) + 1
    lines = [f"{label + ':':<{width}} {_text(value)}" for label, value in fields]
    return "\n".join(lines)


def _format_table(actions: list[JsonDict]) -> str:
    """Render response actions as an aligned text table.

    `analysis_source` is printed on every row on purpose: an operator must be
    able to see at a glance whether a model or a heuristic produced the score
    behind a proposed action, because a heuristic score can never authorize one.

    Inputs:
        actions: Stored action payloads, in the order the store returned them.

    Outputs:
        Table text without a trailing newline.
    """

    headers = [
        "#",
        "PROPOSAL ID",
        "PLAYBOOK",
        "ACTION",
        "TARGET",
        "STATUS",
        "SCORE",
        "SOURCE",
        "APPROVER",
        "DRY RUN",
    ]

    rows: list[list[str]] = []
    for position, action in enumerate(actions, start=1):
        rows.append(
            [
                str(position),
                _text(action.get("id")),
                _text(action.get("playbook_name")),
                _text(action.get("action")),
                _text(action.get("target")),
                _text(action.get("status")),
                _text(action.get("triage_score")),
                _text(action.get("analysis_source")),
                _text(action.get("approved_by")),
                "yes" if action.get("dry_run") else "no",
            ]
        )

    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    lines = [
        "  ".join(value.ljust(widths[index]) for index, value in enumerate(headers)).rstrip()
    ]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append(
            "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip()
        )
    return "\n".join(lines)


def _text(value: Any) -> str:
    """Render one field value for human reading.

    Inputs:
        value: Any stored value.

    Outputs:
        Display text, "-" when the value is absent or blank.
    """

    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _validate_limit(limit: int | None) -> int | None:
    """Validate an optional row limit.

    Inputs:
        limit: Requested limit, or None for no limit.

    Outputs:
        The validated limit, or None.

    Raises:
        CliError: If the limit is not positive.
    """

    if limit is not None and limit < 1:
        raise CliError("--limit must be a positive integer")
    return limit


def _validate_status(status: str | None) -> ResponseStatus | None:
    """Validate an optional lifecycle status filter.

    An unknown status is refused rather than matching nothing: silently listing
    zero rows would read as "no such actions exist".

    Inputs:
        status: Requested status name, or None.

    Outputs:
        The ResponseStatus, or None.

    Raises:
        CliError: If the status name is unknown.
    """

    if status is None:
        return None
    try:
        return ResponseStatus(str(status).strip().lower())
    except ValueError as exc:
        known = ", ".join(item.value for item in ResponseStatus)
        raise CliError(f"unknown --status {status!r}; known statuses: {known}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
