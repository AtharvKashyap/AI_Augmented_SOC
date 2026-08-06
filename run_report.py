"""Command-line incident reporting tool for AI_Augmented_SOC.

Milestone 4.1 promotes candidates into `INC-*` incidents and stores them; this
CLI is what makes an incident readable. It lists recent incidents, shows the
candidates and triage results behind one of them, and drafts the Markdown
incident report for delivery to an analyst by file or email.

Two properties of this file matter more than its size:

- **Provenance is stated, never implied.** Every generated report and every JSON
  summary says whether the narrative was model-drafted or produced by the
  deterministic renderer, and the CLI only claims a model when something
  actually recorded one. A templated report must never be mistakable for a
  model-drafted one, exactly as `run_pipeline.py` reports `triage_mode` and
  `analysis_sources` for triage.
- **Rendering lives in `soc/report.py`.** This file loads stored payloads,
  rehydrates them into the models in `soc/models.py`, and calls the report
  builder. It contains no Markdown section logic of its own beyond the
  provenance footer it adds when the renderer did not state provenance itself.

Like `run_pipeline.py` and `run_review.py` this file is intentionally thin: it
parses arguments, loads settings, opens the store, and formats output.
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
import typing
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from soc import incidents as incidents_module
from soc.config import ConfigError, get_settings
from soc.notifier import (
    NotificationAttachment,
    NotificationDispatcher,
    NotificationMessage,
)
from soc.openrouter_client import OpenRouterClient, OpenRouterError
from soc.report import ReportError, create_incident_report, write_report_file
from soc.splunk_client import SplunkClient, SplunkError
from soc.store import SQLiteStore, StoreError

JsonDict = dict[str, Any]

#: Narrative produced by an LLM.
NARRATIVE_MODEL_DRAFTED = "model_drafted"

#: Narrative produced by the deterministic Markdown renderer.
NARRATIVE_TEMPLATED = "templated"

#: Lowercased substrings that show a report already states its own provenance.
PROVENANCE_MARKERS = (
    "model-drafted",
    "model_drafted",
    "llm-drafted",
    "templated",
    "deterministic renderer",
)


class CliError(RuntimeError):
    """Raised when CLI input or execution is invalid."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Three verbs read better as subcommands than as flags, so `list`, `show`, and
    `generate` are subparsers that each carry the shared `--db` / `--env-file`
    arguments.

    Inputs:
        None.

    Outputs:
        Configured ArgumentParser.
    """

    parser = argparse.ArgumentParser(
        description="List, inspect, and draft Markdown reports for stored SOC incidents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser(
        "list",
        help="List recent incidents, newest first.",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of incidents to list. Defaults to all.",
    )
    _add_shared_arguments(list_parser)

    show_parser = subparsers.add_parser(
        "show",
        help="Show one incident with the candidates and triage results behind it.",
    )
    show_parser.add_argument("incident_id", help="Incident ID such as INC-20260610-001-ab12cd34.")
    _add_shared_arguments(show_parser)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Draft the Markdown incident report and write it out.",
    )
    generate_parser.add_argument("incident_id", help="Incident ID to report on.")
    generate_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Report file path. Defaults to <OUTPUT_DIR>/<incident-id>.md.",
    )
    notes_group = generate_parser.add_mutually_exclusive_group()
    notes_group.add_argument(
        "--notes",
        default=None,
        help="Analyst notes to include in the report.",
    )
    notes_group.add_argument(
        "--notes-file",
        type=Path,
        default=None,
        help="File holding analyst notes to include in the report.",
    )
    generate_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force the deterministic renderer even when an API key is configured.",
    )
    generate_parser.add_argument(
        "--splunk",
        action="store_true",
        help=(
            "Send the incident summary to Splunk HEC. The report body is not sent; "
            "it is written to disk and can be emailed with --email."
        ),
    )
    generate_parser.add_argument(
        "--email",
        action="store_true",
        help="Email the report as a Markdown attachment as well as writing the file.",
    )
    _add_shared_arguments(generate_parser)

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
    """Run the incident reporting CLI.

    Inputs:
        argv: Optional argument list. Defaults to sys.argv.

    Outputs:
        Process exit code: 0 on success, 1 on handled errors, 130 on interrupt.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        run_from_args(args)
    except (CliError, ConfigError, StoreError, ReportError, SplunkError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130

    return 0


def run_from_args(args: argparse.Namespace) -> JsonDict:
    """Dispatch one reporting subcommand.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        JSON-safe summary dictionary describing what the command did.

    Raises:
        CliError: If the command is unknown or its input is invalid.
        ConfigError: If settings cannot be loaded.
        StoreError: If the store rejects the operation.
        ReportError: If report rendering fails.
    """

    settings = get_settings(args.env_file, reload=True)
    store, db_path = _build_store(args, settings)
    summary: JsonDict = {"command": args.command, "db_path": str(db_path)}

    if args.command == "list":
        summary.update(_run_list(store, args))
    elif args.command == "show":
        summary.update(_run_show(store, args))
    elif args.command == "generate":
        summary.update(_run_generate(store, args, settings))
    else:
        raise CliError(f"unknown command: {args.command}")

    return summary


def _build_store(args: argparse.Namespace, settings: Any) -> tuple[SQLiteStore, Path]:
    """Open and initialize the store the command should read.

    Inputs:
        args: Parsed argparse namespace carrying --db.
        settings: Loaded application settings.

    Outputs:
        Tuple of initialized store and the resolved database path.

    Raises:
        CliError: If the database cannot be opened or initialized.
    """

    db_path = Path(args.db or settings.sqlite_db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(db_path)
    try:
        store.initialize()
    except Exception as exc:
        raise CliError(f"cannot initialize database: {exc}") from exc
    return store, db_path


def _run_list(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """List recent incidents as a compact table, newest first.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying --limit.

    Outputs:
        Summary dictionary with the row count.

    Raises:
        CliError: If --limit is not positive.
    """

    limit = _validate_limit(args.limit)
    incidents = store.list_recent_incidents(limit)

    if not incidents:
        print("No incidents recorded. Run the pipeline first, or widen --limit.")
        return {"count": 0}

    print(_format_incident_table(incidents))
    return {"count": len(incidents)}


def _run_show(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """Print one incident with the candidates and triage results behind it.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying incident_id.

    Outputs:
        Summary dictionary naming the incident shown.

    Raises:
        CliError: If the incident ID is unknown.
    """

    incident = _load_incident_payload(store, args.incident_id)
    candidates = _load_candidate_payloads(store, incident)
    triage_results = _load_triage_payloads(store, incident)

    lines = [
        f"Incident:        {incident.get('id')}",
        f"Time span:       {_format_span(incident)}",
        f"Primary host:    {incident.get('primary_host') or '-'}",
        f"Primary user:    {incident.get('primary_user') or '-'}",
        f"Max score:       {incident.get('max_score')}/10",
        f"Candidates:      {len(candidates)}",
        f"Alerts:          {len(incident.get('alert_ids') or [])}",
        f"Source IPs:      {_join(incident.get('src_ips'))}",
        f"Destination IPs: {_join(incident.get('dst_ips'))}",
        f"Created at:      {incident.get('created_at') or '-'}",
        "",
        "Candidates:",
    ]

    for payload in candidates:
        lines.append(
            f"  - {payload.get('id')}: {len(payload.get('alerts') or [])} alert(s) on "
            f"{payload.get('primary_host') or 'unknown host'} "
            f"({_format_span(payload)})"
        )
    if not candidates:
        lines.append("  (none stored)")

    lines += ["", "Triage results:"]
    for payload in triage_results:
        lines += [
            f"  - {payload.get('id')} score {payload.get('score')}/10 "
            f"action {payload.get('action')} source {payload.get('analysis_source')} "
            f"model {payload.get('model') or '-'}",
            f"    {payload.get('summary') or '(no summary recorded)'}",
        ]
    if not triage_results:
        lines.append("  (none stored)")

    print("\n".join(lines))
    return {
        "incident_id": str(incident.get("id")),
        "candidates": len(candidates),
        "triage_results": len(triage_results),
    }


def _run_generate(store: SQLiteStore, args: argparse.Namespace, settings: Any) -> JsonDict:
    """Draft, write, and optionally email one incident report.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace for the generate subcommand.
        settings: Loaded application settings.

    Outputs:
        Summary dictionary describing the report and its delivery.

    Raises:
        CliError: If the incident is unknown, the notes file is missing, or the
            requested model narrative cannot be wired up.
        ReportError: If report rendering fails.
    """

    incident_payload = _load_incident_payload(store, args.incident_id)
    candidate_payloads = _load_candidate_payloads(store, incident_payload)
    triage_payloads = _load_triage_payloads(store, incident_payload)
    notes = _read_notes(args)

    incident = _hydrate(incidents_module.Incident, incident_payload)
    candidates = [_hydrate(_models().IncidentCandidate, payload) for payload in candidate_payloads]
    triage_results = [_hydrate(_models().TriageResult, payload) for payload in triage_payloads]

    client, requested_model = _build_narrative_client(settings, use_llm=not args.no_llm)
    report = create_incident_report(
        incident,
        candidates=candidates,
        triage_results=triage_results,
        analyst_notes=notes,
        narrative_client=client,
        model=requested_model,
    )

    narrative_mode, narrative_model = narrative_provenance(report, requested_model=requested_model)
    markdown = _ensure_provenance_footer(report.markdown, narrative_mode, narrative_model)

    output_path = Path(args.output) if args.output else Path(settings.output_dir) / f"{incident.id}.md"
    written = write_report_file(markdown, output_path)

    provenance_text = _provenance_sentence(narrative_mode, narrative_model)
    print(f"Wrote incident report for {incident.id} to {written}")
    print(f"Narrative: {provenance_text}")
    if requested_model and narrative_mode == NARRATIVE_TEMPLATED:
        print(
            f"note: a model narrative was requested from {requested_model} but the "
            "deterministic renderer produced this report.",
            file=sys.stderr,
        )

    summary: JsonDict = {
        "incident_id": incident.id,
        "output_path": str(written),
        "candidates": len(candidates),
        "triage_results": len(triage_results),
        "analyst_notes": notes is not None,
        # Provenance is reported the way run_pipeline.py reports triage_mode: what
        # was asked for, what actually produced the text, and whether it degraded.
        "narrative_requested": NARRATIVE_MODEL_DRAFTED if requested_model else NARRATIVE_TEMPLATED,
        "narrative_mode": narrative_mode,
        "narrative_model": narrative_model,
        "narrative_fallback": bool(requested_model) and narrative_mode == NARRATIVE_TEMPLATED,
        "email": bool(args.email),
    }

    if getattr(args, "splunk", False):
        summary.update(_push_incident_to_splunk(settings, incident))

    if args.email:
        summary["notifications"] = _send_report_email(
            settings,
            incident_payload=incident_payload,
            markdown=markdown,
            report_path=written,
            provenance_text=provenance_text,
        )

    return summary


def _build_narrative_client(settings: Any, *, use_llm: bool) -> tuple[Any | None, str | None]:
    """Build the OpenRouter client that may draft the report narrative.

    A model narrative is used only when it is both requested and configured. A
    missing API key is a normal operating mode: the deterministic renderer still
    produces a full report, and the summary reports which one ran.
    `OPENROUTER_REPORT_MODEL` wins over `OPENROUTER_MODEL` so reports can use a
    better model than triage.

    Inputs:
        settings: Application settings object.
        use_llm: Whether a model narrative is permitted for this run.

    Outputs:
        Tuple of client (or None) and the model name that was requested.

    Raises:
        CliError: If the model narrative is configured but the client cannot be
            built.
    """

    if not use_llm or not str(getattr(settings, "openrouter_api_key", "") or "").strip():
        return None, None

    model = str(getattr(settings, "report_model", "") or "").strip() or None
    try:
        client = OpenRouterClient.from_settings(settings, model=model)
    except OpenRouterError as exc:
        raise CliError(f"cannot build OpenRouter client: {exc}") from exc
    return client, model


def narrative_provenance(report: Any, *, requested_model: str | None) -> tuple[str, str | None]:
    """Decide what actually drafted the narrative of a report.

    `soc.report` populates `IncidentReport.generated_by_model` only when a model
    genuinely drafted the prose, so that field — not the fact that a model was
    *requested* — is the single thing this trusts. A requested draft that fell
    back to the deterministic renderer must read as templated, the same way a
    failed LLM triage call is relabelled `local` in `soc/triage.py`.

    Inputs:
        report: IncidentReport returned by `create_incident_report`.
        requested_model: Model that was asked for, or None. Recorded by the
            caller for the summary; it is deliberately not used as evidence.

    Outputs:
        Tuple of narrative mode and the model name, if any.
    """

    del requested_model
    model = getattr(report, "generated_by_model", None)
    if isinstance(model, str) and model.strip():
        return NARRATIVE_MODEL_DRAFTED, model.strip()
    return NARRATIVE_TEMPLATED, None


def _provenance_sentence(narrative_mode: str, narrative_model: str | None) -> str:
    """Describe the narrative provenance in one human-readable clause.

    Inputs:
        narrative_mode: Narrative mode from `narrative_provenance`.
        narrative_model: Model name, if any.

    Outputs:
        Provenance description.
    """

    if narrative_mode == NARRATIVE_MODEL_DRAFTED:
        return f"model-drafted by {narrative_model or 'an unnamed model'}"
    return "templated by the deterministic renderer (no model was consulted)"


def _ensure_provenance_footer(markdown: str, narrative_mode: str, narrative_model: str | None) -> str:
    """Guarantee the report file itself states how it was drafted.

    The renderer is expected to mark provenance on the report. When it does not,
    the file would leave a reader unable to tell a drafted narrative from a
    templated one, so the CLI appends the statement rather than shipping a report
    that is silent about it.

    Inputs:
        markdown: Rendered report text.
        narrative_mode: Narrative mode from `narrative_provenance`.
        narrative_model: Model name, if any.

    Outputs:
        Report text that states its provenance.
    """

    lowered = markdown.lower()
    if any(marker in lowered for marker in PROVENANCE_MARKERS):
        return markdown

    footer = f"_Narrative provenance: {_provenance_sentence(narrative_mode, narrative_model)}._"
    return markdown.rstrip() + "\n\n" + footer + "\n"


def _push_incident_to_splunk(settings: Any, incident: Any) -> JsonDict:
    """Send one incident summary to Splunk HEC.

    Only the incident summary goes out. The report body stays local: it is
    already written to disk and can be emailed, and a Splunk index is the wrong
    place to accumulate narrative documents.

    A send that fails is recorded rather than raised. By the time this runs the
    report file exists, so failing the command would tell an operator the report
    was not produced when it was.

    Inputs:
        settings: Application settings carrying the HEC URL and token.
        incident: Incident to summarize.

    Outputs:
        Summary fields describing the export.

    Raises:
        CliError: If `--splunk` was requested but HEC is not configured. An
        unconfigured export must not be silently downgraded to no export.
    """

    # from_settings raises SplunkError when unconfigured rather than returning None,
    # and main reports that as `error: ...`. Requesting an export that cannot happen
    # must fail loudly, not silently become no export.
    client = SplunkClient.from_settings(settings)

    try:
        sent = client.send_incidents([incident])
    except Exception as exc:  # any transport failure is non-fatal here
        return {"splunk_events_sent": 0, "splunk_error": str(exc)}
    return {"splunk_events_sent": int(sent)}


def _send_report_email(
    settings: Any,
    *,
    incident_payload: JsonDict,
    markdown: str,
    report_path: Path,
    provenance_text: str,
) -> list[JsonDict]:
    """Send the report as a Markdown attachment through the notifier.

    The body repeats the incident summary and its provenance, because a mail
    client that cannot render the attachment must still show an analyst what
    happened.

    Inputs:
        settings: Application settings object.
        incident_payload: Stored incident payload.
        markdown: Report text to attach.
        report_path: Path the report was written to, used as the filename.
        provenance_text: Human-readable narrative provenance.

    Outputs:
        List of JSON-safe notification result dictionaries.
    """

    incident_id = str(incident_payload.get("id"))
    body = "\n".join(
        [
            f"Incident report for {incident_id} is attached as {report_path.name}.",
            "",
            f"Time span:    {_format_span(incident_payload)}",
            f"Primary host: {incident_payload.get('primary_host') or 'unknown'}",
            f"Primary user: {incident_payload.get('primary_user') or 'unknown'}",
            f"Max score:    {incident_payload.get('max_score')}/10",
            f"Candidates:   {len(incident_payload.get('candidate_ids') or [])}",
            f"Alerts:       {len(incident_payload.get('alert_ids') or [])}",
            f"Narrative:    {provenance_text}",
            f"Report file:  {report_path}",
        ]
    )
    message = NotificationMessage(
        subject=f"[SOC] Incident report {incident_id} (score {incident_payload.get('max_score')}/10)",
        body=body,
        severity="critical" if int(incident_payload.get("max_score") or 0) >= 8 else "warning",
        metadata={
            "incident_id": incident_id,
            "max_score": incident_payload.get("max_score"),
            "report_path": str(report_path),
            "narrative": provenance_text,
        },
        attachments=(
            NotificationAttachment(filename=report_path.name, content=markdown),
        ),
    )

    dispatcher = NotificationDispatcher.from_settings(settings)
    results = dispatcher.send(message)
    payloads = [result.to_dict() for result in results]
    for payload in payloads:
        state = "sent" if payload.get("success") else "failed"
        line = f"Report email {state} via {payload.get('channel')} to {payload.get('destination')}"
        if payload.get("success"):
            print(line)
        else:
            print(f"warning: {line}: {payload.get('error') or 'no detail reported'}", file=sys.stderr)
    return payloads


def _read_notes(args: argparse.Namespace) -> str | None:
    """Read analyst notes from --notes or --notes-file.

    Inputs:
        args: Parsed argparse namespace for the generate subcommand.

    Outputs:
        Notes text, or None when no notes were given.

    Raises:
        CliError: If the notes file cannot be read.
    """

    if args.notes is not None:
        notes = str(args.notes).strip()
        return notes or None

    if args.notes_file is None:
        return None

    path = Path(args.notes_file)
    try:
        notes = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CliError(f"cannot read notes file {path}: {exc}") from exc
    return notes or None


def _load_incident_payload(store: SQLiteStore, incident_id: str) -> JsonDict:
    """Load one stored incident payload.

    Inputs:
        store: Initialized store.
        incident_id: Incident ID.

    Outputs:
        Incident payload dictionary.

    Raises:
        CliError: If the incident is not stored.
    """

    payload = store.get_incident(incident_id)
    if payload is None:
        raise CliError(f"no incident stored with ID {incident_id}")
    return payload


def _load_candidate_payloads(store: SQLiteStore, incident: JsonDict) -> list[JsonDict]:
    """Load the candidate payloads an incident was built from.

    The link table is authoritative; the incident payload is the fallback for a
    record saved before the mapping existed.

    Inputs:
        store: Initialized store.
        incident: Incident payload.

    Outputs:
        List of candidate payloads, skipping any that are no longer stored.
    """

    candidate_ids = store.list_incident_candidate_ids(str(incident.get("id"))) or list(
        incident.get("candidate_ids") or []
    )
    payloads: list[JsonDict] = []
    for candidate_id in candidate_ids:
        payload = store.get_incident_candidate(candidate_id)
        if payload is not None:
            payloads.append(payload)
    return payloads


def _load_triage_payloads(store: SQLiteStore, incident: JsonDict) -> list[JsonDict]:
    """Load the triage result payloads that justified an incident.

    Inputs:
        store: Initialized store.
        incident: Incident payload.

    Outputs:
        List of triage result payloads, skipping any that are no longer stored.
    """

    payloads: list[JsonDict] = []
    for triage_result_id in incident.get("triage_result_ids") or []:
        payload = store.get_triage_result(str(triage_result_id))
        if payload is not None:
            payloads.append(payload)
    return payloads


def _models() -> Any:
    """Return the models module.

    Importing it through a helper keeps the hydration code below readable while
    still naming a single import site.

    Inputs:
        None.

    Outputs:
        The `soc.models` module.
    """

    from soc import models

    return models


def _hydrate(cls: Any, payload: JsonDict) -> Any:
    """Rebuild one dataclass from the JSON payload the store holds.

    The store persists `to_dict()` output, while `soc/report.py` renders model
    objects. This is the inverse of `models._serialize_dataclass`: it is generic
    over the dataclass fields rather than field-by-field, so adding a field to a
    model does not require editing this CLI.

    Inputs:
        cls: Dataclass type to build.
        payload: Serialized payload.

    Outputs:
        Instance of `cls`.

    Raises:
        CliError: If the payload cannot populate the dataclass.
    """

    if not dataclasses.is_dataclass(cls):
        raise CliError(f"{getattr(cls, '__name__', cls)} is not a dataclass")

    hints = typing.get_type_hints(cls)
    kwargs: JsonDict = {}
    for field in dataclasses.fields(cls):
        if field.name in payload:
            kwargs[field.name] = _coerce(hints.get(field.name, Any), payload[field.name])

    try:
        return cls(**kwargs)
    except (TypeError, ValueError) as exc:
        raise CliError(f"cannot rebuild {getattr(cls, '__name__', cls)} from stored payload: {exc}") from exc


def _coerce(annotation: Any, value: Any) -> Any:
    """Convert one serialized value back into the type its field declares.

    Inputs:
        annotation: Field type annotation.
        value: Serialized value.

    Outputs:
        Converted value, or the value unchanged when no conversion applies.
    """

    if value is None:
        return None

    origin = typing.get_origin(annotation)
    if origin is not None:
        args = [arg for arg in typing.get_args(annotation) if arg is not type(None)]
        if origin in (list, tuple, set, frozenset):
            item_type = args[0] if args else Any
            return [_coerce(item_type, item) for item in value]
        if origin is dict:
            return value
        for arg in args:
            converted = _coerce(arg, value)
            if converted is not value:
                return converted
        return value

    if isinstance(annotation, type):
        if issubclass(annotation, Enum):
            try:
                return annotation(value)
            except ValueError:
                return value
        if annotation is datetime:
            return _parse_datetime(value)
        if dataclasses.is_dataclass(annotation) and isinstance(value, dict):
            return _hydrate(annotation, value)

    return value


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a stored ISO-8601 timestamp.

    Inputs:
        value: Timestamp text, datetime, or None.

    Outputs:
        Timezone-aware datetime, or None when unparsable.
    """

    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _format_incident_table(incidents: list[JsonDict]) -> str:
    """Render incidents as an aligned text table.

    Inputs:
        incidents: Incident payloads in the order the store returned them.

    Outputs:
        Table text without a trailing newline.
    """

    headers = ["#", "INCIDENT ID", "TIME SPAN", "PRIMARY HOST", "MAX SCORE", "CANDIDATES"]
    rows: list[list[str]] = []
    for position, incident in enumerate(incidents, start=1):
        rows.append(
            [
                str(position),
                str(incident.get("id") or "-"),
                _format_span(incident),
                str(incident.get("primary_host") or "-"),
                f"{incident.get('max_score')}/10",
                str(len(incident.get("candidate_ids") or [])),
            ]
        )

    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    lines = ["  ".join(value.ljust(widths[index]) for index, value in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
    return "\n".join(lines)


def _format_span(payload: JsonDict) -> str:
    """Render the first-seen to last-seen span of an incident or candidate.

    Inputs:
        payload: Payload carrying first_seen and last_seen.

    Outputs:
        Time span text.
    """

    first = _format_time(payload.get("first_seen"))
    last = _format_time(payload.get("last_seen"))
    if first == last:
        return first
    return f"{first} -> {last}"


def _format_time(value: Any) -> str:
    """Render one timestamp compactly for a table cell.

    Inputs:
        value: ISO-8601 text, datetime, or None.

    Outputs:
        Timestamp text, or "-" when absent.
    """

    parsed = _parse_datetime(value) if value is not None else None
    if parsed is None:
        return "-"
    return parsed.strftime("%Y-%m-%d %H:%M")


def _join(values: Any) -> str:
    """Render a list of values as a comma-separated string.

    Inputs:
        values: List of values, or None.

    Outputs:
        Comma-separated text, or "-" when empty.
    """

    if not values:
        return "-"
    if not isinstance(values, list):
        return str(values)
    return ", ".join(str(value) for value in values)


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


if __name__ == "__main__":
    raise SystemExit(main())
