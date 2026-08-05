"""Command-line runner for the AI_Augmented_SOC pipeline.

This file is intentionally thin. The real workflow lives in `soc.pipeline`.
The CLI only parses arguments, loads settings, constructs the pipeline, runs a
selected event source, and prints a JSON summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from soc.abuseipdb_client import AbuseIPDBClient
from soc.assets import AssetError, AssetInventory
from soc.config import ConfigError, get_settings
from soc.daemon import DaemonConfig, DaemonError, PollingDaemon
from soc.models import AnalysisSource
from soc.notifier import NotificationDispatcher
from soc.openrouter_client import OpenRouterClient, OpenRouterError
from soc.pipeline import PipelineConfig, PipelineError, SOCPipeline
from soc.security_onion_client import SecurityOnionClient, SecurityOnionError
from soc.shodan_client import ShodanClient
from soc.threat_intel import ThreatIntelEnricher, ThreatIntelError
from soc.triage import TriageEngine
from soc.virustotal_client import VirusTotalClient
from soc.wazuh_client import WazuhClient, WazuhError

JsonDict = dict[str, Any]


class CliError(RuntimeError):
    """Raised when CLI input or execution is invalid."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Inputs:
        None.

    Outputs:
        Configured ArgumentParser.
    """

    parser = argparse.ArgumentParser(
        description="Run the AI_Augmented_SOC pipeline.",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--replay",
        type=Path,
        help="Path to a replay JSON file.",
    )
    source_group.add_argument(
        "--replay-dir",
        type=Path,
        help="Path to a directory containing replay JSON files.",
    )
    source_group.add_argument(
        "--wazuh",
        action="store_true",
        help="Read recent alerts from the Wazuh Manager alerts.json file and process them.",
    )
    source_group.add_argument(
        "--security-onion",
        action="store_true",
        help="Fetch recent alerts from the Security Onion Connect API and process them.",
    )
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
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Report output directory. Defaults to OUTPUT_DIR from .env.",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send notifications using configured channels.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use dry-run notifications instead of real delivery.",
    )
    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="Do not write Markdown report files.",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable deduplication for this run.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Raise immediately on the first pipeline error.",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force deterministic local triage even when an OpenRouter key is configured.",
    )
    parser.add_argument(
        "--no-intel",
        action="store_true",
        help="Skip external threat-intel providers even when API keys are configured.",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Poll continuously instead of running one cycle.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=None,
        help="Seconds between daemon cycles. Defaults to POLL_INTERVAL_SECONDS.",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Stop the daemon after this many cycles. Defaults to running until stopped.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON summary.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the pipeline CLI.

    Inputs:
        argv: Optional argument list. Defaults to sys.argv.

    Outputs:
        Process exit code.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        summary = run_from_args(args)
    except (CliError, ConfigError, PipelineError, SecurityOnionError, WazuhError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130

    indent = 2 if args.pretty else None
    print(json.dumps(summary, indent=indent, sort_keys=True))
    return 0


def run_from_args(args: argparse.Namespace) -> JsonDict:
    """Create and run pipeline from parsed CLI args.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        JSON-safe summary dictionary.
    """

    settings = get_settings(args.env_file, reload=True)
    db_path = Path(args.db or settings.sqlite_db_path)
    output_dir = Path(args.output or settings.output_dir)
    _validate_source_args(args)

    output_dir.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    config = PipelineConfig(
        output_dir=output_dir,
        write_reports=not args.no_reports,
        send_notifications=args.notify,
        deduplicate=not args.no_dedup,
        fail_fast=args.fail_fast,
    )
    notifier = NotificationDispatcher.from_settings(settings, dry_run=args.dry_run)
    triage_engine = _build_triage_engine(settings, use_llm=not args.no_llm)
    intel_enricher = _build_intel_enricher(settings, use_intel=not args.no_intel)
    pipeline = SOCPipeline.with_sqlite_store(
        db_path,
        config=config,
        notifier=notifier,
        triage_engine=triage_engine,
        asset_inventory=_build_asset_inventory(settings),
        intel_enricher=intel_enricher,
    )

    if intel_enricher is not None:
        # Share the pipeline's database as the intel cache. Without it, every run
        # would re-pay for indicators it has already looked up.
        intel_enricher.cache = getattr(pipeline, "store", None)

    # Create the schema before anything reads it. The pipeline initializes the
    # store when it processes events, but the alerts.json read cursor is consulted
    # before that, so the tables must already exist.
    _initialize_store(pipeline)

    source_mode = _source_mode(args)
    triage_mode = "llm" if triage_engine.llm_client is not None else "local"
    # The pipeline, Wazuh client, and read cursor are built once and reused across
    # every cycle. Rebuilding per cycle would reset the cursor and re-read the
    # whole alert file each time.
    run_cycle = _build_run_cycle(args, settings, pipeline, use_cursor=args.daemon)

    if args.daemon:
        summary = _run_daemon(args, settings, run_cycle)
    else:
        summary = _run_once(args, run_cycle)

    summary["source_mode"] = source_mode
    summary["db_path"] = str(db_path)
    summary["output_dir"] = str(output_dir)
    summary["notifications_enabled"] = args.notify
    summary["dry_run"] = args.dry_run
    summary["triage_mode"] = triage_mode
    summary["intel_providers"] = (
        sorted(provider.name for provider in intel_enricher.providers)
        if intel_enricher is not None
        else []
    )
    # Only an LLM-mode run can fall back; a local-mode run scored locally by design.
    if "analysis_sources" in summary:
        summary["local_fallbacks"] = (
            summary["analysis_sources"].get(AnalysisSource.LOCAL.value, 0) if triage_mode == "llm" else 0
        )
    return summary


def _build_intel_enricher(settings: Any, *, use_intel: bool) -> ThreatIntelEnricher | None:
    """Build the external threat-intel enricher from configured provider keys.

    A provider with no key is simply not configured, which is the default and a
    normal offline mode. A provider whose key is present but whose configuration
    is invalid is a misconfiguration and fails loudly, the same way an
    unreadable asset inventory does: quietly dropping it would leave enrichment
    weaker than the operator believes.

    Inputs:
        settings: Application settings object.
        use_intel: Whether external providers are permitted for this run.

    Outputs:
        ThreatIntelEnricher, or None when no provider is configured.

    Raises:
        CliError: If a configured provider cannot be built.
    """

    if not use_intel:
        return None

    factories = (
        ("virustotal_api_key", VirusTotalClient),
        ("abuseipdb_api_key", AbuseIPDBClient),
        ("shodan_api_key", ShodanClient),
    )

    providers = []
    for key_attr, factory in factories:
        if not str(getattr(settings, key_attr, "") or "").strip():
            continue
        try:
            providers.append(factory.from_settings(settings))
        except (ThreatIntelError, ValueError) as exc:
            raise CliError(f"cannot build threat-intel provider from {key_attr}: {exc}") from exc

    if not providers:
        return None

    return ThreatIntelEnricher(
        providers,
        ttl_hours=int(getattr(settings, "enrichment_cache_ttl_hours", 24) or 24),
    )


def _build_asset_inventory(settings: Any) -> AssetInventory | None:
    """Load the asset inventory when one is configured.

    Running without an inventory is a normal mode and returns None. But a
    configured-and-unreadable inventory is a misconfiguration worth failing on:
    continuing silently would leave triage blind to asset criticality while the
    run still looked healthy.

    Inputs:
        settings: Application settings object.

    Outputs:
        Loaded AssetInventory, or None when none is configured.

    Raises:
        CliError: If a configured inventory cannot be loaded.
    """

    configured = str(getattr(settings, "asset_inventory_path", "") or "").strip()
    if not configured:
        return None

    try:
        return AssetInventory.from_csv(configured)
    except AssetError as exc:
        raise CliError(f"cannot load asset inventory {configured}: {exc}") from exc


def _initialize_store(pipeline: Any) -> None:
    """Create the database schema up front.

    Inputs:
        pipeline: Constructed SOCPipeline, whose store may be None.

    Outputs:
        None.

    Raises:
        CliError: If the schema cannot be created.
    """

    store = getattr(pipeline, "store", None)
    if store is None:
        return
    try:
        store.initialize()
    except Exception as exc:
        raise CliError(f"cannot initialize database: {exc}") from exc


def _run_once(args: argparse.Namespace, run_cycle: Callable[[], Any]) -> JsonDict:
    """Run one pipeline cycle and summarize it.

    Inputs:
        args: Parsed argparse namespace.
        run_cycle: Callable performing one cycle.

    Outputs:
        JSON-safe summary dictionary.
    """

    del args
    result = run_cycle()
    summary = result.to_summary()
    summary["reports_written"] = [str(path) for path in result.report_paths]
    summary["analysis_sources"] = _count_analysis_sources(result)
    return summary


def _run_daemon(
    args: argparse.Namespace,
    settings: Any,
    run_cycle: Callable[[], Any],
) -> JsonDict:
    """Run cycles continuously until stopped, and summarize the loop.

    Per-cycle detail goes to the structured daemon log rather than this summary,
    which describes the run as a whole.

    Inputs:
        args: Parsed argparse namespace.
        settings: Application settings object.
        run_cycle: Callable performing one cycle.

    Outputs:
        JSON-safe summary dictionary.

    Raises:
        CliError: If the daemon configuration is invalid.
    """

    try:
        config = DaemonConfig(
            poll_interval_seconds=args.poll_interval or int(settings.poll_interval_seconds),
            max_cycles=args.max_cycles,
            log_dir=Path(settings.log_dir),
        )
    except DaemonError as exc:
        raise CliError(f"invalid daemon configuration: {exc}") from exc

    daemon = PollingDaemon(run_cycle=run_cycle, config=config)
    daemon.install_signal_handlers()
    summary = daemon.run().to_summary()
    summary["poll_interval_seconds"] = config.poll_interval_seconds
    summary["daemon_log"] = str(config.log_dir / "daemon.jsonl")
    return summary


def _build_run_cycle(
    args: argparse.Namespace,
    settings: Any,
    pipeline: Any,
    *,
    use_cursor: bool,
) -> Callable[[], Any]:
    """Build the callable that performs one ingestion cycle.

    The Wazuh client is created once so its auth token and read cursor survive
    across cycles. A read cursor is only used in daemon mode: a one-shot run
    should keep reading the whole alert file, as it always has.

    Inputs:
        args: Parsed argparse namespace.
        settings: Application settings object.
        pipeline: Constructed SOCPipeline.
        use_cursor: Whether to persist and resume from a read cursor.

    Outputs:
        Callable returning a pipeline run result.

    Raises:
        CliError: If no event source was selected.
    """

    if args.replay is not None:
        return lambda: pipeline.run_replay_file(args.replay)
    if args.replay_dir is not None:
        return lambda: pipeline.run_replay_directory(args.replay_dir)
    if args.wazuh:
        wazuh = WazuhClient.from_settings(
            settings,
            cursor_store=getattr(pipeline, "store", None) if use_cursor else None,
        )

        def _wazuh_cycle() -> Any:
            """Fetch recent Wazuh alerts and process them."""

            events = wazuh.fetch_recent_events(
                lookback_minutes=settings.wazuh_alert_lookback_minutes,
                min_level=settings.wazuh_min_level,
                limit=settings.wazuh_alert_limit,
            )
            return pipeline.run_events(events)

        return _wazuh_cycle
    if args.security_onion:
        onion = SecurityOnionClient.from_settings(settings)

        def _security_onion_cycle() -> Any:
            """Fetch recent Security Onion alerts and process them."""

            return pipeline.run_events(onion.fetch_recent_events())

        return _security_onion_cycle
    raise CliError(
        "one source is required: --replay, --replay-dir, --wazuh, or --security-onion"
    )


def _build_triage_engine(settings: Any, *, use_llm: bool) -> TriageEngine:
    """Build the triage engine the pipeline should use.

    LLM triage is used only when it is both requested and configured. A missing
    API key is a normal operating mode, not an error: the deterministic local
    engine still produces scores, and the run summary reports which one ran.

    Inputs:
        settings: Application settings object.
        use_llm: Whether LLM-assisted triage is permitted for this run.

    Outputs:
        TriageEngine, with an OpenRouter client attached when available.

    Raises:
        CliError: If LLM triage is configured but the client cannot be built.
    """

    if not use_llm or not str(getattr(settings, "openrouter_api_key", "") or "").strip():
        return TriageEngine()

    try:
        client = OpenRouterClient.from_settings(settings)
    except OpenRouterError as exc:
        raise CliError(f"cannot build OpenRouter client: {exc}") from exc
    return TriageEngine(client, model=getattr(settings, "openrouter_model", None))


def _count_analysis_sources(result: Any) -> JsonDict:
    """Count triage results by what produced them.

    A run configured for LLM triage that quietly degrades to local scoring under
    rate limits looks identical to a healthy run without this count.

    Inputs:
        result: PipelineRunResult from the pipeline.

    Outputs:
        Mapping of analysis source value to count.
    """

    counts: JsonDict = {}
    for item in result.item_results:
        source = item.triage.analysis_source
        key = source.value if hasattr(source, "value") else str(source)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _validate_source_args(args: argparse.Namespace) -> None:
    """Validate source path arguments.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        None.

    Raises:
        CliError: If source arguments are invalid.
    """

    if args.replay is not None:
        if not args.replay.exists():
            raise CliError(f"replay file does not exist: {args.replay}")
        if not args.replay.is_file():
            raise CliError(f"replay path is not a file: {args.replay}")
    if args.replay_dir is not None:
        if not args.replay_dir.exists():
            raise CliError(f"replay directory does not exist: {args.replay_dir}")
        if not args.replay_dir.is_dir():
            raise CliError(f"replay path is not a directory: {args.replay_dir}")


def _source_mode(args: argparse.Namespace) -> str:
    """Return the selected source mode name."""

    if args.replay is not None:
        return "replay"
    if args.replay_dir is not None:
        return "replay_dir"
    if args.wazuh:
        return "wazuh"
    if args.security_onion:
        return "security_onion"
    raise CliError(
        "one source is required: --replay, --replay-dir, --wazuh, or --security-onion"
    )


if __name__ == "__main__":
    raise SystemExit(main())