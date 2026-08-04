

"""Triage evaluation harness.

Everything else in this project moves data. This module is the only thing that
asks whether the answers are any good.

Without it, a prompt change, a model change, or a heuristic tweak cannot be
judged: the pipeline would run identically and report nothing about quality. So
this module scores a labeled set and reports agreement, band accuracy, and the
two failure modes separately.

The two failure modes are deliberately not averaged together:

    - A **missed true positive** is an alert a human labeled serious that triage
      scored as benign. In a SOC this is the expensive mistake: `mark_likely_benign`
      means nobody looks again.
    - **Noise** is a benign alert scored high enough to page. This wastes analyst
      attention and, sustained, trains people to ignore pages.

A single blended accuracy number would let one hide behind the other.

Label provenance is tracked and reported for the same reason. A label written by
whoever built the system records what we *decided* the scorer should say, so
measuring against it demonstrates self-consistency, not accuracy. Only labels
derived from an analyst reviewing real alerts support an accuracy claim, and
`EvaluationReport.is_analyst_validated` exists so that distinction cannot be
quietly lost.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from soc.clustering import AlertClusterer
from soc.enrichment import LocalEnricher
from soc.models import TriageAction
from soc.normalizer import Normalizer
from soc.replay import load_replay_file
from soc.triage import TriageEngine


JsonDict = dict[str, Any]

LABELED_SET_DIR = Path("tests/fixtures/labeled")
"""Directory holding the shipped labeled evaluation set."""

SERIOUS_BAND_FLOOR = 7
"""Expected-score floor at which a case counts as labeled serious."""

BENIGN_BAND_CEILING = 3
"""Expected-score ceiling at which a case counts as labeled benign."""

BENIGN_SCORE_CEILING = 3
"""Actual score at or below which triage has suppressed an alert."""

PAGING_SCORE_FLOOR = 8
"""Actual score at or above which triage would page an analyst."""


class EvaluationError(ValueError):
    """Raised when a labeled case or evaluation run is invalid."""


class LabelProvenance(str, Enum):
    """Where a label's expected verdict came from.

    Values:
        SYNTHETIC: Authored while building the system. Measures self-consistency.
        ANALYST_REVIEWED: Derived from an analyst judging a real alert. The only
            provenance that supports an accuracy claim.
    """

    SYNTHETIC = "synthetic"
    ANALYST_REVIEWED = "analyst_reviewed"


@dataclass(frozen=True, slots=True)
class LabeledCase:
    """One labeled evaluation case.

    Attributes:
        id: Stable case identifier.
        provenance: Where the expected verdict came from.
        fixture: Replay file holding the event or events to score.
        expected_score_min: Lowest acceptable score.
        expected_score_max: Highest acceptable score.
        expected_actions: Acceptable routing actions. More than one is allowed
            because genuinely ambiguous alerts should not be labeled as though
            they had a single correct answer.
        expected_classification: Optional expected classification label.
        rationale: One line stating why this verdict is expected. Required: a
            label nobody can review is a label nobody should trust.
    """

    id: str
    provenance: LabelProvenance
    fixture: Path
    expected_score_min: int
    expected_score_max: int
    expected_actions: tuple[TriageAction, ...]
    expected_classification: str | None
    rationale: str

    def __post_init__(self) -> None:
        """Validate the labeled case.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            EvaluationError: If the case is not usable as a label.
        """

        if not self.id.strip():
            raise EvaluationError("LabeledCase id is required")
        if not 1 <= self.expected_score_min <= 10:
            raise EvaluationError("expected_score_min must be between 1 and 10")
        if not 1 <= self.expected_score_max <= 10:
            raise EvaluationError("expected_score_max must be between 1 and 10")
        if self.expected_score_min > self.expected_score_max:
            raise EvaluationError("expected_score_min cannot exceed expected_score_max")
        if not self.expected_actions:
            raise EvaluationError("at least one expected action is required")
        if not self.rationale.strip():
            raise EvaluationError(f"LabeledCase {self.id} requires a rationale")

    @property
    def is_labeled_serious(self) -> bool:
        """Return whether a human labeled this as genuinely serious."""

        return self.expected_score_min >= SERIOUS_BAND_FLOOR

    @property
    def is_labeled_benign(self) -> bool:
        """Return whether a human labeled this as benign."""

        return self.expected_score_max <= BENIGN_BAND_CEILING

    def score_error(self, score: int) -> int:
        """Return how far a score falls outside the expected band.

        An in-band score is not an error at all, so this is the distance to the
        nearest band edge rather than a distance from a midpoint.

        Inputs:
            score: Score produced by triage.

        Outputs:
            Zero when in band, otherwise the distance outside it.
        """

        if score < self.expected_score_min:
            return self.expected_score_min - score
        if score > self.expected_score_max:
            return score - self.expected_score_max
        return 0


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """Result of scoring one labeled case.

    Attributes:
        case: The labeled case.
        score: Score triage produced.
        action: Action triage produced.
        in_band: Whether the score fell inside the expected band.
        action_agreed: Whether the action was one of the expected actions.
        score_error: Distance outside the expected band, zero when in band.
    """

    case: LabeledCase
    score: int
    action: TriageAction
    in_band: bool
    action_agreed: bool
    score_error: int

    @property
    def is_missed_true_positive(self) -> bool:
        """Return whether a serious case was scored as benign."""

        return self.case.is_labeled_serious and self.score <= BENIGN_SCORE_CEILING

    @property
    def is_noise(self) -> bool:
        """Return whether a benign case was scored high enough to page."""

        return self.case.is_labeled_benign and self.score >= PAGING_SCORE_FLOOR


@dataclass(slots=True)
class EvaluationReport:
    """Aggregate outcome of one evaluation run.

    Attributes:
        outcomes: Per-case outcomes.
        provenance_counts: Case counts by label provenance.
    """

    outcomes: list[CaseOutcome] = field(default_factory=list)
    provenance_counts: dict[str, int] = field(default_factory=dict)

    @property
    def cases_evaluated(self) -> int:
        """Return the number of cases scored."""

        return len(self.outcomes)

    @property
    def action_agreement_rate(self) -> float:
        """Return the fraction of cases whose action matched a label."""

        if not self.outcomes:
            return 0.0
        agreed = sum(1 for outcome in self.outcomes if outcome.action_agreed)
        return agreed / len(self.outcomes)

    @property
    def in_band_rate(self) -> float:
        """Return the fraction of cases scored inside the expected band."""

        if not self.outcomes:
            return 0.0
        return sum(1 for outcome in self.outcomes if outcome.in_band) / len(self.outcomes)

    @property
    def mean_score_error(self) -> float:
        """Return the mean distance outside the expected band."""

        if not self.outcomes:
            return 0.0
        return sum(outcome.score_error for outcome in self.outcomes) / len(self.outcomes)

    @property
    def missed_true_positives(self) -> list[CaseOutcome]:
        """Return cases labeled serious that were scored as benign."""

        return [outcome for outcome in self.outcomes if outcome.is_missed_true_positive]

    @property
    def noise_cases(self) -> list[CaseOutcome]:
        """Return benign cases scored high enough to page."""

        return [outcome for outcome in self.outcomes if outcome.is_noise]

    @property
    def benign_caught_rate(self) -> float:
        """Return the fraction of benign-labeled cases actually suppressed.

        Returns 1.0 when there are no benign cases, so a set containing none
        does not fail the corresponding threshold vacuously.
        """

        benign = [outcome for outcome in self.outcomes if outcome.case.is_labeled_benign]
        if not benign:
            return 1.0
        suppressed = sum(1 for outcome in benign if outcome.score <= BENIGN_SCORE_CEILING)
        return suppressed / len(benign)

    @property
    def action_confusion(self) -> dict[tuple[str, str], int]:
        """Return counts keyed by (first expected action, actual action).

        Knowing which direction the actions are wrong matters more than the
        aggregate rate: under-scoring and over-scoring need different fixes.
        """

        matrix: dict[tuple[str, str], int] = {}
        for outcome in self.outcomes:
            key = (outcome.case.expected_actions[0].value, outcome.action.value)
            matrix[key] = matrix.get(key, 0) + 1
        return matrix

    @property
    def is_analyst_validated(self) -> bool:
        """Return whether every label came from analyst review.

        False for any run containing synthetic labels. Such a run measures
        self-consistency and must not be reported as an accuracy result.
        """

        if not self.outcomes:
            return False
        return all(
            outcome.case.provenance is LabelProvenance.ANALYST_REVIEWED for outcome in self.outcomes
        )

    def to_summary(self) -> JsonDict:
        """Return a JSON-safe summary of the run.

        Inputs:
            None.

        Outputs:
            Summary dictionary.
        """

        return {
            "cases_evaluated": self.cases_evaluated,
            "action_agreement_rate": round(self.action_agreement_rate, 4),
            "in_band_rate": round(self.in_band_rate, 4),
            "mean_score_error": round(self.mean_score_error, 4),
            "benign_caught_rate": round(self.benign_caught_rate, 4),
            "missed_true_positives": [outcome.case.id for outcome in self.missed_true_positives],
            "noise_cases": [outcome.case.id for outcome in self.noise_cases],
            "action_confusion": {
                f"{expected}->{actual}": count
                for (expected, actual), count in sorted(self.action_confusion.items())
            },
            "provenance_counts": dict(self.provenance_counts),
            "is_analyst_validated": self.is_analyst_validated,
            "cases": [
                {
                    "id": outcome.case.id,
                    "score": outcome.score,
                    "expected_band": [
                        outcome.case.expected_score_min,
                        outcome.case.expected_score_max,
                    ],
                    "action": outcome.action.value,
                    "in_band": outcome.in_band,
                    "action_agreed": outcome.action_agreed,
                }
                for outcome in self.outcomes
            ],
        }


@dataclass(frozen=True, slots=True)
class EvaluationThresholds:
    """Phase 2's exit criteria, expressed so they can actually be checked.

    Attributes:
        max_missed_true_positives: Serious cases allowed to be scored benign.
        min_benign_caught_rate: Minimum fraction of benign cases suppressed.
        min_action_agreement: Minimum action agreement rate.
    """

    max_missed_true_positives: int = 0
    min_benign_caught_rate: float = 0.60
    min_action_agreement: float = 0.70

    def check(self, report: EvaluationReport) -> list[str]:
        """Return one message per unmet criterion.

        Inputs:
            report: Completed evaluation report.

        Outputs:
            List of failure messages, empty when every criterion is met.
        """

        failures: list[str] = []
        missed = len(report.missed_true_positives)
        if missed > self.max_missed_true_positives:
            failures.append(
                f"missed true positives: {missed} > {self.max_missed_true_positives} "
                f"({', '.join(outcome.case.id for outcome in report.missed_true_positives)})"
            )
        if report.benign_caught_rate < self.min_benign_caught_rate:
            failures.append(
                f"benign suppression rate {report.benign_caught_rate:.0%} "
                f"< {self.min_benign_caught_rate:.0%}"
            )
        if report.action_agreement_rate < self.min_action_agreement:
            failures.append(
                f"action agreement {report.action_agreement_rate:.0%} "
                f"< {self.min_action_agreement:.0%}"
            )
        return failures


def load_labeled_cases(path: str | Path) -> list[LabeledCase]:
    """Load labeled cases from a JSON file or a directory of JSON files.

    Inputs:
        path: Label file or directory containing label files.

    Outputs:
        Labeled cases sorted by ID.

    Raises:
        EvaluationError: If the path is missing, a label is malformed, or a
        label points at a fixture that does not exist.
    """

    label_path = Path(path).expanduser()
    if not label_path.exists():
        raise EvaluationError(f"Labeled set path does not exist: {label_path}")

    files = sorted(label_path.glob("*.json")) if label_path.is_dir() else [label_path]
    cases: list[LabeledCase] = []
    for file_path in files:
        for record in _load_label_records(file_path):
            cases.append(_case_from_record(record, file_path))

    return sorted(cases, key=lambda case: case.id)


def promote_reviews_to_labels(
    store: Any,
    *,
    labels_path: str | Path,
    fixtures_dir: str | Path,
) -> list[JsonDict]:
    """Turn analyst-reviewed queue items into loadable labeled cases.

    This is the link that makes the labeled set improvable. A verdict on its own
    records *how* a score was wrong; a labeled case needs a replayable fixture
    and an expected band. This reconstructs the fixture from the raw events the
    store already kept, so each case is self-contained and committable rather
    than dependent on a database whose rows age out.

    Items whose source events are no longer recoverable are skipped: a case that
    cannot be replayed cannot be scored.

    Inputs:
        store: Store exposing `list_reviewed_queue_items` and
            `list_raw_events_for_target`.
        labels_path: JSON file to write the labeled cases to.
        fixtures_dir: Directory to write reconstructed replay fixtures into.

    Outputs:
        The label records written, in the order written.
    """

    labels_file = Path(labels_path).expanduser()
    fixture_root = Path(fixtures_dir).expanduser()
    fixture_root.mkdir(parents=True, exist_ok=True)
    labels_file.parent.mkdir(parents=True, exist_ok=True)

    records: list[JsonDict] = []
    for item in store.list_reviewed_queue_items():
        raw_events = store.list_raw_events_for_target(item.target_id, item.target_type)
        if not raw_events:
            continue

        fixture_path = fixture_root / f"{_slug(item.target_id)}.json"
        fixture_path.write_text(
            json.dumps([_replay_event(event) for event in raw_events], indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        records.append(_label_record_from_review(item, fixture_path))

    labels_file.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return records


def _label_record_from_review(item: Any, fixture_path: Path) -> JsonDict:
    """Build one label record from a reviewed queue item.

    Inputs:
        item: Reviewed ReviewQueueItem.
        fixture_path: Path of the reconstructed replay fixture.

    Outputs:
        Label record dictionary.
    """

    score_min, score_max = _expected_band_from_review(item)
    actions = sorted(
        {
            _action_for_score(score_min).value,
            _action_for_score(score_max).value,
        }
    )
    verdict = item.analyst_verdict.value if item.analyst_verdict else "unknown"

    rationale = (item.notes or "").strip()
    if not rationale:
        rationale = (
            f"Analyst recorded '{verdict}' for a triage score of {item.score} "
            "without further notes."
        )

    return {
        "id": f"review-{_slug(item.triage_result_id)}",
        "provenance": LabelProvenance.ANALYST_REVIEWED.value,
        "fixture": str(fixture_path),
        "expected_score_min": score_min,
        "expected_score_max": score_max,
        "expected_actions": actions,
        "expected_classification": None,
        "rationale": rationale,
        "source_verdict": verdict,
        "source_triage_score": item.score,
        "source_analyst_score": item.analyst_score,
        "source_triage_result_id": item.triage_result_id,
    }


def _expected_band_from_review(item: Any) -> tuple[int, int]:
    """Derive an expected score band from an analyst verdict.

    An explicit analyst score is the strongest evidence available and takes
    precedence over any inference. Otherwise the verdict's direction is used:
    agreement narrows around the score triage gave, while `too_high` and
    `too_low` open the band on the side the analyst indicated rather than
    inventing a specific number the analyst never gave.

    Inputs:
        item: Reviewed ReviewQueueItem.

    Outputs:
        Tuple of expected minimum and maximum score.
    """

    score = _clamp_score(item.score)

    if item.analyst_score is not None:
        analyst_score = _clamp_score(item.analyst_score)
        return _clamp_score(analyst_score - 1), _clamp_score(analyst_score + 1)

    verdict = item.analyst_verdict.value if item.analyst_verdict else ""
    if verdict == "too_high":
        return 1, _clamp_score(score - 1)
    if verdict == "too_low":
        return _clamp_score(score + 1), 10
    return _clamp_score(score - 1), _clamp_score(score + 1)


def _action_for_score(score: int) -> TriageAction:
    """Map a score to the action the router would apply.

    Inputs:
        score: Score from 1 to 10.

    Outputs:
        TriageAction the router would select.
    """

    from soc.router import action_from_score

    return action_from_score(score)


def _replay_event(raw_event: JsonDict) -> JsonDict:
    """Convert a stored raw event into a replay-file event.

    Inputs:
        raw_event: Stored raw event dictionary.

    Outputs:
        Replay event dictionary the replay loader accepts.
    """

    event: JsonDict = {
        "id": raw_event.get("id"),
        "source": raw_event.get("source"),
        "payload": raw_event.get("payload") or {},
    }
    timestamp = raw_event.get("timestamp")
    if timestamp:
        event["timestamp"] = timestamp
    return event


def _clamp_score(score: int) -> int:
    """Clamp a score into the 1-10 scale.

    Inputs:
        score: Any integer score.

    Outputs:
        Score within 1 to 10.
    """

    return max(1, min(10, int(score)))


def _slug(value: str) -> str:
    """Build a filesystem-safe slug from an identifier.

    Inputs:
        value: Identifier to slugify.

    Outputs:
        Slug containing only safe characters.
    """

    safe = "".join(char if char.isalnum() or char in "-_" else "-" for char in value)
    return safe.strip("-") or "unknown"


def evaluate_cases(
    cases: Iterable[LabeledCase],
    *,
    triage_engine: TriageEngine | None = None,
    score_action_source: Callable[[LabeledCase], tuple[int, TriageAction]] | None = None,
) -> EvaluationReport:
    """Score every labeled case and aggregate the outcomes.

    Inputs:
        cases: Labeled cases to evaluate.
        triage_engine: Engine used to score each case. Defaults to deterministic
            local triage, so an evaluation run needs no API key.
        score_action_source: Optional override returning (score, action) for a
            case, used to test the metric arithmetic directly.

    Outputs:
        EvaluationReport.

    Raises:
        EvaluationError: If no cases were supplied.
    """

    case_list = list(cases)
    if not case_list:
        raise EvaluationError("evaluation requires at least one labeled case")

    scorer = score_action_source or _build_triage_scorer(triage_engine or TriageEngine())

    report = EvaluationReport()
    for case in case_list:
        score, action = scorer(case)
        report.outcomes.append(
            CaseOutcome(
                case=case,
                score=score,
                action=action,
                in_band=case.score_error(score) == 0,
                action_agreed=action in case.expected_actions,
                score_error=case.score_error(score),
            )
        )
        key = case.provenance.value
        report.provenance_counts[key] = report.provenance_counts.get(key, 0) + 1

    return report


def _build_triage_scorer(
    engine: TriageEngine,
) -> Callable[[LabeledCase], tuple[int, TriageAction]]:
    """Build a scorer that runs a case's fixture through the real pipeline stages.

    A fixture yielding one event is scored as an alert; several events are
    clustered first and scored as an incident candidate, which is how the
    pipeline would handle them.

    Inputs:
        engine: Triage engine to score with.

    Outputs:
        Callable returning (score, action) for a labeled case.
    """

    normalizer = Normalizer()
    clusterer = AlertClusterer()
    enricher = LocalEnricher()

    def _score(case: LabeledCase) -> tuple[int, TriageAction]:
        """Score one labeled case."""

        events = load_replay_file(case.fixture)
        if not events:
            raise EvaluationError(f"Labeled case {case.id} fixture yielded no events")

        alerts = normalizer.normalize_many(events)
        if len(alerts) == 1:
            alert = alerts[0]
            result = engine.triage_alert(alert, enricher.enrich_alert(alert))
        else:
            candidates = clusterer.cluster(alerts)
            if not candidates:
                raise EvaluationError(f"Labeled case {case.id} produced no candidate")
            candidate = candidates[0]
            result = engine.triage_candidate(candidate, enricher.enrich_candidate(candidate))
        return result.score, result.action

    return _score


def _load_label_records(file_path: Path) -> list[JsonDict]:
    """Read label records from one JSON file.

    Inputs:
        file_path: Label file holding an object or a list of objects.

    Outputs:
        List of label record dictionaries.

    Raises:
        EvaluationError: If the file is not valid JSON or has an unusable shape.
    """

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"Cannot read labeled set file {file_path}: {exc}") from exc

    if isinstance(payload, dict):
        records = payload.get("cases", payload)
        payload = records if isinstance(records, list) else [payload]
    if not isinstance(payload, list):
        raise EvaluationError(f"Labeled set file {file_path} must hold an object or a list")

    for record in payload:
        if not isinstance(record, dict):
            raise EvaluationError(f"Labeled set file {file_path} contains a non-object case")
    return payload


def _case_from_record(record: JsonDict, file_path: Path) -> LabeledCase:
    """Build a LabeledCase from one label record.

    Inputs:
        record: Label record dictionary.
        file_path: Source file, used in error messages.

    Outputs:
        LabeledCase instance.

    Raises:
        EvaluationError: If required fields are missing or the fixture is absent.
    """

    case_id = str(record.get("id", "")).strip()
    fixture = Path(str(record.get("fixture", "")))
    if not fixture.name:
        raise EvaluationError(f"Labeled case {case_id or file_path} is missing a fixture path")
    if not fixture.exists():
        raise EvaluationError(f"Labeled case {case_id} references a missing fixture: {fixture}")

    try:
        provenance = LabelProvenance(str(record.get("provenance", "synthetic")))
    except ValueError as exc:
        raise EvaluationError(f"Labeled case {case_id} has an unknown provenance: {exc}") from exc

    actions = record.get("expected_actions") or []
    if isinstance(actions, str):
        actions = [actions]
    try:
        parsed_actions = tuple(TriageAction(str(action)) for action in actions)
    except ValueError as exc:
        raise EvaluationError(f"Labeled case {case_id} has an unknown action: {exc}") from exc

    try:
        score_min = int(record["expected_score_min"])
        score_max = int(record["expected_score_max"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EvaluationError(f"Labeled case {case_id} needs an integer score band: {exc}") from exc

    classification = record.get("expected_classification")
    return LabeledCase(
        id=case_id,
        provenance=provenance,
        fixture=fixture,
        expected_score_min=score_min,
        expected_score_max=score_max,
        expected_actions=parsed_actions,
        expected_classification=str(classification) if classification else None,
        rationale=str(record.get("rationale", "")),
    )
