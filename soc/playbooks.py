
"""Response playbook definitions.

A playbook states the conditions under which a response action may be *proposed*.
It never authorizes execution on its own — `soc.response.ResponseGate` still
requires the capability to be enabled, the score to have come from a model, and a
named analyst to approve.

Playbooks are JSON rather than YAML, which is a deliberate deviation from the
original plan wording. The project is stdlib-only, and adding a YAML parser to
read a handful of small config files is not worth a dependency. Replay files and
labeled evaluation sets are already JSON, so this stays consistent.

Two defaults are chosen so that a mistake fails safe:

    - `requires_confirmation` defaults to **true** when the field is omitted.
      Silence must never mean "act without asking".
    - `enabled` defaults to **true** in the file, because the real gate is the
      per-capability opt-in in settings. A playbook being enabled is not
      sufficient to do anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from soc.models import TriageAction

JsonDict = dict[str, Any]


class PlaybookError(ValueError):
    """Raised when a playbook definition is invalid."""


@dataclass(frozen=True, slots=True)
class Playbook:
    """Conditions under which one response action may be proposed.

    Attributes:
        name: Short unique playbook name.
        action: The response action this playbook proposes. Typed as
            `soc.response.ResponseActionType`, kept loose here to avoid a circular
            import; the loader validates it.
        required_confidence: Minimum triage score, 1-10.
        description: Why this playbook exists. Required, because an unexplained
            response playbook cannot be reviewed by anyone.
        requires_confirmation: Whether a named analyst must approve. Defaults to
            true and every shipped playbook sets it.
        enabled: Whether the playbook is considered at all. The per-capability
            opt-in in settings is the real gate.
        trigger_actions: Triage actions that may fire this playbook. Empty means
            any action, which is deliberately not what the shipped ones do.
    """

    name: str
    action: Any
    required_confidence: int
    description: str
    requires_confirmation: bool = True
    enabled: bool = True
    trigger_actions: tuple[TriageAction, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Validate the playbook.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            PlaybookError: If the definition is unusable.
        """

        if not str(self.name).strip():
            raise PlaybookError("playbook name is required")
        if not str(self.description).strip():
            raise PlaybookError(f"playbook {self.name} requires a description")
        if not 1 <= int(self.required_confidence) <= 10:
            raise PlaybookError(
                f"playbook {self.name} required_confidence must be between 1 and 10"
            )

    def applies_to(self, action: TriageAction) -> bool:
        """Return whether this playbook is relevant to a triage outcome at all.

        Deliberately does NOT consider `required_confidence`. Applicability and
        safety are different questions: a playbook that does not concern this
        action is simply silent, while a playbook that does concern it but fails a
        confidence or safety check produces an audited refusal. Folding the score
        in here would mean "we declined because confidence was too low" never got
        written down, and that is exactly the record needed to tune the bar.

        Inputs:
            action: Routing or triage action applied.

        Outputs:
            True when this playbook should be evaluated.
        """

        if not self.enabled:
            return False
        return not self.trigger_actions or action in self.trigger_actions


def load_playbooks(path: str | Path) -> list[Playbook]:
    """Load and validate every playbook in a directory or a single file.

    A missing directory yields no playbooks rather than raising: running with no
    response playbooks is a valid and expected mode.

    Inputs:
        path: Playbook file or directory of JSON playbook files.

    Outputs:
        Playbooks sorted by name.

    Raises:
        PlaybookError: If a file is unreadable, malformed, or names an unknown
        action.
    """

    playbook_path = Path(path).expanduser()
    if not playbook_path.exists():
        return []

    files = sorted(playbook_path.glob("*.json")) if playbook_path.is_dir() else [playbook_path]
    playbooks: list[Playbook] = []
    for file_path in files:
        for record in _records_in(file_path):
            playbooks.append(_playbook_from_record(record, file_path))

    names = [playbook.name for playbook in playbooks]
    duplicates = {name for name in names if names.count(name) > 1}
    if duplicates:
        raise PlaybookError(f"duplicate playbook names: {', '.join(sorted(duplicates))}")

    return sorted(playbooks, key=lambda playbook: playbook.name)


def _records_in(file_path: Path) -> list[JsonDict]:
    """Read playbook records from one JSON file.

    Inputs:
        file_path: Playbook file holding an object or a list of objects.

    Outputs:
        List of playbook records.

    Raises:
        PlaybookError: If the file cannot be read or parsed.
    """

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PlaybookError(f"cannot read playbook {file_path}: {exc}") from exc

    if isinstance(payload, dict):
        records = payload.get("playbooks", payload)
        payload = records if isinstance(records, list) else [payload]
    if not isinstance(payload, list):
        raise PlaybookError(f"playbook {file_path} must hold an object or a list")
    for record in payload:
        if not isinstance(record, dict):
            raise PlaybookError(f"playbook {file_path} contains a non-object entry")
    return payload


def _playbook_from_record(record: JsonDict, file_path: Path) -> Playbook:
    """Build a Playbook from one record.

    Inputs:
        record: Playbook record.
        file_path: Source file, for error messages.

    Outputs:
        Playbook instance.

    Raises:
        PlaybookError: If the action is unknown or a field is unusable.
    """

    from soc.response import ResponseActionType

    name = str(record.get("name", "")).strip()
    action_text = str(record.get("action", "")).strip()
    try:
        action = ResponseActionType(action_text)
    except ValueError as exc:
        known = ", ".join(sorted(item.value for item in ResponseActionType))
        raise PlaybookError(
            f"playbook {name or file_path} has an unknown action {action_text!r}; known: {known}"
        ) from exc

    trigger_actions: list[TriageAction] = []
    for value in record.get("trigger_actions") or []:
        try:
            trigger_actions.append(TriageAction(str(value)))
        except ValueError as exc:
            raise PlaybookError(
                f"playbook {name} has an unknown trigger action {value!r}"
            ) from exc

    try:
        required_confidence = int(record["required_confidence"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PlaybookError(f"playbook {name} needs an integer required_confidence") from exc

    return Playbook(
        name=name,
        action=action,
        required_confidence=required_confidence,
        description=str(record.get("description", "")),
        # Absent means confirm. Silence must never mean unattended execution.
        requires_confirmation=bool(record.get("requires_confirmation", True)),
        enabled=bool(record.get("enabled", True)),
        trigger_actions=tuple(trigger_actions),
    )
