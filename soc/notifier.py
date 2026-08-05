

"""Notification delivery for AI_Augmented_SOC.

This module sends analyst notifications after triage/routing/report generation.
It is intentionally conservative:
    - Dry-run mode is available for tests and local development.
    - Email uses the Python standard library smtplib.
    - Slack-compatible webhooks use urllib from the standard library.
    - Failures are returned as NotificationResult objects instead of crashing the
      whole pipeline unless the caller chooses to enforce success.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from soc.config import Settings
from soc.models import AnalysisSource, RoutingDecision, TriageResult, utc_now

JsonDict = dict[str, Any]


class NotificationError(RuntimeError):
    """Raised when notification configuration or delivery fails."""


@dataclass(frozen=True, slots=True)
class NotificationAttachment:
    """One text file to deliver alongside a notification body.

    Attributes:
        filename: File name the recipient sees, such as `INC-20260610-001.md`.
        content: Text content of the file.
        maintype: MIME main type. Defaults to text.
        subtype: MIME subtype. Defaults to markdown, matching this project's
            reports.
    """

    filename: str
    content: str
    maintype: str = "text"
    subtype: str = "markdown"

    def __post_init__(self) -> None:
        """Validate the attachment.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            NotificationError: If the filename or content is empty.
        """

        if self.filename.strip() == "":
            raise NotificationError("attachment filename is required")
        if self.content.strip() == "":
            raise NotificationError("attachment content is required")
        if self.maintype.strip() == "" or self.subtype.strip() == "":
            raise NotificationError("attachment MIME type is required")


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    """Message to send through one or more notification channels.

    Attributes:
        subject: Human-readable notification subject.
        body: Full message body.
        severity: Optional severity label.
        metadata: Optional structured metadata.
        attachments: Optional files to deliver alongside the body. An attachment
            never replaces the body: a client that cannot render the file must
            still show the summary.
    """

    subject: str
    body: str
    severity: str = "info"
    metadata: JsonDict | None = None
    attachments: tuple[NotificationAttachment, ...] = ()

    def __post_init__(self) -> None:
        """Validate notification message.

        Raises:
            NotificationError: If subject or body is empty.
        """

        if self.subject.strip() == "":
            raise NotificationError("notification subject is required")
        if self.body.strip() == "":
            raise NotificationError("notification body is required")


@dataclass(frozen=True, slots=True)
class NotificationResult:
    """Result of one notification attempt.

    Attributes:
        channel: Channel name such as email, slack, or dry_run.
        success: Whether delivery succeeded.
        destination: Destination address or webhook label.
        message: Human-readable result message.
        error: Optional error string.
        sent_at: Timestamp for the attempt.
    """

    channel: str
    success: bool
    destination: str
    message: str
    error: str | None
    sent_at: Any

    def to_dict(self) -> JsonDict:
        """Serialize the notification result.

        Inputs:
            None.

        Outputs:
            JSON-safe dictionary.
        """

        return {
            "channel": self.channel,
            "success": self.success,
            "destination": self.destination,
            "message": self.message,
            "error": self.error,
            "sent_at": self.sent_at.isoformat() if hasattr(self.sent_at, "isoformat") else self.sent_at,
        }


@dataclass(frozen=True, slots=True)
class EmailConfig:
    """SMTP email notification configuration."""

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    email_from: str = ""
    email_to: str = ""
    use_tls: bool = True
    timeout_seconds: int = 30

    @classmethod
    def from_settings(cls, settings: Settings) -> EmailConfig:
        """Build EmailConfig from project Settings.

        Inputs:
            settings: Application settings object.

        Outputs:
            EmailConfig instance.
        """

        return cls(
            enabled=settings.email_enabled,
            smtp_host=settings.smtp_host,
            smtp_port=settings.smtp_port,
            smtp_username=settings.smtp_username,
            smtp_password=settings.smtp_password,
            email_from=settings.email_from,
            email_to=settings.email_to,
            use_tls=settings.email_use_tls,
        )

    def validate(self) -> None:
        """Validate email config when email is enabled.

        Raises:
            NotificationError: If required email fields are missing.
        """

        if not self.enabled:
            return
        required = {
            "smtp_host": self.smtp_host,
            "email_from": self.email_from,
            "email_to": self.email_to,
        }
        missing = [name for name, value in required.items() if str(value).strip() == ""]
        if missing:
            raise NotificationError(f"missing email config fields: {', '.join(missing)}")
        if self.smtp_port <= 0:
            raise NotificationError("smtp_port must be greater than zero")
        if self.timeout_seconds <= 0:
            raise NotificationError("email timeout_seconds must be greater than zero")


@dataclass(frozen=True, slots=True)
class SlackConfig:
    """Slack-compatible webhook notification configuration."""

    webhook_url: str = ""
    timeout_seconds: int = 30

    @classmethod
    def from_settings(cls, settings: Settings) -> SlackConfig:
        """Build SlackConfig from project Settings.

        Inputs:
            settings: Application settings object.

        Outputs:
            SlackConfig instance.
        """

        return cls(webhook_url=settings.slack_webhook_url)

    @property
    def enabled(self) -> bool:
        """Return whether Slack webhook delivery is enabled."""

        return self.webhook_url.strip() != ""

    def validate(self) -> None:
        """Validate Slack config when Slack is enabled.

        Raises:
            NotificationError: If configured webhook is invalid.
        """

        if not self.enabled:
            return
        if not self.webhook_url.startswith(("http://", "https://")):
            raise NotificationError("slack webhook URL must start with http:// or https://")
        if self.timeout_seconds <= 0:
            raise NotificationError("slack timeout_seconds must be greater than zero")


class EmailNotifier:
    """SMTP email notifier."""

    def __init__(self, config: EmailConfig, smtp_factory: Any | None = None) -> None:
        """Initialize email notifier.

        Inputs:
            config: EmailConfig object.
            smtp_factory: Optional SMTP factory for tests.

        Outputs:
            None.
        """

        self.config = config
        self.smtp_factory = smtp_factory or smtplib.SMTP

    def send(self, message: NotificationMessage) -> NotificationResult:
        """Send notification by email.

        Inputs:
            message: NotificationMessage to send.

        Outputs:
            NotificationResult.
        """

        try:
            self.config.validate()
            if not self.config.enabled:
                return _result("email", False, self.config.email_to, "email disabled", None)

            email_message = self._build_email_message(message)
            with self.smtp_factory(
                self.config.smtp_host,
                self.config.smtp_port,
                timeout=self.config.timeout_seconds,
            ) as smtp:
                if self.config.use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                if self.config.smtp_username or self.config.smtp_password:
                    smtp.login(self.config.smtp_username, self.config.smtp_password)
                smtp.send_message(email_message)

            return _result("email", True, self.config.email_to, "email sent", None)
        except Exception as exc:
            return _result("email", False, self.config.email_to, "email failed", str(exc))

    def _build_email_message(self, message: NotificationMessage) -> EmailMessage:
        """Build EmailMessage object.

        The body is always set first and attachments are only added afterwards,
        so an attached report is delivered *in addition to* the summary rather
        than instead of it. With no attachments the message stays a single-part
        text/plain mail, which is the behaviour every existing caller expects.

        Inputs:
            message: NotificationMessage.

        Outputs:
            EmailMessage object.
        """

        email_message = EmailMessage()
        email_message["Subject"] = message.subject
        email_message["From"] = self.config.email_from
        email_message["To"] = self.config.email_to
        email_message.set_content(message.body)
        for attachment in message.attachments or ():
            email_message.add_attachment(
                attachment.content.encode("utf-8"),
                maintype=attachment.maintype,
                subtype=attachment.subtype,
                filename=attachment.filename,
            )
        return email_message


class SlackNotifier:
    """Slack-compatible webhook notifier."""

    def __init__(self, config: SlackConfig, opener: Any | None = None) -> None:
        """Initialize Slack notifier.

        Inputs:
            config: SlackConfig object.
            opener: Optional urllib opener-like object for tests.

        Outputs:
            None.
        """

        self.config = config
        self.opener = opener or urllib.request.build_opener()

    def send(self, message: NotificationMessage) -> NotificationResult:
        """Send notification to a Slack-compatible webhook.

        Inputs:
            message: NotificationMessage to send.

        Outputs:
            NotificationResult.
        """

        try:
            self.config.validate()
            if not self.config.enabled:
                return _result("slack", False, "webhook", "slack disabled", None)

            payload = build_slack_payload(message)
            request = urllib.request.Request(
                self.config.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.opener.open(request, timeout=self.config.timeout_seconds) as response:
                status = getattr(response, "status", 200)
                body = response.read().decode("utf-8")

            if status < 200 or status >= 300:
                return _result("slack", False, "webhook", "slack failed", f"HTTP {status}: {body}")
            return _result("slack", True, "webhook", "slack sent", None)
        except urllib.error.HTTPError as exc:
            body = _read_http_error_body(exc)
            return _result("slack", False, "webhook", "slack failed", f"HTTP {exc.code}: {body}")
        except Exception as exc:
            return _result("slack", False, "webhook", "slack failed", str(exc))


class DryRunNotifier:
    """Notifier that records what would have been sent."""

    def __init__(self) -> None:
        """Initialize dry-run notifier."""

        self.messages: list[NotificationMessage] = []

    def send(self, message: NotificationMessage) -> NotificationResult:
        """Record a dry-run message.

        Inputs:
            message: NotificationMessage.

        Outputs:
            NotificationResult.
        """

        self.messages.append(message)
        return _result("dry_run", True, "local", "notification recorded", None)


class NotificationDispatcher:
    """Dispatch notifications through configured channels."""

    def __init__(
        self,
        *,
        email_notifier: EmailNotifier | None = None,
        slack_notifier: SlackNotifier | None = None,
        dry_run: bool = False,
    ) -> None:
        """Initialize notification dispatcher.

        Inputs:
            email_notifier: Optional email notifier.
            slack_notifier: Optional Slack notifier.
            dry_run: Whether to use dry-run delivery.

        Outputs:
            None.
        """

        self.email_notifier = email_notifier
        self.slack_notifier = slack_notifier
        self.dry_run_notifier = DryRunNotifier() if dry_run else None

    @classmethod
    def from_settings(cls, settings: Settings, *, dry_run: bool = False) -> NotificationDispatcher:
        """Build dispatcher from Settings.

        Inputs:
            settings: Application settings object.
            dry_run: Whether to force dry-run delivery.

        Outputs:
            NotificationDispatcher instance.
        """

        email_notifier = EmailNotifier(EmailConfig.from_settings(settings))
        slack_notifier = SlackNotifier(SlackConfig.from_settings(settings))
        return cls(email_notifier=email_notifier, slack_notifier=slack_notifier, dry_run=dry_run)

    def send(self, message: NotificationMessage) -> list[NotificationResult]:
        """Send notification through active channels.

        Inputs:
            message: NotificationMessage.

        Outputs:
            NotificationResult list.
        """

        results: list[NotificationResult] = []
        if self.dry_run_notifier is not None:
            results.append(self.dry_run_notifier.send(message))
            return results

        if self.email_notifier is not None:
            results.append(self.email_notifier.send(message))
        if self.slack_notifier is not None:
            results.append(self.slack_notifier.send(message))
        if not results:
            results.append(_result("none", False, "none", "no notification channels configured", None))
        return results

    def notify_triage(
        self,
        triage: TriageResult,
        *,
        routing: RoutingDecision | None = None,
        report_text: str | None = None,
    ) -> list[NotificationResult]:
        """Build and send a triage notification.

        Inputs:
            triage: TriageResult object.
            routing: Optional RoutingDecision.
            report_text: Optional report body.

        Outputs:
            NotificationResult list.
        """

        message = build_triage_notification(triage, routing=routing, report_text=report_text)
        return self.send(message)


def build_triage_notification(
    triage: TriageResult,
    *,
    routing: RoutingDecision | None = None,
    report_text: str | None = None,
) -> NotificationMessage:
    """Build a notification message from triage/routing/report context.

    Inputs:
        triage: TriageResult object.
        routing: Optional RoutingDecision.
        report_text: Optional Markdown report text.

    Outputs:
        NotificationMessage.
    """

    subject = f"[{triage.action.value.upper()}] SOC triage {triage.score}/10 for {triage.target_id}"
    lines = [
        f"Target: {triage.target_type}/{triage.target_id}",
        f"Score: {triage.score}/10",
        f"Action: {triage.action.value}",
        f"Classification: {triage.classification}",
        f"False-positive likelihood: {_enum_value(triage.fp_likelihood)}",
        f"Analysis source: {_analysis_source_description(triage)}",
        "",
        triage.summary,
    ]

    if routing is not None:
        lines.extend(
            [
                "",
                "Routing:",
                f"- Status: {_enum_value(getattr(routing, 'status', 'unknown'))}",
                f"- Destination: {getattr(routing, 'destination', 'unknown')}",
                f"- Message: {getattr(routing, 'message', '')}",
            ]
        )

    if report_text:
        lines.extend(["", "Report:", report_text])

    return NotificationMessage(
        subject=subject,
        body="\n".join(lines),
        severity=_severity_from_score(triage.score),
        metadata={
            "target_id": triage.target_id,
            "target_type": triage.target_type,
            "score": triage.score,
            "action": triage.action.value,
            "classification": triage.classification,
            "analysis_source": _enum_value(triage.analysis_source),
            "model": triage.model,
        },
    )


def _analysis_source_description(triage: TriageResult) -> str:
    """Describe what produced the triage score, for notification bodies.

    An analyst being paged needs to know whether a model or a local heuristic
    produced the score before acting on it.

    Inputs:
        triage: TriageResult object.

    Outputs:
        Human-readable provenance description.
    """

    if _enum_value(triage.analysis_source) != AnalysisSource.LLM.value:
        return "deterministic local scoring (no model was consulted)"
    if triage.model:
        return f"LLM {triage.model}"
    return "LLM (model not reported)"


def build_slack_payload(message: NotificationMessage) -> JsonDict:
    """Build Slack-compatible webhook payload.

    Inputs:
        message: NotificationMessage.

    Outputs:
        JSON payload dictionary.
    """

    return {
        "text": f"*{message.subject}*\n{message.body}",
        "metadata": message.metadata or {},
    }


def notify_triage(
    triage: TriageResult,
    *,
    routing: RoutingDecision | None = None,
    report_text: str | None = None,
    dispatcher: NotificationDispatcher | None = None,
) -> list[NotificationResult]:
    """Convenience function for triage notifications.

    Inputs:
        triage: TriageResult object.
        routing: Optional RoutingDecision.
        report_text: Optional Markdown report text.
        dispatcher: Optional NotificationDispatcher. Defaults to dry run.

    Outputs:
        NotificationResult list.
    """

    active_dispatcher = dispatcher or NotificationDispatcher(dry_run=True)
    return active_dispatcher.notify_triage(triage, routing=routing, report_text=report_text)


def write_notification_results(results: list[NotificationResult], output_path: str | Path) -> Path:
    """Write notification results to JSON file.

    Inputs:
        results: Notification results.
        output_path: Destination JSON path.

    Outputs:
        Path written.
    """

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([result.to_dict() for result in results], indent=2), encoding="utf-8")
    return path


def _result(channel: str, success: bool, destination: str, message: str, error: str | None) -> NotificationResult:
    """Create NotificationResult with current timestamp.

    Inputs:
        channel: Notification channel.
        success: Success flag.
        destination: Destination label.
        message: Human-readable result.
        error: Optional error.

    Outputs:
        NotificationResult object.
    """

    return NotificationResult(
        channel=channel,
        success=success,
        destination=destination,
        message=message,
        error=error,
        sent_at=utc_now(),
    )


def _severity_from_score(score: int) -> str:
    """Map triage score to notification severity label.

    Inputs:
        score: Triage score.

    Outputs:
        Severity string.
    """

    if score >= 8:
        return "critical"
    if score >= 4:
        return "warning"
    return "info"


def _enum_value(value: Any) -> Any:
    """Return enum value when available.

    Inputs:
        value: Any value.

    Outputs:
        Enum value or original value.
    """

    return value.value if hasattr(value, "value") else value


def _read_http_error_body(exc: urllib.error.HTTPError) -> str:
    """Read HTTPError body safely.

    Inputs:
        exc: HTTPError instance.

    Outputs:
        Body text or stringified exception.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        body = str(exc)
    return body or str(exc)