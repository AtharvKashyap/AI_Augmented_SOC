

"""Tests for notification delivery helpers.

These tests cover dry-run, SMTP, Slack-compatible webhook, dispatcher, and
triage notification formatting without sending real network traffic.
"""

from __future__ import annotations

import io
import json
import urllib.error
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from soc.models import (
    AnalysisSource,
    FalsePositiveLikelihood,
    RoutingDecision,
    RoutingStatus,
    TriageAction,
    TriageResult,
)
from soc.notifier import (
    DryRunNotifier,
    EmailConfig,
    EmailNotifier,
    NotificationDispatcher,
    NotificationError,
    NotificationMessage,
    NotificationResult,
    SlackConfig,
    SlackNotifier,
    build_slack_payload,
    build_triage_notification,
    notify_triage,
    write_notification_results,
)

BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


class FakeSMTP:
    """Fake SMTP context manager for email tests."""

    instances: list[FakeSMTP] = []

    def __init__(self, host: str, port: int, timeout: int) -> None:
        """Initialize fake SMTP object.

        Inputs:
            host: SMTP host.
            port: SMTP port.
            timeout: SMTP timeout.

        Outputs:
            None.
        """

        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.login_args: tuple[str, str] | None = None
        self.sent_messages = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        """Enter SMTP context manager."""

        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        """Exit SMTP context manager."""

        return

    def starttls(self, context: Any) -> None:
        """Record TLS start."""

        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        """Record login credentials."""

        self.login_args = (username, password)

    def send_message(self, message) -> None:
        """Record sent message."""

        self.sent_messages.append(message)


class FailingSMTP(FakeSMTP):
    """Fake SMTP object that raises during send."""

    def send_message(self, message) -> None:
        """Raise send failure."""

        raise RuntimeError("smtp failed")


class FakeResponse:
    """Fake urllib response object."""

    def __init__(self, body: str = "ok", *, status: int = 200) -> None:
        """Initialize fake response.

        Inputs:
            body: Response body.
            status: HTTP status code.

        Outputs:
            None.
        """

        self.body = body
        self.status = status

    def __enter__(self) -> FakeResponse:
        """Enter context manager."""

        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        """Exit context manager."""

        return

    def read(self) -> bytes:
        """Return response body bytes."""

        return self.body.encode("utf-8")


class FakeOpener:
    """Fake urllib opener that records requests."""

    def __init__(self, responses: list[Any]) -> None:
        """Initialize fake opener.

        Inputs:
            responses: Queued responses or exceptions.

        Outputs:
            None.
        """

        self.responses = responses
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout: int):
        """Return or raise the next queued response."""

        self.requests.append(request)
        self.timeouts.append(timeout)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@dataclass(slots=True)
class FakeSettings:
    """Minimal settings object for dispatcher config tests."""

    email_enabled: bool = True
    smtp_host: str = "smtp.example.com"
    smtp_port: int = 587
    smtp_username: str = "user"
    smtp_password: str = "pass"
    email_from: str = "soc@example.com"
    email_to: str = "analyst@example.com"
    email_use_tls: bool = True
    slack_webhook_url: str = "https://hooks.example.com/test"


def _message() -> NotificationMessage:
    """Create a representative notification message."""

    return NotificationMessage(
        subject="SOC alert",
        body="Investigate candidate-001",
        severity="critical",
        metadata={"candidate_id": "candidate-001"},
    )


def _triage(score: int = 8, action: TriageAction = TriageAction.PAGE_NOW) -> TriageResult:
    """Create a representative triage result."""

    return TriageResult(
        id="triage-001",
        target_id="candidate-001",
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive_high_priority",
        action=action,
        summary="Suspicious PowerShell activity with public destination IP.",
    )


def _routing() -> RoutingDecision:
    """Create a representative routing decision."""

    return RoutingDecision(
        id="route-001",
        triage_result_id="triage-001",
        target_id="candidate-001",
        action=TriageAction.PAGE_NOW,
        status=RoutingStatus.CREATED,
        destination="page_now",
        message="Page analyst immediately.",
        error=None,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def test_notification_message_validates_required_fields():
    """NotificationMessage should reject empty subject or body."""

    with pytest.raises(NotificationError, match="subject"):
        NotificationMessage(subject="", body="body")

    with pytest.raises(NotificationError, match="body"):
        NotificationMessage(subject="subject", body="")


def test_notification_result_to_dict_serializes_timestamp():
    """NotificationResult.to_dict should serialize datetime values."""

    result = NotificationResult(
        channel="dry_run",
        success=True,
        destination="local",
        message="recorded",
        error=None,
        sent_at=BASE_TIME,
    )

    data = result.to_dict()

    assert data["channel"] == "dry_run"
    assert data["success"] is True
    assert data["sent_at"] == BASE_TIME.isoformat()


def test_email_config_validates_only_when_enabled():
    """EmailConfig should validate required fields only when enabled."""

    EmailConfig(enabled=False).validate()

    with pytest.raises(NotificationError, match="missing email config fields"):
        EmailConfig(enabled=True).validate()

    with pytest.raises(NotificationError, match="smtp_port"):
        EmailConfig(
            enabled=True,
            smtp_host="smtp.example.com",
            smtp_port=0,
            email_from="soc@example.com",
            email_to="analyst@example.com",
        ).validate()


def test_email_config_from_settings():
    """EmailConfig.from_settings should copy settings values."""

    config = EmailConfig.from_settings(FakeSettings())

    assert config.enabled is True
    assert config.smtp_host == "smtp.example.com"
    assert config.smtp_port == 587
    assert config.smtp_username == "user"
    assert config.smtp_password == "pass"
    assert config.email_from == "soc@example.com"
    assert config.email_to == "analyst@example.com"
    assert config.use_tls is True


def test_email_notifier_disabled_returns_disabled_result():
    """Disabled email notifier should not attempt SMTP delivery."""

    notifier = EmailNotifier(EmailConfig(enabled=False, email_to="analyst@example.com"), smtp_factory=FakeSMTP)

    result = notifier.send(_message())

    assert result.channel == "email"
    assert result.success is False
    assert result.message == "email disabled"


def test_email_notifier_sends_message_with_tls_and_login():
    """EmailNotifier should build and send an SMTP message."""

    FakeSMTP.instances.clear()
    config = EmailConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="user",
        smtp_password="pass",
        email_from="soc@example.com",
        email_to="analyst@example.com",
        use_tls=True,
        timeout_seconds=10,
    )
    notifier = EmailNotifier(config, smtp_factory=FakeSMTP)

    result = notifier.send(_message())

    assert result.success is True
    assert result.channel == "email"
    assert result.destination == "analyst@example.com"
    assert result.message == "email sent"
    smtp = FakeSMTP.instances[0]
    assert smtp.host == "smtp.example.com"
    assert smtp.port == 587
    assert smtp.timeout == 10
    assert smtp.started_tls is True
    assert smtp.login_args == ("user", "pass")
    assert len(smtp.sent_messages) == 1
    email_message = smtp.sent_messages[0]
    assert email_message["Subject"] == "SOC alert"
    assert email_message["From"] == "soc@example.com"
    assert email_message["To"] == "analyst@example.com"
    assert "Investigate candidate-001" in email_message.get_content()


def test_email_notifier_returns_failure_result_on_exception():
    """EmailNotifier should return failed result when SMTP raises."""

    config = EmailConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        email_from="soc@example.com",
        email_to="analyst@example.com",
    )
    notifier = EmailNotifier(config, smtp_factory=FailingSMTP)

    result = notifier.send(_message())

    assert result.success is False
    assert result.channel == "email"
    assert result.message == "email failed"
    assert "smtp failed" in str(result.error)


def test_slack_config_validation():
    """SlackConfig should validate URL only when enabled."""

    SlackConfig(webhook_url="").validate()

    with pytest.raises(NotificationError, match="webhook URL"):
        SlackConfig(webhook_url="not-a-url").validate()

    with pytest.raises(NotificationError, match="timeout_seconds"):
        SlackConfig(webhook_url="https://hooks.example.com/test", timeout_seconds=0).validate()


def test_slack_config_from_settings():
    """SlackConfig.from_settings should copy webhook URL."""

    config = SlackConfig.from_settings(FakeSettings())

    assert config.enabled is True
    assert config.webhook_url == "https://hooks.example.com/test"


def test_build_slack_payload_contains_subject_body_and_metadata():
    """Slack payload should contain message text and metadata."""

    payload = build_slack_payload(_message())

    assert "*SOC alert*" in payload["text"]
    assert "Investigate candidate-001" in payload["text"]
    assert payload["metadata"] == {"candidate_id": "candidate-001"}


def test_slack_notifier_disabled_returns_disabled_result():
    """Disabled Slack notifier should not attempt webhook delivery."""

    opener = FakeOpener([])
    notifier = SlackNotifier(SlackConfig(webhook_url=""), opener=opener)

    result = notifier.send(_message())

    assert result.channel == "slack"
    assert result.success is False
    assert result.message == "slack disabled"
    assert opener.requests == []


def test_slack_notifier_sends_webhook_request():
    """SlackNotifier should POST a JSON webhook payload."""

    opener = FakeOpener([FakeResponse("ok", status=200)])
    notifier = SlackNotifier(
        SlackConfig(webhook_url="https://hooks.example.com/test", timeout_seconds=15),
        opener=opener,
    )

    result = notifier.send(_message())

    assert result.success is True
    assert result.channel == "slack"
    assert result.message == "slack sent"
    assert opener.timeouts == [15]
    request = opener.requests[0]
    assert request.full_url == "https://hooks.example.com/test"
    assert request.get_method() == "POST"
    assert request.headers["Content-type"] == "application/json"
    body = json.loads(request.data.decode("utf-8"))
    assert "SOC alert" in body["text"]
    assert body["metadata"] == {"candidate_id": "candidate-001"}


def test_slack_notifier_returns_failure_for_non_2xx_status():
    """SlackNotifier should return failed result for non-2xx responses."""

    opener = FakeOpener([FakeResponse("bad", status=500)])
    notifier = SlackNotifier(SlackConfig(webhook_url="https://hooks.example.com/test"), opener=opener)

    result = notifier.send(_message())

    assert result.success is False
    assert result.channel == "slack"
    assert result.message == "slack failed"
    assert "HTTP 500" in str(result.error)


def test_slack_notifier_returns_failure_for_http_error():
    """SlackNotifier should include HTTPError body in failure result."""

    http_error = urllib.error.HTTPError(
        url="https://hooks.example.com/test",
        code=403,
        msg="Forbidden",
        hdrs=None,
        fp=io.BytesIO(b"forbidden"),
    )
    opener = FakeOpener([http_error])
    notifier = SlackNotifier(SlackConfig(webhook_url="https://hooks.example.com/test"), opener=opener)

    result = notifier.send(_message())

    assert result.success is False
    assert result.channel == "slack"
    assert "HTTP 403" in str(result.error)
    assert "forbidden" in str(result.error)


def test_dry_run_notifier_records_messages():
    """DryRunNotifier should record messages without external delivery."""

    notifier = DryRunNotifier()
    message = _message()

    result = notifier.send(message)

    assert result.success is True
    assert result.channel == "dry_run"
    assert result.destination == "local"
    assert notifier.messages == [message]


def test_notification_dispatcher_dry_run_short_circuits_channels():
    """Dry-run dispatcher should not call configured real channels."""

    email_notifier = EmailNotifier(EmailConfig(enabled=True), smtp_factory=FailingSMTP)
    slack_notifier = SlackNotifier(SlackConfig(webhook_url="not-a-url"))
    dispatcher = NotificationDispatcher(
        email_notifier=email_notifier,
        slack_notifier=slack_notifier,
        dry_run=True,
    )

    results = dispatcher.send(_message())

    assert len(results) == 1
    assert results[0].channel == "dry_run"
    assert results[0].success is True


def test_notification_dispatcher_sends_to_configured_channels():
    """Dispatcher should send to email and Slack when not in dry-run mode."""

    FakeSMTP.instances.clear()
    opener = FakeOpener([FakeResponse("ok")])
    email_notifier = EmailNotifier(
        EmailConfig(
            enabled=True,
            smtp_host="smtp.example.com",
            email_from="soc@example.com",
            email_to="analyst@example.com",
            use_tls=False,
        ),
        smtp_factory=FakeSMTP,
    )
    slack_notifier = SlackNotifier(SlackConfig(webhook_url="https://hooks.example.com/test"), opener=opener)
    dispatcher = NotificationDispatcher(email_notifier=email_notifier, slack_notifier=slack_notifier)

    results = dispatcher.send(_message())

    assert [result.channel for result in results] == ["email", "slack"]
    assert all(result.success for result in results)


def test_notification_dispatcher_no_channels_returns_failure():
    """Dispatcher with no channels should return one failure result."""

    results = NotificationDispatcher().send(_message())

    assert len(results) == 1
    assert results[0].channel == "none"
    assert results[0].success is False


def test_notification_dispatcher_from_settings_can_dry_run():
    """Dispatcher.from_settings should support dry-run creation."""

    dispatcher = NotificationDispatcher.from_settings(FakeSettings(), dry_run=True)

    results = dispatcher.send(_message())

    assert len(results) == 1
    assert results[0].channel == "dry_run"
    assert results[0].success is True


def test_build_triage_notification_contains_triage_and_routing_context():
    """build_triage_notification should include triage and routing details."""

    notification = build_triage_notification(_triage(), routing=_routing(), report_text="# Report")

    assert notification.subject == "[PAGE_NOW] SOC triage 8/10 for candidate-001"
    assert notification.severity == "critical"
    assert "Target: incident_candidate/candidate-001" in notification.body
    assert "Score: 8/10" in notification.body
    assert "Action: page_now" in notification.body
    assert "False-positive likelihood: low" in notification.body
    assert "Routing:" in notification.body
    assert "Page analyst immediately." in notification.body
    assert "# Report" in notification.body
    assert notification.metadata == {
        "target_id": "candidate-001",
        "target_type": "incident_candidate",
        "score": 8,
        "action": "page_now",
        "classification": "likely_true_positive_high_priority",
        "analysis_source": "local",
        "model": None,
    }


def test_build_triage_notification_maps_score_to_severity():
    """Notification severity should follow triage score."""

    assert build_triage_notification(_triage(score=9)).severity == "critical"
    assert build_triage_notification(_triage(score=5, action=TriageAction.QUEUE_REVIEW)).severity == "warning"
    assert build_triage_notification(
        _triage(score=2, action=TriageAction.MARK_LIKELY_BENIGN)
    ).severity == "info"


def test_notify_triage_defaults_to_dry_run():
    """notify_triage convenience function should default to dry-run delivery."""

    results = notify_triage(_triage(), routing=_routing(), report_text="# Report")

    assert len(results) == 1
    assert results[0].channel == "dry_run"
    assert results[0].success is True


def test_dispatcher_notify_triage_uses_dispatcher_send():
    """NotificationDispatcher.notify_triage should build and send message."""

    dispatcher = NotificationDispatcher(dry_run=True)

    results = dispatcher.notify_triage(_triage(), routing=_routing())

    assert len(results) == 1
    assert results[0].channel == "dry_run"
    assert dispatcher.dry_run_notifier is not None
    assert dispatcher.dry_run_notifier.messages[0].subject.startswith("[PAGE_NOW]")


def test_write_notification_results_writes_json(tmp_path):
    """write_notification_results should write serializable JSON results."""

    results = [
        NotificationResult(
            channel="dry_run",
            success=True,
            destination="local",
            message="recorded",
            error=None,
            sent_at=BASE_TIME,
        )
    ]
    output_path = tmp_path / "notifications" / "results.json"

    written_path = write_notification_results(results, output_path)

    assert written_path == output_path
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data == [
        {
            "channel": "dry_run",
            "success": True,
            "destination": "local",
            "message": "recorded",
            "error": None,
            "sent_at": BASE_TIME.isoformat(),
        }
    ]

def test_triage_notification_states_analysis_source():
    """An analyst paged on a heuristic score must be able to see that it is one."""

    message = build_triage_notification(_triage())

    assert "deterministic local scoring" in message.body.lower()
    assert message.metadata["analysis_source"] == "local"


def test_triage_notification_names_model_when_llm_scored():
    """An LLM-scored notification must name the model in body and metadata."""

    triage = _triage()
    triage.analysis_source = AnalysisSource.LLM
    triage.model = "vendor/model-x"

    message = build_triage_notification(triage)

    assert "vendor/model-x" in message.body
    assert message.metadata["analysis_source"] == "llm"
    assert message.metadata["model"] == "vendor/model-x"
