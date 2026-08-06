
"""Wazuh active-response executors.

Two executors live here, `WazuhFirewallDropExecutor` and
`WazuhHostDenyExecutor`. Each triggers one Wazuh active-response command on one
named agent through the Manager API, using an injected
`soc.wazuh_client.WazuhManagerClient`. Deciding *whether* the action may happen
is not their job: `soc.response.ResponseGate` owns every gate, and these classes
are deliberately the narrowest possible things that can act.

NOT FULLY VERIFIED — the request shape, correctable in ONE place
---------------------------------------------------------------
This project has no Wazuh deployment to verify the active-response request
against, so the request shape below is stated as module constants rather than
being spread across call sites. Anyone running against a real Manager corrects
these constants and nothing else, exactly as
`soc.security_onion_client` does for its undocumented query parameters.

    WAZUH_ACTIVE_RESPONSE_METHOD  ("PUT")            documented
    WAZUH_ACTIVE_RESPONSE_PATH    ("/active-response") documented
    WAZUH_COMMAND_FIELD           ("command")        INFERRED field name
    WAZUH_ARGUMENTS_FIELD         ("arguments")      INFERRED field name
    WAZUH_AGENTS_LIST_FIELD       ("agents_list")    INFERRED field name
    WAZUH_FIREWALL_DROP_COMMAND   ("firewall-drop0") INFERRED, including the
        trailing "0" that Wazuh's own examples use to mean "run on the agent
        itself rather than fan out"
    WAZUH_HOST_DENY_COMMAND       ("host-deny0")     INFERRED, same caveat
    WAZUH_AGENT_SCOPE_IN_BODY     (True)             INFERRED: whether the agent
        scope travels in the JSON body or as a query parameter. Each executor
        takes `agent_scope_in_body` so a deployment can switch it without a code
        change.

Two safety properties are not negotiable regardless of the shape:

    1. **The agent ID and the address are validated before they are sent.** Both
       come from alert data, and the arguments of an active-response command are
       consumed by a script running with high privilege on the endpoint. The
       agent ID must be alphanumeric; the address must parse with `ipaddress`.
    2. **A dry run performs no request at all.** It returns a description.

There is **no rollback path through this API**: nothing in the active-response
endpoint undoes a firewall-drop or a host-deny. `describe()` therefore returns
`WAZUH_ROLLBACK_UNAVAILABLE` rather than inventing a command that would not
work. A rollback field that lies is worse than one that admits the limitation.

Errors raise. `soc.response.ResponseGate` catches them and records the action as
FAILED, so nothing here is swallowed and no failure returns a fake success.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any, Protocol

from soc.response import ResponseActionType

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

WAZUH_ACTIVE_RESPONSE_METHOD = "PUT"
"""HTTP method used to trigger an active response."""

WAZUH_ACTIVE_RESPONSE_PATH = "/active-response"
"""Manager API path used to trigger an active response."""

WAZUH_COMMAND_FIELD = "command"
"""INFERRED request field naming the active-response command."""

WAZUH_ARGUMENTS_FIELD = "arguments"
"""INFERRED request field carrying the command arguments."""

WAZUH_AGENTS_LIST_FIELD = "agents_list"
"""INFERRED field/parameter name scoping the command to specific agents."""

WAZUH_FIREWALL_DROP_COMMAND = "firewall-drop0"
"""INFERRED command name for the firewall-drop active response."""

WAZUH_HOST_DENY_COMMAND = "host-deny0"
"""INFERRED command name for the host-deny active response."""

WAZUH_AGENT_SCOPE_IN_BODY = True
"""INFERRED: whether agent scope is sent in the body rather than the query."""

WAZUH_ROLLBACK_UNAVAILABLE = (
    "NO ROLLBACK AVAILABLE: the Wazuh active-response API exposes no call that "
    "undoes this command. Reverse it on the agent itself, by removing the local "
    "firewall or hosts.deny entry the active-response script created."
)
"""Honest rollback text. Nothing in this API can undo an active response."""

WAZUH_TARGET_SEPARATOR = "/"
"""Separator between the agent ID and the address in a target string."""

AGENT_ID_PATTERN = re.compile(r"\A[A-Za-z0-9]{1,32}\Z")
"""Allowed agent IDs. An agent ID reaches a request, so it is validated."""


class WazuhResponseError(RuntimeError):
    """Raised when an active response is refused, malformed, or fails."""


class ManagerRequester(Protocol):
    """The one method these executors need from a Wazuh Manager client.

    `soc.wazuh_client.WazuhManagerClient` satisfies this. Tests substitute a fake
    so no HTTP request is ever made.
    """

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: JsonDict | None = None,
    ) -> JsonDict:
        """Send an authenticated request to the Wazuh Manager API."""


def parse_wazuh_target(target: str, *, default_agent_id: str = "") -> tuple[str, str]:
    """Split and validate a target into an agent ID and an address.

    An endpoint action needs both: which agent to act on, and what to act
    against. The accepted forms are "<agent_id>/<ip>", or a bare "<ip>" when the
    executor was constructed with an agent ID.

    This is the injection boundary for this module. Both halves come from alert
    data, and the arguments of an active-response command are consumed by a
    privileged script on the endpoint, so neither half is passed through
    unvalidated.

    Inputs:
        target: Target string.
        default_agent_id: Agent ID to use when the target carries none.

    Outputs:
        Tuple of (agent ID, normalized address).

    Raises:
        WazuhResponseError: If the agent ID or the address is missing or invalid.
    """

    text = str(target).strip()
    if not text:
        raise WazuhResponseError("active response target is empty")

    if WAZUH_TARGET_SEPARATOR in text:
        agent_part, _, address_part = text.partition(WAZUH_TARGET_SEPARATOR)
    else:
        agent_part, address_part = default_agent_id, text

    return _validate_agent_id(agent_part), _validate_address(address_part)


def build_active_response_body(command: str, arguments: list[str]) -> JsonDict:
    """Build the active-response request body.

    Field names are INFERRED and read from module constants, so a deployment
    correcting them changes one place.

    Inputs:
        command: Active-response command name.
        arguments: Command arguments, already validated.

    Outputs:
        JSON body without the agent scope, which the caller adds.
    """

    return {WAZUH_COMMAND_FIELD: command, WAZUH_ARGUMENTS_FIELD: list(arguments)}


class _WazuhActiveResponseExecutor:
    """Shared implementation of one Wazuh active-response command.

    Attributes:
        action: The single response action a subclass handles.
        command_name: The active-response command a subclass sends.
    """

    action: ResponseActionType
    command_name: str

    def __init__(
        self,
        client: ManagerRequester,
        *,
        agent_id: str = "",
        agent_scope_in_body: bool = WAZUH_AGENT_SCOPE_IN_BODY,
    ) -> None:
        """Initialize the executor.

        The agent ID is not validated here, only when it is used. Construction
        must not raise for a target-shaped reason: the gate builds executors up
        front and validation belongs on the path that would act.

        Inputs:
            client: Wazuh Manager client used to send the request.
            agent_id: Optional default agent, used when a target carries none.
            agent_scope_in_body: INFERRED transport detail. True sends the agent
                scope in the JSON body; False sends it as a query parameter.

        Outputs:
            None.
        """

        self.client = client
        self.agent_id = agent_id
        self.agent_scope_in_body = agent_scope_in_body

    def describe(self, target: str) -> tuple[str, str]:
        """Return the request that would be sent and an honest rollback string.

        Pure: safe to call at any time, because the gate calls it to record the
        action *before* deciding to act. It sends nothing.

        Inputs:
            target: Target string of the form "<agent_id>/<ip>" or "<ip>".

        Outputs:
            Tuple of (request description, rollback text). The rollback text
            states that this API cannot undo the action, because it cannot.

        Raises:
            WazuhResponseError: If the target is invalid.
        """

        agent_id, address = parse_wazuh_target(target, default_agent_id=self.agent_id)
        return self._request_text(agent_id, address), WAZUH_ROLLBACK_UNAVAILABLE

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Trigger the active response on one agent.

        Inputs:
            target: Target string of the form "<agent_id>/<ip>" or "<ip>".
            dry_run: When True, describe the action and perform no side effect
                whatsoever: no HTTP request of any kind.

        Outputs:
            Human-readable result, or a description of what would have happened.

        Raises:
            WazuhResponseError: If the target is invalid or the Manager reported
            that the command was not applied.
        """

        agent_id, address = parse_wazuh_target(target, default_agent_id=self.agent_id)

        if dry_run:
            return (
                f"DRY RUN: would send {self._request_text(agent_id, address)} to trigger "
                f"{self.command_name} against {address} on Wazuh agent {agent_id}. "
                "No request sent."
            )

        body = build_active_response_body(self.command_name, [address])
        query: dict[str, str] | None = None
        if self.agent_scope_in_body:
            body[WAZUH_AGENTS_LIST_FIELD] = [agent_id]
        else:
            query = {WAZUH_AGENTS_LIST_FIELD: agent_id}

        logger.warning(
            "Sending Wazuh active response %s against %s on agent %s",
            self.command_name,
            address,
            agent_id,
        )
        response = self.client.request(
            WAZUH_ACTIVE_RESPONSE_METHOD,
            WAZUH_ACTIVE_RESPONSE_PATH,
            query=query,
            body=body,
        )
        affected = self._check_response(response, agent_id, address)
        return (
            f"Wazuh active response {self.command_name} against {address} was accepted "
            f"for agent(s) {', '.join(affected)}"
        )

    def _check_response(self, response: JsonDict, agent_id: str, address: str) -> list[str]:
        """Verify the Manager actually applied the command.

        A response envelope that reports a failed item, or that reports no
        affected agent at all, means nothing happened. Returning a success string
        for either would put a false record in the audit trail.

        Inputs:
            response: Parsed Manager response.
            agent_id: Agent the command was scoped to.
            address: Address the command targeted.

        Outputs:
            List of affected agent identifiers.

        Raises:
            WazuhResponseError: If the Manager reported a failure or no effect.
        """

        data = response.get("data")
        payload: JsonDict = data if isinstance(data, dict) else response

        failed_items = payload.get("failed_items") or []
        if failed_items:
            raise WazuhResponseError(
                f"Wazuh refused active response {self.command_name} against {address} "
                f"on agent {agent_id}: {_failure_text(failed_items)}"
            )

        affected_items = payload.get("affected_items") or []
        affected = [str(item) for item in affected_items if str(item).strip()]
        if not affected:
            raise WazuhResponseError(
                f"Wazuh applied active response {self.command_name} against {address} "
                f"to no agent; requested agent was {agent_id}"
            )

        return affected

    def _request_text(self, agent_id: str, address: str) -> str:
        """Render the request as deterministic text for the audit trail.

        This string is a record, not something that is ever executed or sent.

        Inputs:
            agent_id: Validated agent ID.
            address: Validated address.

        Outputs:
            Text of the form "PUT /active-response {json}".
        """

        body = build_active_response_body(self.command_name, [address])
        body[WAZUH_AGENTS_LIST_FIELD] = [agent_id]
        rendered = json.dumps(body, sort_keys=True)
        return f"{WAZUH_ACTIVE_RESPONSE_METHOD} {WAZUH_ACTIVE_RESPONSE_PATH} {rendered}"


class WazuhFirewallDropExecutor(_WazuhActiveResponseExecutor):
    """Trigger the Wazuh firewall-drop active response on one agent.

    Attributes:
        action: PF-independent endpoint firewall drop action.
        command_name: INFERRED active-response command name.
    """

    action = ResponseActionType.WAZUH_FIREWALL_DROP
    command_name = WAZUH_FIREWALL_DROP_COMMAND


class WazuhHostDenyExecutor(_WazuhActiveResponseExecutor):
    """Trigger the Wazuh host-deny active response on one agent.

    Attributes:
        action: Endpoint host-deny action.
        command_name: INFERRED active-response command name.
    """

    action = ResponseActionType.WAZUH_HOST_DENY
    command_name = WAZUH_HOST_DENY_COMMAND


def _validate_agent_id(value: str) -> str:
    """Validate a Wazuh agent ID.

    Inputs:
        value: Candidate agent ID.

    Outputs:
        The trimmed agent ID.

    Raises:
        WazuhResponseError: If the agent ID is empty or not alphanumeric.
    """

    candidate = str(value).strip()
    if not candidate:
        raise WazuhResponseError(
            "active response requires a Wazuh agent id; pass one as '<agent_id>/<ip>' "
            "or in the executor constructor"
        )
    if not AGENT_ID_PATTERN.match(candidate):
        raise WazuhResponseError(
            f"Wazuh agent id {value!r} is not alphanumeric and will not be used"
        )
    return candidate


def _validate_address(value: str) -> str:
    """Validate that a value is a single IP address.

    A CIDR range is refused: an active response applies to one address.

    Inputs:
        value: Candidate address.

    Outputs:
        Normalized address text.

    Raises:
        WazuhResponseError: If the value is not a single valid IP address.
    """

    candidate = str(value).strip()
    if not candidate:
        raise WazuhResponseError("active response target address is empty")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise WazuhResponseError(
            f"active response target address {value!r} is not a valid IP address "
            "and will not be used"
        ) from exc

    return str(address)


def _failure_text(failed_items: Any) -> str:
    """Summarize Wazuh failed_items for an error message.

    Only the Manager's own error codes and messages are quoted. No credential,
    token, or request header is ever included.

    Inputs:
        failed_items: The failed_items value from a Manager response.

    Outputs:
        Human-readable failure summary.
    """

    if not isinstance(failed_items, list):
        return str(failed_items)

    parts: list[str] = []
    for item in failed_items:
        if not isinstance(item, dict):
            parts.append(str(item))
            continue
        error = item.get("error")
        if isinstance(error, dict):
            parts.append(f"code {error.get('code')}: {error.get('message')}")
        else:
            parts.append(str(error or item))
    return "; ".join(parts)
