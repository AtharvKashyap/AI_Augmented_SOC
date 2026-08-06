
"""OpenBSD pf block executor for approved response actions.

This module performs exactly one thing: it adds a single validated address to one
named pf table on one firewall over SSH, and removes it again. Deciding *whether*
that may happen is not its job — `soc.response.ResponseGate` owns every gate, and
this module is deliberately the narrowest possible thing that can act.

Three rules shape the whole module, and none of them are style preferences:

    1. **The target is untrusted input.** A blocked address originates in alert
       data, so it is parsed with `ipaddress` and rejected unless it is a single
       valid address. An unvalidated string never reaches a command.
    2. **No shell, ever.** Commands are built as argument lists and handed to
       `subprocess.run` without `shell=True`, and no shell string is ever
       constructed for execution. The strings `describe()` returns are for humans
       and for the audit trail only; nothing executes them.
    3. **A dry run does nothing at all.** No process, no SSH connection, no
       network. It returns a description and returns it without acting.

Errors raise. `soc.response.ResponseGate` catches them and records the action as
FAILED, so nothing here is swallowed and no failure returns a fake success.

The command performed and the command that undoes it are:

    pfctl -t <block_table> -T add <ip>
    pfctl -t <block_table> -T delete <ip>

`identity_file` is treated as a credential path: it is passed to ssh as its own
argument and is redacted out of every error message, log line, and returned
string, because those all end up in the audit trail.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from soc.response import ResponseActionType

logger = logging.getLogger(__name__)

PfctlRunner = Callable[[list[str]], tuple[int, str, str]]
"""Callable taking an argument list and returning (exit code, stdout, stderr)."""

PF_BINARY = "pfctl"
"""Remote binary invoked on the firewall."""

TABLE_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9_.-]{1,31}\Z")
"""Allowed pf table names. A table name reaches a command, so it is validated."""

REDACTED = "<redacted-identity-file>"
"""Placeholder substituted for a credential path in any disclosed text."""


class PfctlError(RuntimeError):
    """Raised when a pf block is misconfigured, refused, or fails."""


@dataclass(frozen=True, slots=True)
class PfctlConfig:
    """Connection and table settings for one pf firewall.

    Attributes:
        host: Firewall hostname or address reachable over SSH.
        user: SSH user with permission to run pfctl on the firewall.
        block_table: Name of the pf table this executor may modify. Restricted to
            one table so a compromised or buggy caller cannot touch another.
        ssh_binary: SSH client binary to invoke.
        ssh_port: SSH port.
        timeout_seconds: Timeout applied to the SSH invocation.
        identity_file: Optional SSH private key path. Treated as a credential and
            never disclosed in output, logs, or errors.
        strict_host_key_checking: Whether ssh verifies the firewall host key.
            Defaults to True. Disabling it on a firewall management path invites a
            man-in-the-middle who can then rewrite the firewall, so disabling it
            emits a warning naming the host.
    """

    host: str
    user: str
    block_table: str
    ssh_binary: str = "ssh"
    ssh_port: int = 22
    timeout_seconds: int = 30
    identity_file: str = ""
    strict_host_key_checking: bool = True

    def __post_init__(self) -> None:
        """Validate the configuration and warn about weakened host key checking.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            PfctlError: If any field is missing or unusable.
        """

        if not str(self.host).strip():
            raise PfctlError("pfctl host cannot be empty")
        if not str(self.user).strip():
            raise PfctlError("pfctl user cannot be empty")
        if not TABLE_NAME_PATTERN.match(str(self.block_table)):
            raise PfctlError(
                "pfctl block table must be 1-31 characters of letters, digits, "
                f"underscore, dot, or hyphen, got {self.block_table!r}"
            )
        if not str(self.ssh_binary).strip():
            raise PfctlError("pfctl ssh_binary cannot be empty")
        if not 1 <= int(self.ssh_port) <= 65535:
            raise PfctlError(f"pfctl ssh port must be between 1 and 65535, got {self.ssh_port}")
        if int(self.timeout_seconds) <= 0:
            raise PfctlError(
                f"pfctl timeout must be greater than zero, got {self.timeout_seconds}"
            )

        if not self.strict_host_key_checking:
            logger.warning(
                "SSH host key checking is DISABLED for pf firewall %s; a "
                "man-in-the-middle on this path can rewrite firewall rules",
                self.host,
            )


class PfctlBlockExecutor:
    """Add or remove one address in one pf block table over SSH.

    Attributes:
        action: The single response action this executor handles.
    """

    action = ResponseActionType.PF_BLOCK_IP

    def __init__(self, config: PfctlConfig, *, runner: PfctlRunner | None = None) -> None:
        """Initialize the executor.

        Inputs:
            config: Firewall connection and table settings.
            runner: Optional callable receiving the argument list and returning
                (exit code, stdout, stderr). Defaults to a `subprocess.run`
                wrapper. Injecting it means tests never spawn a process.

        Outputs:
            None.
        """

        self.config = config
        self._runner = runner

    def describe(self, target: str) -> tuple[str, str]:
        """Return the pfctl command that would run and the one that undoes it.

        Pure: safe to call at any time, because the gate calls it to record the
        command *before* deciding to act. It performs no SSH and no subprocess
        call. It does validate the target, since an invalid one has no honest
        command to describe.

        Inputs:
            target: Candidate address to block.

        Outputs:
            Tuple of (add command, delete command).

        Raises:
            PfctlError: If the target is not a single valid IP address.
        """

        address = _validate_target(target)
        return (
            self._remote_command_text("add", address),
            self._remote_command_text("delete", address),
        )

    def execute(self, target: str, *, dry_run: bool) -> str:
        """Add the target to the pf block table.

        Inputs:
            target: Address to block.
            dry_run: When True, describe the action and perform no side effect
                whatsoever: no SSH, no subprocess, no network.

        Outputs:
            Human-readable result, or a description of what would have happened.

        Raises:
            PfctlError: If the target is invalid or the command fails.
        """

        return self._apply("add", target, dry_run=dry_run)

    def rollback(self, target: str, *, dry_run: bool) -> str:
        """Remove the target from the pf block table.

        A block nobody can undo is not a controlled action, so removal is a first
        class operation rather than a command string in an audit record.

        Inputs:
            target: Address to unblock.
            dry_run: When True, describe the action and perform no side effect.

        Outputs:
            Human-readable result, or a description of what would have happened.

        Raises:
            PfctlError: If the target is invalid or the command fails.
        """

        return self._apply("delete", target, dry_run=dry_run)

    def _apply(self, operation: str, target: str, *, dry_run: bool) -> str:
        """Run one pf table operation, or describe it without acting.

        Inputs:
            operation: Either "add" or "delete".
            target: Address the operation applies to.
            dry_run: Whether to describe rather than perform.

        Outputs:
            Human-readable result string.

        Raises:
            PfctlError: If the target is invalid or the command exits non-zero.
        """

        address = _validate_target(target)
        command_text = self._remote_command_text(operation, address)

        if dry_run:
            return (
                f"DRY RUN: would run '{command_text}' as "
                f"{self.config.user}@{self.config.host} over SSH. No action taken."
            )

        argv = self._ssh_argv(operation, address)
        exit_code, stdout, stderr = self._run(argv)

        if exit_code != 0:
            raise PfctlError(
                f"pfctl {operation} of {address} in table {self.config.block_table} on "
                f"{self.config.host} failed with exit code {exit_code}: "
                f"{self._sanitize(stderr) or 'no stderr output'}"
            )

        detail = self._sanitize(stdout).strip()
        summary = (
            f"pfctl {operation} of {address} in table {self.config.block_table} on "
            f"{self.config.host} succeeded"
        )
        if detail:
            return f"{summary}: {detail}"
        return summary

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        """Invoke the configured runner, defaulting to subprocess.

        Inputs:
            argv: Argument list to run. Never a shell string.

        Outputs:
            Tuple of (exit code, stdout, stderr).

        Raises:
            PfctlError: If the command could not be run at all.
        """

        if self._runner is not None:
            return self._runner(argv)
        return self._subprocess_run(argv)

    def _subprocess_run(self, argv: list[str]) -> tuple[int, str, str]:
        """Default runner: run the argument list without a shell.

        Inputs:
            argv: Argument list to run.

        Outputs:
            Tuple of (exit code, stdout, stderr).

        Raises:
            PfctlError: If the process timed out or could not be started.
        """

        try:
            # An argument list with shell=False stated explicitly. Never a string.
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PfctlError(
                f"pfctl command on {self.config.host} timed out after "
                f"{self.config.timeout_seconds}s"
            ) from exc
        except OSError as exc:
            raise PfctlError(
                f"cannot run {self.config.ssh_binary} for pf firewall "
                f"{self.config.host}: {self._sanitize(str(exc))}"
            ) from exc

        return completed.returncode, completed.stdout or "", completed.stderr or ""

    def _remote_command_text(self, operation: str, address: str) -> str:
        """Build the human-readable pfctl command for the audit trail.

        This string is never executed. It exists so the exact change can be
        recorded and reviewed, and so a rollback can be read by a person.

        Inputs:
            operation: Either "add" or "delete".
            address: Validated address.

        Outputs:
            Command text, for example "pfctl -t blocklist -T add 8.8.8.8".
        """

        return f"{PF_BINARY} -t {self.config.block_table} -T {operation} {address}"

    def _ssh_argv(self, operation: str, address: str) -> list[str]:
        """Build the SSH argument list that performs one table operation.

        Every element is either a literal, a validated table name, or a validated
        IP address, so no element can carry shell syntax even though ssh joins the
        remote portion for the login shell on the far side.

        Inputs:
            operation: Either "add" or "delete".
            address: Validated address.

        Outputs:
            Argument list suitable for subprocess without a shell.
        """

        argv = [
            self.config.ssh_binary,
            "-p",
            str(int(self.config.ssh_port)),
            "-o",
            "BatchMode=yes",
            "-o",
            f"StrictHostKeyChecking={'yes' if self.config.strict_host_key_checking else 'no'}",
            "-o",
            f"ConnectTimeout={int(self.config.timeout_seconds)}",
        ]
        if self.config.identity_file:
            argv += ["-i", self.config.identity_file]
        argv.append(f"{self.config.user}@{self.config.host}")
        argv += [PF_BINARY, "-t", self.config.block_table, "-T", operation, address]
        return argv

    def _sanitize(self, text: str) -> str:
        """Remove the identity file path from text that will be disclosed.

        ssh readily prints the identity path in its own warnings, and every string
        this module returns or raises is written to the audit trail.

        Inputs:
            text: Text to sanitize.

        Outputs:
            Text with any configured identity path replaced.
        """

        if not self.config.identity_file:
            return text
        return text.replace(self.config.identity_file, REDACTED)


def _validate_target(target: str) -> str:
    """Validate that a target is a single IP address and return its normal form.

    This is the command-injection boundary for this module. The target comes from
    alert data, so anything that is not exactly one IP address is refused here,
    before it can appear in an argument list or a command string. A CIDR range is
    refused too: this executor blocks one address at a time on purpose.

    Inputs:
        target: Candidate target string.

    Outputs:
        Normalized address text.

    Raises:
        PfctlError: If the target is not a single valid IP address.
    """

    candidate = str(target).strip()
    if not candidate:
        raise PfctlError("pf block target is empty")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise PfctlError(
            f"pf block target {target!r} is not a valid IP address and will not be used"
        ) from exc

    return str(address)
