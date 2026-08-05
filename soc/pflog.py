"""OpenBSD pflog firewall log parsing.

`pflog` is a binary pcap file, not text. Operators read it with tcpdump:

    tcpdump -n -e -ttt -r /var/log/pflog

This module parses the *text* that command emits into PflogEvent objects and
then into RawEvent objects for SOCPipeline.run_events(). Normalization into the
shared Alert model lives in soc.normalizer.normalize_openbsd_pf_event; this
module only handles reading and parsing.

NOT VERIFIED — the line format is inferred, change it in ONE place
-----------------------------------------------------------------
The expected line shape below was derived from common tcpdump output and has
**not** been verified against a live OpenBSD host. tcpdump's rendering varies
with flags, tcpdump version, and protocol, so the whole line grammar lives in a
single module constant:

    PFLOG_LINE_PATTERN      INFERRED

Anyone testing against a real OpenBSD firewall corrects that one regex and
nothing else. Parsing is tolerant by design: `parse_pflog_line` returns None for
a line it cannot read, and `read_pflog_file` skips such lines, counts them on
`PflogReader.last_malformed_line_count`, and logs one warning naming the file
and the count — the same contract soc.wazuh_client.WazuhAlertJsonReader uses for
malformed alerts.json lines. A firewall log is appended to continuously, so an
unreadable or partially written line is expected and must never fail the read.

Lines the pattern expects, in the two common port-bearing and portless forms:

    Aug 05 12:00:00.123456 rule 12/(match) block in on em0: \
203.0.113.5.4444 > 10.0.1.5.22: S 12345:12345(0) win 65535
    Aug 05 12:00:02.222333 rule 12/(match) block in on em0: \
198.51.100.7 > 10.0.1.5: icmp: echo request

pflog lines carry no year, so `year` defaults to the current UTC year. Pass it
explicitly when parsing an archived log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc.models import EventSource, RawEvent, utc_now

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


class PflogError(ValueError):
    """Raised when a pflog source cannot be read."""


PFLOG_LINE_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)
    \s+rule\s+(?P<rule_number>[^/\s]+)/\((?P<rule_verdict>[^)]*)\)
    \s+(?P<action>block|pass|match|rdr|nat)
    \s+(?P<direction>in|out)
    \s+on\s+(?P<interface>[^\s:]+):
    \s+(?P<src>\S+)\s+>\s+(?P<dst>\S+?):
    (?:\s+(?P<detail>.*))?
    $
    """,
    re.VERBOSE,
)
"""INFERRED grammar of one tcpdump-rendered pflog line. See the module docstring.

This is the single place a real deployment corrects the expected format. Named
groups `timestamp`, `rule_number`, `action`, `direction`, `interface`, `src`,
`dst`, and `detail` are the parser's whole contract with the log format.
"""

PFLOG_TIMESTAMP_FORMATS = ("%Y %b %d %H:%M:%S.%f", "%Y %b %d %H:%M:%S")
"""INFERRED strptime formats for the leading `tcpdump -ttt` timestamp.

The log line has no year, so the assumed year is prepended before parsing.
Parsing without a year is deprecated in Python 3.14 and mishandles Feb 29.
"""

KNOWN_PROTOCOLS = frozenset(
    {"tcp", "udp", "icmp", "icmp6", "igmp", "esp", "ah", "gre", "ipv6", "ospf", "pim"}
)
"""Protocol tokens tcpdump names explicitly at the start of the packet detail.

TCP is the exception: tcpdump prints TCP flags rather than the word "tcp", so a
port-bearing line with an unrecognized detail token is treated as TCP.
"""

_IPV4_ENDPOINT_PATTERN = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?P<port>\d+))?$")
"""Split a tcpdump IPv4 endpoint token, where the port is a fifth dotted field."""


@dataclass(frozen=True, slots=True)
class PflogEvent:
    """One parsed pflog packet-filter decision.

    Attributes:
        timestamp: Packet time in UTC, or None when it could not be parsed.
        action: Filter action, normally "block" or "pass".
        direction: Packet direction, "in" or "out".
        interface: Interface name the rule matched on, such as "em0".
        rule_number: Matching pf rule number, or None when not numeric.
        protocol: Lowercase protocol name, or None when not determinable.
        src_ip: Source address.
        src_port: Source port, or None for protocols without ports.
        dst_ip: Destination address.
        dst_port: Destination port, or None for protocols without ports.
        raw_line: The original log line, kept verbatim for auditability.
    """

    timestamp: datetime | None
    action: str | None
    direction: str | None
    interface: str | None
    rule_number: int | None
    protocol: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    raw_line: str

    def to_payload(self) -> JsonDict:
        """Serialize the parsed event into a JSON-compatible payload.

        This payload becomes RawEvent.payload and, after normalization,
        Alert.raw, so it carries every parsed field plus the original line.

        Inputs:
            None.

        Outputs:
            Dictionary of parsed fields with an ISO-8601 timestamp.
        """

        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "action": self.action,
            "direction": self.direction,
            "interface": self.interface,
            "rule_number": self.rule_number,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "raw_line": self.raw_line,
        }


class PflogReader:
    """Reader for tcpdump-rendered pflog text files.

    The reader is stateless apart from `last_malformed_line_count`, which
    records how many lines the most recent read could not parse. This mirrors
    soc.wazuh_client.WazuhAlertJsonReader so both line-oriented readers report
    skipped input the same way.
    """

    def __init__(self) -> None:
        """Initialize the reader.

        Inputs:
            None.

        Outputs:
            None.
        """

        self.last_malformed_line_count = 0

    def read_pflog_file(self, path: Path | str, *, year: int | None = None) -> list[PflogEvent]:
        """Read and parse every readable line of a pflog text file.

        Inputs:
            path: Path to a text file of tcpdump-rendered pflog output.
            year: Calendar year to assume for the year-less log timestamps.
                Defaults to the current UTC year.

        Outputs:
            Parsed events in file order. Unparseable lines are skipped and
            counted on last_malformed_line_count.

        Raises:
            PflogError: If the path does not exist, is not a file, or cannot be
                read.
        """

        self.last_malformed_line_count = 0
        resolved = Path(path)

        if not resolved.exists():
            raise PflogError(f"pflog file does not exist: {resolved}")
        if not resolved.is_file():
            raise PflogError(f"pflog path is not a file: {resolved}")

        events: list[PflogEvent] = []
        try:
            with resolved.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    event = parse_pflog_line(line, year=year)
                    if event is None:
                        self.last_malformed_line_count += 1
                        continue
                    events.append(event)
        except OSError as exc:
            raise PflogError(f"pflog file could not be read: {resolved}: {exc}") from exc

        if self.last_malformed_line_count:
            logger.warning(
                "Skipped %d unparseable line(s) in pflog file %s",
                self.last_malformed_line_count,
                resolved,
            )

        return events

    def fetch_recent_events(
        self,
        path: Path | str,
        *,
        year: int | None = None,
        hostname: str | None = None,
    ) -> list[RawEvent]:
        """Read a pflog text file and convert it into RawEvent objects.

        Inputs:
            path: Path to a text file of tcpdump-rendered pflog output.
            year: Calendar year to assume for year-less log timestamps.
            hostname: Optional firewall hostname to attach to each payload.

        Outputs:
            RawEvent objects with source EventSource.OPENBSD_PF.

        Raises:
            PflogError: If the path cannot be read.
        """

        return [
            raw_event_from_pflog(event, hostname=hostname)
            for event in self.read_pflog_file(path, year=year)
        ]


def parse_pflog_line(line: str, *, year: int | None = None) -> PflogEvent | None:
    """Parse one tcpdump-rendered pflog line.

    A line that does not match PFLOG_LINE_PATTERN returns None rather than
    raising, because tcpdump output varies and one unreadable line must not fail
    a whole read.

    Inputs:
        line: One line of tcpdump-rendered pflog output.
        year: Calendar year to assume for the year-less timestamp. Defaults to
            the current UTC year.

    Outputs:
        PflogEvent, or None when the line does not match the expected format.
    """

    if not line or not line.strip():
        return None

    match = PFLOG_LINE_PATTERN.match(line.strip())
    if match is None:
        return None

    src_ip, src_port = _split_endpoint(match.group("src"))
    dst_ip, dst_port = _split_endpoint(match.group("dst"))
    has_ports = src_port is not None or dst_port is not None

    return PflogEvent(
        timestamp=_parse_pflog_timestamp(match.group("timestamp"), year=year),
        action=match.group("action").lower(),
        direction=match.group("direction").lower(),
        interface=match.group("interface"),
        rule_number=_to_int(match.group("rule_number")),
        protocol=_protocol_from_detail(match.group("detail"), has_ports=has_ports),
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        raw_line=line.strip(),
    )


def read_pflog_file(path: Path | str, *, year: int | None = None) -> list[PflogEvent]:
    """Read and parse a pflog text file.

    This is the stateless entry point. Callers that need the number of skipped
    lines use PflogReader, whose last_malformed_line_count exposes it the same
    way the Wazuh alerts.json reader does; the count is logged either way.

    Inputs:
        path: Path to a text file of tcpdump-rendered pflog output.
        year: Calendar year to assume for year-less log timestamps.

    Outputs:
        Parsed events in file order, with unparseable lines skipped.

    Raises:
        PflogError: If the path does not exist, is not a file, or cannot be read.
    """

    return PflogReader().read_pflog_file(path, year=year)


def raw_event_from_pflog(event: PflogEvent, *, hostname: str | None = None) -> RawEvent:
    """Convert one parsed pflog event into a RawEvent.

    The ID is a deterministic fingerprint of the payload, so reprocessing the
    same log line produces the same IDs downstream and dedup works. The optional
    hostname participates in that fingerprint, so the same packet logged by two
    firewalls does not collapse into one event.

    Inputs:
        event: Parsed pflog event.
        hostname: Optional firewall hostname to record on the payload.

    Outputs:
        RawEvent with source EventSource.OPENBSD_PF.
    """

    payload = event.to_payload()
    if hostname and hostname.strip():
        payload["hostname"] = hostname.strip()

    return RawEvent(
        id=_event_id_from_payload(payload),
        source=EventSource.OPENBSD_PF,
        timestamp=event.timestamp,
        payload=payload,
        received_at=utc_now(),
    )


def _event_id_from_payload(payload: JsonDict) -> str:
    """Build a deterministic content-addressed event ID.

    Inputs:
        payload: Parsed pflog payload.

    Outputs:
        Event ID string of the form "openbsd_pf-<sha256 prefix>".
    """

    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return f"{EventSource.OPENBSD_PF.value}-{fingerprint}"


def _parse_pflog_timestamp(value: str, *, year: int | None = None) -> datetime | None:
    """Parse a year-less pflog timestamp into a UTC datetime.

    Inputs:
        value: Timestamp text such as "Aug 05 12:00:00.123456".
        year: Calendar year to assume. Defaults to the current UTC year.

    Outputs:
        Timezone-aware UTC datetime, or None when the text cannot be parsed.
    """

    text = " ".join(value.split())
    resolved_year = year if year is not None else utc_now().year

    dated_text = f"{resolved_year} {text}"
    for time_format in PFLOG_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(dated_text, time_format)
        except ValueError:
            continue
        return parsed.replace(tzinfo=UTC)

    return None


def _split_endpoint(token: str) -> tuple[str | None, int | None]:
    """Split a tcpdump endpoint token into address and optional port.

    tcpdump appends the port as an extra dotted field ("10.0.1.5.22"), so the
    split is positional rather than delimiter-based.

    Inputs:
        token: Endpoint text from a pflog line.

    Outputs:
        Tuple of address (or None) and port (or None).
    """

    text = token.strip()
    if not text:
        return None, None

    match = _IPV4_ENDPOINT_PATTERN.match(text)
    if match is not None:
        return match.group("ip"), _to_int(match.group("port"))

    host, separator, tail = text.rpartition(".")
    if separator and host and tail.isdigit():
        return host, int(tail)

    return text, None


def _protocol_from_detail(detail: str | None, *, has_ports: bool) -> str | None:
    """Infer the protocol from the packet detail tcpdump printed.

    tcpdump names UDP, ICMP and friends explicitly but renders TCP as flags, so
    an unrecognized detail on a line carrying ports is treated as TCP.

    Inputs:
        detail: Trailing packet detail text, if any.
        has_ports: Whether either endpoint carried a port.

    Outputs:
        Lowercase protocol name, or None when it cannot be determined.
    """

    if detail:
        token = detail.split()[0].strip(":,").lower() if detail.split() else ""
        if token in KNOWN_PROTOCOLS:
            return token

    if has_ports:
        return "tcp"
    return None


def _to_int(value: Any) -> int | None:
    """Convert a value to int when possible.

    Inputs:
        value: Candidate integer value.

    Outputs:
        Integer, or None when conversion fails.
    """

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None
