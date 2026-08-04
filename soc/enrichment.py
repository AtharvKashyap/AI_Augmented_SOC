

"""Local enrichment helpers for AI_Augmented_SOC.

This module extracts and enriches indicators from normalized alerts and incident
candidates without requiring paid API keys or live internet access.

The MVP enrichment layer is intentionally safe and local:
    - Extract IPs, domains, URLs, email addresses, hashes, users, and hosts.
    - Classify IPs as private/public/loopback/link-local/reserved.
    - Flag obviously suspicious strings such as encoded PowerShell commands.
    - Produce EnrichmentResult objects that can later be extended with
      VirusTotal, AbuseIPDB, Shodan, MISP, or local threat-intel lookups.

External threat-intelligence calls should be added later behind this interface,
not mixed into the pipeline directly.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from typing import Any

from soc.models import Alert, EnrichmentResult, IncidentCandidate, utc_now

JsonDict = dict[str, Any]


class EnrichmentError(ValueError):
    """Raised when enrichment input is invalid."""


IOC_TYPE_IP = "ip"
IOC_TYPE_DOMAIN = "domain"

NON_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    # Filenames whose extension parses as a plausible TLD. Log lines are full of
    # these, and a filename promoted to a "domain" IOC pollutes reports and
    # invites the LLM to reason about a file as though it were infrastructure.
    ".bak",
    ".bat",
    ".cfg",
    ".cmd",
    ".conf",
    ".dll",
    ".evtx",
    ".exe",
    ".ini",
    ".jar",
    ".js",
    ".json",
    ".log",
    ".msi",
    ".pcap",
    ".ps1",
    ".py",
    ".sqlite",
    ".sys",
    ".tmp",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
)
"""Suffixes that look like domains but are filenames or non-routable names.

Deliberately excludes extensions that are also real TLDs, such as .sh, .zip and
.mov, since suppressing those would hide genuine domains.
"""
IOC_TYPE_URL = "url"
IOC_TYPE_EMAIL = "email"
IOC_TYPE_HASH = "hash"
IOC_TYPE_USER = "user"
IOC_TYPE_HOST = "host"
IOC_TYPE_COMMAND = "command"
IOC_TYPE_PROCESS = "process"


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")


class LocalEnricher:
    """Perform local enrichment for alerts and incident candidates.

    This class does not call external services. It extracts observables and
    generates structured local context that downstream triage can use.
    """

    def enrich_alert(self, alert: Alert) -> list[EnrichmentResult]:
        """Extract and enrich indicators from one alert.

        Inputs:
            alert: Normalized Alert object.

        Outputs:
            List of EnrichmentResult objects.
        """

        indicators = extract_alert_indicators(alert)
        return [enrich_indicator(indicator_type, value, target_id=alert.id) for indicator_type, value in indicators]

    def enrich_candidate(self, candidate: IncidentCandidate) -> list[EnrichmentResult]:
        """Extract and enrich indicators from an incident candidate.

        Inputs:
            candidate: IncidentCandidate containing related alerts.

        Outputs:
            List of EnrichmentResult objects.
        """

        indicators = extract_candidate_indicators(candidate)
        return [
            enrich_indicator(indicator_type, value, target_id=candidate.id)
            for indicator_type, value in indicators
        ]


def enrich_alert(alert: Alert) -> list[EnrichmentResult]:
    """Convenience function for enriching one alert.

    Inputs:
        alert: Normalized Alert object.

    Outputs:
        List of EnrichmentResult objects.
    """

    return LocalEnricher().enrich_alert(alert)


def enrich_candidate(candidate: IncidentCandidate) -> list[EnrichmentResult]:
    """Convenience function for enriching one incident candidate.

    Inputs:
        candidate: IncidentCandidate object.

    Outputs:
        List of EnrichmentResult objects.
    """

    return LocalEnricher().enrich_candidate(candidate)


def enrich_indicator(indicator_type: str, value: str, *, target_id: str | None = None) -> EnrichmentResult:
    """Create a local enrichment result for one indicator.

    Inputs:
        indicator_type: IOC/entity type such as ip, domain, hash, user, or host.
        value: Indicator value.
        target_id: Optional alert or candidate ID that produced the indicator.

    Outputs:
        EnrichmentResult object.
    """

    indicator_type = _clean_text(indicator_type)
    value = _clean_text(value)
    if indicator_type == "" or value == "":
        raise EnrichmentError("indicator_type and value are required")

    details = _build_local_details(indicator_type, value)
    summary = _build_summary(indicator_type, value, details)
    confidence = _confidence_for_details(details)
    severity_hint = _severity_hint_for_details(details)
    enrichment_id = _build_enrichment_id(indicator_type, value, target_id)
    now = utc_now()

    details["enrichment_id"] = enrichment_id
    details["target_id"] = target_id
    details["confidence"] = confidence
    details["severity_hint"] = severity_hint

    payload = {
        "id": enrichment_id,
        "target_id": target_id,
        "indicator_type": indicator_type,
        "indicator": value,
        "value": value,
        "source": "local",
        "provider": "local",
        "summary": summary,
        "confidence": confidence,
        "severity_hint": severity_hint,
        "details": details,
        "raw": details,
        "created_at": now,
        "timestamp": now,
        "looked_up_at": now,
    }
    return _make_enrichment_result(payload)


def extract_alert_indicators(alert: Alert) -> list[tuple[str, str]]:
    """Extract indicators and useful entities from an alert.

    Inputs:
        alert: Normalized Alert object.

    Outputs:
        Ordered list of unique (indicator_type, value) pairs.
    """

    indicators: list[tuple[str, str]] = []
    _append_indicator(indicators, IOC_TYPE_IP, alert.src_ip)
    _append_indicator(indicators, IOC_TYPE_IP, alert.dst_ip)
    _append_indicator(indicators, IOC_TYPE_HOST, alert.hostname)
    _append_indicator(indicators, IOC_TYPE_USER, alert.user)
    _append_indicator(indicators, IOC_TYPE_COMMAND, alert.command_line)
    _append_indicator(indicators, IOC_TYPE_PROCESS, alert.process_name)

    searchable_values = [alert.rule_name, alert.command_line, alert.process_name]
    searchable_values.extend(str(value) for value in alert.raw.values())
    indicators.extend(extract_iocs_from_text(" ".join(value for value in searchable_values if value)))

    return _dedupe_indicators(indicators)


def extract_candidate_indicators(candidate: IncidentCandidate) -> list[tuple[str, str]]:
    """Extract indicators and useful entities from an incident candidate.

    Inputs:
        candidate: IncidentCandidate object.

    Outputs:
        Ordered list of unique (indicator_type, value) pairs.
    """

    indicators: list[tuple[str, str]] = []
    for src_ip in candidate.src_ips:
        _append_indicator(indicators, IOC_TYPE_IP, src_ip)
    for dst_ip in candidate.dst_ips:
        _append_indicator(indicators, IOC_TYPE_IP, dst_ip)
    _append_indicator(indicators, IOC_TYPE_HOST, candidate.primary_host)
    _append_indicator(indicators, IOC_TYPE_USER, candidate.primary_user)

    for alert in candidate.alerts:
        indicators.extend(extract_alert_indicators(alert))

    return _dedupe_indicators(indicators)


def extract_iocs_from_text(text: str) -> list[tuple[str, str]]:
    """Extract common IOCs from free text.

    Inputs:
        text: Free-form text to scan.

    Outputs:
        Ordered list of unique (indicator_type, value) pairs.
    """

    indicators: list[tuple[str, str]] = []
    if not text:
        return indicators

    for value in URL_RE.findall(text):
        _append_indicator(indicators, IOC_TYPE_URL, value.rstrip(".,;)"))
    for value in EMAIL_RE.findall(text):
        _append_indicator(indicators, IOC_TYPE_EMAIL, value.rstrip(".,;)"))
    for value in IP_RE.findall(text):
        if _is_valid_ip(value):
            _append_indicator(indicators, IOC_TYPE_IP, value)
    for value in HASH_RE.findall(text):
        _append_indicator(indicators, IOC_TYPE_HASH, value.lower())
    for value in DOMAIN_RE.findall(text):
        cleaned = value.rstrip(".,;)").lower()
        if not _looks_like_ip(cleaned) and not _is_common_false_domain(cleaned):
            _append_indicator(indicators, IOC_TYPE_DOMAIN, cleaned)

    return _dedupe_indicators(indicators)


def classify_ip(value: str) -> JsonDict:
    """Classify an IP address using Python's local ipaddress module.

    Inputs:
        value: IP address string.

    Outputs:
        Dictionary containing local classification fields.

    Raises:
        EnrichmentError: If the value is not a valid IP address.
    """

    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EnrichmentError(f"Invalid IP address: {value}") from exc

    return {
        "ip_version": parsed.version,
        "is_private": parsed.is_private,
        "is_global": parsed.is_global,
        "is_loopback": parsed.is_loopback,
        "is_link_local": parsed.is_link_local,
        "is_multicast": parsed.is_multicast,
        "is_reserved": parsed.is_reserved,
        "is_unspecified": parsed.is_unspecified,
        "risk_factors": _ip_risk_factors(parsed),
    }


def _build_local_details(indicator_type: str, value: str) -> JsonDict:
    """Build local enrichment details for one indicator.

    Inputs:
        indicator_type: IOC/entity type.
        value: Indicator value.

    Outputs:
        Dictionary of local enrichment details.
    """

    details: JsonDict = {
        "indicator_type": indicator_type,
        "value": value,
        "provider": "local",
        "looked_up_at": _utc_iso(),
        "risk_factors": [],
    }

    if indicator_type == IOC_TYPE_IP:
        details.update(classify_ip(value))
    elif indicator_type == IOC_TYPE_HASH:
        details["hash_type"] = _hash_type(value)
        details["risk_factors"] = ["hash_observable"]
    elif indicator_type == IOC_TYPE_URL:
        details["risk_factors"] = _url_risk_factors(value)
    elif indicator_type == IOC_TYPE_DOMAIN:
        details["risk_factors"] = _domain_risk_factors(value)
    elif indicator_type == IOC_TYPE_COMMAND:
        details["risk_factors"] = _command_risk_factors(value)
    elif indicator_type == IOC_TYPE_PROCESS:
        details["risk_factors"] = _process_risk_factors(value)
    elif indicator_type in {IOC_TYPE_USER, IOC_TYPE_HOST, IOC_TYPE_EMAIL}:
        details["risk_factors"] = []

    return details


def _build_summary(indicator_type: str, value: str, details: JsonDict) -> str:
    """Build a concise human-readable enrichment summary.

    Inputs:
        indicator_type: IOC/entity type.
        value: Indicator value.
        details: Local enrichment details.

    Outputs:
        Summary string.
    """

    risk_factors = details.get("risk_factors") or []
    if indicator_type == IOC_TYPE_IP:
        if details.get("is_private"):
            return f"Local enrichment: {value} is a private/internal IP address."
        if details.get("is_global"):
            return f"Local enrichment: {value} is a public/global IP address."
        return f"Local enrichment: {value} is a non-global IP address."
    if risk_factors:
        return f"Local enrichment: {indicator_type} {value} has hints: {', '.join(risk_factors)}."
    return f"Local enrichment: observed {indicator_type} {value}."


def _confidence_for_details(details: JsonDict) -> float:
    """Estimate confidence for local enrichment.

    Inputs:
        details: Local enrichment details.

    Outputs:
        Confidence float from 0.0 to 1.0.
    """

    indicator_type = details.get("indicator_type")
    if indicator_type == IOC_TYPE_IP:
        return 0.95
    if indicator_type in {IOC_TYPE_HASH, IOC_TYPE_URL, IOC_TYPE_DOMAIN, IOC_TYPE_EMAIL}:
        return 0.85
    return 0.7


def _severity_hint_for_details(details: JsonDict) -> str:
    """Calculate a local severity hint from risk factors.

    Inputs:
        details: Local enrichment details.

    Outputs:
        Severity hint string: info, low, medium, high, or unknown.
    """

    risk_factors = set(details.get("risk_factors") or [])
    if risk_factors & {"encoded_powershell", "download_cradle", "credential_dumping_hint"}:
        return "high"
    if risk_factors & {"public_ip", "hash_observable", "suspicious_tld", "url_with_ip"}:
        return "medium"
    if risk_factors:
        return "low"
    return "info"


def _make_enrichment_result(payload: JsonDict) -> EnrichmentResult:
    """Create EnrichmentResult while tolerating model field evolution.

    Inputs:
        payload: Candidate field values for EnrichmentResult.

    Outputs:
        EnrichmentResult instance.

    Raises:
        EnrichmentError: If EnrichmentResult is not a dataclass or required
        fields cannot be populated.
    """

    if not is_dataclass(EnrichmentResult):
        raise EnrichmentError("EnrichmentResult must be a dataclass")

    kwargs: JsonDict = {}
    for field in fields(EnrichmentResult):
        if field.name in payload:
            kwargs[field.name] = payload[field.name]
        elif field.name == "ioc_type":
            kwargs[field.name] = payload["indicator_type"]
        elif field.name == "ioc":
            kwargs[field.name] = payload["indicator"]
        elif field.name == "observable_type":
            kwargs[field.name] = payload["indicator_type"]
        elif field.name == "observable":
            kwargs[field.name] = payload["indicator"]
        elif field.name == "reputation":
            kwargs[field.name] = payload["severity_hint"]
        elif field.name == "metadata" or field.name == "data":
            kwargs[field.name] = payload["details"]
        elif field.name == "looked_up_at":
            kwargs[field.name] = payload["looked_up_at"]

    try:
        return EnrichmentResult(**kwargs)
    except TypeError as exc:
        raise EnrichmentError(f"Could not create EnrichmentResult: {exc}") from exc


def _append_indicator(indicators: list[tuple[str, str]], indicator_type: str, value: Any) -> None:
    """Append a non-empty indicator to an indicator list.

    Inputs:
        indicators: List to mutate.
        indicator_type: IOC/entity type.
        value: Candidate value.

    Outputs:
        None.
    """

    if value is None:
        return
    text = str(value).strip()
    if text == "":
        return
    indicators.append((indicator_type, text))


def _dedupe_indicators(indicators: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Deduplicate indicators while preserving first-seen order.

    Inputs:
        indicators: Indicator pairs.

    Outputs:
        Deduplicated indicator pairs.
    """

    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for indicator_type, value in indicators:
        normalized = (indicator_type.lower(), value.strip().lower())
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append((indicator_type.lower(), value.strip()))
    return result


def _ip_risk_factors(ip_value: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
    """Create local risk factors for an IP address.

    Inputs:
        ip_value: Parsed IP address.

    Outputs:
        List of risk factor labels.
    """

    factors: list[str] = []
    if ip_value.is_global:
        factors.append("public_ip")
    if ip_value.is_private:
        factors.append("private_ip")
    if ip_value.is_loopback:
        factors.append("loopback_ip")
    if ip_value.is_link_local:
        factors.append("link_local_ip")
    if ip_value.is_reserved:
        factors.append("reserved_ip")
    return factors


def _url_risk_factors(value: str) -> list[str]:
    """Create local risk factors for a URL.

    Inputs:
        value: URL string.

    Outputs:
        List of risk factor labels.
    """

    lowered = value.lower()
    factors: list[str] = []
    if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", lowered):
        factors.append("url_with_ip")
    if lowered.startswith("http://"):
        factors.append("cleartext_http")
    if any(token in lowered for token in ("/login", "/signin", "/wp-admin", "/admin")):
        factors.append("credential_page_path")
    return factors


def _domain_risk_factors(value: str) -> list[str]:
    """Create local risk factors for a domain.

    Inputs:
        value: Domain string.

    Outputs:
        List of risk factor labels.
    """

    lowered = value.lower()
    factors: list[str] = []
    suspicious_tlds = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk"}
    tld = lowered.rsplit(".", maxsplit=1)[-1]
    if tld in suspicious_tlds:
        factors.append("suspicious_tld")
    if len(lowered) > 60:
        factors.append("long_domain")
    return factors


def _command_risk_factors(value: str) -> list[str]:
    """Create local risk factors for a command line.

    Inputs:
        value: Command-line string.

    Outputs:
        List of risk factor labels.
    """

    lowered = value.lower()
    factors: list[str] = []
    if "powershell" in lowered and any(token in lowered for token in ("-enc", "encodedcommand")):
        factors.append("encoded_powershell")
    if any(token in lowered for token in ("downloadstring", "invoke-webrequest", "curl ", "wget ")):
        factors.append("download_cradle")
    if any(token in lowered for token in ("mimikatz", "sekurlsa", "lsass", "procdump")):
        factors.append("credential_dumping_hint")
    return factors


def _process_risk_factors(value: str) -> list[str]:
    """Create local risk factors for a process name/path.

    Inputs:
        value: Process name or executable path.

    Outputs:
        List of risk factor labels.
    """

    lowered = value.lower()
    factors: list[str] = []
    suspicious_processes = ("powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe")
    if any(process in lowered for process in suspicious_processes):
        factors.append("living_off_the_land_process")
    return factors


def _hash_type(value: str) -> str:
    """Return hash type based on hex digest length.

    Inputs:
        value: Hash string.

    Outputs:
        Hash type label.
    """

    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    return "unknown"


def _build_enrichment_id(indicator_type: str, value: str, target_id: str | None) -> str:
    """Build a stable enrichment ID.

    Inputs:
        indicator_type: IOC/entity type.
        value: Indicator value.
        target_id: Optional source alert or candidate ID.

    Outputs:
        Enrichment ID string.
    """

    raw = f"{target_id or 'global'}:{indicator_type}:{value.lower()}"
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"enrich-{fingerprint}"


def _is_valid_ip(value: str) -> bool:
    """Return True if value is a valid IP address.

    Inputs:
        value: Candidate IP string.

    Outputs:
        Boolean validity flag.
    """

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _looks_like_ip(value: str) -> bool:
    """Return True if a string resembles an IPv4 address.

    Inputs:
        value: Candidate string.

    Outputs:
        Boolean flag.
    """

    return bool(IP_RE.fullmatch(value))


def _is_common_false_domain(value: str) -> bool:
    """Filter common strings that look like domains but are not useful IOCs.

    Inputs:
        value: Candidate domain string.

    Outputs:
        True if the value should be filtered out.
    """

    lowered = value.lower()
    false_values = {"powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"}
    if lowered in false_values:
        return True
    return lowered.endswith(NON_DOMAIN_SUFFIXES)


def _clean_text(value: Any) -> str:
    """Convert a value to stripped text.

    Inputs:
        value: Any value.

    Outputs:
        Stripped string.
    """

    if value is None:
        return ""
    return str(value).strip()


def _utc_iso() -> str:
    """Return the current UTC time as an ISO string.

    Inputs:
        None.

    Outputs:
        UTC ISO timestamp string.
    """

    return datetime.now(UTC).isoformat()