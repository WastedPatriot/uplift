"""Likelihood labels. The number is a triage hint, not an exploit prediction."""

from __future__ import annotations

from uplift.models import SEVERITIES, Finding

_LABELS = (
    (9, "very high"),
    (7, "high"),
    (4, "moderate"),
    (2, "low"),
    (0, "slight"),
)


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def likelihood_label(score: int) -> str:
    for threshold, label in _LABELS:
        if score >= threshold:
            return label
    return "slight"


def is_interesting(finding: Finding) -> bool:
    return finding.severity != "info"


def meets_threshold(finding: Finding, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    return severity_rank(finding.severity) >= severity_rank(fail_on)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -finding.likelihood,
            -severity_rank(finding.severity),
            finding.title,
            finding.check_id,
        ),
    )
