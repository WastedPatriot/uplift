"""Run the checks that match an operating system, and keep going when one cannot."""

from __future__ import annotations

from datetime import UTC, datetime

from uplift.checks import checks_for
from uplift.models import Check, Host, PlannedCheck, Report, Skipped
from uplift.score import sort_findings


def run_assessment(
    host: Host,
    *,
    selected_os: str = "auto",
    dry_run: bool = False,
    now: datetime | None = None,
    checks: list[Check] | None = None,
) -> Report:
    chosen = host.os_name if selected_os == "auto" else selected_os
    checks = checks_for(chosen) if checks is None else checks
    moment = now or datetime.now(UTC)
    report = Report(
        label=host.label,
        os_name=host.os_name,
        selected_os=chosen,
        username=host.username,
        uid=host.uid,
        kernel=None if dry_run else host.kernel(),
        findings=[],
        skipped=[],
        planned=[PlannedCheck(check.id, check.blurb) for check in checks],
        dry_run=dry_run,
        generated_at=moment.strftime("%Y-%m-%d %H:%M UTC"),
    )
    if dry_run:
        return report
    if not checks:
        report.skipped.append(Skipped("os", f"no checks are registered for {chosen}"))
        return report
    for check in checks:
        try:
            outcome = check.run(host)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            report.skipped.append(Skipped(check.id, f"skipped after an unexpected {type(exc).__name__}"))
            continue
        if outcome.skipped is not None:
            report.skipped.append(outcome.skipped)
        report.findings.extend(outcome.findings)
    report.findings = sort_findings(report.findings)
    return report
