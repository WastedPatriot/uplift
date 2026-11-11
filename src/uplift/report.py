"""Text, Markdown, and self-contained HTML reports."""

from __future__ import annotations

import html

from uplift import AUTHORISED_USE, __version__
from uplift.models import Finding, Report, Skipped
from uplift.patter import empty_message
from uplift.score import is_interesting, likelihood_label, severity_rank

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def render_text(report: Report) -> str:
    if report.dry_run:
        return _dry_text(report)
    lines = [
        f"uplift {__version__}",
        AUTHORISED_USE,
        "",
        f"Host        {report.label}",
        f"User        {report.username} (uid {report.uid})",
        f"OS          {report.os_name} (checked {report.selected_os})",
        f"Kernel      {report.kernel or 'unknown'}",
        f"Generated   {report.generated_at}",
        (
            f"Findings    {_interesting_count(report)} interesting, "
            f"{_info_count(report)} info, {_skipped_count(report)} skipped"
        ),
        "",
        (
            "Likelihood is scored from 0 to 10 by how directly the configuration weakens a privilege boundary. "
            "It is a triage hint, not a claim that a particular exploit applies."
        ),
        "",
    ]
    if not any(is_interesting(finding) for finding in report.findings):
        lines.append(empty_message())
        lines.append("")
    if not report.findings:
        lines.append("No notes.")
        lines.append("")
    for finding in report.findings:
        lines.append(_rule())
        lines.extend(_finding_text(finding))
        lines.append("")
    lines.append(_rule())
    lines.append("Skipped")
    if not report.skipped:
        lines.append("  none")
    for skipped in report.skipped:
        lines.append(f"  {skipped.check_id:<24} {skipped.reason}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(report: Report) -> str:
    if report.dry_run:
        return _dry_markdown(report)
    lines = [
        f"# uplift {__version__}",
        "",
        f"_{AUTHORISED_USE}_",
        "",
        f"- Host: `{report.label}`",
        f"- User: `{report.username}` (uid {report.uid})",
        f"- OS: `{report.os_name}` (checked `{report.selected_os}`)",
        f"- Kernel: `{report.kernel or 'unknown'}`",
        f"- Generated: {report.generated_at}",
        (
            f"- Findings: {_interesting_count(report)} interesting, "
            f"{_info_count(report)} info, {_skipped_count(report)} skipped"
        ),
        "",
        (
            "Likelihood runs from 0 to 10 and asks how directly this configuration weakens a privilege boundary. "
            "It does not mean an exploit was attempted, or that one exists."
        ),
        "",
    ]
    if not any(is_interesting(finding) for finding in report.findings):
        lines.append(empty_message().replace("\n", "\n\n"))
        lines.append("")
    counts = _counts(report)
    if any(counts.values()):
        lines.append("## Counts")
        lines.append("")
        for severity in _SEVERITY_ORDER:
            if counts[severity]:
                lines.append(f"- {severity}: {counts[severity]}")
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("No notes.")
        lines.append("")
    for finding in report.findings:
        lines.extend(_finding_markdown(finding))
    lines.append("## Skipped")
    lines.append("")
    if not report.skipped:
        lines.append("None.")
    for skipped in report.skipped:
        lines.append(f"- `{skipped.check_id}` — {skipped.reason}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: Report) -> str:
    if report.dry_run:
        body = _dry_html_body(report)
        title = "uplift dry run"
    else:
        body = _html_body(report)
        title = f"uplift inspection — {report.label}"
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>\n{_CSS}\n</style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        "</body>\n"
        "</html>\n"
    )


def _finding_text(finding: Finding) -> list[str]:
    label = likelihood_label(finding.likelihood)
    lines = [
        finding.title,
        f"severity    {finding.severity}",
        f"likelihood  {finding.likelihood}/10 ({label})",
        f"check       {finding.check_id}",
    ]
    lines.extend(f"  {row}" for row in finding.evidence)
    lines.append(finding.summary)
    lines.append(f"Fix: {finding.remediation}")
    return lines


def _finding_markdown(finding: Finding) -> list[str]:
    label = likelihood_label(finding.likelihood)
    lines = [
        f"### {finding.title}",
        "",
        f"- Severity: **{finding.severity}**",
        f"- Likelihood: **{finding.likelihood}/10** ({label})",
        f"- Check: `{finding.check_id}`",
        "",
        finding.summary,
        "",
        "Evidence:",
        "",
    ]
    for row in finding.evidence:
        lines.append(f"- `{row}`")
    lines.extend(["", f"Fix: {finding.remediation}", ""])
    return lines


def _html_body(report: Report) -> str:
    counts = _counts(report)
    chips = []
    for severity in _SEVERITY_ORDER:
        if counts[severity]:
            chips.append(f'<li class="chip {severity}"><span>{counts[severity]}</span> {_esc(severity)}</li>')
    count_html = f'<ul class="counts">{"".join(chips)}</ul>' if chips else ""
    empty = ""
    if not any(is_interesting(finding) for finding in report.findings):
        empty = f'<p class="empty">{_esc(empty_message())}</p>'
    findings = "\n".join(_finding_html(finding) for finding in report.findings) or "<p>No notes.</p>"
    skipped = _skipped_html(report.skipped)
    kernel = report.kernel or "unknown"
    return f"""
<header>
  <p class="brand">uplift {_esc(__version__)} · inspection certificate</p>
  <h1>{_esc(report.label)}</h1>
  <p class="notice">{_esc(AUTHORISED_USE)}</p>
</header>
<dl class="meta">
  <div><dt>User</dt><dd>{_esc(report.username)} (uid {report.uid})</dd></div>
  <div><dt>OS</dt><dd>{_esc(report.os_name)} · checked {_esc(report.selected_os)}</dd></div>
  <div><dt>Kernel</dt><dd>{_esc(kernel)}</dd></div>
  <div><dt>Generated</dt><dd>{_esc(report.generated_at)}</dd></div>
</dl>
{count_html}
<p class="lede">Likelihood runs from 0 to 10 and asks how directly this configuration
weakens a privilege boundary. It does not mean an exploit was attempted, or that one exists.</p>
{empty}
<section>
  <h2>Findings</h2>
  {findings}
</section>
<section>
  <h2>Skipped</h2>
  {skipped}
</section>
<footer>Certificate for an authorised assessment. Configuration only.</footer>
""".strip()


def _finding_html(finding: Finding) -> str:
    opened = " open" if severity_rank(finding.severity) >= severity_rank("high") else ""
    label = likelihood_label(finding.likelihood)
    evidence = "".join(f"<li>{_esc(row)}</li>" for row in finding.evidence)
    return f"""
<details class="finding {finding.severity}"{opened}>
  <summary>
    <span class="sev">{_esc(finding.severity)}</span>
    <span class="title">{_esc(finding.title)}</span>
    <span class="score">{finding.likelihood}/10 · {_esc(label)}</span>
  </summary>
  <p>{_esc(finding.summary)}</p>
  <p class="check">Check <code>{_esc(finding.check_id)}</code></p>
  <ul class="evidence">{evidence}</ul>
  <p class="fix"><strong>Fix.</strong> {_esc(finding.remediation)}</p>
</details>
""".strip()


def _skipped_html(skipped: list[Skipped]) -> str:
    if not skipped:
        return "<p>None.</p>"
    items = "".join(f"<li><code>{_esc(item.check_id)}</code> — {_esc(item.reason)}</li>" for item in skipped)
    return f"<ul>{items}</ul>"


def _dry_text(report: Report) -> str:
    lines = [
        f"uplift {__version__} dry run",
        AUTHORISED_USE,
        "",
        f"Host        {report.label}",
        f"OS          {report.os_name} (would check {report.selected_os})",
        f"Checks      {len(report.planned)}",
        "",
        "No checks were executed and no report file was written.",
        "",
    ]
    if not report.planned:
        lines.append(f"No checks are registered for {report.selected_os}.")
    for planned in report.planned:
        lines.append(f"  {planned.id:<24} {planned.blurb}")
    lines.append("")
    return "\n".join(lines)


def _dry_markdown(report: Report) -> str:
    lines = [
        f"# uplift {__version__} dry run",
        "",
        f"_{AUTHORISED_USE}_",
        "",
        f"- Host: `{report.label}`",
        f"- OS: `{report.os_name}` (would check `{report.selected_os}`)",
        "",
        "No checks were executed and no report file was written.",
        "",
    ]
    for planned in report.planned:
        lines.append(f"- `{planned.id}` — {planned.blurb}")
    if not report.planned:
        lines.append(f"No checks are registered for `{report.selected_os}`.")
    lines.append("")
    return "\n".join(lines)


def _dry_html_body(report: Report) -> str:
    items = "".join(f"<li><code>{_esc(planned.id)}</code> — {_esc(planned.blurb)}</li>" for planned in report.planned)
    if not items:
        items = f"<li>No checks are registered for {_esc(report.selected_os)}.</li>"
    return f"""
<header>
  <p class="brand">uplift {_esc(__version__)} · dry run</p>
  <h1>{_esc(report.label)}</h1>
  <p class="notice">{_esc(AUTHORISED_USE)}</p>
</header>
<p class="lede">No checks were executed and no report file was written.
OS {_esc(report.os_name)}, would check {_esc(report.selected_os)}.</p>
<ul>{items}</ul>
<footer>The lift did not leave the lobby.</footer>
""".strip()


def _counts(report: Report) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in report.findings:
        counts[finding.severity] += 1
    return counts


def _interesting_count(report: Report) -> int:
    return sum(1 for finding in report.findings if is_interesting(finding))


def _info_count(report: Report) -> int:
    return sum(1 for finding in report.findings if finding.severity == "info")


def _skipped_count(report: Report) -> int:
    return len(report.skipped)


def _rule() -> str:
    return "-" * 72


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


_CSS = """
:root {
  --ink: #1c1915;
  --muted: #5e584e;
  --paper: #f3efe4;
  --card: #fffdf8;
  --rule: #d9d0c1;
  --critical: #8c2f2b;
  --high: #9a5316;
  --medium: #8a6d12;
  --low: #2f6f4e;
  --info: #5c6570;
}
* { box-sizing: border-box; }
body {
  margin: 0 auto;
  max-width: 52rem;
  padding: 2.5rem 1.25rem 4rem;
  background: var(--paper);
  color: var(--ink);
  font: 18px/1.5 "Iowan Old Style", Palatino, "Palatino Linotype", Georgia, serif;
}
header { border-bottom: 1px solid var(--ink); padding-bottom: 1rem; margin-bottom: 1.25rem; }
.brand {
  margin: 0;
  font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
  font-size: 0.78rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
h1 { font-size: 2.4rem; line-height: 1.1; margin: 0.35rem 0; font-weight: 600; }
h2 { font-size: 1.2rem; margin: 2rem 0 0.75rem; }
.notice, .lede, footer { color: var(--muted); }
.notice { margin: 0.4rem 0 0; }
dl.meta { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem 1.5rem; margin: 0 0 1.25rem; }
dl.meta div { border-top: 1px solid var(--rule); padding-top: 0.35rem; }
dt {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 0.72rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--muted);
}
dd { margin: 0.15rem 0 0; }
.counts { display: flex; flex-wrap: wrap; gap: 0.5rem; padding: 0; list-style: none; }
.chip { border: 1px solid var(--rule); background: var(--card); padding: 0.35rem 0.6rem; }
.chip span { font-weight: 700; margin-right: 0.35rem; }
.chip.critical span { color: var(--critical); }
.chip.high span { color: var(--high); }
.chip.medium span { color: var(--medium); }
.chip.low span { color: var(--low); }
.chip.info span { color: var(--info); }
.empty { background: var(--card); border-left: 4px solid var(--ink); padding: 0.8rem 1rem; white-space: pre-wrap; }
details.finding {
  background: var(--card);
  border: 1px solid var(--rule);
  border-left-width: 4px;
  margin: 0.7rem 0;
  padding: 0.35rem 0.9rem 0.2rem;
}
details.critical { border-left-color: var(--critical); }
details.high { border-left-color: var(--high); }
details.medium { border-left-color: var(--medium); }
details.low { border-left-color: var(--low); }
details.info { border-left-color: var(--info); }
summary {
  cursor: pointer;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 0.8rem;
  align-items: baseline;
  padding: 0.45rem 0;
}
.sev {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 0.72rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.title { font-weight: 650; }
.score { margin-left: auto; color: var(--muted); font-family: ui-monospace, Consolas, monospace; font-size: 0.85rem; }
.evidence {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 0.86rem;
  background: #f6f1e6;
  padding: 0.6rem 0.8rem 0.6rem 1.6rem;
}
.fix { margin-top: 0.2rem; }
.check { color: var(--muted); }
footer { margin-top: 2.5rem; border-top: 1px solid var(--rule); padding-top: 0.8rem; font-size: 0.95rem; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 0.9em; }
@media (max-width: 640px) {
  body { padding-top: 1.4rem; }
  dl.meta { grid-template-columns: 1fr; }
  h1 { font-size: 1.9rem; }
  .score { margin-left: 0; }
}
@media print {
  body { background: white; }
  details.finding { break-inside: avoid; }
}
"""
