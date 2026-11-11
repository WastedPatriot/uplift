from uplift.engine import run_assessment
from uplift.host import load_snapshot
from uplift.models import Check, Finding, Outcome
from uplift.report import render_html, render_markdown, render_text

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"


def test_reports_escape_html_and_stay_self_contained():
    host = load_snapshot(FIXTURES / "linux_quiet.json")

    def sneaky(_host):
        return Outcome(
            [
                Finding(
                    check_id="suid_sgid",
                    title="<script>alert(1)</script>",
                    severity="low",
                    likelihood=2,
                    summary='quotes " and <tags>',
                    evidence=("<img src=x onerror=alert(1)>",),
                    remediation="Remove the bit.",
                )
            ]
        )

    report = run_assessment(
        host,
        checks=[Check("suid_sgid", "linux", "sneaky", sneaky)],
    )
    page = render_html(report)
    assert "<style>" in page
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert "http://" not in page
    assert "https://" not in page
    assert "<link" not in page
    text = render_text(report)
    markdown = render_markdown(report)
    assert "<script>alert(1)</script>" in text
    assert "Remove the bit." in markdown


def test_quiet_report_includes_the_empty_lift():
    report = run_assessment(load_snapshot(FIXTURES / "linux_quiet.json"))
    text = render_text(report)
    assert "Nothing interesting was found." in text
    assert "lobby" in text
    assert "Authorised" in text or "authorised" in text.lower()
    assert "Baseline setuid binary" in render_markdown(report)
    assert "Nothing interesting was found." in render_html(report)


def test_dry_run_lists_checks_without_findings():
    report = run_assessment(load_snapshot(FIXTURES / "linux_quiet.json"), dry_run=True)
    text = render_text(report)
    assert "dry run" in text
    assert "suid_sgid" in text
    assert "No checks were executed" in text
    assert report.findings == []
    assert "kernel" in render_html(report)
