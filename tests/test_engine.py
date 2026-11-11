from tests.conftest import make_host

from uplift.engine import run_assessment
from uplift.models import Check


def test_a_broken_check_is_skipped_and_the_rest_still_run():
    def boom(_host):
        raise RuntimeError("do not put this on the certificate")

    def fine(_host):
        from uplift.models import Finding, Outcome

        return Outcome(
            [
                Finding(
                    check_id="fine",
                    title="Still here",
                    severity="low",
                    likelihood=2,
                    summary="The other check fell over.",
                    evidence=(),
                    remediation="None.",
                )
            ]
        )

    host = make_host()
    report = run_assessment(
        host,
        checks=[
            Check("boom", "linux", "breaks", boom),
            Check("fine", "linux", "works", fine),
        ],
    )
    assert report.findings[0].title == "Still here"
    assert len(report.skipped) == 1
    assert "RuntimeError" in report.skipped[0].reason
    assert "do not put this" not in report.skipped[0].reason


def test_unknown_os_is_a_skip_not_a_crash():
    host = make_host()
    report = run_assessment(host, selected_os="darwin")
    assert report.findings == []
    assert report.skipped[0].check_id == "os"
