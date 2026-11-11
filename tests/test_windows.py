from tests.conftest import make_host

from uplift.checks.windows import (
    run_always_install_elevated,
    run_autologon,
    run_privileges,
    run_services,
    run_unattend,
)
from uplift.engine import run_assessment
from uplift.host import load_snapshot

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"


def test_always_install_elevated_needs_both_hives():
    both = make_host(
        os="windows",
        registry={
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer": {"AlwaysInstallElevated": 1},
            r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer": {"AlwaysInstallElevated": "1"},
        },
    )
    one = make_host(
        os="windows",
        registry={
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer": {"AlwaysInstallElevated": 1},
        },
    )
    empty = make_host(os="windows", registry={})
    missing = make_host(os="windows")
    assert run_always_install_elevated(both).findings[0].severity == "high"
    assert run_always_install_elevated(one).findings[0].severity == "low"
    assert run_always_install_elevated(empty).findings == []
    assert run_always_install_elevated(missing).skipped is not None


def test_services_unquoted_and_writable_ignore_quoted_svchost():
    host = make_host(
        os="windows",
        services=[
            {
                "name": "VulnAgent",
                "image_path": r"C:\Program Files\Vuln Agent\agent.exe",
                "account": "LocalSystem",
                "binary_writable": False,
            },
            {
                "name": "Helper",
                "image_path": r'"C:\Program Files\Helper\helper.exe"',
                "account": r"NT AUTHORITY\SYSTEM",
                "binary_writable": True,
            },
            {
                "name": "Spooler",
                "image_path": r"C:\Windows\System32\svchost.exe -k netsvcs",
                "account": r"NT AUTHORITY\NetworkService",
            },
        ],
    )
    findings = run_services(host).findings
    titles = [(finding.title, finding.evidence[0]) for finding in findings]
    assert ("Unquoted service path", "VulnAgent") in titles
    assert ("Service binary is writable", "Helper") in titles
    assert all("Spooler" not in evidence for _title, evidence in titles)
    unquoted = next(finding for finding in findings if finding.evidence[0] == "VulnAgent")
    assert unquoted.severity == "high"
    assert run_services(make_host(os="windows")).skipped is not None


def test_privileges_ignore_the_ordinary_ones():
    host = make_host(
        os="windows",
        privileges=["SeChangeNotifyPrivilege", "SeDebugPrivilege", "SeTcbPrivilege", "SeMysteryPrivilege"],
    )
    by_title = {finding.title: finding for finding in run_privileges(host).findings}
    assert "SeChangeNotifyPrivilege" not in by_title
    assert by_title["SeDebugPrivilege"].severity == "high"
    assert by_title["SeTcbPrivilege"].severity == "critical"
    assert by_title["SeMysteryPrivilege"].severity == "low"
    assert run_privileges(make_host(os="windows", privileges=[])).findings == []
    assert run_privileges(make_host(os="windows")).skipped is not None


def test_autologon_redacts_the_password_and_unattend_is_presence_only():
    host = load_snapshot(FIXTURES / "windows_messy.json")
    report = run_assessment(host)
    rendered = "\n".join(finding.title + finding.summary + "\n".join(finding.evidence) for finding in report.findings)
    assert "LabPassword!" not in rendered
    assert "<Password>" not in rendered
    assert any(finding.title == "Winlogon DefaultPassword is set" for finding in report.findings)
    assert any(finding.check_id == "unattend" for finding in report.findings)
    assert any("redacted" in row for finding in report.findings for row in finding.evidence)

    auto_only = make_host(
        os="windows",
        registry={r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": {"AutoAdminLogon": 1}},
    )
    assert run_autologon(auto_only).findings[0].title == "AutoAdminLogon is enabled"
    linux = make_host(files={r"C:\Windows\Panther\Unattend.xml": {"type": "file", "mode": "0644", "uid": 0, "gid": 0}})
    assert run_unattend(linux).skipped is not None
