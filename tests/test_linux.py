from tests.conftest import make_host

from uplift.checks.linux import (
    run_capabilities,
    run_cron,
    run_kernel,
    run_path,
    run_sensitive_files,
    run_sudo,
    run_suid,
)
from uplift.engine import run_assessment
from uplift.host import load_snapshot
from uplift.score import is_interesting

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"


def _titles(outcome):
    return [finding.title for finding in outcome.findings]


def test_suid_baseline_sensitive_and_writable():
    host = make_host(
        files={
            "/usr/bin/sudo": {"type": "file", "mode": "4755", "uid": 0, "gid": 0},
            "/usr/bin/find": {"type": "file", "mode": "4755", "uid": 0, "gid": 0},
            "/usr/bin/python3.11": {"type": "file", "mode": "6755", "uid": 1000, "gid": 1000},
            "/opt/custom": {"type": "file", "mode": "4755", "uid": 0, "gid": 0},
            "/tmp/owned": {"type": "file", "mode": "4755", "uid": 0, "gid": 0, "writable": True},
        }
    )
    by_path = {finding.evidence[0]: finding for finding in run_suid(host).findings}
    assert by_path["/usr/bin/sudo"].severity == "info"
    assert by_path["/usr/bin/find"].severity == "high"
    assert "program that runs other programs" in by_path["/usr/bin/find"].title
    assert by_path["/usr/bin/python3.11"].severity == "critical"
    assert by_path["/opt/custom"].severity == "medium"
    assert by_path["/tmp/owned"].severity == "critical"
    assert by_path["/tmp/owned"].likelihood == 9


def test_capabilities_rank_setuid_and_leave_ping_alone():
    host = make_host(
        files={
            "/usr/bin/python3.11": {
                "type": "file",
                "mode": "0755",
                "uid": 0,
                "gid": 0,
                "capabilities": ["cap_setuid=ep"],
            },
            "/usr/bin/ping": {"type": "file", "mode": "0755", "uid": 0, "gid": 0, "capabilities": ["cap_net_raw=ep"]},
        }
    )
    findings = {finding.evidence[0]: finding for finding in run_capabilities(host).findings}
    assert findings["/usr/bin/python3.11"].severity == "critical"
    assert findings["/usr/bin/ping"].severity == "info"
    assert run_capabilities(make_host()).skipped is not None


def test_passwd_shadow_and_preload_do_not_leak_secrets():
    host = make_host(
        files={
            "/etc/passwd": {
                "type": "file",
                "mode": "0666",
                "uid": 0,
                "gid": 0,
                "content": (
                    "root:x:0:0::/root:/bin/bash\n"
                    "blank::1001:1001::/home/blank:/bin/sh\n"
                    "hashed:$6$SECRET_HASH_VALUE:1002:1002::/home/hashed:/bin/sh\n"
                    "toor:x:0:0::/root:/bin/bash\n"
                ),
            },
            "/etc/shadow": {
                "type": "file",
                "mode": "0644",
                "uid": 0,
                "gid": 0,
                "content": "root:$6$SECRET_HASH_VALUE:1::::::\n",
            },
            "/etc/ld.so.preload": {
                "type": "file",
                "mode": "0644",
                "uid": 0,
                "gid": 0,
                "content": "/opt/libs/EVIL_LIB_PATH.so\n",
            },
        }
    )
    outcome = run_sensitive_files(host)
    blob = "\n".join(finding.summary + "\n" + "\n".join(finding.evidence) for finding in outcome.findings)
    assert "SECRET_HASH_VALUE" not in blob
    assert "EVIL_LIB_PATH" not in blob
    titles = _titles(outcome)
    assert "Writable sensitive file" in titles
    assert "Shadow file is exposed" in titles
    assert "Empty password field in passwd" in titles
    assert "Password hash stored in passwd" in titles
    assert "Extra account with uid 0" in titles
    assert "Loader preload file is non-empty" in titles


def test_cron_writable_script_relative_path_and_missing_locations():
    host = make_host(
        files={
            "/etc/crontab": {
                "type": "file",
                "mode": "0644",
                "uid": 0,
                "gid": 0,
                "content": "*/5 * * * * root scripts/backup.sh\n",
            },
            "/etc/cron.d": {"type": "dir", "mode": "0755", "uid": 0, "gid": 0},
            "/etc/cron.d/backup": {
                "type": "file",
                "mode": "0644",
                "uid": 0,
                "gid": 0,
                "content": "*/15 * * * * root /opt/scripts/backup.sh\n",
            },
            "/opt/scripts/backup.sh": {"type": "file", "mode": "0666", "uid": 0, "gid": 0, "content": "#!/bin/sh\n"},
            "/etc/cron.hourly/tidy": {"type": "file", "mode": "0777", "uid": 0, "gid": 0, "content": "#!/bin/sh\n"},
        }
    )
    titles = _titles(run_cron(host))
    assert titles.count("Cron job runs a writable program") == 1
    assert "Cron job uses a relative path" in titles
    assert "Cron script is writable" in titles
    assert run_cron(make_host()).skipped is not None
    assert "not present" in run_cron(make_host()).skipped.reason


def test_sudo_nopasswd_env_keep_and_unreadable():
    wide = make_host(
        user={"name": "student", "uid": 1000, "gids": [27], "groups": ["student", "sudo"]},
        sudo_l="",
        files={
            "/etc/sudoers": {
                "type": "file",
                "mode": "0440",
                "uid": 0,
                "gid": 0,
                "content": "\n".join(
                    [
                        "root ALL=(ALL:ALL) ALL",
                        'Defaults env_keep += "LD_PRELOAD SSH_AUTH_SOCK"',
                        "%sudo ALL=(ALL:ALL) ALL",
                        "student ALL=(ALL) NOPASSWD: ALL",
                    ]
                ),
            }
        },
    )
    titles = _titles(run_sudo(wide))
    assert "Passwordless sudo for every command" in titles
    assert "Broad sudo rule" in titles
    assert "Sudo preserves a sensitive environment variable" in titles
    assert all("root ALL" not in row for finding in run_sudo(wide).findings for row in finding.evidence)

    hidden = make_host(files={"/etc/sudoers": {"type": "file", "mode": "0440", "uid": 0, "gid": 0}})
    assert run_sudo(hidden).skipped is not None
    assert run_sudo(make_host()).skipped is not None


def test_path_and_kernel():
    dotted_files = {
        "/home/student/bin": {"type": "dir", "mode": "0755", "uid": 1000, "gid": 1000},
        "/usr/bin": {"type": "dir", "mode": "0755", "uid": 0, "gid": 0},
    }
    host = make_host(env={"PATH": "/home/student/bin::/usr/bin:."}, files=dotted_files)
    titles = _titles(run_path(host))
    assert titles.count("PATH includes the current directory") == 2
    assert "Writable directory on PATH" in titles
    assert run_path(make_host(env={})).skipped is not None

    old = run_kernel(make_host(kernel="4.15.0-20-generic"))
    assert old.findings[0].severity == "low"
    assert "exploit" in old.findings[0].summary
    assert run_kernel(make_host(kernel="6.8.0-31-generic")).findings == []
    assert run_kernel(make_host(kernel=None)).skipped is not None
    odd = run_kernel(make_host(kernel="not-a-version"))
    assert odd.findings[0].severity == "info"


def test_quiet_fixture_has_nothing_interesting_and_skips_cleanly():
    report = run_assessment(load_snapshot(FIXTURES / "linux_quiet.json"))
    assert not any(is_interesting(finding) for finding in report.findings)
    skipped = {item.check_id for item in report.skipped}
    assert {"capabilities", "cron", "sudo"} <= skipped
    assert any(finding.title.startswith("Baseline") for finding in report.findings)


def test_messy_fixture_scores_the_lab_and_redacts():
    report = run_assessment(load_snapshot(FIXTURES / "linux_messy.json"))
    blob = "\n".join(finding.title + finding.summary + "\n".join(finding.evidence) for finding in report.findings)
    assert "SECRET_HASH_VALUE" not in blob
    assert "EVIL_LIB_PATH" not in blob
    assert any(finding.severity == "critical" for finding in report.findings)
    assert [finding.likelihood for finding in report.findings] == sorted(
        (finding.likelihood for finding in report.findings),
        reverse=True,
    )
    ids = {finding.check_id for finding in report.findings}
    assert {"suid_sgid", "capabilities", "sensitive_files", "cron", "sudo", "path", "kernel"} <= ids
