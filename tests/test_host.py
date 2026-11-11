import json
from pathlib import Path

import pytest
from tests.conftest import make_host

from uplift.host import SnapshotError, load_snapshot, parse_getcap

FIXTURES = Path(__file__).parent / "fixtures"


def test_implied_directory_listing_and_walk():
    host = make_host(
        files={
            "/usr/bin/find": {"type": "file", "mode": "4755", "uid": 0, "gid": 0},
            "/etc/cron.d/backup": {"type": "file", "mode": "0644", "uid": 0, "gid": 0, "content": ""},
        }
    )
    assert host.list_dir("/usr/bin") == ("find",)
    assert host.list_dir("/etc/cron.d") == ("backup",)
    assert host.list_dir("/usr/bin/find") is None
    walked = [fact.path for fact in host.walk_files(("/usr", "/etc"))]
    assert walked == ["/etc/cron.d/backup", "/usr/bin/find"]


def test_registry_lookup_is_case_insensitive_and_can_be_absent():
    host = make_host(
        os="windows",
        registry={r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer": {"AlwaysInstallElevated": 1}},
    )
    found = host.registry(r"hklm/software/policies/microsoft/windows/installer", "alwaysinstallelevated")
    missing = host.registry(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer", "Other")
    assert found.status == "ok" and found.value == 1
    assert missing.status == "absent"
    bare = make_host(os="windows")
    assert bare.registry("HKLM\\SOFTWARE", "x").status == "unavailable"


def test_windows_directory_listing_uses_backslashes():
    host = make_host(
        os="windows",
        files={
            r"C:\Windows\Panther\Unattend.xml": {"type": "file", "mode": "0644", "uid": 0, "gid": 0},
        },
    )
    assert host.list_dir(r"C:\Windows") == ("Panther",)
    assert host.file(r"c:/windows/panther/unattend.xml") is not None


def test_getcap_parser_allows_spaces_in_the_path():
    parsed = parse_getcap(
        "/usr/bin/ping cap_net_raw=ep\n"
        "/opt/My Tools/python cap_setuid,cap_sys_admin=ep\n"
        "Failed to get capabilities of /root\n"
    )
    assert parsed["/usr/bin/ping"] == ("cap_net_raw",)
    assert parsed["/opt/My Tools/python"] == ("cap_setuid", "cap_sys_admin")


def test_bad_snapshot_is_a_clear_error(tmp_path: Path):
    path = tmp_path / "nope.json"
    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(SnapshotError):
        load_snapshot(path)
    missing = tmp_path / "missing.json"
    with pytest.raises(SnapshotError):
        load_snapshot(missing)


def test_fixture_files_load():
    for name in ("linux_quiet.json", "linux_messy.json", "windows_messy.json"):
        host = load_snapshot(FIXTURES / name)
        assert host.username == "student"
