from tests.conftest import make_host

from uplift.access import can_replace, parent_path, parse_mode, user_can_write


def test_parse_mode_accepts_octal_strings():
    assert parse_mode("4755") == 0o4755
    assert parse_mode("0o644") == 0o644
    assert parse_mode(493) == 493


def test_write_access_respects_owner_group_and_world():
    host = make_host()
    owned = make_host(files={"/home/student/note": {"type": "file", "mode": "0644", "uid": 1000, "gid": 1000}}).file(
        "/home/student/note"
    )
    group = make_host(
        user={"name": "student", "uid": 1000, "gids": [1000], "groups": ["student"]},
        files={"/var/tmp/job": {"type": "file", "mode": "0664", "uid": 0, "gid": 1000}},
    ).file("/var/tmp/job")
    closed = make_host(files={"/etc/shadow": {"type": "file", "mode": "0640", "uid": 0, "gid": 42}}).file("/etc/shadow")
    assert owned is not None and user_can_write(host, owned)
    assert group is not None and user_can_write(host, group)
    assert closed is not None and not user_can_write(host, closed)


def test_sticky_directory_does_not_let_you_replace_someone_elses_file():
    host = make_host(
        files={
            "/tmp": {"type": "dir", "mode": "1777", "uid": 0, "gid": 0},
            "/tmp/root-owned": {"type": "file", "mode": "0644", "uid": 0, "gid": 0},
            "/tmp/mine": {"type": "file", "mode": "0644", "uid": 1000, "gid": 1000},
            "/opt/scripts": {"type": "dir", "mode": "0777", "uid": 0, "gid": 0},
            "/opt/scripts/backup.sh": {"type": "file", "mode": "0755", "uid": 0, "gid": 0},
        }
    )
    assert not can_replace(host, "/tmp/root-owned")
    assert can_replace(host, "/tmp/mine")
    assert can_replace(host, "/opt/scripts/backup.sh")


def test_symlink_mode_is_not_write_access():
    host = make_host(
        files={
            "/etc/cron.daily": {"type": "dir", "mode": "0755", "uid": 0, "gid": 0},
            "/etc/cron.daily/google-chrome": {"type": "symlink", "mode": "0777", "uid": 0, "gid": 0},
        }
    )
    assert not can_replace(host, "/etc/cron.daily/google-chrome")


def test_parent_path_for_both_styles():
    assert parent_path("/opt/scripts/backup.sh") == "/opt/scripts"
    assert parent_path("/") == "/"
    assert parent_path(r"C:\Program Files\Vuln Agent\agent.exe") == r"C:\Program Files\Vuln Agent"
    assert parent_path(r"C:\Windows") == "C:"
