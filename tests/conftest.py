"""Snapshot builders for tests. Nothing here touches a real root filesystem."""

from __future__ import annotations

from uplift.host import SnapshotHost, snapshot_from_dict


def make_host(**overrides: object) -> SnapshotHost:
    data: dict[str, object] = {
        "label": "fixture",
        "os": "linux",
        "user": {"name": "student", "uid": 1000, "gids": [1000], "groups": ["student"]},
        "env": {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/home/student",
        },
        "kernel": "6.8.0-31-generic",
        "files": {},
    }
    data.update(overrides)
    return snapshot_from_dict(data)
