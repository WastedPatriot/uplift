"""Mode-bit questions. Windows facts can set an explicit writable flag."""

from __future__ import annotations

import re

from uplift.models import FileFact, Host

S_ISUID = 0o4000
S_ISGID = 0o2000
S_ISVTX = 0o1000


def parse_mode(value: object) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"mode must be an octal string, not {value!r}")
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text.startswith("0o"):
        text = text[2:]
    return int(text, 8)


def is_setuid(mode: int) -> bool:
    return bool(mode & S_ISUID)


def is_setgid(mode: int) -> bool:
    return bool(mode & S_ISGID)


def is_sticky(mode: int) -> bool:
    return bool(mode & S_ISVTX)


def mode_text(mode: int) -> str:
    bits = mode & 0o7777
    labels: list[str] = []
    if is_setuid(mode):
        labels.append("setuid")
    if is_setgid(mode):
        labels.append("setgid")
    if is_sticky(mode):
        labels.append("sticky")
    suffix = f" ({', '.join(labels)})" if labels else ""
    return f"{bits:04o}{suffix}"


def world_writable(fact: FileFact) -> bool:
    return bool(fact.mode & 0o002)


def world_readable(fact: FileFact) -> bool:
    return bool(fact.mode & 0o004)


def user_can_write(host: Host, fact: FileFact) -> bool:
    """Whether this account could write the path. Root is treated as already able.

    Symlink mode is typically 0777 and does not describe the target. Ignore it
    unless the snapshot set an explicit writable flag.
    """

    if fact.kind == "symlink" and fact.writable is None:
        return False
    if fact.writable is not None:
        return fact.writable
    if host.os_name == "windows":
        return False
    if host.uid == 0:
        return True
    if fact.uid == host.uid and fact.mode & 0o200:
        return True
    if fact.gid in host.gids and fact.mode & 0o020:
        return True
    return bool(fact.mode & 0o002)


def user_can_read(host: Host, fact: FileFact) -> bool:
    if fact.readable is not None:
        return fact.readable
    if host.os_name == "windows":
        return fact.content is not None
    if host.uid == 0:
        return True
    if fact.uid == host.uid and fact.mode & 0o400:
        return True
    if fact.gid in host.gids and fact.mode & 0o040:
        return True
    return bool(fact.mode & 0o004)


def caller_can_write(host: Host, fact: FileFact) -> bool:
    """Write access that is interesting for a non-root caller."""

    if host.uid == 0 and host.os_name != "windows":
        return world_writable(fact)
    return user_can_write(host, fact)


def parent_path(path: str) -> str:
    if "\\" in path and "/" not in path:
        trimmed = path.rstrip("\\")
        if re.fullmatch(r"[A-Za-z]:\\", path) or "\\" not in trimmed:
            return trimmed
        return trimmed.rsplit("\\", 1)[0]
    if path == "/":
        return "/"
    trimmed = path.rstrip("/")
    if "/" not in trimmed:
        return "/"
    parent = trimmed.rsplit("/", 1)[0]
    return parent or "/"


def can_replace(host: Host, path: str) -> bool:
    """True when this account can alter the file, or replace it via the parent directory.

    A sticky parent only allows replacement of files this account owns. Root's ordinary
    write access is ignored; world-writable modes still count.
    """

    fact = host.file(path)
    if fact is not None and fact.kind == "symlink":
        fact = host.follow(path)
    if fact is not None and caller_can_write(host, fact):
        return True
    parent = host.file(parent_path(path))
    if parent is None or parent.kind != "dir" or not caller_can_write(host, parent):
        return False
    if is_sticky(parent.mode):
        if fact is None:
            return host.uid != 0
        return fact.uid == host.uid and host.uid != 0
    return True
