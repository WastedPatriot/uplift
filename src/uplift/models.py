"""Shared records for checks and reports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: str
    likelihood: int
    summary: str
    evidence: tuple[str, ...]
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")
        if not 0 <= self.likelihood <= 10:
            raise ValueError(f"likelihood out of range: {self.likelihood}")


@dataclass(frozen=True)
class Skipped:
    check_id: str
    reason: str


@dataclass
class Outcome:
    findings: list[Finding] = field(default_factory=list)
    skipped: Skipped | None = None

    @classmethod
    def skip(cls, check_id: str, reason: str) -> Outcome:
        return cls(skipped=Skipped(check_id, reason))


@dataclass(frozen=True)
class FileFact:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    content: str | None = None
    capabilities: tuple[str, ...] | None = None
    writable: bool | None = None
    readable: bool | None = None
    size: int | None = None

    @property
    def content_length(self) -> int | None:
        if self.content is not None:
            return len(self.content)
        return self.size


@dataclass(frozen=True)
class ServiceFact:
    name: str
    image_path: str
    account: str = ""
    start: str = ""
    binary_writable: bool | None = None


@dataclass(frozen=True)
class RegResult:
    status: str
    value: Any = None

    @property
    def available(self) -> bool:
        return self.status != "unavailable"


@dataclass(frozen=True)
class PlannedCheck:
    id: str
    blurb: str


@dataclass(frozen=True)
class Check:
    id: str
    os_name: str
    blurb: str
    run: Callable[[Host], Outcome]


@dataclass
class Report:
    label: str
    os_name: str
    selected_os: str
    username: str
    uid: int
    kernel: str | None
    findings: list[Finding]
    skipped: list[Skipped]
    planned: list[PlannedCheck]
    dry_run: bool
    generated_at: str


class Host:
    """Filesystem, registry, and identity surface a check is allowed to use."""

    label: str
    os_name: str
    username: str
    uid: int
    gids: tuple[int, ...]
    groups: tuple[str, ...]

    def file(self, path: str) -> FileFact | None:
        raise NotImplementedError

    def list_dir(self, path: str) -> tuple[str, ...] | None:
        raise NotImplementedError

    def read_text(self, path: str, max_bytes: int = 1_000_000) -> str | None:
        raise NotImplementedError

    def walk_files(self, roots: tuple[str, ...], *, max_files: int = 20_000) -> list[FileFact]:
        raise NotImplementedError

    def env(self, key: str) -> str | None:
        raise NotImplementedError

    def kernel(self) -> str | None:
        raise NotImplementedError

    def sudo_l(self) -> str | None:
        raise NotImplementedError

    def capability_map(self) -> dict[str, tuple[str, ...]] | None:
        raise NotImplementedError

    def registry(self, key: str, name: str) -> RegResult:
        raise NotImplementedError

    def services(self) -> tuple[ServiceFact, ...] | None:
        raise NotImplementedError

    def privileges(self) -> tuple[str, ...] | None:
        raise NotImplementedError

    def realpath(self, path: str) -> str:
        """Canonical path. Snapshots have no link targets, so this is the path itself."""

        return path

    def follow(self, path: str) -> FileFact | None:
        """The file a symlink points at. Unknown targets are not treated as writable."""

        fact = self.file(path)
        if fact is None or fact.kind == "symlink":
            return None
        return fact
