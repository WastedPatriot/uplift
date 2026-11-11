"""Check catalogue."""

from __future__ import annotations

from uplift.checks.linux import linux_checks
from uplift.checks.windows import windows_checks
from uplift.models import Check


def all_checks() -> list[Check]:
    return linux_checks() + windows_checks()


def checks_for(os_name: str) -> list[Check]:
    return [check for check in all_checks() if check.os_name == os_name]
