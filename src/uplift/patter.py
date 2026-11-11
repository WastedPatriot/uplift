"""Short bits of copy. The lift has opinions. The checks do not."""

from __future__ import annotations

from uplift.models import Finding
from uplift.score import is_interesting


def empty_message() -> str:
    return (
        "Nothing interesting was found.\n"
        "The lift is back at the lobby, empty, with a small poster about authorised use. "
        "Either this host is tidy, or the interesting bit is wearing a vendor signature and a straight face."
    )


def elevator_script(*, dry_run: bool, os_name: str, findings: list[Finding]) -> str:
    if dry_run:
        return "\n".join(
            [
                "[lift] Dry run. Doors open, car empty, nobody has pressed a floor.",
                f"[lift] The board says {os_name}. The host will not be touched.",
            ]
        )
    if os_name == "windows":
        middle = "[lift] One: services, tokens, installer policy. Please have your badge ready."
    else:
        middle = "[lift] One: setuid, capabilities, cron, sudo, PATH. Please have your badge ready."
    interesting = sum(1 for finding in findings if is_interesting(finding))
    if interesting == 0:
        top = "[lift] Top. Nothing in the shaft but dust. Ding."
    else:
        noun = "item" if interesting == 1 else "items"
        top = f"[lift] Top. {interesting} {noun} in the car. Ding. Please mind the gap."
    return "\n".join(
        [
            "[lift] Doors closing.",
            "[lift] Ground: modes, policies, and other things people leave on the floor.",
            middle,
            "[lift] Two: mind the gap between this account and a better one.",
            top,
        ]
    )
