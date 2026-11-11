"""Windows configuration checks. Registry secrets are detected, then left out of the report."""

from __future__ import annotations

from uplift.catalog import (
    BENIGN_PRIVILEGES,
    INSTALLER_KEY,
    SENSITIVE_PRIVILEGES,
    UNATTEND_PATHS,
    WINLOGON_KEY,
)
from uplift.checks.linux import path_findings
from uplift.models import Check, Finding, Host, Outcome, ServiceFact


def windows_checks() -> list[Check]:
    return [
        Check(
            "always_install_elevated",
            "windows",
            "AlwaysInstallElevated in HKLM and HKCU",
            run_always_install_elevated,
        ),
        Check(
            "services",
            "windows",
            "Unquoted service paths and service binaries marked writable",
            run_services,
        ),
        Check("privileges", "windows", "Sensitive privileges on the current token", run_privileges),
        Check("autologon", "windows", "Winlogon auto-logon, with any password redacted", run_autologon),
        Check(
            "unattend",
            "windows",
            "Leftover unattended-install files, contents not copied",
            run_unattend,
        ),
        Check("path", "windows", "PATH entries that are writable or mean the current directory", run_path),
    ]


def run_always_install_elevated(host: Host) -> Outcome:
    hklm = host.registry(r"HKLM\\" + INSTALLER_KEY, "AlwaysInstallElevated")
    hkcu = host.registry(r"HKCU\\" + INSTALLER_KEY, "AlwaysInstallElevated")
    if hklm.status == "unavailable" or hkcu.status == "unavailable":
        return Outcome.skip("always_install_elevated", "installer policy registry was not available")
    hklm_on = hklm.status == "ok" and _policy_on(hklm.value)
    hkcu_on = hkcu.status == "ok" and _policy_on(hkcu.value)
    if hklm_on and hkcu_on:
        return Outcome(
            [
                Finding(
                    check_id="always_install_elevated",
                    title="AlwaysInstallElevated is set in both hives",
                    severity="high",
                    likelihood=8,
                    summary=(
                        "Both HKLM and HKCU set AlwaysInstallElevated. "
                        "Windows Installer packages can then be installed with elevated rights. "
                        "Disable both values unless a managed deployment design truly needs them."
                    ),
                    evidence=(
                        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated",
                        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated",
                    ),
                    remediation="Set both values to 0, or delete them.",
                )
            ]
        )
    if hklm_on or hkcu_on:
        hive = "HKLM" if hklm_on else "HKCU"
        return Outcome(
            [
                Finding(
                    check_id="always_install_elevated",
                    title=f"AlwaysInstallElevated is set only in {hive}",
                    severity="low",
                    likelihood=2,
                    summary=(
                        "Windows applies this policy only when both HKLM and HKCU are set. "
                        "A stray value is still worth removing so the pair cannot be completed by accident."
                    ),
                    evidence=(f"{hive} AlwaysInstallElevated is enabled",),
                    remediation="Delete the remaining AlwaysInstallElevated value.",
                )
            ]
        )
    return Outcome()


def run_services(host: Host) -> Outcome:
    services = host.services()
    if services is None:
        return Outcome.skip("services", "service list was not available")
    findings: list[Finding] = []
    for service in services:
        if service.binary_writable:
            findings.append(
                Finding(
                    check_id="services",
                    title="Service binary is writable",
                    severity="critical",
                    likelihood=9,
                    summary=(
                        f"Service {service.name} runs {service.image_path}, and this account can write that program. "
                        "Change the access control so only administrators can replace it, "
                        "and confirm it is the vendor copy."
                    ),
                    evidence=_service_evidence(service),
                    remediation="Give the binary an administrator-only ACL and a quoted ImagePath.",
                )
            )
        if _unquoted(service.image_path):
            privileged = _privileged_account(service.account)
            findings.append(
                Finding(
                    check_id="services",
                    title="Unquoted service path",
                    severity="high" if privileged else "medium",
                    likelihood=7 if privileged else 6,
                    summary=(
                        f"Service {service.name} has an ImagePath containing spaces that is not quoted. "
                        "Windows can then treat an earlier path segment as the program. Quote the binary path."
                    ),
                    evidence=_service_evidence(service),
                    remediation="Set ImagePath to the full binary path wrapped in quotes, then arguments.",
                )
            )
    return Outcome(findings)


def _service_evidence(service: ServiceFact) -> tuple[str, ...]:
    rows = [service.name, service.image_path]
    if service.account:
        rows.append(f"account {service.account}")
    if service.start:
        rows.append(f"start {service.start}")
    return tuple(rows)


def _unquoted(image: str) -> bool:
    text = image.strip()
    if not text or text.startswith('"'):
        return False
    lowered = text.lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        index = lowered.find(ext)
        if index != -1:
            return " " in text[:index]
    return " " in text


def _privileged_account(account: str) -> bool:
    text = account.lower().replace(" ", "")
    return text in {"localsystem", "ntauthority\\system", "system"} or text.endswith("\\system")


def run_privileges(host: Host) -> Outcome:
    privileges = host.privileges()
    if privileges is None:
        return Outcome.skip("privileges", "privilege list was not available")
    findings: list[Finding] = []
    for name in privileges:
        if name in BENIGN_PRIVILEGES:
            continue
        if name in SENSITIVE_PRIVILEGES:
            severity, likelihood, summary = SENSITIVE_PRIVILEGES[name]
            findings.append(
                Finding(
                    check_id="privileges",
                    title=name,
                    severity=severity,
                    likelihood=likelihood,
                    summary=summary,
                    evidence=(name, f"account {host.username}"),
                    remediation="Remove the privilege from this account if the lab does not require it.",
                )
            )
        elif name.startswith("Se"):
            findings.append(
                Finding(
                    check_id="privileges",
                    title=name,
                    severity="low",
                    likelihood=3,
                    summary=(
                        f"{name} is present and is not on the short benign list. Review whether this account needs it."
                    ),
                    evidence=(name,),
                    remediation="Drop privileges that are not required for the account's job.",
                )
            )
    return Outcome(findings)


def run_autologon(host: Host) -> Outcome:
    key = r"HKLM\\" + WINLOGON_KEY
    password = host.registry(key, "DefaultPassword")
    auto = host.registry(key, "AutoAdminLogon")
    user = host.registry(key, "DefaultUserName")
    if password.status == "unavailable" and auto.status == "unavailable":
        return Outcome.skip("autologon", "Winlogon registry was not available")
    findings: list[Finding] = []
    if password.status == "ok" and str(password.value).strip():
        username = str(user.value) if user.status == "ok" else ""
        evidence = [r"HKLM\...\Winlogon\DefaultPassword is present (redacted)"]
        if username:
            evidence.append(f"DefaultUserName {username}")
        findings.append(
            Finding(
                check_id="autologon",
                title="Winlogon DefaultPassword is set",
                severity="high",
                likelihood=8,
                summary=(
                    "Automatic logon is storing a password in the registry. The value was not copied into this report."
                ),
                evidence=tuple(evidence),
                remediation=(
                    "Remove DefaultPassword and turn AutoAdminLogon off. Use a managed secret if a service must log on."
                ),
            )
        )
    elif auto.status == "ok" and _policy_on(auto.value):
        findings.append(
            Finding(
                check_id="autologon",
                title="AutoAdminLogon is enabled",
                severity="medium",
                likelihood=5,
                summary="Winlogon AutoAdminLogon is enabled. Confirm a password is not stored alongside it.",
                evidence=(r"HKLM\...\Winlogon\AutoAdminLogon",),
                remediation="Turn AutoAdminLogon off unless the lab image documents why it is on.",
            )
        )
    return Outcome(findings)


def run_unattend(host: Host) -> Outcome:
    if host.os_name != "windows":
        return Outcome.skip("unattend", "not a Windows host, so unattended-install paths were not searched")
    findings: list[Finding] = []
    for path in UNATTEND_PATHS:
        fact = host.file(path)
        if fact is None or fact.kind != "file":
            continue
        findings.append(
            Finding(
                check_id="unattend",
                title="Unattended installation file is present",
                severity="medium",
                likelihood=6,
                summary=(
                    "Files left by Windows setup sometimes contain credentials. "
                    "uplift does not copy their contents. Review the file locally and delete leftover copies."
                ),
                evidence=(fact.path,),
                remediation="Delete leftover unattend files after confirming the deployment no longer needs them.",
            )
        )
    return Outcome(findings)


def run_path(host: Host) -> Outcome:
    return path_findings(host, separator=";")


def _policy_on(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    text = str(value).strip().lower()
    return text in {"1", "0x1", "yes", "true"}
