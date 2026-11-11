"""Linux configuration checks. Findings describe impact and a fix, not a method."""

from __future__ import annotations

import re
from dataclasses import replace

from uplift.access import (
    caller_can_write,
    can_replace,
    is_setgid,
    is_setuid,
    mode_text,
    user_can_read,
    world_readable,
)
from uplift.catalog import (
    BASELINE_SUID,
    BENIGN_CAP_FILES,
    DANGEROUS_CAPABILITIES,
    DANGEROUS_ENV,
    KERNEL_FLOOR,
    SUID_ROOTS,
    sensitive_program,
)
from uplift.models import Check, FileFact, Finding, Host, Outcome

_CRON_FILES = ("/etc/crontab",)
_CRON_DIRS = ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs")
_CRON_SCRIPT_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")
_SUDO_FILES = ("/etc/sudoers",)
_SUDO_DIRS = ("/etc/sudoers.d",)


def linux_checks() -> list[Check]:
    return [
        Check("suid_sgid", "linux", "Setuid and setgid files, measured against a short baseline", run_suid),
        Check(
            "capabilities",
            "linux",
            "File capabilities that can cross a privilege boundary",
            run_capabilities,
        ),
        Check(
            "sensitive_files",
            "linux",
            "Modes on passwd, shadow, sudoers, and the loader preload file",
            run_sensitive_files,
        ),
        Check("cron", "linux", "Cron tables and whether the jobs they run are writable", run_cron),
        Check("sudo", "linux", "Sudoers and optional sudo -l text, when it is available", run_sudo),
        Check("path", "linux", "PATH entries that are writable or mean the current directory", run_path),
        Check(
            "kernel",
            "linux",
            "Kernel series against a coarse age floor, not an exploit list",
            run_kernel,
        ),
    ]


def run_suid(host: Host) -> Outcome:
    findings: list[Finding] = []
    seen: set[str] = set()
    for fact in host.walk_files(SUID_ROOTS):
        suid = is_setuid(fact.mode)
        sgid = is_setgid(fact.mode)
        if not suid and not sgid:
            continue
        real = host.realpath(fact.path)
        if real in seen:
            continue
        seen.add(real)
        if real != fact.path:
            fact = replace(fact, path=real)
        findings.append(_suid_finding(host, fact, suid, sgid))
    return Outcome(findings)


def _suid_finding(host: Host, fact: FileFact, suid: bool, sgid: bool) -> Finding:
    base = fact.path.rsplit("/", 1)[-1]
    category = sensitive_program(base)
    writable = caller_can_write(host, fact)
    bits = "setuid and setgid" if suid and sgid else "setuid" if suid else "setgid"
    evidence = (fact.path, f"mode {mode_text(fact.mode)}", f"owner uid {fact.uid} gid {fact.gid}")
    if writable and host.uid != 0:
        return Finding(
            check_id="suid_sgid",
            title=f"Writable {bits} file",
            severity="critical",
            likelihood=9,
            summary=(
                f"{fact.path} is {bits} and this account can write it. "
                "A privileged file that an unprivileged account can change no longer protects that boundary."
            ),
            evidence=evidence,
            remediation="Restore a root-owned mode such as 0755, and remove setuid if the program does not need it.",
        )
    if category and (fact.uid == 0 or (sgid and fact.gid == 0)) and (suid or sgid):
        severity, likelihood, phrase = category
        if sgid and not suid:
            likelihood = max(6, likelihood - 1)
            severity = "high"
        article = "an" if phrase[0] in "aeiou" else "a"
        return Finding(
            check_id="suid_sgid",
            title=f"{bits.capitalize()} {phrase}",
            severity=severity,
            likelihood=likelihood,
            summary=(
                f"{fact.path} is {article} {phrase} and is marked {bits}. "
                "Programs in this class can run other programs or write files, so the extra bit "
                "crosses a privilege boundary. Confirm a vendor package still requires it."
            ),
            evidence=evidence,
            remediation=(
                "Remove the setuid or setgid bit unless the distribution package requires it, "
                "and keep the file root-owned."
            ),
        )
    if fact.path in BASELINE_SUID:
        return Finding(
            check_id="suid_sgid",
            title=f"Baseline {bits} binary",
            severity="info",
            likelihood=1,
            summary=(
                f"{fact.path} is on the short baseline of common distro {bits} programs. "
                "It is recorded so the inventory is complete."
            ),
            evidence=evidence,
            remediation=(
                "Leave it in place if the package still owns that mode. Revisit it after distribution upgrades."
            ),
        )
    owned_by_root = fact.uid == 0 if suid else fact.gid == 0
    return Finding(
        check_id="suid_sgid",
        title=f"Unexpected {bits} file",
        severity="medium" if owned_by_root else "low",
        likelihood=5 if owned_by_root else 3,
        summary=(
            f"{fact.path} is {bits} and is not on the short baseline. "
            "Confirm which package owns it and whether the bit is still required."
        ),
        evidence=evidence,
        remediation="Clear the bit if no current package needs it, or document why it remains.",
    )


def run_capabilities(host: Host) -> Outcome:
    caps = host.capability_map()
    if caps is None:
        return Outcome.skip("capabilities", "file capabilities were not available (no getcap data)")
    findings: list[Finding] = []
    for path in sorted(caps):
        names = caps[path]
        if not names:
            continue
        base = path.rsplit("/", 1)[-1].lower()
        benign = BENIGN_CAP_FILES.get(base, set())
        if set(names) <= benign and benign:
            findings.append(
                Finding(
                    check_id="capabilities",
                    title="Ordinary capability on a network tool",
                    severity="info",
                    likelihood=1,
                    summary=f"{path} carries {', '.join(names)}, which is the usual arrangement for this tool.",
                    evidence=(path, ", ".join(names)),
                    remediation="Keep the distribution's capability rather than adding further ones.",
                )
            )
            continue
        ranked = []
        for name in names:
            if name in DANGEROUS_CAPABILITIES:
                severity, likelihood, phrase = DANGEROUS_CAPABILITIES[name]
                ranked.append((likelihood, severity, name, phrase))
            else:
                ranked.append((2, "info", name, "is not in the short review list"))
        ranked.sort(reverse=True)
        top_likelihood, top_severity, _top_name, _top_phrase = ranked[0]
        described = ", ".join(f"{name} ({phrase})" for _lh, _sev, name, phrase in ranked)
        findings.append(
            Finding(
                check_id="capabilities",
                title="File capability can cross a privilege boundary",
                severity=top_severity,
                likelihood=top_likelihood,
                summary=(
                    f"{path} carries file capabilities: {described}. "
                    "A capability on a program applies when that program runs, including for this account."
                ),
                evidence=(path, " ".join(names)),
                remediation="Remove capabilities the program does not need, and prefer the distribution package.",
            )
        )
    return Outcome(findings)


def run_sensitive_files(host: Host) -> Outcome:
    findings: list[Finding] = []
    passwd = host.file("/etc/passwd")
    if passwd is not None:
        findings.extend(_mode_finding(host, passwd, "critical", 9, read_matters=False))
        text = host.read_text("/etc/passwd")
        if text:
            findings.extend(_passwd_content(text))
    shadow = host.file("/etc/shadow")
    if shadow is not None:
        findings.extend(_shadow_finding(host, shadow))
    for path, severity, likelihood in (
        ("/etc/sudoers", "critical", 9),
        ("/etc/group", "high", 7),
        ("/etc/gshadow", "high", 8),
        ("/etc/crontab", "high", 8),
    ):
        fact = host.file(path)
        if fact is not None:
            findings.extend(
                _mode_finding(host, fact, severity, likelihood, read_matters=path in {"/etc/sudoers", "/etc/gshadow"})
            )
    for directory in ("/etc/sudoers.d", "/etc/cron.d", "/etc/systemd/system", "/usr/lib/systemd/system"):
        fact = host.file(directory)
        if fact is not None and fact.kind == "dir":
            findings.extend(_mode_finding(host, fact, "high", 7, read_matters=False))
    preload = host.file("/etc/ld.so.preload")
    if preload is not None:
        findings.extend(_preload_finding(host, preload))
    if not findings and passwd is None and shadow is None and host.file("/etc") is None:
        return Outcome.skip("sensitive_files", "/etc was not available to this account")
    return Outcome(findings)


def _mode_finding(
    host: Host,
    fact: FileFact,
    severity: str,
    likelihood: int,
    *,
    read_matters: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    if caller_can_write(host, fact):
        noun = "directory" if fact.kind == "dir" else "file"
        findings.append(
            Finding(
                check_id="sensitive_files",
                title=f"Writable sensitive {noun}",
                severity=severity,
                likelihood=likelihood,
                summary=(
                    f"{fact.path} can be written by an account that should not own that change. "
                    "Writes here alter authentication, scheduled work, or service configuration."
                ),
                evidence=(fact.path, f"mode {mode_text(fact.mode)}", f"owner uid {fact.uid} gid {fact.gid}"),
                remediation="Return the path to root ownership and a mode that only root can write.",
            )
        )
    elif read_matters and (world_readable(fact) or (host.uid != 0 and _caller_read(host, fact))):
        findings.append(
            Finding(
                check_id="sensitive_files",
                title="Sensitive file is readable",
                severity="medium" if severity == "critical" else "low",
                likelihood=max(4, likelihood - 3),
                summary=(
                    f"{fact.path} is readable more widely than it needs to be. "
                    "The contents were not copied into this report."
                ),
                evidence=(fact.path, f"mode {mode_text(fact.mode)}", f"owner uid {fact.uid} gid {fact.gid}"),
                remediation="Restrict the mode so only root and the appropriate system group can read it.",
            )
        )
    return findings


def _caller_read(host: Host, fact: FileFact) -> bool:
    if fact.uid == 0 and not world_readable(fact) and fact.gid not in host.gids:
        return False
    return user_can_read(host, fact) and fact.uid != host.uid


def _shadow_finding(host: Host, fact: FileFact) -> list[Finding]:
    writable = caller_can_write(host, fact)
    exposed = writable or world_readable(fact) or (host.uid != 0 and _group_readable(host, fact))
    if not exposed:
        return []
    if writable:
        severity, likelihood = "critical", 9
        why = "this account can write it"
    elif world_readable(fact):
        severity, likelihood = "high", 8
        why = "the mode allows any local account to read it"
    else:
        severity, likelihood = "high", 7
        why = "this account's group can read it"
    return [
        Finding(
            check_id="sensitive_files",
            title="Shadow file is exposed",
            severity=severity,
            likelihood=likelihood,
            summary=(f"/etc/shadow holds password hashes and {why}. The hashes were not copied into this report."),
            evidence=(fact.path, f"mode {mode_text(fact.mode)}", f"owner uid {fact.uid} gid {fact.gid}"),
            remediation="Restore mode 0640, owner root, group shadow (or the distribution equivalent).",
        )
    ]


def _group_readable(host: Host, fact: FileFact) -> bool:
    return fact.gid in host.gids and bool(fact.mode & 0o040)


def _passwd_content(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        name, password, uid_text = parts[0], parts[1], parts[2]
        if password == "":
            findings.append(
                Finding(
                    check_id="sensitive_files",
                    title="Empty password field in passwd",
                    severity="high",
                    likelihood=8,
                    summary=(
                        f"Account {name!r} has an empty password field in /etc/passwd. "
                        "Authentication policy should not leave that field blank."
                    ),
                    evidence=(f"account {name}", "password field is empty"),
                    remediation="Lock the account or move authentication to a shadowed, locked password.",
                )
            )
        elif password.startswith("$"):
            findings.append(
                Finding(
                    check_id="sensitive_files",
                    title="Password hash stored in passwd",
                    severity="high",
                    likelihood=7,
                    summary=(
                        f"Account {name!r} stores a password hash in /etc/passwd, which is normally world-readable. "
                        "The hash was not copied into this report."
                    ),
                    evidence=(f"account {name}", "password field contains a hash (redacted)"),
                    remediation="Move hashes to /etc/shadow and replace the passwd field with x.",
                )
            )
        if uid_text == "0" and name != "root":
            findings.append(
                Finding(
                    check_id="sensitive_files",
                    title="Extra account with uid 0",
                    severity="critical",
                    likelihood=9,
                    summary=(
                        f"Account {name!r} has uid 0 as well as root. "
                        "That account is another superuser, whatever its name is."
                    ),
                    evidence=(f"account {name}", "uid 0"),
                    remediation="Remove the extra uid 0 account, or give it a normal uid if it must keep the name.",
                )
            )
    return findings


def _preload_finding(host: Host, fact: FileFact) -> list[Finding]:
    length = fact.content_length
    evidence = [fact.path, f"mode {mode_text(fact.mode)}"]
    if length is None:
        evidence.append("contents were not readable")
    else:
        evidence.append(f"content length {length} bytes")
    if caller_can_write(host, fact):
        return [
            Finding(
                check_id="sensitive_files",
                title="Loader preload file is writable",
                severity="critical",
                likelihood=9,
                summary=(
                    "/etc/ld.so.preload names libraries the dynamic loader maps into programs. "
                    "This account can write that list. The contents were not copied."
                ),
                evidence=tuple(evidence),
                remediation="Remove the file unless a vendor requires it, and never leave it writable.",
            )
        ]
    if length:
        return [
            Finding(
                check_id="sensitive_files",
                title="Loader preload file is non-empty",
                severity="medium",
                likelihood=5,
                summary=(
                    "/etc/ld.so.preload is non-empty, so the dynamic loader maps extra libraries into programs. "
                    "Confirm each path is intentional. The contents were not copied."
                ),
                evidence=tuple(evidence),
                remediation="Empty or remove the file if those libraries are not a deliberate system policy.",
            )
        ]
    return [
        Finding(
            check_id="sensitive_files",
            title="Loader preload file is present",
            severity="info",
            likelihood=2,
            summary="/etc/ld.so.preload exists. Empty, it has no effect, but the path is worth knowing about.",
            evidence=tuple(evidence),
            remediation="Delete the file if nothing on the host is supposed to use it.",
        )
    ]


def run_cron(host: Host) -> Outcome:
    saw = False
    findings: list[Finding] = []
    for path in _CRON_FILES:
        fact = host.file(path)
        if fact is None:
            continue
        saw = True
        findings.extend(_cron_file(host, fact, with_user=True))
    for directory in _CRON_DIRS:
        names = host.list_dir(directory)
        fact = host.file(directory)
        if names is None and fact is None:
            continue
        saw = True
        if fact is not None and fact.kind == "dir" and caller_can_write(host, fact):
            findings.append(_writable_cron(fact.path, "cron directory"))
        for name in names or ():
            child = f"{directory.rstrip('/')}/{name}"
            child_fact = host.file(child)
            if child_fact is None or child_fact.kind != "file":
                continue
            with_user = "/cron.d/" in child or child.endswith("/cron.d")
            findings.extend(_cron_file(host, child_fact, with_user=with_user))
    for directory in _CRON_SCRIPT_DIRS:
        names = host.list_dir(directory)
        if names is None and host.file(directory) is None:
            continue
        saw = True
        for name in names or ():
            child = f"{directory.rstrip('/')}/{name}"
            if can_replace(host, child):
                findings.append(
                    Finding(
                        check_id="cron",
                        title="Cron script is writable",
                        severity="high",
                        likelihood=8,
                        summary=(
                            f"{child} lives in a cron script directory and this account can change it. "
                            "The periodic job would then run that change with the job's privileges."
                        ),
                        evidence=(child,),
                        remediation="Make the script and its directory writable only by root.",
                    )
                )
    if not saw:
        return Outcome.skip("cron", "cron locations were not present or not readable")
    return Outcome(findings)


def _writable_cron(path: str, noun: str) -> Finding:
    return Finding(
        check_id="cron",
        title=f"Writable {noun}",
        severity="high",
        likelihood=8,
        summary=(
            f"{path} can be changed by this account. "
            "Cron reads that path as root on a normal system, so the write crosses a privilege boundary."
        ),
        evidence=(path,),
        remediation="Return the path to root ownership and a mode that only root can write.",
    )


def _cron_file(host: Host, fact: FileFact, *, with_user: bool) -> list[Finding]:
    findings: list[Finding] = []
    if caller_can_write(host, fact):
        findings.append(_writable_cron(fact.path, "cron file"))
    text = host.read_text(fact.path)
    if not text:
        return findings
    for job in _parse_cron(text, with_user=with_user):
        for token in _absolute_targets(job):
            if token in {"/", "/bin", "/usr", "/usr/bin"}:
                continue
            if can_replace(host, token):
                findings.append(
                    Finding(
                        check_id="cron",
                        title="Cron job runs a writable program",
                        severity="high",
                        likelihood=8,
                        summary=(
                            f"A cron entry in {fact.path} runs {token}, and this account can change that program. "
                            "The scheduled command would pick up the change."
                        ),
                        evidence=(fact.path, job),
                        remediation=(
                            "Point the job at a root-owned absolute path, and remove write access to that program."
                        ),
                    )
                )
        for token in job.split():
            cleaned = token.strip("'\"")
            if cleaned.startswith("./") or ("/" in cleaned and not cleaned.startswith("/")):
                findings.append(
                    Finding(
                        check_id="cron",
                        title="Cron job uses a relative path",
                        severity="medium",
                        likelihood=5,
                        summary=(
                            f"A cron entry in {fact.path} uses relative path {cleaned!r}. "
                            "The directory cron starts in then decides which file runs."
                        ),
                        evidence=(fact.path, job),
                        remediation="Use an absolute path owned by root.",
                    )
                )
                break
    return findings


def _parse_cron(text: str, *, with_user: bool) -> list[str]:
    jobs: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            parts = line.split()
            need = 3 if with_user else 2
            if len(parts) >= need:
                jobs.append(" ".join(parts[need - 1 :]))
            continue
        parts = line.split()
        if not parts or ("=" in parts[0] and not parts[0][0].isdigit() and parts[0][0] != "*"):
            continue
        need = 6 if with_user else 5
        if len(parts) <= need:
            continue
        jobs.append(" ".join(parts[need:]))
    return jobs


def _absolute_targets(command: str) -> list[str]:
    targets: list[str] = []
    for token in command.split():
        cleaned = token.strip("'\"")
        if cleaned.startswith("/") and not any(char in cleaned for char in "*?["):
            if cleaned not in targets:
                targets.append(cleaned)
    return targets


def run_sudo(host: Host) -> Outcome:
    texts: list[tuple[str, str]] = []
    saw_unreadable = False
    saw_file = False
    sudo_l = host.sudo_l()
    if sudo_l is not None:
        if sudo_l.strip():
            texts.append(("sudo -l", sudo_l))
    paths = list(_SUDO_FILES)
    for directory in _SUDO_DIRS:
        names = host.list_dir(directory)
        if not names:
            continue
        for name in names:
            paths.append(f"{directory.rstrip('/')}/{name}")
    for path in paths:
        fact = host.file(path)
        if fact is None or fact.kind != "file":
            continue
        saw_file = True
        text = host.read_text(path)
        if text is None:
            saw_unreadable = True
            continue
        if text.strip():
            texts.append((path, text))
            extra = _include_paths(text)
            for included in extra:
                included_text = host.read_text(included)
                if included_text and included_text.strip():
                    texts.append((included, included_text))
    if not texts:
        if sudo_l is None and not saw_file:
            return Outcome.skip("sudo", "sudo configuration was not available")
        if saw_unreadable or sudo_l is None:
            return Outcome.skip(
                "sudo",
                "sudoers is not readable from this account, and no sudo -l output was provided",
            )
        return Outcome()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for source, text in texts:
        from_sudo_l = source == "sudo -l"
        for raw in text.splitlines():
            line = _strip_hash_comment(raw)
            if not line:
                continue
            if not from_sudo_l and not _sudo_line_applies(line, host):
                continue
            for finding in _sudo_line_findings(source, line):
                key = (finding.title, finding.evidence[-1] if finding.evidence else "")
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
    return Outcome(findings)


def _include_paths(text: str) -> list[str]:
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        for prefix in ("#include ", "@include ", "#includedir ", "@includedir "):
            if line.startswith(prefix):
                path = line[len(prefix) :].strip()
                if path.startswith("/") and path not in found:
                    found.append(path)
    return found


def _strip_hash_comment(raw: str) -> str:
    line = raw.strip()
    if line.startswith("#include") or line.startswith("#includedir"):
        return line
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    return line


def _sudo_line_applies(line: str, host: Host) -> bool:
    if line.startswith("Defaults") or line.startswith("Cmnd_Alias") or line.startswith("User_Alias"):
        return line.startswith("Defaults")
    subject = line.split()[0]
    if subject in {host.username, "ALL"}:
        return True
    if subject.startswith("%") and subject[1:] in host.groups:
        return True
    return False


def _sudo_line_findings(source: str, line: str) -> list[Finding]:
    findings: list[Finding] = []
    kept = [name for name in DANGEROUS_ENV if re.search(rf"\b{name}\b", line)]
    if ("env_keep" in line.lower() or "setenv" in line.lower()) and kept:
        findings.append(
            Finding(
                check_id="sudo",
                title="Sudo preserves a sensitive environment variable",
                severity="high",
                likelihood=7,
                summary=(
                    "A sudo rule keeps an environment variable that can change which code a program loads "
                    f"({', '.join(kept)}). Drop those names from env_keep, and avoid SETENV on broad rules."
                ),
                evidence=(source, line.strip()),
                remediation="Remove loader and interpreter variables from env_keep. Keep env_reset on.",
            )
        )
    if re.search(r"\bSETENV\b", line) and "env_keep" not in line.lower():
        findings.append(
            Finding(
                check_id="sudo",
                title="Sudo rule allows the caller to set the environment",
                severity="high",
                likelihood=7,
                summary=(
                    "The SETENV tag lets the invoking account influence the environment of a privileged command. "
                    "That is a wide grant."
                ),
                evidence=(source, line.strip()),
                remediation="Remove the SETENV tag unless a specific, reviewed variable is required.",
            )
        )
    if "NOPASSWD" in line or re.search(r"\(ALL(?::ALL)?\)\s+ALL\b", line) or re.search(r"\bALL\s*$", line):
        nopass = "NOPASSWD" in line
        broad = bool(re.search(r"NOPASSWD:\s*ALL\b", line) or re.search(r"\bALL\s*$", line))
        if nopass and broad:
            severity, likelihood = "critical", 9
            title = "Passwordless sudo for every command"
            summary = (
                "This account may run any command through sudo without a password. "
                "That is a full privilege boundary crossing, by policy."
            )
        elif nopass:
            severity, likelihood = "high", 8
            title = "Passwordless sudo rule"
            summary = (
                "A sudo rule grants a command without a password. "
                "Review that command: editors, shells, and interpreters are the usual mistakes."
            )
        elif broad:
            severity, likelihood = "medium", 6
            title = "Broad sudo rule"
            summary = (
                "A sudo rule matching this account can run every command. "
                "It may be an intentional admin grant. Confirm the lab expected it."
            )
        else:
            return findings
        findings.append(
            Finding(
                check_id="sudo",
                title=title,
                severity=severity,
                likelihood=likelihood,
                summary=summary,
                evidence=(source, line.strip()),
                remediation="Narrow the command list, require a password, and avoid granting shells or interpreters.",
            )
        )
    return findings


def run_path(host: Host) -> Outcome:
    return path_findings(host, separator=":")


def path_findings(host: Host, *, separator: str) -> Outcome:
    raw = host.env("PATH")
    if raw is None:
        return Outcome.skip("path", "PATH is not set")
    shown = raw if len(raw) <= 180 else raw[:177] + "..."
    findings: list[Finding] = []
    parts = raw.split(separator)
    seen: set[str] = set()
    for index, part in enumerate(parts):
        if part in seen:
            continue
        seen.add(part)
        if part in {"", "."}:
            findings.append(
                Finding(
                    check_id="path",
                    title="PATH includes the current directory",
                    severity="high",
                    likelihood=7,
                    summary=(
                        "An empty PATH component, or '.', means a command name is resolved in the current directory. "
                        "A privileged job that uses an unqualified name can then run the wrong file."
                    ),
                    evidence=(f"component {index + 1} is {part!r}", f"PATH={shown}"),
                    remediation="Remove '.' and empty components from PATH.",
                )
            )
            continue
        fact = host.file(part)
        if fact is None or fact.kind != "dir":
            continue
        if caller_can_write(host, fact):
            sticky = (
                " The directory is sticky, which stops other people deleting files, not planting a name."
                if fact.mode & 0o1000
                else ""
            )
            findings.append(
                Finding(
                    check_id="path",
                    title="Writable directory on PATH",
                    severity="high",
                    likelihood=7,
                    summary=(
                        f"{part} is on PATH and this account can write to it. "
                        "An unqualified command can resolve to a file placed there." + sticky
                    ),
                    evidence=(part, f"mode {mode_text(fact.mode)}", f"PATH={shown}"),
                    remediation="Remove the writable directory from PATH, or make it writable only by root.",
                )
            )
    return Outcome(findings)


def run_kernel(host: Host) -> Outcome:
    version = host.kernel()
    if not version:
        return Outcome.skip("kernel", "kernel version was not available")
    parsed = _parse_kernel(version)
    if parsed is None:
        return Outcome(
            [
                Finding(
                    check_id="kernel",
                    title="Kernel version could not be parsed",
                    severity="info",
                    likelihood=1,
                    summary="uplift records the version string and does not map kernels to exploits.",
                    evidence=(version,),
                    remediation="Compare the running build with the distribution security tracker.",
                )
            ]
        )
    if parsed < KERNEL_FLOOR:
        pretty = ".".join(str(part) for part in parsed)
        floor = ".".join(str(part) for part in KERNEL_FLOOR)
        return Outcome(
            [
                Finding(
                    check_id="kernel",
                    title=f"Kernel {pretty} is older than {floor}",
                    severity="low",
                    likelihood=3,
                    summary=(
                        "This is a coarse age check. Older series accumulate local-privilege fixes. "
                        "uplift does not suggest exploits or match this version to a vulnerability list. "
                        "Compare the running build with the distribution security tracker."
                    ),
                    evidence=(version,),
                    remediation=(
                        "Install the vendor's current kernel and reboot when the host is meant to be maintained."
                    ),
                )
            ]
        )
    return Outcome()


def _parse_kernel(version: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)
