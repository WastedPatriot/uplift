"""Names and capability classes used to triage findings.

The lists describe what a program is for. They are not recipes.
"""

from __future__ import annotations

# Common distro paths. Anything else with a setuid bit is worth a look.
BASELINE_SUID = {
    "/bin/su",
    "/usr/bin/su",
    "/bin/sudo",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/bin/mount",
    "/usr/bin/mount",
    "/bin/umount",
    "/usr/bin/umount",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/bin/ping",
    "/usr/bin/ping",
    "/bin/ping6",
    "/usr/bin/ping6",
    "/usr/bin/chage",
    "/usr/bin/expiry",
    "/usr/sbin/unix_chkpwd",
    "/sbin/unix_chkpwd",
    "/usr/bin/dotlockfile",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
}

# basename -> (category phrase, severity when setuid-root, likelihood)
_SHELLS = ("critical", 9, "shell")
_INTERPRETERS = ("critical", 9, "interpreter")
_EDITORS = ("high", 8, "editor or pager")
_RUNNERS = ("high", 8, "program that runs other programs")
_WRITERS = ("high", 7, "program that copies or writes files")

SENSITIVE_PROGRAMS: dict[str, tuple[str, int, str]] = {}
for _name in ("ash", "bash", "busybox", "csh", "dash", "ksh", "sh", "zsh", "fish"):
    SENSITIVE_PROGRAMS[_name] = _SHELLS
for _name in ("perl", "ruby", "php", "node", "nodejs", "lua", "irb"):
    SENSITIVE_PROGRAMS[_name] = _INTERPRETERS
for _name in ("vim", "vi", "nvim", "nano", "emacs", "less", "more", "view"):
    SENSITIVE_PROGRAMS[_name] = _EDITORS
for _name in (
    "find",
    "gawk",
    "nawk",
    "mawk",
    "awk",
    "env",
    "stdbuf",
    "gdb",
    "strace",
    "ltrace",
    "nmap",
    "make",
):
    SENSITIVE_PROGRAMS[_name] = _RUNNERS
for _name in ("cp", "mv", "install", "tar", "zip", "unzip", "gzip", "dd", "rsync"):
    SENSITIVE_PROGRAMS[_name] = _WRITERS


def sensitive_program(basename: str) -> tuple[str, int, str] | None:
    name = basename.lower()
    if name.startswith("python"):
        return _INTERPRETERS
    return SENSITIVE_PROGRAMS.get(name)


# Capability -> (severity, likelihood, plain description)
DANGEROUS_CAPABILITIES: dict[str, tuple[str, int, str]] = {
    "cap_setuid": ("critical", 9, "can change the process user id"),
    "cap_setgid": ("high", 8, "can change the process group id"),
    "cap_dac_override": ("critical", 9, "can bypass file read, write, and execute checks"),
    "cap_dac_read_search": ("high", 8, "can bypass file read and directory search checks"),
    "cap_sys_admin": ("critical", 9, "grants a broad set of administrative operations"),
    "cap_sys_ptrace": ("high", 8, "can trace and inspect other processes"),
    "cap_sys_module": ("critical", 9, "can load and unload kernel modules"),
    "cap_sys_rawio": ("high", 7, "can perform raw I/O"),
    "cap_fowner": ("high", 7, "can bypass permission checks on files it does not own"),
    "cap_chown": ("high", 7, "can change file owners"),
    "cap_setfcap": ("high", 8, "can set file capabilities"),
    "cap_net_admin": ("medium", 5, "can change network configuration"),
    "cap_net_raw": ("low", 3, "can open raw sockets"),
    "cap_bpf": ("high", 7, "can load BPF programs"),
    "cap_audit_control": ("medium", 5, "can configure auditing"),
    "cap_mac_admin": ("high", 7, "can change mandatory access control policy"),
    "cap_perfmon": ("medium", 5, "can observe performance events"),
}

# ping is routinely shipped with cap_net_raw and nothing else.
BENIGN_CAP_FILES = {
    "ping": {"cap_net_raw"},
    "ping6": {"cap_net_raw"},
}

DANGEROUS_ENV = (
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "BASH_ENV",
    "ENV",
    "PS4",
    "PYTHONPATH",
    "PYTHONINSPECT",
    "PERL5OPT",
    "RUBYOPT",
    "NODE_OPTIONS",
    "SHELLOPTS",
)

SUID_ROOTS = ("/bin", "/sbin", "/usr", "/opt", "/home", "/root", "/tmp", "/var", "/etc", "/srv")

KERNEL_FLOOR = (5, 10, 0)

SENSITIVE_PRIVILEGES: dict[str, tuple[str, int, str]] = {
    "SeDebugPrivilege": (
        "high",
        8,
        "Can open other users' processes. Restrict it to accounts that genuinely debug them.",
    ),
    "SeImpersonatePrivilege": (
        "high",
        7,
        "Can impersonate a client that authenticated to this account. "
        "Keep it to services that must accept those connections.",
    ),
    "SeAssignPrimaryTokenPrivilege": (
        "high",
        8,
        "Can assign a process token. It should be rare outside the service control manager.",
    ),
    "SeTcbPrivilege": (
        "critical",
        9,
        "Acts as part of the operating system. It does not belong on an ordinary lab user.",
    ),
    "SeCreateTokenPrivilege": (
        "critical",
        9,
        "Can create a token. Ordinary accounts do not need this.",
    ),
    "SeLoadDriverPrivilege": (
        "critical",
        9,
        "Can load a driver, which reaches the kernel. Remove it from interactive users.",
    ),
    "SeBackupPrivilege": (
        "high",
        7,
        "Can read files the account otherwise could not, via backup APIs. Limit it to backup operators.",
    ),
    "SeRestorePrivilege": (
        "high",
        7,
        "Can write files the account otherwise could not, via restore APIs. Limit it to backup operators.",
    ),
    "SeTakeOwnershipPrivilege": (
        "high",
        7,
        "Can take ownership of objects and then change their access control.",
    ),
    "SeRelabelPrivilege": (
        "medium",
        5,
        "Can change an object's integrity label.",
    ),
}

BENIGN_PRIVILEGES = {
    "SeChangeNotifyPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTimeZonePrivilege",
    "SeUndockPrivilege",
    "SeShutdownPrivilege",
    "SeCreateGlobalPrivilege",
}

UNATTEND_PATHS = (
    r"C:\Windows\Panther\Unattend.xml",
    r"C:\Windows\Panther\unattend.xml",
    r"C:\Windows\System32\sysprep\unattend.xml",
    r"C:\Windows\System32\sysprep\sysprep.xml",
    r"C:\Windows\System32\sysprep\Panther\unattend.xml",
)

INSTALLER_KEY = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
