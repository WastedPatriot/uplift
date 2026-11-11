"""Live host reads, and JSON snapshots so tests never need root."""

from __future__ import annotations

import getpass
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from uplift.access import parse_mode
from uplift.models import FileFact, Host, RegResult, ServiceFact

_GETCAP_ROOTS = ("/usr", "/bin", "/sbin", "/opt", "/home", "/tmp", "/var", "/etc", "/srv")


class SnapshotError(ValueError):
    """The snapshot JSON is missing or not in the expected shape."""


def detect_os() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return sys.platform


def normalise_path(path: str, os_name: str) -> str:
    raw = path.strip()
    if os_name == "windows":
        raw = raw.replace("/", "\\")
        match = re.fullmatch(r"([A-Za-z]):\\*", raw)
        if match:
            return f"{match.group(1).upper()}:\\"
        if re.fullmatch(r"[A-Za-z]:", raw):
            return f"{raw[0].upper()}:\\"
        return raw.rstrip("\\")
    if raw in {"", "/"}:
        return "/"
    return raw.rstrip("/") or "/"


def _split_caps(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        tokens = [value]
    elif isinstance(value, list):
        tokens = [str(item) for item in value]
    else:
        raise SnapshotError("capabilities must be a string or a list of strings")
    names: list[str] = []
    for token in tokens:
        bare = token.split("=", 1)[0]
        for piece in bare.split(","):
            name = piece.strip().lower().lstrip("+")
            if name.startswith("cap_") and name not in names:
                names.append(name)
    return tuple(names)


def parse_getcap(text: str) -> dict[str, tuple[str, ...]]:
    """Parse `getcap -r` output. Paths may contain spaces; capability tokens start with cap_."""

    found: dict[str, tuple[str, ...]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Failed") or "No such file" in stripped:
            continue
        parts = stripped.split()
        cap_at = next((i for i, part in enumerate(parts) if part.lower().startswith("cap_")), None)
        if cap_at is None or cap_at == 0:
            continue
        path = " ".join(parts[:cap_at])
        caps = _split_caps(parts[cap_at:])
        if caps:
            found[path] = caps
    return found


class SnapshotHost(Host):
    def __init__(self, data: dict[str, object]) -> None:
        os_name = str(data.get("os", "")).strip().lower()
        if os_name not in {"linux", "windows"}:
            raise SnapshotError("snapshot os must be 'linux' or 'windows'")
        user = data.get("user")
        if not isinstance(user, dict) or "name" not in user or "uid" not in user:
            raise SnapshotError("snapshot user needs name and uid")
        try:
            uid = int(user["uid"])
        except (TypeError, ValueError) as exc:
            raise SnapshotError("snapshot user.uid must be an integer") from exc
        gids_raw = user.get("gids", [uid])
        if not isinstance(gids_raw, list):
            raise SnapshotError("snapshot user.gids must be a list")
        groups_raw = user.get("groups", [])
        if not isinstance(groups_raw, list):
            raise SnapshotError("snapshot user.groups must be a list")
        env = data.get("env") or {}
        if not isinstance(env, dict):
            raise SnapshotError("snapshot env must be an object")
        files = data.get("files") or {}
        if not isinstance(files, dict):
            raise SnapshotError("snapshot files must be an object")

        self.os_name = os_name
        self.label = str(data.get("label") or "snapshot")
        self.username = str(user["name"])
        self.uid = uid
        self.gids = tuple(int(gid) for gid in gids_raw)
        self.groups = tuple(str(group) for group in groups_raw)
        self._env = {str(key): str(value) for key, value in env.items()}
        self._kernel = _optional_str(data.get("kernel"))
        self._sudo_l = _optional_str(data.get("sudo_l"))
        self._files = _load_files(files, os_name)
        self._registry_available = "registry" in data and data["registry"] is not None
        self._registry = _load_registry(data.get("registry"))
        self._services = _load_services(data.get("services"))
        self._privileges = _load_privileges(data.get("privileges"))
        self._getcap_text = _optional_str(data.get("getcap"))
        self._caps_explicit = any(isinstance(raw, dict) and "capabilities" in raw for raw in files.values())

    def file(self, path: str) -> FileFact | None:
        return self._files.get(_key(path, self.os_name))

    def list_dir(self, path: str) -> tuple[str, ...] | None:
        norm = normalise_path(path, self.os_name)
        fact = self.file(norm)
        if fact is not None and fact.kind != "dir":
            return None
        sep = "\\" if self.os_name == "windows" else "/"
        if self.os_name == "windows":
            prefix = norm if norm.endswith("\\") else norm + "\\"
        else:
            prefix = "/" if norm == "/" else norm + "/"
        names: list[str] = []
        seen: set[str] = set()
        prefix_cmp = prefix.lower() if self.os_name == "windows" else prefix
        for fact_path in self._display_paths():
            compare = fact_path.lower() if self.os_name == "windows" else fact_path
            if not compare.startswith(prefix_cmp):
                continue
            rest = fact_path[len(prefix) :]
            if not rest:
                continue
            name = rest.split(sep)[0]
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        if fact is None and not names:
            return None
        return tuple(sorted(names))

    def read_text(self, path: str, max_bytes: int = 1_000_000) -> str | None:
        fact = self.file(path)
        if fact is None or fact.content is None:
            return None
        if fact.readable is False:
            return None
        return fact.content[:max_bytes]

    def walk_files(self, roots: tuple[str, ...], *, max_files: int = 20_000) -> list[FileFact]:
        found = [
            fact
            for fact in self._files.values()
            if fact.kind == "file" and any(_is_under(fact.path, root, self.os_name) for root in roots)
        ]
        found.sort(key=lambda fact: fact.path)
        return found[:max_files]

    def env(self, key: str) -> str | None:
        if key in self._env:
            return self._env[key]
        for candidate, value in self._env.items():
            if candidate.lower() == key.lower():
                return value
        return None

    def kernel(self) -> str | None:
        return self._kernel

    def sudo_l(self) -> str | None:
        return self._sudo_l

    def capability_map(self) -> dict[str, tuple[str, ...]] | None:
        collected: dict[str, tuple[str, ...]] = {}
        explicit = False
        for fact in self._files.values():
            if fact.capabilities is not None:
                explicit = True
                if fact.capabilities:
                    collected[fact.path] = fact.capabilities
        if self._getcap_text is not None:
            explicit = True
            for path, caps in parse_getcap(self._getcap_text).items():
                collected.setdefault(path, caps)
        if not explicit and not self._caps_explicit:
            return None
        return collected

    def registry(self, key: str, name: str) -> RegResult:
        if not self._registry_available:
            return RegResult("unavailable")
        found = self._registry.get(_reg_key(key, name))
        if found is None:
            return RegResult("absent")
        return RegResult("ok", found)

    def services(self) -> tuple[ServiceFact, ...] | None:
        return self._services

    def privileges(self) -> tuple[str, ...] | None:
        return self._privileges

    def _display_paths(self) -> list[str]:
        return [fact.path for fact in self._files.values()]


class LiveHost(Host):
    def __init__(self) -> None:
        self.os_name = detect_os()
        self.label = _hostname()
        self.username = getpass.getuser()
        self.uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        self.gids = tuple(os.getgroups()) if hasattr(os, "getgroups") else ()
        self.groups = _group_names(self.gids)
        self._sudo_l = None

    def file(self, path: str) -> FileFact | None:
        try:
            st = os.lstat(path)
        except OSError:
            return None
        kind = _kind(st.st_mode)
        return FileFact(
            path=path,
            kind=kind,
            mode=stat.S_IMODE(st.st_mode) | (st.st_mode & 0o7000),
            uid=st.st_uid,
            gid=st.st_gid,
            size=st.st_size if kind == "file" else None,
        )

    def list_dir(self, path: str) -> tuple[str, ...] | None:
        try:
            return tuple(sorted(os.listdir(path)))
        except OSError:
            return None

    def read_text(self, path: str, max_bytes: int = 1_000_000) -> str | None:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                return handle.read(max_bytes)
        except OSError:
            return None

    def walk_files(self, roots: tuple[str, ...], *, max_files: int = 20_000) -> list[FileFact]:
        found: list[FileFact] = []
        skip = {"proc", "sys", "dev", "run"}
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [name for name in dirnames if name not in skip]
                for name in filenames:
                    fact = self.file(os.path.join(dirpath, name))
                    if fact is not None and fact.kind == "file":
                        found.append(fact)
                    if len(found) >= max_files:
                        return found
        return found

    def env(self, key: str) -> str | None:
        return os.environ.get(key)

    def kernel(self) -> str | None:
        try:
            uname = os.uname()
        except AttributeError:
            return None
        return f"{uname.release} {uname.version}".strip()

    def sudo_l(self) -> str | None:
        return None

    def capability_map(self) -> dict[str, tuple[str, ...]] | None:
        if self.os_name != "linux" or shutil.which("getcap") is None:
            return None
        collected: dict[str, tuple[str, ...]] = {}
        ran = False
        for root in _GETCAP_ROOTS:
            if not os.path.isdir(root):
                continue
            try:
                proc = subprocess.run(
                    ["getcap", "-r", root],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            ran = True
            collected.update(parse_getcap(proc.stdout or ""))
        return collected if ran else None

    def registry(self, key: str, name: str) -> RegResult:
        if self.os_name != "windows":
            return RegResult("unavailable")
        try:
            import winreg
        except ImportError:
            return RegResult("unavailable")
        hive_name, subkey = _split_hive(key)
        hives = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        }
        hive = hives.get(hive_name)
        if hive is None:
            return RegResult("unavailable")
        try:
            with winreg.OpenKey(hive, subkey) as handle:
                value, _typ = winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return RegResult("absent")
        except OSError:
            return RegResult("unavailable")
        return RegResult("ok", value)

    def services(self) -> tuple[ServiceFact, ...] | None:
        if self.os_name != "windows":
            return None
        try:
            import winreg
        except ImportError:
            return None
        root = r"SYSTEM\CurrentControlSet\Services"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root) as handle:
                count = winreg.QueryInfoKey(handle)[0]
                names = [winreg.EnumKey(handle, index) for index in range(count)]
        except OSError:
            return None
        found: list[ServiceFact] = []
        for name in names:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root + "\\" + name) as svc:
                    image, _typ = winreg.QueryValueEx(svc, "ImagePath")
            except OSError:
                continue
            if not isinstance(image, str) or not image.strip():
                continue
            account = _reg_string(winreg, winreg.HKEY_LOCAL_MACHINE, root + "\\" + name, "ObjectName")
            start = _reg_string(winreg, winreg.HKEY_LOCAL_MACHINE, root + "\\" + name, "Start")
            found.append(ServiceFact(name=name, image_path=image, account=account, start=start))
        return tuple(found)

    def realpath(self, path: str) -> str:
        try:
            return os.path.realpath(path)
        except OSError:
            return path

    def follow(self, path: str) -> FileFact | None:
        try:
            st = os.stat(path)
            real = os.path.realpath(path)
        except OSError:
            return None
        kind = _kind(st.st_mode)
        return FileFact(
            path=real,
            kind=kind,
            mode=stat.S_IMODE(st.st_mode),
            uid=st.st_uid,
            gid=st.st_gid,
            size=st.st_size if kind == "file" else None,
        )

    def privileges(self) -> tuple[str, ...] | None:
        if self.os_name != "windows":
            return None
        try:
            proc = subprocess.run(
                ["whoami", "/priv"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0 and not proc.stdout:
            return None
        names = []
        for line in proc.stdout.splitlines():
            match = re.search(r"\b(Se[A-Za-z]+Privilege)\b", line)
            if match and "Enabled" in line and match.group(1) not in names:
                names.append(match.group(1))
        return tuple(names)


def load_snapshot(path: Path) -> SnapshotHost:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SnapshotError(f"cannot read snapshot: {exc.strerror or exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"snapshot is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SnapshotError("snapshot must be a JSON object")
    return snapshot_from_dict(data)


def snapshot_from_dict(data: dict[str, object]) -> SnapshotHost:
    return SnapshotHost(data)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _key(path: str, os_name: str) -> str:
    norm = normalise_path(path, os_name)
    return norm.lower() if os_name == "windows" else norm


def _is_under(path: str, root: str, os_name: str) -> bool:
    if os_name == "windows":
        path_l = path.lower().rstrip("\\")
        root_l = root.lower().rstrip("\\")
        return path_l == root_l or path_l.startswith(root_l + "\\")
    root_n = root.rstrip("/") or "/"
    if root_n == "/":
        return path.startswith("/")
    return path == root_n or path.startswith(root_n + "/")


def _load_files(files: dict[object, object], os_name: str) -> dict[str, FileFact]:
    loaded: dict[str, FileFact] = {}
    for raw_path, raw in files.items():
        if not isinstance(raw_path, str) or not isinstance(raw, dict):
            raise SnapshotError("each file entry needs a string path and an object value")
        kind = str(raw.get("type") or raw.get("kind") or "file")
        if kind not in {"file", "dir", "symlink", "other"}:
            raise SnapshotError(f"unsupported file type for {raw_path}: {kind}")
        mode = parse_mode(raw.get("mode", "0755" if kind == "dir" else "0644"))
        try:
            uid = int(raw.get("uid", 0))
            gid = int(raw.get("gid", 0))
        except (TypeError, ValueError) as exc:
            raise SnapshotError(f"uid and gid must be integers for {raw_path}") from exc
        content = raw.get("content")
        if content is not None and not isinstance(content, str):
            raise SnapshotError(f"content must be a string for {raw_path}")
        caps = _split_caps(raw["capabilities"]) if "capabilities" in raw else None
        writable = raw.get("writable")
        readable = raw.get("readable")
        if writable is not None and not isinstance(writable, bool):
            raise SnapshotError(f"writable must be a boolean for {raw_path}")
        if readable is not None and not isinstance(readable, bool):
            raise SnapshotError(f"readable must be a boolean for {raw_path}")
        size = raw.get("size")
        if size is not None:
            try:
                size = int(size)
            except (TypeError, ValueError) as exc:
                raise SnapshotError(f"size must be an integer for {raw_path}") from exc
        path = normalise_path(raw_path, os_name)
        loaded[_key(path, os_name)] = FileFact(
            path=path,
            kind=kind,
            mode=mode,
            uid=uid,
            gid=gid,
            content=content,
            capabilities=caps,
            writable=writable,
            readable=readable,
            size=size,
        )
    return loaded


def _reg_key(key: str, name: str) -> tuple[str, str]:
    cleaned = re.sub(r"[\\/]+", r"\\", key.strip()).rstrip("\\").upper()
    return cleaned, name.strip().upper()


def _load_registry(raw: object) -> dict[tuple[str, str], object]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise SnapshotError("registry must be an object")
    values: dict[tuple[str, str], object] = {}
    for key, names in raw.items():
        if not isinstance(key, str) or not isinstance(names, dict):
            raise SnapshotError("registry entries must map a key to an object of values")
        for name, value in names.items():
            if not isinstance(name, str):
                raise SnapshotError("registry value names must be strings")
            values[_reg_key(key, name)] = value
    return values


def _load_services(raw: object) -> tuple[ServiceFact, ...] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise SnapshotError("services must be a list")
    services: list[ServiceFact] = []
    for item in raw:
        if not isinstance(item, dict) or "name" not in item or "image_path" not in item:
            raise SnapshotError("each service needs name and image_path")
        writable = item.get("binary_writable")
        if writable is not None and not isinstance(writable, bool):
            raise SnapshotError("service binary_writable must be a boolean")
        services.append(
            ServiceFact(
                name=str(item["name"]),
                image_path=str(item["image_path"]),
                account=str(item.get("account") or ""),
                start=str(item.get("start") or ""),
                binary_writable=writable,
            )
        )
    return tuple(services)


def _load_privileges(raw: object) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise SnapshotError("privileges must be a list")
    return tuple(str(item) for item in raw)


def _hostname() -> str:
    try:
        return os.uname().nodename
    except AttributeError:
        return os.environ.get("COMPUTERNAME", "localhost")


def _group_names(gids: tuple[int, ...]) -> tuple[str, ...]:
    try:
        import grp
    except ImportError:
        return ()
    names: list[str] = []
    for gid in gids:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return tuple(names)


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _split_hive(key: str) -> tuple[str, str]:
    cleaned = key.replace("/", "\\").lstrip("\\")
    hive, _, subkey = cleaned.partition("\\")
    return hive.upper(), subkey


def _reg_string(winreg: object, hive: int, subkey: str, name: str) -> str:
    try:
        with winreg.OpenKey(hive, subkey) as handle:  # type: ignore[attr-defined]
            value, _typ = winreg.QueryValueEx(handle, name)  # type: ignore[attr-defined]
    except OSError:
        return ""
    return str(value)
