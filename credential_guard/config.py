"""Strict loader for credential-guard.json (Schema v2)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from types import MappingProxyType
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from .bindings import (
    ALLOWED_CREDENTIAL_TYPES,
    validate_binding,
)
from .redactor import MAX_SECRET_LENGTH
from .registry import MIN_SECRET_LENGTH

CONFIG_FILENAME = "credential-guard.json"
SUPPORTED_VERSION = 2
MAX_CONFIG_FILE_BYTES = 2_097_152
NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
PathLike = Union[str, Path]

_TOKEN_FIELDS = frozenset({"type", "value"})
_USERPASS_FIELDS = frozenset({"type", "username", "password"})
_TOP_FIELDS = frozenset({"version", "credentials", "bindings"})


class ConfigError(Exception):
    """Fail-closed config error. Never embed secrets, hosts, or paths."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str = "configuration error") -> None:
        object.__setattr__(self, "code", code)
        super().__init__(message)

    def __repr__(self) -> str:
        return f"ConfigError(code={self.code!r})"


def _mode_bits(mode: int) -> int:
    return stat.S_IMODE(mode)


def _reject_duplicate_keys(pairs: list) -> dict:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ConfigError("CONFIG_DUPLICATE_KEY", "configuration error")
        out[key] = value
    return out


def _loads_strict(text: str) -> Any:
    err: Optional[str] = None
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ConfigError:
        raise
    except json.JSONDecodeError:
        err = "CONFIG_INVALID_JSON"
    if err is not None:
        raise ConfigError(err, "configuration error")
    raise ConfigError("CONFIG_INVALID_JSON", "configuration error")


def _freeze(obj: Any) -> Any:
    if isinstance(obj, dict):
        return MappingProxyType({k: _freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return tuple(_freeze(v) for v in obj)
    return obj


def _canonical_dumps(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _validate_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return name


def _validate_secret_string(value: Any, *, allow_short: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if any(ord(ch) < 32 for ch in value):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if len(value) > MAX_SECRET_LENGTH:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if not allow_short and len(value.strip()) < MIN_SECRET_LENGTH:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return value


def _validate_credential(name: str, entry: Any) -> Dict[str, Any]:
    _validate_name(name)
    if not isinstance(entry, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    ctype = entry.get("type")
    if ctype not in ALLOWED_CREDENTIAL_TYPES:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if ctype == "token":
        if set(entry) != _TOKEN_FIELDS:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        return {"type": "token", "value": _validate_secret_string(entry["value"])}
    if ctype == "username_password":
        if set(entry) != _USERPASS_FIELDS:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        username = entry["username"]
        if not isinstance(username, str) or not username:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if any(ord(ch) < 32 for ch in username):
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if len(username) > MAX_SECRET_LENGTH:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        return {
            "type": "username_password",
            "username": username,
            "password": _validate_secret_string(entry["password"]),
        }
    raise ConfigError("CONFIG_SCHEMA", "invalid configuration")


def parse_config_document(data: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate a decoded v2 document. Returns mutable credential/binding maps."""
    if not isinstance(data, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if set(data) != _TOP_FIELDS:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    version = data.get("version")
    if type(version) is not int or version != SUPPORTED_VERSION:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    cred_raw = data.get("credentials")
    bind_raw = data.get("bindings")
    if not isinstance(cred_raw, dict) or not isinstance(bind_raw, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")

    credentials: Dict[str, Any] = {}
    for name, entry in cred_raw.items():
        if not isinstance(name, str):
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if name in credentials:
            raise ConfigError("CONFIG_DUPLICATE_KEY", "configuration error")
        credentials[name] = _validate_credential(name, entry)

    # Secret uniqueness across token values / passwords (name-conflict / placeholder).
    seen_secrets: Dict[str, str] = {}
    for name, entry in credentials.items():
        secret: Optional[str] = None
        if entry["type"] == "token":
            secret = entry["value"]
        elif entry["type"] == "username_password":
            secret = entry["password"]
        if secret is not None:
            prev = seen_secrets.get(secret)
            if prev is not None and prev != name:
                raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
            seen_secrets[secret] = name

    bindings: Dict[str, Any] = {}
    for name, entry in bind_raw.items():
        if not isinstance(name, str):
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        _validate_name(name)
        if name in bindings:
            raise ConfigError("CONFIG_DUPLICATE_KEY", "configuration error")
        bindings[name] = validate_binding(name, entry, credentials)

    return credentials, bindings


def _assert_secure_parent_dir(path: Path) -> None:
    """Fail-closed check of the config file's direct parent directory."""
    parent = path.parent
    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(parent)
    except FileNotFoundError:
        err = "CONFIG_NOT_FOUND"
    except OSError:
        err = "CONFIG_UNAVAILABLE"
    if err is not None:
        raise ConfigError(err, "configuration error")
    assert lst is not None
    if stat.S_ISLNK(lst.st_mode):
        raise ConfigError("CONFIG_PARENT_SYMLINK", "configuration error")
    if not stat.S_ISDIR(lst.st_mode):
        raise ConfigError("CONFIG_UNAVAILABLE", "configuration error")
    if _mode_bits(lst.st_mode) != 0o700:
        raise ConfigError("CONFIG_PARENT_INSECURE_MODE", "configuration error")
    if lst.st_uid != os.geteuid():
        raise ConfigError("CONFIG_PARENT_OWNER", "configuration error")


def _open_and_read(path: PathLike) -> bytes:
    path_obj = _as_path(path)
    _assert_secure_parent_dir(path_obj)

    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(path_obj)
    except FileNotFoundError:
        err = "CONFIG_NOT_FOUND"
    except OSError:
        err = "CONFIG_UNAVAILABLE"
    if err is not None:
        raise ConfigError(err, "configuration error")
    assert lst is not None

    if stat.S_ISLNK(lst.st_mode):
        raise ConfigError("CONFIG_SYMLINK", "configuration error")
    if not stat.S_ISREG(lst.st_mode):
        raise ConfigError("CONFIG_NOT_FILE", "configuration error")
    if _mode_bits(lst.st_mode) != 0o600:
        raise ConfigError("CONFIG_INSECURE_MODE", "configuration error")
    if lst.st_uid != os.geteuid():
        raise ConfigError("CONFIG_OWNER_MISMATCH", "configuration error")
    if lst.st_size > MAX_CONFIG_FILE_BYTES:
        raise ConfigError("CONFIG_TOO_LARGE", "configuration error")

    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    open_err: Optional[str] = None
    try:
        if nofollow:
            fd = os.open(path_obj, open_flags | nofollow)
        else:
            fd = os.open(path_obj, open_flags)
    except OSError as exc:
        if getattr(exc, "errno", None) in {
            getattr(os, "ELOOP", -1),
            getattr(__import__("errno"), "ELOOP", -1),
        }:
            open_err = "CONFIG_SYMLINK"
        else:
            open_err = "CONFIG_UNAVAILABLE"
    if open_err is not None:
        raise ConfigError(open_err, "configuration error")

    try:
        read_err: Optional[str] = None
        try:
            st = os.fstat(fd)
        except OSError:
            read_err = "CONFIG_UNAVAILABLE"
            st = None  # type: ignore[assignment]
        if read_err is not None:
            raise ConfigError(read_err, "configuration error")
        assert st is not None
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError("CONFIG_NOT_FILE", "configuration error")
        if _mode_bits(st.st_mode) != 0o600:
            raise ConfigError("CONFIG_INSECURE_MODE", "configuration error")
        if st.st_uid != os.geteuid():
            raise ConfigError("CONFIG_OWNER_MISMATCH", "configuration error")
        if st.st_size > MAX_CONFIG_FILE_BYTES:
            raise ConfigError("CONFIG_TOO_LARGE", "configuration error")
        if st.st_ino != lst.st_ino or st.st_dev != lst.st_dev:
            raise ConfigError("CONFIG_TOCTOU", "configuration error")

        post_err: Optional[str] = None
        lst2 = None
        try:
            lst2 = os.lstat(path_obj)
        except OSError:
            post_err = "CONFIG_UNAVAILABLE"
        if post_err is not None:
            raise ConfigError(post_err, "configuration error")
        assert lst2 is not None
        if stat.S_ISLNK(lst2.st_mode):
            raise ConfigError("CONFIG_SYMLINK", "configuration error")
        if lst2.st_ino != st.st_ino or lst2.st_dev != st.st_dev:
            raise ConfigError("CONFIG_TOCTOU", "configuration error")

        chunks = []
        total = 0
        while True:
            read_block_err: Optional[str] = None
            block = None
            try:
                block = os.read(fd, 65536)
            except OSError:
                read_block_err = "CONFIG_UNAVAILABLE"
            if read_block_err is not None:
                raise ConfigError(read_block_err, "configuration error")
            assert block is not None
            if not block:
                break
            total += len(block)
            if total > MAX_CONFIG_FILE_BYTES:
                raise ConfigError("CONFIG_TOO_LARGE", "configuration error")
            chunks.append(block)
        raw = b"".join(chunks)

        post3_err: Optional[str] = None
        lst3 = None
        try:
            lst3 = os.lstat(path_obj)
        except OSError:
            post3_err = "CONFIG_UNAVAILABLE"
        if post3_err is not None:
            raise ConfigError(post3_err, "configuration error")
        assert lst3 is not None
        if stat.S_ISLNK(lst3.st_mode):
            raise ConfigError("CONFIG_SYMLINK", "configuration error")
        if lst3.st_ino != st.st_ino or lst3.st_dev != st.st_dev:
            raise ConfigError("CONFIG_TOCTOU", "configuration error")
        return raw
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _as_path(path: PathLike) -> Path:
    return Path(path)


class CredentialGuardConfig:
    """Immutable validated snapshot of credential-guard.json (no instance __dict__)."""

    __slots__ = ("_credentials", "_bindings", "_config_digest")

    def __init__(self, data: Any) -> None:
        """Public constructor: full Schema validate, deep-freeze, recompute digest."""
        credentials, bindings = parse_config_document(data)
        frozen_creds = _freeze(credentials)
        frozen_binds = _freeze(bindings)
        digest = hashlib.sha256(
            _canonical_dumps(
                {
                    "version": SUPPORTED_VERSION,
                    "credentials": credentials,
                    "bindings": bindings,
                }
            )
        ).hexdigest()
        object.__setattr__(self, "_credentials", frozen_creds)
        object.__setattr__(self, "_bindings", frozen_binds)
        object.__setattr__(self, "_config_digest", digest)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("CredentialGuardConfig is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("CredentialGuardConfig is immutable")

    @property
    def credentials(self) -> Mapping[str, Any]:
        return self._credentials

    @property
    def bindings(self) -> Mapping[str, Any]:
        return self._bindings

    @property
    def config_digest(self) -> str:
        return self._config_digest

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "version": SUPPORTED_VERSION,
            "credentials": _unfreeze(self._credentials),
            "bindings": _unfreeze(self._bindings),
        }

    def to_canonical_json(self) -> bytes:
        return _canonical_dumps(self.to_canonical_dict())

    @classmethod
    def from_mapping(cls, data: Any) -> "CredentialGuardConfig":
        return cls(data)

    @classmethod
    def load(cls, path: PathLike) -> "CredentialGuardConfig":
        raw = _open_and_read(path)
        err: Optional[str] = None
        text: Optional[str] = None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            err = "CONFIG_INVALID_UTF8"
        if err is not None:
            raise ConfigError(err, "configuration error")
        assert text is not None
        data = _loads_strict(text)
        return cls(data)


def _unfreeze(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {k: _unfreeze(v) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return [_unfreeze(v) for v in obj]
    return obj


__all__ = [
    "CONFIG_FILENAME",
    "MAX_CONFIG_FILE_BYTES",
    "NAME_RE",
    "SUPPORTED_VERSION",
    "ConfigError",
    "CredentialGuardConfig",
    "parse_config_document",
]
