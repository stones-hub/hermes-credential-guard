"""Sensitive path and private-key content detection (pure helpers)."""

from __future__ import annotations

import ast
import base64
import json
import os
import re
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import unquote, unquote_plus

# PEM private-key markers (case-insensitive). Certificates are excluded.
_PRIVATE_KEY_BEGIN = re.compile(
    r"-----BEGIN[^\n-]{0,80}PRIVATE KEY-----",
    re.IGNORECASE,
)
_PRIVATE_KEY_END = re.compile(
    r"-----END[^\n-]{0,80}PRIVATE KEY-----",
    re.IGNORECASE,
)

_READ_PATH_KEYS = ("path", "file_path", "filename", "file")
_SEARCH_PATH_KEYS = ("path", "directory", "root", "dir")
_SEARCH_TOOL_NAMES = frozenset(
    {"search_files", "search", "find_files", "grep_files"}
)
_READ_TOOL_NAMES = frozenset({"read_file", "read", "open_file"})

_PROTECTED_SSH_BASENAMES = frozenset(
    {
        "config",
        "authorized_keys",
        "authorized_keys2",
    }
)
_STORE_BASENAMES = frozenset(
    {
        "credentials.json",
        "targets.json",
        "credential-guard.json",
        "credentials.json.v1.bak",
        "targets.json.v1.bak",
        ".cg-migrate.journal",
        ".cg-migrate.lock",
        ".credential-guard.runtime.lock",
    }
)

# Leading $HOME / ${HOME} / $HERMES_HOME / ${HERMES_HOME} only — no shell.
_CONTROLLED_ENV_PREFIX = re.compile(
    r"^(?P<var>\$\{HOME\}|\$HOME|\$\{HERMES_HOME\}|\$HERMES_HOME)(?P<rest>/.*)?$"
)

# Encoded private-key scan bounds (fail closed when exceeded).
MAX_PRIVATE_KEY_SCAN_BYTES = 512_000
MAX_PRIVATE_KEY_DECODE_CANDIDATES = 64
MAX_PRIVATE_KEY_CANDIDATE_LENGTH = 65_536
MIN_PRIVATE_KEY_B64_CANDIDATE = 48
MIN_PRIVATE_KEY_PERCENT_CANDIDATE = 40

_B64_ALPHABET_RE = re.compile(r"[A-Za-z0-9+/_-]+=*")
_PERCENT_RUN_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~]){" + str(MIN_PRIVATE_KEY_PERCENT_CANDIDATE) + r",}")
# Bounded JSON-escape runs (fixed-width tokens + counted repetition — no backtracking traps).
MIN_PRIVATE_KEY_JSON_ESCAPE_TOKENS = 8
_JSON_ESCAPE_RUN_RE = re.compile(
    r'(?:\\u[0-9a-fA-F]{4}|\\["\\/bfnrt]|\\\\){'
    + str(MIN_PRIVATE_KEY_JSON_ESCAPE_TOKENS)
    + r",}"
)


class EncodedPrivateKeyScanError(RuntimeError):
    """Raised when encoded private-key scanning exceeds bounds or fails closed."""


def looks_like_private_key(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False
    if _PRIVATE_KEY_BEGIN.search(text) and _PRIVATE_KEY_END.search(text):
        return True
    # Single-marker high-confidence OpenSSH/RSA/EC/PKCS8 begins.
    if re.search(
        r"-----BEGIN\s+(OPENSSH|RSA|EC|DSA|ENCRYPTED)?\s*PRIVATE KEY-----",
        text,
        re.IGNORECASE,
    ):
        return True
    return False


def _try_b64_decode(candidate: str) -> Optional[str]:
    s = candidate.strip()
    if len(s) < MIN_PRIVATE_KEY_B64_CANDIDATE:
        return None
    if len(s) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
        raise EncodedPrivateKeyScanError("candidate exceeds max length")
    # Strict alphabet + padding.
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s):
        return None
    if len(s) % 4 != 0:
        return None
    try:
        # Prefer alphabet-appropriate decoder.
        # urlsafe_b64decode has no validate=; use altchars for strict URL-safe.
        if "-" in s or "_" in s:
            raw = base64.b64decode(s, altchars=b"-_", validate=True)
        else:
            raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_percent_decode(candidate: str) -> Optional[str]:
    s = candidate.strip()
    if len(s) < MIN_PRIVATE_KEY_PERCENT_CANDIDATE:
        return None
    if len(s) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
        raise EncodedPrivateKeyScanError("candidate exceeds max length")
    if "%" not in s:
        return None
    try:
        a = unquote(s)
        b = unquote_plus(s)
    except Exception:
        return None
    # Prefer the decode that actually changed something.
    for decoded in (a, b):
        if decoded != s and looks_like_private_key(decoded):
            return decoded
    if a != s:
        return a
    if b != s:
        return b
    return None


def _try_json_unescape(candidate: str) -> Optional[str]:
    s = candidate
    if len(s) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
        raise EncodedPrivateKeyScanError("candidate exceeds max length")
    if "\\" not in s and "\\u" not in s:
        # Still allow when only quotes escaped... require backslash form.
        if '\\"' not in s and "\\\\" not in s:
            return None
    try:
        decoded = json.loads(f'"{s}"')
    except Exception:
        return None
    if not isinstance(decoded, str) or decoded == s:
        return None
    return decoded


def _iter_decode_candidates(text: str) -> List[str]:
    """Collect bounded decode candidates for one-shot encoded private-key scan.

    Distinguishes the whole-payload scan budget (enforced by the caller via
    ``MAX_PRIVATE_KEY_SCAN_BYTES``) from the per-candidate decode length
    (``MAX_PRIVATE_KEY_CANDIDATE_LENGTH``). Ordinary long prose must not be
    treated as a single decode candidate; bounded Base64 / percent /
    JSON-escape runs inside it are still collected. A token that itself looks
    like an encoding candidate and exceeds the per-candidate limit fails closed.
    """
    candidates: List[str] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        if not item or item in seen:
            return
        if len(item) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
            raise EncodedPrivateKeyScanError("candidate exceeds max length")
        seen.add(item)
        candidates.append(item)
        if len(candidates) > MAX_PRIVATE_KEY_DECODE_CANDIDATES:
            raise EncodedPrivateKeyScanError("too many decode candidates")

    # Whole-string candidate only when within the per-candidate decode budget.
    # Overlong ordinary text is skipped here; substring extractors below still run.
    stripped = text.strip()
    if len(stripped) <= MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
        add(stripped)
    for match in _B64_ALPHABET_RE.finditer(text):
        token = match.group(0)
        if len(token) >= MIN_PRIVATE_KEY_B64_CANDIDATE:
            add(token)
    for match in _PERCENT_RUN_RE.finditer(text):
        add(match.group(0))
    # JSON-escape: short fields may be whole-string candidates; overlong ordinary
    # prose must NOT be decoded as one blob — only bounded escape runs inside it.
    if "\\u" in text or '\\"' in text or "\\\\" in text:
        if len(text) <= MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
            add(text)
        else:
            for match in _JSON_ESCAPE_RUN_RE.finditer(text):
                add(match.group(0))
    return candidates


def contains_private_key_material(text: str) -> bool:
    """Authoritative private-key detector for provider/tool boundaries.

    Detects raw PEM and one-shot percent / quote-plus / Base64 / URL-safe Base64
    / JSON-unescape forms. Exceeding scan bounds raises EncodedPrivateKeyScanError
    (callers must fail closed). Does not recurse.
    """
    if not isinstance(text, str) or not text:
        return False
    if len(text.encode("utf-8", errors="surrogatepass")) > MAX_PRIVATE_KEY_SCAN_BYTES:
        raise EncodedPrivateKeyScanError("payload exceeds scan byte limit")
    if looks_like_private_key(text):
        return True

    try:
        candidates = _iter_decode_candidates(text)
    except EncodedPrivateKeyScanError:
        raise
    except Exception as exc:
        raise EncodedPrivateKeyScanError("candidate extraction failed") from exc

    for candidate in candidates:
        try:
            decoded_forms = [
                _try_percent_decode(candidate),
                _try_b64_decode(candidate),
                _try_json_unescape(candidate),
            ]
        except EncodedPrivateKeyScanError:
            raise
        except Exception as exc:
            raise EncodedPrivateKeyScanError("decode attempt failed") from exc
        for decoded in decoded_forms:
            if decoded and looks_like_private_key(decoded):
                return True
    return False


def extract_path_candidates(tool_name: str, args: Any) -> List[str]:
    if not isinstance(args, dict):
        return []
    name = (tool_name or "").strip()
    keys: Sequence[str]
    if name in _READ_TOOL_NAMES:
        keys = _READ_PATH_KEYS
    elif name in _SEARCH_TOOL_NAMES:
        keys = _SEARCH_PATH_KEYS
    else:
        return []
    out: List[str] = []
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    # Hermes search_files defaults omitted path to "."
    if name in _SEARCH_TOOL_NAMES and not out:
        out.append(".")
    return out


def _strip_wrapping_quotes(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def _expand_controlled_env_prefix(raw: str) -> str:
    """Expand only leading HOME / HERMES_HOME. Never invokes a shell."""
    s = _strip_wrapping_quotes(raw)
    match = _CONTROLLED_ENV_PREFIX.match(s)
    if not match:
        return raw
    token = match.group("var")
    if token in ("$HOME", "${HOME}"):
        env_name = "HOME"
    else:
        env_name = "HERMES_HOME"
    value = os.environ.get(env_name, "").strip()
    if not value:
        # Undefined — do not claim a resolved protected path via this prefix.
        return raw
    rest = match.group("rest") or ""
    return value + rest


def _expand_user(raw: str) -> Path:
    return Path(os.path.expanduser(raw)).expanduser()


def _normalize_path_input(raw: str) -> Path:
    expanded = _expand_controlled_env_prefix(raw.strip())
    return _expand_user(expanded)


def _home_ssh_dir() -> Path:
    return Path.home() / ".ssh"


def _store_dir() -> Path:
    hermes = os.environ.get("HERMES_HOME", "").strip()
    if hermes:
        return Path(hermes) / "credential-guard"
    return Path.home() / ".hermes" / "credential-guard"


def _safe_realpath(path: Path) -> Optional[Path]:
    try:
        if path.exists():
            return Path(os.path.realpath(path))
    except OSError:
        return None
    try:
        # Non-existent: resolve parents best-effort without requiring final file.
        parent = path.parent
        if parent.exists():
            return Path(os.path.realpath(parent)) / path.name
        return path.absolute()
    except OSError:
        return None


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child_r = Path(os.path.realpath(child)) if child.exists() else child.resolve()
        parent_r = Path(os.path.realpath(parent)) if parent.exists() else parent.resolve()
        child_r.relative_to(parent_r)
        return True
    except (OSError, ValueError):
        return False


def _is_protected_known_hosts_name(name: str) -> bool:
    if name == "known_hosts":
        return True
    if not name.startswith("known_hosts."):
        return False
    suffix = name[len("known_hosts.") :]
    # Obvious example files are not protected material.
    if suffix == "example" or suffix.endswith(".example"):
        return False
    return True


def _is_protected_identity_name(name: str) -> bool:
    if not name.startswith("id_"):
        return False
    # Public keys remain readable.
    if name.endswith(".pub"):
        return False
    return True


def _ssh_basename_is_protected(name: str) -> bool:
    if name in _PROTECTED_SSH_BASENAMES:
        return True
    if _is_protected_known_hosts_name(name):
        return True
    if _is_protected_identity_name(name):
        return True
    return False


def _ssh_file_is_protected(path: Path) -> bool:
    """Return True if path is a protected SSH material path."""
    ssh = _home_ssh_dir()
    try:
        name = path.name
    except Exception:
        return False

    # Direct basename rules under ~/.ssh
    under_ssh = _is_under(path, ssh) or _path_looks_like_ssh_child(path, ssh)
    if under_ssh:
        if _ssh_basename_is_protected(name):
            return True
        # ssh_key/** under ~/.ssh
        try:
            rel = _relative_to_ssh(path, ssh)
            if rel is not None:
                parts = rel.parts
                if parts and parts[0] == "ssh_key":
                    # Still allow obvious public keys under ssh_key.
                    if name.endswith(".pub"):
                        return False
                    return True
                if _ssh_basename_is_protected(name):
                    return True
        except Exception:
            return True  # fail closed when uncertain under .ssh
        # Any path under ~/.ssh/ssh_key (except .pub handled above)
        if "ssh_key" in path.parts and not name.endswith(".pub"):
            return True

    # Symlink / realpath landing on protected
    real = _safe_realpath(path)
    if real is not None and real != path:
        return _ssh_file_is_protected(real) or _store_file_is_protected(real)
    return False


def _path_looks_like_ssh_child(path: Path, ssh: Path) -> bool:
    try:
        expanded = _expand_user(str(path))
        parts = expanded.parts
        ssh_parts = ssh.parts
        if len(parts) >= len(ssh_parts) and parts[: len(ssh_parts)] == ssh_parts:
            return True
    except Exception:
        return False
    # String form with ~/.ssh
    raw = str(path)
    if raw.startswith("~/.ssh/") or raw.startswith("~/.ssh"):
        return True
    return False


def _relative_to_ssh(path: Path, ssh: Path) -> Optional[Path]:
    try:
        expanded = _expand_user(str(path))
        if expanded.exists() or ssh.exists():
            try:
                return Path(os.path.realpath(expanded)).relative_to(
                    Path(os.path.realpath(ssh))
                )
            except ValueError:
                pass
        return expanded.resolve(strict=False).relative_to(ssh.resolve(strict=False))
    except (OSError, ValueError):
        return None


def _store_basename_is_protected(name: str) -> bool:
    if name in _STORE_BASENAMES:
        return True
    if name.endswith(".v1.bak"):
        return True
    if name.startswith(".cg-migrate-") and name.endswith(".tmp"):
        return True
    if name.startswith(".cg-migrate-isol-"):
        return True
    if name.startswith(".cg-migrate"):
        return True
    return False


def _store_file_is_protected(path: Path) -> bool:
    """Protect Credential Guard unified config, legacy dual files, and migrate artifacts."""
    store = _store_dir()
    try:
        name = path.name
        check = path
        if not _store_basename_is_protected(name):
            real = _safe_realpath(path)
            if real is None or not _store_basename_is_protected(real.name):
                # Any path under the store directory is treated as sensitive.
                if _is_under(path, store) or _is_under(real or path, store):
                    return True
                return False
            check = real
            name = real.name
        expected = store / name
        expected_real = _safe_realpath(expected) or expected
        path_real = _safe_realpath(check) or check
        if path_real == expected_real:
            return True
        if Path(os.path.abspath(path_real)) == Path(os.path.abspath(expected_real)):
            return True
        if _is_under(path_real, store) or _is_under(check, store):
            return True
    except OSError:
        return False
    return False


def path_is_protected(raw_path: str) -> bool:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False
    try:
        path = _normalize_path_input(raw_path)
    except Exception:
        return True  # fail closed on weird input
    if _store_file_is_protected(path):
        return True
    if _ssh_file_is_protected(path):
        return True
    # Resolve symlink / .. components when present.
    real = _safe_realpath(path)
    if real is not None:
        if _store_file_is_protected(real):
            return True
        if _ssh_file_is_protected(real):
            return True
    return False


def search_path_is_protected(raw_path: str) -> bool:
    """Fail closed when a search root is or can scan into a protected tree."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False
    try:
        root = _normalize_path_input(raw_path)
    except Exception:
        return True
    ssh = _home_ssh_dir()
    store = _store_dir()

    # Searching the protected path itself or anything under it.
    if path_is_protected(str(root)):
        return True
    if _is_under(root, ssh) or _path_looks_like_ssh_child(root, ssh):
        return True
    if root == ssh or str(root).rstrip("/") == str(ssh):
        return True

    # Searching a parent that contains the protected tree → can scan into it.
    try:
        if ssh.exists() and _is_under(ssh, root):
            return True
        # Even if .ssh does not exist yet, searching HOME covers ~/.ssh.
        home = Path.home()
        if _is_under(home, root) or root == home:
            return True
        if _path_looks_like_ssh_child(root, ssh):
            return True
        if store.exists() and _is_under(store, root):
            return True
        if root == store or _is_under(root, store):
            return True
    except OSError:
        return True
    return False


def args_target_protected(tool_name: str, args: Any) -> bool:
    name = (tool_name or "").strip()
    candidates = extract_path_candidates(name, args)
    if name in _SEARCH_TOOL_NAMES:
        return any(search_path_is_protected(c) for c in candidates)
    return any(path_is_protected(c) for c in candidates)


_DIRECT_READ_RE = re.compile(
    r"(?i)(?:^|[;&|`\n]|&&|\|\|)\s*(?:"
    r"cat|head|tail|less|more|nl|od|hexdump|xxd|bat|view|vim|vi|emacs|nano|"
    r"type|Get-Content"
    r")\s+(?P<path>[^\s;|&]+)"
)


def terminal_command_reads_protected(command: str) -> bool:
    """Block only clearly direct reads of protected paths (honest boundary)."""
    if not isinstance(command, str) or not command.strip():
        return False
    for match in _DIRECT_READ_RE.finditer(command):
        raw = match.group("path").strip("'\"")
        if path_is_protected(raw):
            return True
    # Explicit path tokens that are protected absolute/~ paths.
    for token in re.findall(r"(~/\.ssh/\S+|/(?:Users|home)/\S+/\.ssh/\S+)", command):
        cleaned = token.strip("'\"")
        if path_is_protected(cleaned):
            return True
    # Store unified/legacy/migrate artifact absolute / env-expanded references
    for token in re.findall(
        r"(\S*(?:credentials|targets|credential-guard)\.json(?:\.v1\.bak)?)",
        command,
    ):
        if path_is_protected(token.strip("'\"")):
            return True
    for token in re.findall(r"(\S*\.cg-migrate\S*)", command):
        cleaned = token.strip("'\"")
        if path_is_protected(cleaned):
            return True
    return False


# ---------------------------------------------------------------------------
# execute_code: static Python AST detection (honest, non-DLP boundary)
# ---------------------------------------------------------------------------

_PATH_READ_METHODS = frozenset(
    {
        "read_text",
        "read_bytes",
        "read",
        "readline",
        "readlines",
        "open",
    }
)
_BUILTIN_OPEN_NAMES = frozenset({"open"})
_OS_OPEN_ATTR = "open"
_FILE_READ_INTENT_HINT = re.compile(
    r"(?i)\b(open|read_text|read_bytes|Path|pathlib)\b"
)
# Bounded cartesian product for multi-candidate path concat / join / f-string.
# Exceeding the limit fails closed (avoids model-crafted combinatorial blow-up).
MAX_PATH_CANDIDATE_COMBOS = 64


def _syntax_error_suggests_file_read(code: str) -> bool:
    """Fail closed only when parse fails and file-read intent is plausible."""
    if not _FILE_READ_INTENT_HINT.search(code):
        return False
    # Plausible read + any protected-looking basename / ssh fragment.
    lowered = code.lower()
    hints = (
        "credential-guard.json",
        "credentials.json",
        "targets.json",
        ".cg-migrate",
        ".ssh",
        "id_",
        "known_hosts",
        "authorized_keys",
    )
    return any(h in lowered for h in hints)


def _ast_const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _ast_const_bool(node: ast.AST) -> Optional[bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


class _PathBinding:
    """Static path candidates for one name/expr; unknown means not fully static."""

    __slots__ = ("values", "unknown")

    def __init__(
        self,
        values: Optional[Set[str]] = None,
        *,
        unknown: bool = False,
    ) -> None:
        self.values: Set[str] = set(values or ())
        self.unknown = unknown

    def union(self, other: "_PathBinding") -> "_PathBinding":
        return _PathBinding(self.values | other.values, unknown=self.unknown or other.unknown)

    def single(self) -> Optional[str]:
        if self.unknown or len(self.values) != 1:
            return None
        return next(iter(self.values))

    def any_protected(self) -> bool:
        return any(path_is_protected(v) for v in self.values)


def _binding_from_optional_str(value: Optional[str]) -> _PathBinding:
    if value is None:
        return _PathBinding(unknown=True)
    return _PathBinding({value})


class _PythonProtectedReadChecker(ast.NodeVisitor):
    """Detect statically-resolvable reads of protected paths in execute_code."""

    def __init__(self) -> None:
        self.env: Dict[str, _PathBinding] = {}
        self.hits = False
        # Controlled import aliases — never execute import / eval.
        self.path_ctors: Set[str] = {"Path"}
        self.pathlib_modules: Set[str] = set()
        self.open_names: Set[str] = set(_BUILTIN_OPEN_NAMES)
        self.os_modules: Set[str] = {"os"}

    def check(self, tree: ast.AST) -> bool:
        self.visit(tree)
        return self.hits

    def _snapshot_env(self) -> Dict[str, _PathBinding]:
        return {
            k: _PathBinding(set(v.values), unknown=v.unknown) for k, v in self.env.items()
        }

    def _merge_envs(
        self,
        left: Dict[str, _PathBinding],
        right: Dict[str, _PathBinding],
    ) -> Dict[str, _PathBinding]:
        keys = set(left) | set(right)
        out: Dict[str, _PathBinding] = {}
        for key in keys:
            lv = left.get(key)
            rv = right.get(key)
            if lv is None and rv is None:
                continue
            if lv is None:
                # Assigned only on right branch → other branch keeps prior absence = unknown.
                out[key] = rv.union(_PathBinding(unknown=True)) if rv else _PathBinding(unknown=True)
            elif rv is None:
                out[key] = lv.union(_PathBinding(unknown=True))
            else:
                out[key] = lv.union(rv)
        return out

    def _bind_name(self, name: str, binding: _PathBinding) -> None:
        if binding.unknown and not binding.values:
            self.env.pop(name, None)
        else:
            self.env[name] = binding

    def _resolve_name(self, name: str) -> _PathBinding:
        bound = self.env.get(name)
        if bound is None:
            return _PathBinding(unknown=True)
        return _PathBinding(set(bound.values), unknown=bound.unknown)

    def _is_path_ctor_name(self, name: str) -> bool:
        return name in self.path_ctors

    def _is_pathlib_module_name(self, name: str) -> bool:
        return name in self.pathlib_modules

    def _is_os_module_name(self, name: str) -> bool:
        return name in self.os_modules

    def _is_path_home_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call) or node.args or node.keywords:
            return False
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "home":
            return False
        # Path.home() / P.home()
        if isinstance(func.value, ast.Name) and self._is_path_ctor_name(func.value.id):
            return True
        # pathlib.Path.home() / pl.Path.home()
        if (
            isinstance(func.value, ast.Attribute)
            and func.value.attr == "Path"
            and isinstance(func.value.value, ast.Name)
            and self._is_pathlib_module_name(func.value.value.id)
        ):
            return True
        return False

    def _is_os_environ_home(self, node: ast.AST, *, keys: Set[str]) -> bool:
        if isinstance(node, ast.Subscript):
            if not (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "environ"
                and isinstance(node.value.value, ast.Name)
                and self._is_os_module_name(node.value.value.id)
            ):
                return False
            key = _ast_const_str(node.slice)
            return key in keys if key else False
        if isinstance(node, ast.Call):
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "environ"
                and isinstance(func.value.value, ast.Name)
                and self._is_os_module_name(func.value.value.id)
            ):
                return False
            if not node.args:
                return False
            key = _ast_const_str(node.args[0])
            return key in keys if key else False
        return False

    def _is_os_open_call(self, func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr == _OS_OPEN_ATTR
            and isinstance(func.value, ast.Name)
            and self._is_os_module_name(func.value.id)
        )

    def _is_path_ctor_call(self, func: ast.AST) -> bool:
        if isinstance(func, ast.Name) and self._is_path_ctor_name(func.id):
            return True
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "Path"
            and isinstance(func.value, ast.Name)
            and self._is_pathlib_module_name(func.value.id)
        ):
            return True
        return False

    def _bounded_product_strings(
        self,
        sets: List[Sequence[str]],
        *,
        combine,
    ) -> Set[str]:
        """Cartesian product with an explicit upper bound; exceed → fail closed."""
        if not sets:
            raise RuntimeError("path candidate product empty")
        total = 1
        for s in sets:
            if not s:
                raise RuntimeError("path candidate segment empty")
            total *= len(s)
            if total > MAX_PATH_CANDIDATE_COMBOS:
                raise RuntimeError("path candidate product exceeds bound")
        out: Set[str] = set()
        for combo in product(*sets):
            out.add(combine(combo))
            if len(out) > MAX_PATH_CANDIDATE_COMBOS:
                raise RuntimeError("path candidate product exceeds bound")
        return out

    def _concat_bindings(self, parts: List[_PathBinding]) -> _PathBinding:
        """Propagate multi-candidate sets through string concatenation."""
        if not parts:
            return _PathBinding(unknown=True)
        unknown = any(p.unknown for p in parts)
        sets: List[Sequence[str]] = []
        for p in parts:
            if p.values:
                # Keep known candidates even when unknown flag is also set.
                sets.append(sorted(p.values))
            else:
                # Fully-unknown segment: cannot form concrete path strings.
                return _PathBinding(unknown=True)
        values = self._bounded_product_strings(sets, combine=lambda combo: "".join(combo))
        return _PathBinding(values, unknown=unknown)

    def _joined_binding(self, node: ast.AST) -> _PathBinding:
        """Resolve JoinedStr / string Add into a multi-candidate binding."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._concat_bindings(
                [self._candidates(node.left), self._candidates(node.right)]
            )
        if isinstance(node, ast.JoinedStr):
            parts: List[_PathBinding] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(_PathBinding({value.value}))
                elif isinstance(value, ast.FormattedValue):
                    if value.format_spec is not None or value.conversion != -1:
                        return _PathBinding(unknown=True)
                    parts.append(self._candidates(value.value))
                else:
                    return _PathBinding(unknown=True)
            return self._concat_bindings(parts)
        return _PathBinding(unknown=True)

    def _candidates(self, node: ast.AST) -> _PathBinding:
        """Resolve path-like expression to candidate strings (conservative)."""
        direct = _ast_const_str(node)
        if direct is not None:
            return _PathBinding({direct})

        if isinstance(node, ast.Name):
            return self._resolve_name(node.id)

        if isinstance(node, ast.IfExp):
            test = _ast_const_bool(node.test)
            body_b = self._candidates(node.body)
            else_b = self._candidates(node.orelse)
            if test is True:
                return body_b
            if test is False:
                return else_b
            return body_b.union(else_b)

        # Multi-candidate string + / f-string propagation (do not collapse via .single()).
        if isinstance(node, ast.JoinedStr) or (
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        ):
            return self._joined_binding(node)

        if self._is_os_environ_home(node, keys={"HOME"}):
            home = os.environ.get("HOME", "").strip()
            return _binding_from_optional_str(home or None)
        if self._is_os_environ_home(node, keys={"HERMES_HOME"}):
            hermes = os.environ.get("HERMES_HOME", "").strip()
            return _binding_from_optional_str(hermes or None)

        if isinstance(node, ast.Call):
            func = node.func
            # os.path.join(...)
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "join"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "path"
                and isinstance(func.value.value, ast.Name)
                and self._is_os_module_name(func.value.value.id)
            ):
                return self._join_arg_bindings([self._candidates(a) for a in node.args])

            if self._is_path_ctor_call(func):
                return self._join_arg_bindings([self._candidates(a) for a in node.args])

            if self._is_path_home_call(node):
                return _PathBinding({str(Path.home())})

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self._candidates(node.left)
            right = self._candidates(node.right)
            return self._div_bindings(left, right)

        return _PathBinding(unknown=True)

    def _join_arg_bindings(self, parts: List[_PathBinding]) -> _PathBinding:
        if not parts:
            return _PathBinding(unknown=True)
        unknown = any(p.unknown for p in parts)
        sets: List[Sequence[str]] = []
        for p in parts:
            if p.values:
                sets.append(sorted(p.values))
            else:
                return _PathBinding(unknown=True)
        values = self._bounded_product_strings(
            sets,
            combine=lambda combo: str(Path(*combo)) if len(combo) > 1 else combo[0],
        )
        return _PathBinding(values, unknown=unknown)

    def _div_bindings(self, left: _PathBinding, right: _PathBinding) -> _PathBinding:
        unknown = left.unknown or right.unknown
        if not left.values or not right.values:
            return _PathBinding(unknown=True)
        values = self._bounded_product_strings(
            [sorted(left.values), sorted(right.values)],
            combine=lambda combo: str(Path(combo[0]) / combo[1]),
        )
        return _PathBinding(values, unknown=unknown)

    def _call_path_binding(
        self,
        node: ast.Call,
        *,
        keyword_names: Sequence[str],
    ) -> _PathBinding:
        if node.args:
            return self._candidates(node.args[0])
        for kw in node.keywords:
            if kw.arg in keyword_names:
                return self._candidates(kw.value)
        return _PathBinding(unknown=True)

    def _path_from_open_receiver(self, node: ast.AST) -> _PathBinding:
        if not isinstance(node, ast.Call):
            return _PathBinding(unknown=True)
        func = node.func
        if isinstance(func, ast.Name) and func.id in self.open_names:
            return self._call_path_binding(node, keyword_names=("file",))
        if isinstance(func, ast.Attribute) and func.attr == "open":
            # Path(...).open() — path is receiver, not kw.
            if self._is_os_open_call(func):
                return self._call_path_binding(node, keyword_names=("path",))
            return self._candidates(func.value)
        if self._is_os_open_call(func):
            return self._call_path_binding(node, keyword_names=("path",))
        return _PathBinding(unknown=True)

    def _mark_if_protected(self, binding: _PathBinding) -> bool:
        if binding.any_protected():
            self.hits = True
            return True
        return False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            top = alias.name.split(".", 1)[0]
            if top == "pathlib" and alias.name == "pathlib":
                self.pathlib_modules.add(local)
            if top == "os" and alias.name == "os":
                self.os_modules.add(local)
        # no generic_visit — Import has no nested stmts of interest

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            if mod == "pathlib" and alias.name == "Path":
                self.path_ctors.add(local)
            if mod in ("builtins", "") and alias.name == "open":
                self.open_names.add(local)
            if mod == "os" and alias.name == "path":
                # not required this round
                pass

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self._bind_name(node.targets[0].id, self._candidates(node.value))
        # Visit value for nested calls (e.g. x = open(prot).read() patterns via Call).
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._bind_name(node.target.id, self._candidates(node.value))
            self.visit(node.value)

    def visit_If(self, node: ast.If) -> None:
        # Evaluate test for nested calls first (rare); do not treat as binding CFG.
        self.visit(node.test)
        flag = _ast_const_bool(node.test)
        before = self._snapshot_env()
        if flag is True:
            for stmt in node.body:
                self.visit(stmt)
            return
        if flag is False:
            for stmt in node.orelse:
                self.visit(stmt)
            return
        # Dynamic condition: branch snapshot + merge (not linear visit order).
        self.env = self._snapshot_env()
        for stmt in node.body:
            self.visit(stmt)
        body_env = self._snapshot_env()
        self.env = before
        for stmt in node.orelse:
            self.visit(stmt)
        else_env = self._snapshot_env()
        self.env = self._merge_envs(body_env, else_env)

    def visit_Call(self, node: ast.Call) -> None:
        if self.hits:
            return
        func = node.func

        # open(...) / alias / os.open(...)
        if isinstance(func, ast.Name) and func.id in self.open_names:
            binding = self._call_path_binding(node, keyword_names=("file",))
            if self._mark_if_protected(binding):
                return
        elif self._is_os_open_call(func):
            binding = self._call_path_binding(node, keyword_names=("path",))
            if self._mark_if_protected(binding):
                return

        # Path(...).read_text() / read_bytes() / open() / read()
        if isinstance(func, ast.Attribute) and func.attr in _PATH_READ_METHODS:
            binding = self._candidates(func.value)
            if not binding.values and not binding.unknown:
                binding = self._path_from_open_receiver(func.value)
            if self._mark_if_protected(binding):
                return
            if isinstance(func.value, ast.Call):
                nested = self._path_from_open_receiver(func.value)
                if self._mark_if_protected(nested):
                    return

        self.generic_visit(node)


def python_code_reads_protected(code: str) -> bool:
    """Return True when execute_code body statically reads a protected path.

    Honest boundary: only AST-resolvable open/Path/os.open reads. Does not
    execute code, eval, or touch the filesystem for judgment beyond path_is_protected.
    Helper exceptions fail closed. Syntax errors fail closed only when file-read
    intent looks plausible; plain arithmetic with bad syntax is not blanket-blocked.
    """
    if not isinstance(code, str) or not code.strip():
        return False
    try:
        tree = ast.parse(code)
    except SyntaxError:
        try:
            return _syntax_error_suggests_file_read(code)
        except Exception:
            return True
    except Exception:
        return True
    try:
        return _PythonProtectedReadChecker().check(tree)
    except Exception:
        return True
