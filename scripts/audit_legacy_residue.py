#!/usr/bin/env python3
"""R5 semantic legacy-residue auditor (AST / structured config inspection).

Scans a candidate tree for old MySQL/SSH fixed-action registration, old
production modules, PyMySQL / vendored-deps package membership, and
unauthorized dual-file (credentials.json / targets.json) runtime reads.

Dual-file allowlisting is function/symbol scoped — never whole-file
allowlisting (production or tests). Migration may declare filename constants
at module scope but must not perform module-scope runtime reads.

Does not read Hermes Profiles or real credential stores.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

REPO_DEFAULT = Path(__file__).resolve().parents[1]

OLD_TOOL_NAMES = frozenset({"mysql_credential_action", "ssh_credential_action"})
OLD_MODULES = frozenset(
    {
        "credential_guard/tools.py",
        "credential_guard/mysql_executor.py",
        "credential_guard/ssh_tools.py",
        "credential_guard/ssh_executor.py",
        "credential_guard/targets.py",
        "credential_guard/file_backend.py",
        "credential_guard/deps_integrity.py",
    }
)
OLD_IMPORT_MODULES = frozenset(
    {
        "tools",
        "mysql_executor",
        "ssh_tools",
        "ssh_executor",
        "targets",
        "file_backend",
        "deps_integrity",
    }
)
# Legacy module names that collide with a Hermes *host* package of the same
# bare name. ``tools.approval`` / ``tools.registry`` / ``tools.terminal_tool``
# are the host's formal approval-chain interface and must stay importable; only
# the plugin's own ``credential_guard.tools`` / ``.tools`` is R5 residue.
# Names outside this set have no host homonym, so bare-segment matching is kept.
HOST_HOMONYM_MODULES = frozenset({"tools"})
DUAL_FILE_NAMES = frozenset(
    {
        "credentials.json",
        "targets.json",
        "credentials.json.v1.bak",
        "targets.json.v1.bak",
    }
)
PATH_READ_ATTRS = frozenset(
    {"read_text", "read_bytes", "open", "read", "write_text", "write_bytes"}
)
BUILTIN_READ_FUNCS = frozenset({"open"})

# Production modules that must not import file_backend or parse dual files.
DUAL_FILE_FORBIDDEN_IMPORT_PATHS = frozenset(
    {
        "credential_guard/approval.py",
        "credential_guard/hooks.py",
        "credential_guard/middleware.py",
        "credential_guard/state.py",
        "credential_guard/runtime_config.py",
        "credential_guard/tools.py",
        "credential_guard/ssh_tools.py",
        "credential_guard/mysql_executor.py",
        "credential_guard/ssh_executor.py",
        "credential_guard/targets.py",
        "credential_guard/release_identity.py",
        "credential_guard/cli.py",
        "credential_guard/__init__.py",
        "credential_guard/reference_tools.py",
        "credential_guard/process_tools.py",
        "credential_guard/tool_execution.py",
        "credential_guard/tool_request.py",
        "credential_guard/injection.py",
        "credential_guard/injection_plan.py",
        "credential_guard/result_guard.py",
        "credential_guard/bindings.py",
        "credential_guard/config.py",
        "scripts/build_release_artifacts.py",
    }
)

# Function/symbol-scoped dual-file allowlist (no whole-file pass — incl. tests).
ALLOWED_DUAL_FILE_SYMBOLS: Dict[str, frozenset] = {
    "credential_guard/migration.py": frozenset(
        {
            "CREDENTIALS_FILENAME",
            "TARGETS_FILENAME",
            "CREDENTIALS_BAK",
            "TARGETS_BAK",
            "_validate_v1_credentials",
            "_validate_v1_targets",
            "_build_v2_document",
            "migrate_config",
            "_read_secure_json",
            "_read_secure_bytes",
            "_SourceIdentity",
            "_assert_source_identity",
            "_isolate_owned_source",
            "_new_journal",
            "_validate_journal_doc",
            "_assert_success_contract",
            # Filename constant declarations only — not runtime reads.
            "<module>",
        }
    ),
    "credential_guard/sensitive_paths.py": frozenset(
        {
            "_STORE_BASENAMES",
            "_credentials_json_path",
            "_store_basename_is_protected",
            "_store_file_is_protected",
            "path_is_protected",
            "search_path_is_protected",
            "args_target_protected",
            "terminal_command_reads_protected",
            "_syntax_error_suggests_file_read",
            "<module>",
        }
    ),
    # migrate-config CLI help may name the migration inputs; not a runtime read.
    "credential_guard/cli.py": frozenset({"setup_parser", "<module>"}),
    # Auditor metadata (detection constants), not a runtime dual-file read.
    "scripts/audit_legacy_residue.py": frozenset(
        {
            "DUAL_FILE_NAMES",
            "ALLOWED_DUAL_FILE_SYMBOLS",
            "_mentions_dual_file",
            "_dual_file_symbol_allowed",
            "_dual_file_read_allowed",
            "_fold_str",
            "_scan_python",
            "audit_tree",
            "main",
            "<module>",
        }
    ),
    # Symbol-scoped test allowlists (never whole-file).
    "tests/test_config_migration.py": frozenset(
        {
            "<module>",
            "_assert_pre_migration_state",
            "_old_bytes_still_present",
            "_prepare_store",
            "boom_lstat",
            "boom_open",
            "flaky_isolate",
            "isolate_and_recreate",
            "publish_then_plant",
            "test_atomic_backup_no_clobber",
            "test_atomic_target_no_clobber",
            "test_compensate_cleanup_backup_tmp_failure",
            "test_compensate_delete_new_file_failure_keeps_old_copy",
            "test_compensate_dir_fsync_failure_not_claimed_restored",
            "test_compensate_when_second_backup_rename_fails",
            "test_concurrent_migration_lock_blocks_second",
            "test_crash_after_prepared_journal_recovers_prestate",
            "test_exception_graph_migration_source_json",
            "test_final_old_name_recreation_never_returns_success",
            "test_foreign_formal_with_owned_backup_keeps_journal",
            "test_foreign_prefixed_temp_never_deleted_on_recovery",
            "test_full_traceback_migration_missing_source",
            "test_isolate_old_source_toctou_preserves_competitor",
            "test_journal_replaced_before_clear_never_reports_recovered",
            "test_migrate_credentials_only_requires_manual_review",
            "test_migrate_empty_v1_pair_success",
            "test_migrate_mysql_requires_manual_review",
            "test_migrate_rejects_insecure_store_directory",
            "test_migrate_ssh_v1_requires_manual_review",
            "test_migrate_ssh_v1_success",
            "test_migration_os_branch_exception_graph_clean_for_all_ops",
            "test_migration_source_postread_toctou_blocked",
            "test_migration_source_prebackup_toctou_blocked",
            "test_one_shot_restore_replace_fails_once_then_recovers",
            "test_one_shot_second_finalize_fails_restores_prestate",
            "test_owned_backup_residual_never_reports_recovered",
            "test_persistent_recovery_then_next_run_recovers_before_new_migration",
            "test_recovered_only_on_exact_prestate",
            "test_recovery_exact_temp_replacement_never_deleted",
            "test_recovery_preserves_competitor_mismatched_new_file",
            "test_rejects_duplicate_key_in_old",
            "test_rejects_missing_old_file",
            "test_rejects_non_strict_v1_version_type",
            "test_rejects_old_file_bad_mode",
            "test_rejects_old_symlink",
            "test_rejects_when_backup_exists",
            "test_rejects_when_new_exists",
            "test_rollback_on_dir_fsync_failure",
            "test_rollback_on_final_rename_failure",
            "test_rollback_on_fsync_failure",
            "test_rollback_on_reread_failure",
            "test_rollback_on_temp_write_failure",
            "test_second_migrate_refuses_overwrite",
            "test_stale_lock_file_allows_acquire_and_recovery",
        }
    ),
    "tests/test_sensitive_paths.py": frozenset(
        {"test_blocks_credential_guard_credentials_json"}
    ),
    "tests/test_execute_code_sensitive_paths.py": frozenset(
        {
            "test_slice_b_const_binding_concat_fstring",
            "test_slice_b_home_and_environ_static",
            "test_slice_b_store_basenames_blocked",
            "test_slice_c_mention_in_string_or_comment_allowed",
        }
    ),
    "tests/test_file_registry_bridge.py": frozenset(
        {"test_t2_missing_unified_config_fail_closed"}
    ),
    "tests/test_target_catalog_boundary.py": frozenset(
        {
            "<module>",
            "_assert_safe_block",
            "_make_store",
            "test_t1_read_file_targets_traversal_and_symlink_blocked",
            "test_t3_env_var_direct_reads_blocked",
            "test_t3_undefined_and_other_vars_not_false_positive",
            "test_t4_terminal_result_blocks_even_without_pem_marker",
        }
    ),
    "tests/test_profile_write_boundary.py": frozenset(
        {"test_load_and_migrate_reject_insecure_parent_without_path_leak"}
    ),
    "tests/test_legacy_residue_gate.py": frozenset(
        {
            "_clean_tree",
            "test_mutation_unauthorized_dual_file_runtime_is_red",
            "test_mutation_concatenated_dual_file_read_is_red",
            "test_mutation_test_allowlist_abuse_is_red",
            "test_mutation_migration_module_scope_read_is_red",
            "test_mutation_stem_ext_name_binding_dual_file_read_is_red",
            "test_mutation_sensitive_paths_dual_file_read_is_red",
        }
    ),
}

# Symbols in which dual-file *runtime reads* are permitted (subset of above).
# Module-scope ``<module>`` is never a read-allowed symbol.
ALLOWED_DUAL_FILE_READ_SYMBOLS: Dict[str, frozenset] = {
    # Only private byte/JSON reader entry points may open/read old dual files.
    # Validators / _build_v2_document / journal helpers / migrate_config may
    # receive already-read data but must not directly Path/open old files.
    # The identity helpers below are also secure readers: each lstat-guards the
    # path (reject symlink / non-regular / wrong mode / wrong owner) before
    # reading and returns only a digest, a bool or identity metadata.
    "credential_guard/migration.py": frozenset(
        {
            "_read_secure_json",
            "_read_secure_bytes",
            "_capture_owned_artifact",
            "_matches_artifact_identity",
            "_file_sha256_if_regular",
        }
    ),
    # sensitive_paths.py may declare protected basenames but must never read/open
    # old dual files — no read allowlist entries for that module.
    "tests/test_config_migration.py": ALLOWED_DUAL_FILE_SYMBOLS[
        "tests/test_config_migration.py"
    ]
    - frozenset({"<module>"}),
    "tests/test_sensitive_paths.py": ALLOWED_DUAL_FILE_SYMBOLS[
        "tests/test_sensitive_paths.py"
    ],
    "tests/test_execute_code_sensitive_paths.py": ALLOWED_DUAL_FILE_SYMBOLS[
        "tests/test_execute_code_sensitive_paths.py"
    ],
    "tests/test_file_registry_bridge.py": ALLOWED_DUAL_FILE_SYMBOLS[
        "tests/test_file_registry_bridge.py"
    ],
    "tests/test_target_catalog_boundary.py": ALLOWED_DUAL_FILE_SYMBOLS[
        "tests/test_target_catalog_boundary.py"
    ]
    - frozenset({"<module>"}),
    "tests/test_profile_write_boundary.py": ALLOWED_DUAL_FILE_SYMBOLS[
        "tests/test_profile_write_boundary.py"
    ],
    "tests/test_legacy_residue_gate.py": frozenset(
        {
            "test_mutation_unauthorized_dual_file_runtime_is_red",
            "test_mutation_concatenated_dual_file_read_is_red",
            "test_mutation_test_allowlist_abuse_is_red",
            "test_mutation_migration_module_scope_read_is_red",
            "test_mutation_stem_ext_name_binding_dual_file_read_is_red",
            "test_mutation_sensitive_paths_dual_file_read_is_red",
            "test_mutation_if_else_maybe_old_registration_is_red",
            "test_mutation_if_else_maybe_dual_file_read_is_red",
            "test_mutation_if_else_maybe_dynamic_import_is_red",
            "test_mutation_closure_nonlocal_mutates_tool_name_is_red",
            "test_mutation_global_mutation_before_sink_is_red",
            "test_mutation_loop_try_walrus_reassignment_before_sink_is_red",
            "test_mutation_param_shadows_safe_module_constant_is_red",
            "test_mutation_builder_discover_members_call_is_red",
            "test_mutation_builder_branch_assignment_is_red",
            "test_mutation_builder_append_extend_is_red",
            "test_mutation_builder_reassignment_is_red",
            "test_mutation_build_v2_document_direct_read_is_red",
            "test_mutation_bound_method_alias_sensitive_paths_is_red",
            "test_mutation_bound_method_alias_migration_helper_is_red",
            "test_mutation_private_reader_bound_alias_stays_green",
        }
    ),
}

SKIP_DIR_NAMES = frozenset(
    {".venv", "__pycache__", ".git", ".pytest_cache", "eggs", ".eggs", "build"}
)

_VENDORED_DISTINFO_RE = re.compile(r"^deps/pymysql-[^/]+\.dist-info(/|$)")
_VENDORED_PKG_RE = re.compile(r"^deps/pymysql(/|$)")


@dataclass(frozen=True)
class Violation:
    path: str
    kind: str
    summary: str

    def line(self) -> str:
        return f"{self.path}\t{self.kind}\t{self.summary}"


def _rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIR_NAMES for part in rel_parts):
            continue
        if path.suffix == ".pyc":
            continue
        # Never traverse Profile trees.
        if any(p.lower() == "profiles" for p in rel_parts):
            continue
        yield path


def _parse_yaml_provides_tools(text: str) -> List[str]:
    """Parse provides_tools in block or flow style without third-party YAML."""
    tools: List[str] = []
    in_section = False
    for raw in text.splitlines():
        line = raw.rstrip()
        # Flow: provides_tools: [a, b, c]
        m_flow = re.match(
            r"^provides_tools:\s*\[(.*)\]\s*$",
            line,
        )
        if m_flow:
            inner = m_flow.group(1).strip()
            if inner:
                for part in inner.split(","):
                    name = part.strip().strip("'\"")
                    if re.fullmatch(r"[A-Za-z0-9_]+", name):
                        tools.append(name)
            in_section = False
            continue
        if re.match(r"^provides_tools:\s*$", line):
            in_section = True
            continue
        if in_section:
            if re.match(r"^[A-Za-z0-9_]+:", line):
                break
            # Block entries: - name / - "name" / - 'name'
            m = re.match(r"^\s+-\s+[\"']?([A-Za-z0-9_]+)[\"']?\s*$", line)
            if m:
                tools.append(m.group(1))
                continue
            # Quoted flow scalar form on its own line: - "name"
            m_q = re.match(r'^\s+-\s+["\']([A-Za-z0-9_]+)["\']\s*$', line)
            if m_q:
                tools.append(m_q.group(1))
    return tools


def _parse_toml_pymysql_signals(text: str) -> List[str]:
    hits: List[str] = []
    if re.search(r"(?i)pymysql", text):
        hits.append("PyMySQL dependency/reference")
    if re.search(r"deps\*", text):
        hits.append("packages.find include deps*")
    if re.search(r'(?m)^\s*"deps(\.|")', text):
        hits.append("package-data deps entry")
    return hits


def _symbol_chain(stack: List[ast.AST]) -> List[str]:
    """Outermost-first chain of enclosing function / class names."""
    return [
        node.name
        for node in stack
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]


def _enclosing_symbol(stack: List[ast.AST]) -> str:
    """Qualified enclosing symbol, e.g. ``migrate_config._read_secure_bytes``.

    Reporting uses the qualified name so a nested / method definition can never
    be mistaken for the module-level symbol of the same bare name.
    """
    chain = _symbol_chain(stack)
    if not chain:
        return "<module>"
    return ".".join(chain)


def _allowlist_symbol(stack: List[ast.AST]) -> str:
    """Allowlist key: the module-level symbol that owns this code.

    Allowlists are declared for module top-level symbols only. A shadow
    definition nested inside another function (or a method of an arbitrary
    class) keys on its *outermost* owner, so it cannot borrow the allowlist
    entry of a private reader by copying its name.
    """
    chain = _symbol_chain(stack)
    if not chain:
        return "<module>"
    return chain[0]


# Sentinel: name is known-invalid in this scope (reassigned / param / uncertain).
_INVALID: Optional[str] = None

# Names suggesting builder candidate/member/package/file inclusion containers.
_BUILDER_CONTAINER_NAME_RE = re.compile(
    r"(?i)(candidate|member|package|archive|source|files?|include|payload|artifact)"
)
_BUILDER_MUTATORS = frozenset({"append", "extend", "update", "add", "insert"})
_PATH_CTOR_NAMES = frozenset({"Path", "PurePath", "PurePosixPath", "PosixPath"})


class _ConstEnv:
    """Conservative lexical-scope abstract env for immutable strings / aliases."""

    __slots__ = (
        "parent",
        "bindings",
        "path_vals",
        "read_aliases",
        "fn_writes",
        "global_names",
        "nonlocal_names",
    )

    def __init__(self, parent: Optional["_ConstEnv"] = None) -> None:
        self.parent = parent
        # name -> folded str, or None if invalidated in this frame
        self.bindings: Dict[str, Optional[str]] = {}
        # name -> folded path string for Path(...) objects, or None if unknown
        self.path_vals: Dict[str, Optional[str]] = {}
        # name -> folded path for bound read/open method aliases, or None unknown
        self.read_aliases: Dict[str, Optional[str]] = {}
        # local callable name -> outer/global names it may write
        self.fn_writes: Dict[str, Set[str]] = {}
        # Declarations in this function frame
        self.global_names: Set[str] = set()
        self.nonlocal_names: Set[str] = set()

    def lookup(self, name: str) -> Tuple[str, Optional[str]]:
        """Return (status, value) with status in bound|invalid|missing."""
        if name in self.bindings:
            val = self.bindings[name]
            if val is None:
                return "invalid", None
            return "bound", val
        if self.parent is not None:
            return self.parent.lookup(name)
        return "missing", None

    def lookup_path(self, name: str) -> Tuple[str, Optional[str]]:
        if name in self.path_vals:
            val = self.path_vals[name]
            if val is None:
                return "invalid", None
            return "bound", val
        if self.parent is not None:
            return self.parent.lookup_path(name)
        return "missing", None

    def lookup_read_alias(self, name: str) -> Tuple[str, Optional[str]]:
        if name in self.read_aliases:
            val = self.read_aliases[name]
            if val is None:
                return "invalid", None
            return "bound", val
        if self.parent is not None:
            return self.parent.lookup_read_alias(name)
        return "missing", None

    def lookup_fn_writes(self, name: str) -> Optional[Set[str]]:
        if name in self.fn_writes:
            return self.fn_writes[name]
        if self.parent is not None:
            return self.parent.lookup_fn_writes(name)
        return None

    def bind(self, name: str, value: str) -> None:
        self.bindings[name] = value
        # Concrete string bind clears path/alias for the same name.
        self.path_vals.pop(name, None)
        self.read_aliases.pop(name, None)

    def invalidate(self, name: str) -> None:
        self.bindings[name] = _INVALID
        self.path_vals[name] = _INVALID
        self.read_aliases[name] = _INVALID

    def bind_path(self, name: str, value: Optional[str]) -> None:
        self.path_vals[name] = value
        self.bindings[name] = _INVALID
        self.read_aliases.pop(name, None)

    def bind_read_alias(self, name: str, value: Optional[str]) -> None:
        self.read_aliases[name] = value
        self.bindings[name] = _INVALID
        self.path_vals.pop(name, None)

    def bind_fn_writes(self, name: str, writes: Set[str]) -> None:
        self.fn_writes[name] = set(writes)

    def fork(self) -> "_ConstEnv":
        """Copy local maps for a branch; share parent / declaration sets."""
        child = _ConstEnv(parent=self.parent)
        child.bindings = dict(self.bindings)
        child.path_vals = dict(self.path_vals)
        child.read_aliases = dict(self.read_aliases)
        child.fn_writes = {k: set(v) for k, v in self.fn_writes.items()}
        child.global_names = self.global_names
        child.nonlocal_names = self.nonlocal_names
        return child

    def adopt(self, other: "_ConstEnv") -> None:
        self.bindings = dict(other.bindings)
        self.path_vals = dict(other.path_vals)
        self.read_aliases = dict(other.read_aliases)
        self.fn_writes = {k: set(v) for k, v in other.fn_writes.items()}

    def merge_from(self, branches: Sequence["_ConstEnv"]) -> None:
        """Merge branch forks: same immutable value kept; else UNKNOWN."""
        if not branches:
            return
        keys: Set[str] = set()
        path_keys: Set[str] = set()
        alias_keys: Set[str] = set()
        for b in branches:
            keys |= set(b.bindings)
            path_keys |= set(b.path_vals)
            alias_keys |= set(b.read_aliases)
        # Also consider names present pre-branch but written in some forks only —
        # handled because forks copy pre-branch maps.
        for name in keys:
            vals: List[Optional[str]] = []
            any_invalid = False
            for b in branches:
                if name in b.bindings:
                    v = b.bindings[name]
                    if v is None:
                        any_invalid = True
                    vals.append(v)
                else:
                    st, v = self.lookup(name)
                    if st == "invalid":
                        any_invalid = True
                        vals.append(None)
                    elif st == "bound":
                        vals.append(v)
                    else:
                        vals.append(None)
                        any_invalid = True
            if any_invalid or len(set(vals)) != 1 or vals[0] is None:
                self.bindings[name] = _INVALID
            else:
                self.bindings[name] = vals[0]
        for name in path_keys:
            vals = []
            any_invalid = False
            for b in branches:
                if name in b.path_vals:
                    v = b.path_vals[name]
                    if v is None:
                        any_invalid = True
                    vals.append(v)
                else:
                    st, v = self.lookup_path(name)
                    if st == "bound":
                        vals.append(v)
                    else:
                        any_invalid = True
                        vals.append(None)
            if any_invalid or len(set(vals)) != 1 or vals[0] is None:
                self.path_vals[name] = _INVALID
            else:
                self.path_vals[name] = vals[0]
        for name in alias_keys:
            vals = []
            any_invalid = False
            for b in branches:
                if name in b.read_aliases:
                    v = b.read_aliases[name]
                    if v is None:
                        any_invalid = True
                    vals.append(v)
                else:
                    st, v = self.lookup_read_alias(name)
                    if st == "bound":
                        vals.append(v)
                    else:
                        any_invalid = True
                        vals.append(None)
            if any_invalid or len(set(vals)) != 1 or vals[0] is None:
                self.read_aliases[name] = _INVALID
            else:
                self.read_aliases[name] = vals[0]
        # fn_writes: union across branches
        fn_keys: Set[str] = set()
        for b in branches:
            fn_keys |= set(b.fn_writes)
        for name in fn_keys:
            merged: Set[str] = set()
            for b in branches:
                if name in b.fn_writes:
                    merged |= b.fn_writes[name]
                elif name in self.fn_writes:
                    merged |= self.fn_writes[name]
            self.fn_writes[name] = merged


def _fold_str(
    node: ast.AST, env: Optional[_ConstEnv] = None
) -> Optional[str]:
    """Safe compile-time string folding with optional lexical Name bindings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and env is not None:
        status, val = env.lookup(node.id)
        return val if status == "bound" else None
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                inner = _fold_str(v.value, env)
                if inner is None:
                    return None
                parts.append(inner)
            else:
                piece = _fold_str(v, env)
                if piece is None:
                    return None
                parts.append(piece)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str(node.left, env)
        right = _fold_str(node.right, env)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.IfExp):
        # Both arms must agree on the same immutable string.
        body = _fold_str(node.body, env)
        orelse = _fold_str(node.orelse, env)
        if body is not None and body == orelse:
            return body
        return None
    if isinstance(node, ast.Call):
        func = node.func
        # "".join([...]) / "".join((...))
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "join"
            and isinstance(func.value, ast.Constant)
            and isinstance(func.value.value, str)
            and node.args
        ):
            seq = node.args[0]
            elts: Optional[Sequence[ast.AST]] = None
            if isinstance(seq, (ast.List, ast.Tuple)):
                elts = seq.elts
            if elts is not None:
                parts = [_fold_str(e, env) for e in elts]
                if all(p is not None for p in parts):
                    return func.value.value.join(parts)  # type: ignore[arg-type]
    return None


def _resolve_str(
    node: ast.AST, env: Optional[_ConstEnv]
) -> Tuple[str, Optional[str]]:
    """Return ('resolved', s) | ('unresolved', None). Never evaluates code."""
    folded = _fold_str(node, env)
    if folded is not None:
        return "resolved", folded
    return "unresolved", None


def _is_dynamic_unresolved(
    node: ast.AST, env: Optional[_ConstEnv]
) -> bool:
    """True when sink arg is dynamically unresolved (fail closed).

    Parameters, rebindings, path-merged UNKNOWN, calls, and non-foldable
    expressions fail closed. Bare missing Names remain non-dynamic except at
    dedicated dynamic-import sinks (handled by callers).
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return False
    if isinstance(node, ast.Name) and env is not None:
        status, _ = env.lookup(node.id)
        if status == "bound":
            return False
        if status == "invalid":
            return True
        return False
    if isinstance(node, ast.Name):
        return False
    folded = _fold_str(node, env)
    return folded is None


def _string_values(node: ast.AST, env: Optional[_ConstEnv] = None) -> List[str]:
    folded = _fold_str(node, env)
    if folded is not None:
        return [folded]
    out: List[str] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
    elif isinstance(node, ast.JoinedStr):
        for v in node.values:
            out.extend(_string_values(v, env))
    return out


def _assign_target_names(target: ast.AST) -> List[str]:
    names: List[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_assign_target_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_assign_target_names(target.value))
    return names


def _invalidate_targets(env: _ConstEnv, target: ast.AST) -> None:
    for name in _assign_target_names(target):
        env.invalidate(name)
    # Attribute / subscript writes are uncertain for the base name when Name.
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        env.invalidate(target.value.id)
    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
        env.invalidate(target.value.id)


def _module_env(env: _ConstEnv) -> _ConstEnv:
    cur = env
    while cur.parent is not None:
        cur = cur.parent
    return cur


def _resolve_write_env(env: _ConstEnv, name: str) -> _ConstEnv:
    """Env frame that should receive a write, honouring global/nonlocal."""
    if name in env.global_names:
        return _module_env(env)
    if name in env.nonlocal_names:
        cur = env.parent
        while cur is not None:
            if name in cur.bindings or name in cur.path_vals or name in cur.read_aliases:
                return cur
            if cur.parent is None:
                return cur
            cur = cur.parent
        return env
    return env


def _path_from_value(value: ast.AST, env: _ConstEnv) -> Tuple[str, Optional[str]]:
    """Return ('resolved', path) | ('unresolved', None) | ('none', None)."""
    if isinstance(value, ast.Call):
        fname, _ = _call_func_name(value)
        if fname in _PATH_CTOR_NAMES and value.args:
            st, folded = _resolve_str(value.args[0], env)
            if st == "resolved":
                return "resolved", folded
            return "unresolved", None
    if isinstance(value, ast.Name):
        return env.lookup_path(value.id)
    return "none", None


def _bound_read_from_value(
    value: ast.AST, env: _ConstEnv
) -> Tuple[str, Optional[str]]:
    """Detect ``p.read_text`` / ``Path(...).read_text`` bound-method aliases."""
    if not isinstance(value, ast.Attribute):
        return "none", None
    if value.attr not in PATH_READ_ATTRS and value.attr not in {"read", "readline", "readlines"}:
        # open is a Name, not attribute — handled elsewhere
        if value.attr not in PATH_READ_ATTRS:
            return "none", None
    if value.attr not in PATH_READ_ATTRS:
        return "none", None
    # Path("credentials.json").read_text
    if isinstance(value.value, ast.Call):
        st, path = _path_from_value(value.value, env)
        if st == "resolved":
            return "resolved", path
        if st == "unresolved":
            return "unresolved", None
    if isinstance(value.value, ast.Name):
        st, path = env.lookup_path(value.value.id)
        if st == "bound":
            return "resolved", path
        if st == "invalid":
            return "unresolved", None
        # Unknown path object — fail closed when used as read alias
        return "unresolved", None
    return "unresolved", None


def _apply_assignment(env: _ConstEnv, target: ast.AST, value: ast.AST) -> None:
    """Bind simple Name = foldable string / path / read alias; else invalidate."""
    if isinstance(target, ast.Name):
        write_env = _resolve_write_env(env, target.id)
        folded = _fold_str(value, env)
        if folded is not None:
            write_env.bind(target.id, folded)
            return
        pst, pval = _path_from_value(value, env)
        if pst == "resolved":
            write_env.bind_path(target.id, pval)
            return
        if pst == "unresolved":
            write_env.bind_path(target.id, None)
            return
        rst, rval = _bound_read_from_value(value, env)
        if rst == "resolved":
            write_env.bind_read_alias(target.id, rval)
            return
        if rst == "unresolved":
            write_env.bind_read_alias(target.id, None)
            return
        write_env.invalidate(target.id)
        return
    # Tuple unpacking of literal tuple of strings: a, b = "x", "y"
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(
        value, (ast.Tuple, ast.List)
    ):
        if len(target.elts) == len(value.elts):
            for t, v in zip(target.elts, value.elts):
                _apply_assignment(env, t, v)
            return
    _invalidate_targets(env, target)


def _collect_assigned_names(node: ast.AST) -> Set[str]:
    names: Set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Assign):
            for t in sub.targets:
                names.update(_assign_target_names(t))
        elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
            names.add(sub.target.id)
        elif isinstance(sub, ast.AugAssign):
            names.update(_assign_target_names(sub.target))
        elif isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
            names.add(sub.target.id)
        elif isinstance(sub, (ast.For, ast.AsyncFor)):
            names.update(_assign_target_names(sub.target))
        elif isinstance(sub, ast.comprehension):
            names.update(_assign_target_names(sub.target))
        elif isinstance(sub, (ast.With, ast.AsyncWith)):
            for item in sub.items:
                if item.optional_vars is not None:
                    names.update(_assign_target_names(item.optional_vars))
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            names.add(sub.name)
        elif isinstance(sub, ast.Delete):
            for t in sub.targets:
                names.update(_assign_target_names(t))
    return names


def _function_nonlocal_writes(node: ast.AST) -> Set[str]:
    """Names a nested function may write via nonlocal/global."""
    writes: Set[str] = set()
    globals_decl: Set[str] = set()
    nonlocals_decl: Set[str] = set()
    for stmt in getattr(node, "body", []) or []:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Global):
                globals_decl.update(sub.names)
            elif isinstance(sub, ast.Nonlocal):
                nonlocals_decl.update(sub.names)
    targets = globals_decl | nonlocals_decl
    if not targets:
        return writes
    for stmt in getattr(node, "body", []) or []:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    for n in _assign_target_names(t):
                        if n in targets:
                            writes.add(n)
            elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                if sub.target.id in targets:
                    writes.add(sub.target.id)
            elif isinstance(sub, ast.AugAssign):
                for n in _assign_target_names(sub.target):
                    if n in targets:
                        writes.add(n)
            elif isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                if sub.target.id in targets:
                    writes.add(sub.target.id)
            elif isinstance(sub, ast.Delete):
                for t in sub.targets:
                    for n in _assign_target_names(t):
                        if n in targets:
                            writes.add(n)
    return writes


def _builder_container_name(name: str) -> bool:
    return bool(_BUILDER_CONTAINER_NAME_RE.search(name))


def _legacy_member_in_text(text: str) -> Optional[str]:
    """Return a forbidden legacy module/vendor member path if present in text."""
    for mod in sorted(OLD_MODULES):
        if text == mod or text.endswith("/" + mod) or f"/{mod}" in f"/{text}":
            return mod
        # dotted form
        dotted = mod.replace("/", ".")
        if dotted.endswith(".py"):
            dotted = dotted[:-3]
        if text == dotted or text.endswith(dotted):
            return mod
    if text.startswith("deps/pymysql") or "/deps/pymysql" in text:
        return text if len(text) < 120 else "deps/pymysql"
    if re.search(r"(?i)pymysql", text) and "deps" in text:
        return "deps/pymysql"
    return None


_BUILDER_FILENAME_RE = re.compile(
    r"(?i)(build|package|dist|release|wheel|sdist|artifact|publish)"
)
AUDITOR_SELF_PATH = "scripts/audit_legacy_residue.py"


def _is_builder_path(rel: str) -> bool:
    """Scripts whose *literal* strings are audited as packaging members.

    Round 1E widens this from ``scripts/*build*.py`` to every ``scripts/*.py``:
    a ``MEMBERS = ["credential_guard/tools.py", "deps/pymysql"]`` list smuggled
    into ``scripts/package_dist.py`` was previously fully silent. Literal
    legacy members are cheap to detect and have no false-positive cost.
    """
    if rel == AUDITOR_SELF_PATH:
        # The auditor's own detection constants name the legacy modules by
        # design; scanning them as packaging members is pure self-reference.
        return False
    return rel.startswith("scripts/") and rel.endswith(".py")


def _is_packaging_builder_path(rel: str) -> bool:
    """Scripts that actually assemble artifacts.

    Only these get the aggressive *unresolved container* fail-closed rule:
    a dynamically built ``members``/``candidates`` list there really can decide
    artifact contents. Applying it to every e2e runner under ``scripts/`` just
    produced noise, which is what §3.7 exists to prevent.
    """
    if not rel.startswith("scripts/") or not rel.endswith(".py"):
        return False
    if rel == AUDITOR_SELF_PATH:
        return False
    if rel == "scripts/build_release_artifacts.py":
        return True
    return bool(_BUILDER_FILENAME_RE.search(Path(rel).name))


def _expr_is_dual_suspicious(
    node: ast.AST, tainted: Set[str], tainted_funcs: Set[str]
) -> bool:
    """True when a path expression could denote one of the old dual files.

    Round 1E scopes ``unresolved_dynamic_sink at path_read`` to paths that
    *may* reach ``credentials.json`` / ``targets.json``. A read built from an
    ordinary parameter (``Path(dest).write_bytes(...)`` in an adapter) is not a
    dual-file read and must not consume the gate's signal budget.
    """
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if _mentions_dual_file(sub.value):
                return True
        elif isinstance(sub, ast.Name):
            if sub.id in tainted:
                return True
        elif isinstance(sub, ast.Call):
            fname, _ = _call_func_name(sub)
            if fname and fname in tainted_funcs:
                return True
    return False


_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)


class _DualTaint:
    """Scope-aware over-approximation of "this value may be an old dual file".

    Taint is per lexical scope (module / each function / each lambda) with
    parent scopes visible to children, so a helper named ``path`` in one
    function cannot be poisoned by an unrelated ``path`` elsewhere in the file
    — that file-global confusion is exactly what produced the 384-entry
    ``path_read`` false-positive wave in Round 1D.

    Propagation: literal dual-file names, assignments, loop / with /
    comprehension targets, call arguments into locally defined functions
    (parameter taint), and functions that return tainted expressions.
    """

    def __init__(self, tree: ast.AST) -> None:
        self.tainted: Dict[int, Set[str]] = {}
        self.tainted_funcs: Set[str] = set()
        self.parent: Dict[int, Optional[int]] = {}
        self.scope_of: Dict[int, int] = {}
        self.functions: Dict[str, ast.AST] = {}
        self._index(tree)
        self._solve(tree)

    # --- indexing ---------------------------------------------------------
    def _index(self, tree: ast.AST) -> None:
        def walk(node: ast.AST, scope: ast.AST, parent_scope: Optional[ast.AST]) -> None:
            self.parent.setdefault(id(scope), id(parent_scope) if parent_scope else None)
            self.tainted.setdefault(id(scope), set())
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions.setdefault(child.name, child)
                if isinstance(child, _SCOPE_NODES):
                    self.scope_of[id(child)] = id(scope)
                    walk(child, child, scope)
                else:
                    self.scope_of[id(child)] = id(scope)
                    walk(child, scope, parent_scope)

        if isinstance(tree, ast.Module):
            self.scope_of[id(tree)] = id(tree)
            walk(tree, tree, None)

    def _scope_id(self, node: ast.AST) -> int:
        return self.scope_of.get(id(node), 0)

    def visible(self, scope_id: int) -> Set[str]:
        out: Set[str] = set()
        cur: Optional[int] = scope_id
        while cur is not None:
            out |= self.tainted.get(cur, set())
            cur = self.parent.get(cur)
        return out

    # --- solving ----------------------------------------------------------
    def suspicious_in(self, node: Optional[ast.AST], scope_id: int) -> bool:
        if node is None:
            return False
        return _expr_is_dual_suspicious(node, self.visible(scope_id), self.tainted_funcs)

    def suspicious(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        return self.suspicious_in(node, self._scope_id(node))

    def _taint(self, scope_id: int, names: Iterable[str]) -> bool:
        bucket = self.tainted.setdefault(scope_id, set())
        changed = False
        for name in names:
            if name not in bucket:
                bucket.add(name)
                changed = True
        return changed

    @staticmethod
    def _params(fn: ast.AST) -> List[str]:
        args = getattr(fn, "args", None)
        if args is None:
            return []
        return [
            a.arg
            for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        ]

    def _solve(self, tree: ast.AST) -> None:
        for _ in range(12):
            changed = False
            for node in ast.walk(tree):
                scope = self._scope_id(node)
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    value = node.value
                    if value is None or not self.suspicious_in(value, scope):
                        continue
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for target in targets:
                        changed |= self._taint(scope, _assign_target_names(target))
                        if isinstance(
                            target, (ast.Attribute, ast.Subscript)
                        ) and isinstance(target.value, ast.Name):
                            changed |= self._taint(scope, [target.value.id])
                elif isinstance(node, ast.AugAssign):
                    if self.suspicious_in(node.value, scope):
                        changed |= self._taint(
                            scope, _assign_target_names(node.target)
                        )
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    if self.suspicious_in(node.iter, scope):
                        changed |= self._taint(
                            scope, _assign_target_names(node.target)
                        )
                elif isinstance(node, ast.comprehension):
                    if self.suspicious_in(node.iter, scope):
                        changed |= self._taint(
                            scope, _assign_target_names(node.target)
                        )
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if item.optional_vars is not None and self.suspicious_in(
                            item.context_expr, scope
                        ):
                            changed |= self._taint(
                                scope, _assign_target_names(item.optional_vars)
                            )
                elif isinstance(node, ast.Call):
                    fname, _ = _call_func_name(node)
                    fn = self.functions.get(fname)
                    if fn is None:
                        continue
                    params = self._params(fn)
                    callee_scope = id(fn)
                    for idx, arg in enumerate(node.args):
                        if self.suspicious_in(arg, scope) and idx < len(params):
                            changed |= self._taint(callee_scope, [params[idx]])
                    for kw in node.keywords:
                        if not self.suspicious_in(kw.value, scope):
                            continue
                        if kw.arg is None:
                            changed |= self._taint(callee_scope, params)
                        else:
                            changed |= self._taint(callee_scope, [kw.arg])
            for name, fn in self.functions.items():
                if name in self.tainted_funcs:
                    continue
                for sub in ast.walk(fn):
                    if isinstance(sub, ast.Return) and self.suspicious_in(
                        sub.value, self._scope_id(sub)
                    ):
                        self.tainted_funcs.add(name)
                        changed = True
                        break
            if not changed:
                break


def _note_unresolved_sink(
    violations: List[Violation], rel: str, symbol: str, sink: str
) -> None:
    """Fail closed at security-critical sinks; never echo source values."""
    violations.append(
        Violation(
            rel,
            "unresolved_dynamic_sink",
            f"symbol={symbol} unresolved dynamic at {sink}",
        )
    )


def _legacy_part_applies(part: str, *, guard_scoped: bool) -> bool:
    """Whether a matching bare segment really names the deleted plugin module.

    ``guard_scoped`` means the segment was reached through the plugin package —
    a relative import, or a dotted path rooted at ``credential_guard``. Host
    homonyms only count when guard-scoped; every other legacy name counts
    unconditionally.
    """
    if part in HOST_HOMONYM_MODULES:
        return guard_scoped
    return True


def _import_from_legacy(node: ast.ImportFrom) -> List[str]:
    hits: List[str] = []
    module_parts = node.module.split(".") if node.module else []
    # ``from .tools import X`` / ``from . import tools`` /
    # ``from credential_guard.tools import X`` are plugin-scoped; a top-level
    # ``from tools.approval import X`` is the Hermes host package.
    guard_scoped = bool(node.level) or module_parts[:1] == ["credential_guard"]
    for part in module_parts:
        if part in OLD_IMPORT_MODULES and _legacy_part_applies(
            part, guard_scoped=guard_scoped
        ):
            hits.append(part)
    for alias in node.names:
        if alias.name in OLD_IMPORT_MODULES and _legacy_part_applies(
            alias.name, guard_scoped=guard_scoped
        ):
            hits.append(alias.name)
    return sorted(set(hits))


def _legacy_module_from_string(mod: str) -> Optional[str]:
    """Legacy module named by a dotted/slashed module string, if any.

    Same qualified-path rule as :func:`_import_from_legacy`: a leading dot
    (relative ``import_module(".tools", package=...)``) or a
    ``credential_guard`` root makes a host homonym count as residue.
    """
    dotted = mod.replace("/", ".")
    parts = dotted.split(".")
    guard_scoped = dotted.startswith(".") or parts[:1] == ["credential_guard"]
    for part in parts:
        if part in OLD_IMPORT_MODULES and _legacy_part_applies(
            part, guard_scoped=guard_scoped
        ):
            return part
    return None


def _is_historical_doc(rel: str) -> bool:
    if rel.startswith("docs/"):
        return True
    base = Path(rel).name
    if re.match(r"^\.(r2|r3|r4|m0|m2|m3)", base):
        return True
    return False


def _allowlist_key(symbol: str) -> str:
    """Map a qualified symbol to its module-top-level owner (allowlist key).

    Allowlists only ever name module top-level symbols, so a shadow definition
    (``migrate_config._read_secure_bytes``, ``Shim._read_secure_bytes``) keys on
    the outer owner and cannot inherit a private reader's permission.
    """
    return symbol.split(".", 1)[0]


def _dual_file_symbol_allowed(rel: str, symbol: str) -> bool:
    symbol = _allowlist_key(symbol)
    if rel in ALLOWED_DUAL_FILE_SYMBOLS:
        return symbol in ALLOWED_DUAL_FILE_SYMBOLS[rel]
    if _is_historical_doc(rel):
        return True
    # Old runtime backend module itself — reported via old_module, not dual-file.
    if rel == "credential_guard/file_backend.py":
        return True
    return False


def _dual_file_read_allowed(rel: str, symbol: str) -> bool:
    """Runtime path reads: ``<module>`` never allowed; symbol must be read-scoped."""
    if symbol == "<module>":
        return False
    symbol = _allowlist_key(symbol)
    if rel in ALLOWED_DUAL_FILE_READ_SYMBOLS:
        return symbol in ALLOWED_DUAL_FILE_READ_SYMBOLS[rel]
    if _is_historical_doc(rel):
        return True
    if rel == "credential_guard/file_backend.py":
        return True
    return False


def _is_docstring(stack: List[ast.AST], node: ast.Constant) -> bool:
    """True when this string constant is a module/class/function docstring."""
    if not stack:
        return False
    parent = stack[-1]
    if not isinstance(parent, ast.Expr):
        return False
    if len(stack) < 2:
        return False
    owner = stack[-2]
    body = getattr(owner, "body", None)
    if not body:
        return False
    return body[0] is parent


def _mentions_dual_file(text: str) -> bool:
    if text in DUAL_FILE_NAMES:
        return True
    for name in DUAL_FILE_NAMES:
        if name in text:
            return True
    return False


def _call_func_name(node: ast.Call) -> Tuple[str, Optional[str]]:
    """Return (attr_or_name, attribute_base_hint)."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr, None
    if isinstance(func, ast.Name):
        return func.id, None
    return "", None


def _path_ctor_folded_arg(
    node: ast.AST, env: Optional[_ConstEnv] = None
) -> Optional[str]:
    """If node is Path(...)/PurePath(...) with foldable arg, return folded string."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    name = ""
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = func.attr
    if name not in {"Path", "PurePath", "PurePosixPath", "PosixPath"}:
        return None
    if not node.args:
        return None
    return _fold_str(node.args[0], env)


_MODULE_CONST_CACHE: Dict[Tuple[str, int, int], Dict[str, Optional[str]]] = {}


def _module_top_level_strings(path: Path) -> Dict[str, Optional[str]]:
    """Module top-level ``NAME = "literal"`` bindings (None when not a literal)."""
    try:
        stat = path.stat()
    except OSError:
        return {}
    key = (str(path), int(stat.st_mtime_ns), int(stat.st_size))
    cached = _MODULE_CONST_CACHE.get(key)
    if cached is not None:
        return cached
    out: Dict[str, Optional[str]] = {}
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError):
        _MODULE_CONST_CACHE[key] = out
        return out
    env = _ConstEnv()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    folded = _fold_str(node.value, env)
                    out[target.id] = folded
                    if folded is not None:
                        env.bind(target.id, folded)
                    else:
                        env.invalidate(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            folded = _fold_str(node.value, env) if node.value is not None else None
            out[node.target.id] = folded
            if folded is not None:
                env.bind(node.target.id, folded)
            else:
                env.invalidate(node.target.id)
    _MODULE_CONST_CACHE[key] = out
    return out


def _resolve_import_source(root: Path, rel: str, node: ast.ImportFrom) -> Optional[Path]:
    """Locate the in-tree source file an ``ImportFrom`` refers to, if any."""
    if node.level:
        base = Path(rel).parent
        for _ in range(node.level - 1):
            base = base.parent
        parts = node.module.split(".") if node.module else []
        target = base.joinpath(*parts) if parts else base
    else:
        if not node.module:
            return None
        target = Path(*node.module.split("."))
    candidates = [
        root / target.with_suffix(".py"),
        root / target / "__init__.py",
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _register_tool_alias_names(tree: ast.AST) -> Set[str]:
    """Names bound to a ``register_tool`` callable (``rt = reg.register_tool``).

    Over-approximating on purpose: any assignment whose value is a
    ``.register_tool`` attribute or the bare name counts, in any scope.
    """
    out: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            value = node.value
            if value is None:
                continue
            hit = (
                isinstance(value, ast.Attribute) and value.attr == "register_tool"
            ) or (isinstance(value, ast.Name) and value.id == "register_tool")
            if not hit:
                continue
            for target in targets:
                out.update(_assign_target_names(target))
    return out


def _collect_imported_string_consts(
    root: Path, rel: str, tree: ast.AST
) -> Dict[str, Optional[str]]:
    """Resolve ``from .mod import NAME`` string constants declared in-tree.

    Value is the folded string when the source module binds a literal, or None
    when the source cannot be resolved (caller fails closed at critical sinks).
    """
    out: Dict[str, Optional[str]] = {}
    if not isinstance(tree, ast.Module):
        return out
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        src = _resolve_import_source(root, rel, node)
        consts = _module_top_level_strings(src) if src is not None else {}
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            out[local] = consts.get(alias.name)
    return out


def _scan_python(root: Path, path: Path, rel: str, violations: List[Violation]) -> None:
    try:
        src = path.read_text(encoding="utf-8")
    except OSError as exc:
        violations.append(
            Violation(
                rel, "io_error", f"cannot read python source: {exc.__class__.__name__}"
            )
        )
        return
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError as exc:
        violations.append(Violation(rel, "syntax_error", f"AST parse failed: {exc.msg}"))
        return

    stack: List[ast.AST] = []
    module_env = _ConstEnv()
    # Cross-module constants: ``from .constants import LEGACY_NAME`` resolves to
    # the literal when declared in-tree; unresolvable imports stay UNKNOWN so
    # critical sinks fail closed instead of silently passing.
    imported_consts = _collect_imported_string_consts(root, rel, tree)
    for _name, _val in imported_consts.items():
        if _val is not None:
            module_env.bind(_name, _val)
        else:
            module_env.invalidate(_name)
    env_stack: List[_ConstEnv] = [module_env]
    critical = rel.startswith("credential_guard/") or rel.startswith("scripts/")
    register_tool_aliases = _register_tool_alias_names(tree)
    dual_taint = _DualTaint(tree)

    def env() -> _ConstEnv:
        return env_stack[-1]

    def dual_suspicious(node: Optional[ast.AST]) -> bool:
        """Whether an unresolved path expression may denote an old dual file."""
        return dual_taint.suspicious(node)

    def note_old_import(symbol: str, mod: str) -> None:
        if critical:
            violations.append(
                Violation(
                    rel,
                    "old_import",
                    f"symbol={symbol} imports legacy module {mod}",
                )
            )
            if (
                mod in {"deps_integrity", "file_backend"}
                and rel == "scripts/build_release_artifacts.py"
            ):
                violations.append(
                    Violation(
                        rel,
                        "builder_legacy_dependency",
                        f"symbol={symbol} loads legacy {mod}",
                    )
                )
            if _is_builder_path(rel) and mod in OLD_IMPORT_MODULES:
                violations.append(
                    Violation(
                        rel,
                        "builder_legacy_dependency",
                        f"symbol={symbol} builder loads legacy {mod}",
                    )
                )
        if mod == "file_backend" and rel in DUAL_FILE_FORBIDDEN_IMPORT_PATHS:
            violations.append(
                Violation(
                    rel,
                    "dual_file_runtime",
                    f"symbol={symbol} imports file_backend",
                )
            )

    def is_register_tool_call(node: ast.Call) -> bool:
        """register_tool by attribute, bare name, or a bound alias."""
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr == "register_tool"
        if isinstance(func, ast.Name):
            return func.id == "register_tool" or func.id in register_tool_aliases
        return False

    def note_builder_member(symbol: str, member: str) -> None:
        if not _is_builder_path(rel):
            return
        hit = _legacy_member_in_text(member)
        if hit:
            violations.append(
                Violation(
                    rel,
                    "builder_legacy_dependency",
                    f"symbol={symbol} builder member/candidate references legacy {hit}",
                )
            )

    def handle_dual_file_read(
        symbol: str,
        status: str,
        dual_target: Optional[str],
        *,
        suspicious: bool = True,
    ) -> None:
        if status == "unresolved":
            # Only fail closed when the path may actually reach an old dual
            # file; ordinary parameter-derived reads are not a residue signal.
            if not suspicious:
                return
            if critical and not _dual_file_read_allowed(rel, symbol):
                _note_unresolved_sink(
                    violations, rel, symbol, "path_read"
                )
            elif (
                rel.startswith("tests/")
                and not _dual_file_read_allowed(rel, symbol)
            ):
                _note_unresolved_sink(
                    violations, rel, symbol, "path_read"
                )
            return
        if dual_target is None or not _mentions_dual_file(dual_target):
            return
        if critical:
            if not _dual_file_read_allowed(rel, symbol):
                violations.append(
                    Violation(
                        rel,
                        "dual_file_runtime",
                        f"symbol={symbol} runtime-reads dual-file",
                    )
                )
        elif rel.startswith("tests/"):
            if not _dual_file_read_allowed(rel, symbol):
                violations.append(
                    Violation(
                        rel,
                        "dual_file_runtime",
                        f"symbol={symbol} unauthorized dual-file test read",
                    )
                )

    class Visitor(ast.NodeVisitor):
        def generic_visit(self, node: ast.AST) -> None:
            stack.append(node)
            try:
                super().generic_visit(node)
            finally:
                stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function_like(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function_like(node)

        def _visit_function_like(self, node: ast.AST) -> None:
            # Record closure write effects on the outer env before entering.
            fname = getattr(node, "name", None)
            if isinstance(fname, str):
                writes = _function_nonlocal_writes(node)
                if writes:
                    env().bind_fn_writes(fname, writes)
            # Default expressions evaluate in the *enclosing* scope at def time,
            # so they are visited before the function frame is pushed.
            outer_args = getattr(node, "args", None)
            if outer_args is not None:
                for default in list(outer_args.defaults) + [
                    d for d in outer_args.kw_defaults if d is not None
                ]:
                    self.visit(default)
            stack.append(node)
            child = _ConstEnv(parent=env())
            args = getattr(node, "args", None)
            if args is not None:
                for arg in list(args.posonlyargs) + list(args.args) + list(
                    args.kwonlyargs
                ):
                    child.invalidate(arg.arg)
                if args.vararg:
                    child.invalidate(args.vararg.arg)
                if args.kwarg:
                    child.invalidate(args.kwarg.arg)
            env_stack.append(child)
            try:
                for dec in getattr(node, "decorator_list", []):
                    self.visit(dec)
                returns = getattr(node, "returns", None)
                if returns is not None:
                    self.visit(returns)
                for stmt in node.body:
                    self.visit(stmt)
            finally:
                env_stack.pop()
                stack.pop()

        def visit_Lambda(self, node: ast.Lambda) -> None:
            for default in list(node.args.defaults) + [
                d for d in node.args.kw_defaults if d is not None
            ]:
                self.visit(default)
            stack.append(node)
            child = _ConstEnv(parent=env())
            for arg in list(node.args.posonlyargs) + list(node.args.args) + list(
                node.args.kwonlyargs
            ):
                child.invalidate(arg.arg)
            if node.args.vararg:
                child.invalidate(node.args.vararg.arg)
            if node.args.kwarg:
                child.invalidate(node.args.kwarg.arg)
            env_stack.append(child)
            try:
                self.visit(node.body)
            finally:
                env_stack.pop()
                stack.pop()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            stack.append(node)
            child = _ConstEnv(parent=env())
            env_stack.append(child)
            try:
                for dec in node.decorator_list:
                    self.visit(dec)
                for base in node.bases:
                    self.visit(base)
                for kw in node.keywords:
                    self.visit(kw.value)
                for stmt in node.body:
                    self.visit(stmt)
            finally:
                env_stack.pop()
                stack.pop()

        def _visit_branch_body(self, stmts, base: _ConstEnv) -> _ConstEnv:
            fork = base.fork()
            env_stack.append(fork)
            try:
                for stmt in stmts:
                    self.visit(stmt)
            finally:
                env_stack.pop()
            return fork

        def visit_If(self, node: ast.If) -> None:
            self.visit(node.test)
            base = env()
            then_env = self._visit_branch_body(node.body, base)
            else_env = self._visit_branch_body(node.orelse, base)
            base.merge_from([then_env, else_env])

        def visit_IfExp(self, node: ast.IfExp) -> None:
            self.visit(node.test)
            base = env()
            then_fork = base.fork()
            env_stack.append(then_fork)
            try:
                self.visit(node.body)
            finally:
                env_stack.pop()
            else_fork = base.fork()
            env_stack.append(else_fork)
            try:
                self.visit(node.orelse)
            finally:
                env_stack.pop()
            base.merge_from([then_fork, else_fork])

        def visit_For(self, node: ast.For) -> None:
            self.visit(node.iter)
            base = env()
            zero = base.fork()
            once = base.fork()
            env_stack.append(once)
            try:
                # Loop back edge: every name assigned anywhere in the loop is
                # UNKNOWN on entry to the body, because iteration N sees the
                # value written by iteration N-1. Invalidating *before* the
                # body is a sound over-approximation of the fixpoint.
                _invalidate_targets(once, node.target)
                for name in _collect_assigned_names(node):
                    once.invalidate(name)
                for stmt in node.body:
                    self.visit(stmt)
                for name in _collect_assigned_names(node):
                    once.invalidate(name)
                for stmt in node.orelse:
                    self.visit(stmt)
            finally:
                env_stack.pop()
            base.merge_from([zero, once])

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self.visit_For(node)  # type: ignore[arg-type]

        def visit_While(self, node: ast.While) -> None:
            self.visit(node.test)
            base = env()
            zero = base.fork()
            once = base.fork()
            env_stack.append(once)
            try:
                # Same loop back-edge rule as visit_For (see comment there).
                for name in _collect_assigned_names(node):
                    once.invalidate(name)
                for stmt in node.body:
                    self.visit(stmt)
                for name in _collect_assigned_names(node):
                    once.invalidate(name)
                for stmt in node.orelse:
                    self.visit(stmt)
            finally:
                env_stack.pop()
            base.merge_from([zero, once])

        def visit_Try(self, node: ast.Try) -> None:
            base = env()
            body_fork = self._visit_branch_body(node.body, base)
            branches = [body_fork]
            for handler in node.handlers:
                hfork = base.fork()
                env_stack.append(hfork)
                try:
                    if handler.type is not None:
                        self.visit(handler.type)
                    if handler.name:
                        hfork.invalidate(handler.name)
                    for stmt in handler.body:
                        self.visit(stmt)
                finally:
                    env_stack.pop()
                branches.append(hfork)
            if node.orelse:
                else_fork = body_fork.fork()
                env_stack.append(else_fork)
                try:
                    for stmt in node.orelse:
                        self.visit(stmt)
                finally:
                    env_stack.pop()
                branches.append(else_fork)
            base.merge_from(branches)
            if node.finalbody:
                for stmt in node.finalbody:
                    self.visit(stmt)

        def visit_With(self, node: ast.With) -> None:
            for item in node.items:
                self.visit(item.context_expr)
                if item.optional_vars is not None:
                    _invalidate_targets(env(), item.optional_vars)
            for stmt in node.body:
                self.visit(stmt)

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            self.visit_With(node)  # type: ignore[arg-type]

        def visit_Global(self, node: ast.Global) -> None:
            env().global_names.update(node.names)

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            env().nonlocal_names.update(node.names)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            self.visit(node.value)
            _apply_assignment(env(), node.target, node.value)

        def _note_escaping_read_alias(
            self, symbol: str, target: ast.AST, value: ast.AST
        ) -> None:
            """A bound read alias stored somewhere we cannot track fails closed.

            ``holder["r"] = p.read_text`` / ``self.r = p.read_text`` /
            ``rs = [p.read_text]`` escape the Name-keyed env, so the later call
            site is invisible. Only dual-file-suspicious aliases are reported.
            """
            cur = env()
            candidates: List[ast.AST]
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                # Container element: escapes even when the target is a Name.
                candidates = list(value.elts)
            elif isinstance(value, ast.Dict):
                candidates = list(value.values)
            elif isinstance(target, ast.Name):
                # Plain ``r = p.read_text`` is tracked by the env — nothing to do.
                return
            else:
                candidates = [value]
            for cand in candidates:
                rst, rval = _bound_read_from_value(cand, cur)
                if rst == "none":
                    continue
                if rst == "resolved" and rval is not None:
                    handle_dual_file_read(symbol, "resolved", rval)
                    continue
                if dual_suspicious(cand):
                    _note_unresolved_sink(violations, rel, symbol, "path_read")

        def visit_Assign(self, node: ast.Assign) -> None:
            symbol = _enclosing_symbol(stack)
            self.visit(node.value)
            for t in node.targets:
                _apply_assignment(env(), t, node.value)
                self._note_escaping_read_alias(symbol, t, node.value)
                if _is_builder_path(rel):
                    self._scan_builder_assignment(symbol, t, node.value)
            for t in node.targets:
                if not isinstance(t, ast.Name):
                    self.visit(t)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            symbol = _enclosing_symbol(stack)
            if node.value is not None:
                self.visit(node.value)
                _apply_assignment(env(), node.target, node.value)
                self._note_escaping_read_alias(symbol, node.target, node.value)
                if _is_builder_path(rel):
                    self._scan_builder_assignment(symbol, node.target, node.value)
            if node.annotation is not None:
                self.visit(node.annotation)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            self.visit(node.value)
            _invalidate_targets(env(), node.target)
            if _is_packaging_builder_path(rel) and isinstance(node.target, ast.Name):
                if _builder_container_name(node.target.id):
                    _note_unresolved_sink(
                        violations,
                        rel,
                        _enclosing_symbol(stack),
                        "builder_member",
                    )
            if not isinstance(node.target, ast.Name):
                self.visit(node.target)

        def visit_Delete(self, node: ast.Delete) -> None:
            for t in node.targets:
                _invalidate_targets(env(), t)
                self.visit(t)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.type is not None:
                self.visit(node.type)
            if node.name:
                env().invalidate(node.name)
            for stmt in node.body:
                self.visit(stmt)

        def visit_comprehension(self, node: ast.comprehension) -> None:
            self.visit(node.iter)
            _invalidate_targets(env(), node.target)
            for if_ in node.ifs:
                self.visit(if_)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            symbol = _enclosing_symbol(stack)
            legacy = _import_from_legacy(node)
            for mod in legacy:
                note_old_import(symbol, mod)
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            symbol = _enclosing_symbol(stack)
            for alias in node.names:
                parts = alias.name.split(".")
                guard_scoped = parts[:1] == ["credential_guard"]
                for part in parts:
                    if part == "pymysql":
                        violations.append(
                            Violation(
                                rel,
                                "pymysql_import",
                                f"symbol={symbol} imports {alias.name}",
                            )
                        )
                    elif part in OLD_IMPORT_MODULES and _legacy_part_applies(
                        part, guard_scoped=guard_scoped
                    ):
                        note_old_import(symbol, part)
            self.generic_visit(node)

        def _scan_register_tool(
            self, symbol: str, node: ast.Call, cur: _ConstEnv
        ) -> None:
            """Tool name from keyword, first positional, or ``**kwargs`` unpack.

            Any form whose name cannot be resolved to a literal fails closed at
            critical paths — the sink decides registration identity, so an
            unknown name is indistinguishable from a legacy one.
            """

            def check_value(value: ast.AST, where: str) -> None:
                status, val = _resolve_str(value, cur)
                if status == "resolved":
                    if val in OLD_TOOL_NAMES:
                        violations.append(
                            Violation(
                                rel,
                                "old_registration",
                                f"symbol={symbol} register_tool({where}legacy)",
                            )
                        )
                    return
                if critical:
                    _note_unresolved_sink(
                        violations, rel, symbol, f"register_tool({where})"
                    )

            saw_name = False
            for kw in node.keywords:
                if kw.arg is None:
                    # ``register_tool(**opts)`` — the name may be hidden in the
                    # mapping; a literal dict is inspected, anything else fails closed.
                    if isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values):
                            kstatus, kval = _resolve_str(k, cur) if k is not None else (
                                "unresolved",
                                None,
                            )
                            if kstatus == "resolved" and kval == "name":
                                saw_name = True
                                check_value(v, "name=")
                                break
                        else:
                            if critical:
                                _note_unresolved_sink(
                                    violations, rel, symbol, "register_tool(**kwargs)"
                                )
                    elif critical:
                        _note_unresolved_sink(
                            violations, rel, symbol, "register_tool(**kwargs)"
                        )
                    continue
                if kw.arg == "name":
                    saw_name = True
                    check_value(kw.value, "name=")
            if not saw_name and node.args:
                # Positional form: register_tool("mysql_credential_action", fn)
                check_value(node.args[0], "positional name")
            elif not saw_name and not node.args and not node.keywords:
                if critical:
                    _note_unresolved_sink(
                        violations, rel, symbol, "register_tool(name=)"
                    )

        def _scan_builder_assignment(self, symbol: str, target, value) -> None:
            names = _assign_target_names(target)
            containerish = any(_builder_container_name(n) for n in names)
            self._scan_builder_value(symbol, value, container=containerish)
            if not containerish or not _is_packaging_builder_path(rel):
                return
            # Static list/tuple/set/dict literals are scanned element-wise above.
            if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                return
            if isinstance(value, ast.Call):
                _note_unresolved_sink(violations, rel, symbol, "builder_member")
                return
            if isinstance(
                value, (ast.Name, ast.BinOp, ast.JoinedStr, ast.IfExp, ast.Attribute)
            ):
                _note_unresolved_sink(violations, rel, symbol, "builder_member")

        def _scan_builder_value(
            self, symbol: str, value: ast.AST, *, container: bool = False
        ) -> None:
            """Scan a builder expression for legacy members.

            ``container=True`` marks values that really are member/candidate
            containers (named as such, or mutated through one). Only those get
            the unresolved fail-closed treatment; an arbitrary list argument
            such as a subprocess argv is scanned for literals only, which is
            what keeps §3.7's noise budget intact.
            """
            status, folded = _resolve_str(value, env())
            if status == "resolved" and folded is not None:
                note_builder_member(symbol, folded)
                return
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                for elt in value.elts:
                    st, fd = _resolve_str(elt, env())
                    if st == "resolved" and fd is not None:
                        note_builder_member(symbol, fd)
                    elif st == "unresolved" and not isinstance(elt, ast.Constant):
                        if not isinstance(elt, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                            if container and _is_packaging_builder_path(rel):
                                _note_unresolved_sink(
                                    violations, rel, symbol, "builder_member"
                                )
                        else:
                            self._scan_builder_value(
                                symbol, elt, container=container
                            )
                return
            if isinstance(value, ast.Dict):
                for k, v in zip(value.keys, value.values):
                    if k is not None:
                        self._scan_builder_value(symbol, k, container=container)
                    self._scan_builder_value(symbol, v, container=container)
                return
            if status == "unresolved" and isinstance(
                value, (ast.Call, ast.Name, ast.BinOp, ast.JoinedStr, ast.IfExp)
            ):
                if isinstance(value, ast.Call):
                    for arg in value.args:
                        self._scan_builder_value(symbol, arg, container=container)
                    for kw in value.keywords:
                        if kw.value is not None:
                            self._scan_builder_value(
                                symbol, kw.value, container=container
                            )

        def visit_Call(self, node: ast.Call) -> None:
            symbol = _enclosing_symbol(stack)
            func_name, _ = _call_func_name(node)
            cur = env()

            # Closure / global mutator calls invalidate captured bindings.
            if isinstance(node.func, ast.Name):
                writes = cur.lookup_fn_writes(node.func.id)
                if writes:
                    for wname in writes:
                        _resolve_write_env(cur, wname).invalidate(wname)
                        cur.invalidate(wname)

            # Bound read-method alias: reader = p.read_text; reader(...)
            # Arguments are irrelevant — read_text(encoding=...) /
            # opener("rb") / r(*args) all still perform the read.
            if isinstance(node.func, ast.Name):
                rst, rval = cur.lookup_read_alias(node.func.id)
                if rst == "bound" and rval is not None:
                    handle_dual_file_read(symbol, "resolved", rval)
                elif rst == "invalid":
                    handle_dual_file_read(
                        symbol,
                        "unresolved",
                        None,
                        suspicious=dual_suspicious(node.func),
                    )

            if is_register_tool_call(node):
                self._scan_register_tool(symbol, node, cur)

            if func_name in {"import_module", "__import__"}:
                if node.args:
                    status, folded = _resolve_str(node.args[0], cur)
                    if status == "resolved" and folded is not None:
                        legacy = _legacy_module_from_string(folded)
                        if legacy:
                            note_old_import(symbol, legacy)
                    elif _is_dynamic_unresolved(node.args[0], cur):
                        if critical:
                            _note_unresolved_sink(
                                violations, rel, symbol, "dynamic_import"
                            )
                    elif isinstance(node.args[0], ast.Name):
                        if critical:
                            _note_unresolved_sink(
                                violations, rel, symbol, "dynamic_import"
                            )

            if func_name in PATH_READ_ATTRS and isinstance(node.func, ast.Attribute):
                base_expr = node.func.value
                sus = dual_suspicious(base_expr)
                dual_target = _path_ctor_folded_arg(base_expr, cur)
                if dual_target is None:
                    dual_target = _fold_str(base_expr, cur)
                if dual_target is None and isinstance(base_expr, ast.Name):
                    pst, pval = cur.lookup_path(base_expr.id)
                    if pst == "bound":
                        dual_target = pval
                    elif pst == "invalid":
                        handle_dual_file_read(
                            symbol, "unresolved", None, suspicious=sus
                        )
                        dual_target = None
                        # fall through only if still None after invalid handled
                if dual_target is not None:
                    handle_dual_file_read(symbol, "resolved", dual_target)
                elif isinstance(base_expr, ast.Name):
                    pst, _ = cur.lookup_path(base_expr.id)
                    if pst != "invalid":
                        handle_dual_file_read(
                            symbol, "unresolved", None, suspicious=sus
                        )
                elif _is_dynamic_unresolved(base_expr, cur) or not isinstance(
                    base_expr, ast.Name
                ):
                    handle_dual_file_read(symbol, "unresolved", None, suspicious=sus)
            elif func_name in BUILTIN_READ_FUNCS and node.args:
                status, dual_target = _resolve_str(node.args[0], cur)
                if status == "resolved":
                    handle_dual_file_read(symbol, "resolved", dual_target)
                else:
                    alt = _path_ctor_folded_arg(node.args[0], cur)
                    if alt is not None:
                        handle_dual_file_read(symbol, "resolved", alt)
                    else:
                        handle_dual_file_read(
                            symbol,
                            "unresolved",
                            None,
                            suspicious=dual_suspicious(node.args[0]),
                        )

            # Builder container mutators: members.append / extend / update / add
            if _is_builder_path(rel):
                in_container = False
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in _BUILDER_MUTATORS and isinstance(
                        node.func.value, ast.Name
                    ):
                        in_container = _builder_container_name(node.func.value.id)
                        if in_container and _is_packaging_builder_path(rel):
                            cur.invalidate(node.func.value.id)
                            _note_unresolved_sink(
                                violations, rel, symbol, "builder_member"
                            )
                        else:
                            cur.invalidate(node.func.value.id)
                for arg in node.args:
                    st, fd = _resolve_str(arg, cur)
                    if st == "resolved" and fd:
                        note_builder_member(symbol, fd)
                    elif isinstance(arg, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                        self._scan_builder_value(symbol, arg, container=in_container)
                for kw in node.keywords:
                    if kw.value is not None:
                        st, fd = _resolve_str(kw.value, cur)
                        if st == "resolved" and fd:
                            note_builder_member(symbol, fd)
                        elif isinstance(
                            kw.value, (ast.List, ast.Tuple, ast.Set, ast.Dict)
                        ):
                            self._scan_builder_value(
                                symbol, kw.value, container=in_container
                            )

            self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> None:
            if not isinstance(node.value, str):
                return
            if _is_docstring(stack, node):
                return
            symbol = _enclosing_symbol(stack)
            val = node.value
            if val in OLD_TOOL_NAMES and rel.startswith("credential_guard/"):
                if rel in {
                    "credential_guard/__init__.py",
                    "credential_guard/cli.py",
                    "credential_guard/approval.py",
                    "credential_guard/tools.py",
                    "credential_guard/ssh_tools.py",
                }:
                    violations.append(
                        Violation(
                            rel,
                            "old_tool_name",
                            f"symbol={symbol} references tool {val}",
                        )
                    )
            if _mentions_dual_file(val):
                if critical:
                    if not _dual_file_symbol_allowed(rel, symbol):
                        violations.append(
                            Violation(
                                rel,
                                "dual_file_runtime",
                                f"symbol={symbol} references dual-file name",
                            )
                        )
                elif rel.startswith("tests/"):
                    if not _dual_file_symbol_allowed(rel, symbol):
                        violations.append(
                            Violation(
                                rel,
                                "dual_file_runtime",
                                f"symbol={symbol} unauthorized dual-file test reference",
                            )
                        )
            if _is_builder_path(rel):
                note_builder_member(symbol, val)
            self.generic_visit(node)

    Visitor().visit(tree)


def _scan_plugin_yaml(path: Path, rel: str, violations: List[Violation]) -> None:
    text = path.read_text(encoding="utf-8")
    for tool in _parse_yaml_provides_tools(text):
        if tool in OLD_TOOL_NAMES:
            violations.append(
                Violation(rel, "old_registration", f"provides_tools declares {tool}")
            )


def _scan_requirements(path: Path, rel: str, violations: List[Violation]) -> None:
    text = path.read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"(?i)pymysql", stripped):
            violations.append(
                Violation(rel, "pymysql_dependency", f"line {i}: {stripped[:60]}")
            )


def _scan_manifest_in(path: Path, rel: str, violations: List[Violation]) -> None:
    text = path.read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("prune"):
            continue
        if re.search(r"(?i)pymysql|\bdeps\b", stripped):
            violations.append(
                Violation(
                    rel, "pymysql_package_data", f"line {i}: {stripped[:80]}"
                )
            )


def _scan_pyproject(path: Path, rel: str, violations: List[Violation]) -> None:
    text = path.read_text(encoding="utf-8")
    for hit in _parse_toml_pymysql_signals(text):
        violations.append(Violation(rel, "pymysql_dependency", hit))


def _scan_release_metadata(path: Path, rel: str, violations: List[Violation]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        violations.append(
            Violation(
                rel, "io_error", f"release-metadata parse: {exc.__class__.__name__}"
            )
        )
        return
    if not isinstance(data, dict):
        return
    for key in data:
        kl = key.lower()
        if "pymysql" in kl or "vendored" in kl or key == "dist_info":
            violations.append(
                Violation(rel, "pymysql_dependency", f"metadata key {key}")
            )


def _note_vendored_path(rel: str, violations: List[Violation]) -> None:
    if _VENDORED_PKG_RE.match(rel) or _VENDORED_DISTINFO_RE.match(rel):
        root = rel.split("/", 2)
        display = "/".join(root[:2]) if len(root) >= 2 else rel
        violations.append(
            Violation(
                display,
                "vendored_pymysql",
                f"vendored member present: {rel}",
            )
        )


def audit_tree(root: Path) -> List[Violation]:
    """Return residue violations under root (sorted, deduped)."""
    root = root.resolve()
    found: List[Violation] = []
    seen: Set[Tuple[str, str, str]] = set()

    def add(v: Violation) -> None:
        key = (v.path, v.kind, v.summary)
        if key not in seen:
            seen.add(key)
            found.append(v)

    for rel in sorted(OLD_MODULES):
        if (root / rel).is_file():
            add(Violation(rel, "old_module", "legacy production module still present"))

    for path in _iter_files(root):
        rel = _rel(root, path)
        bucket: List[Violation] = []
        _note_vendored_path(rel, bucket)
        if rel == "plugin.yaml":
            _scan_plugin_yaml(path, rel, bucket)
        elif rel == "requirements.txt":
            _scan_requirements(path, rel, bucket)
        elif rel == "MANIFEST.in":
            _scan_manifest_in(path, rel, bucket)
        elif rel == "pyproject.toml":
            _scan_pyproject(path, rel, bucket)
        elif rel == "release-metadata.json":
            _scan_release_metadata(path, rel, bucket)
        elif path.suffix == ".py" and not rel.startswith("deps/"):
            _scan_python(root, path, rel, bucket)
        for v in bucket:
            add(v)

    # Also catch empty vendored dirs / dist-info dirs with only non-file members.
    deps = root / "deps"
    if deps.is_dir():
        for child in sorted(deps.iterdir()):
            name = child.name
            if name == "pymysql" or re.match(r"^pymysql-.+\.dist-info$", name):
                # Any presence of the tree root counts, even without files yet.
                marker = f"deps/{name}"
                if child.is_dir():
                    add(
                        Violation(
                            marker,
                            "vendored_pymysql",
                            f"vendored tree present: {marker}",
                        )
                    )

    return sorted(found, key=lambda v: (v.path, v.kind, v.summary))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_DEFAULT,
        help="Candidate tree root (default: repository root)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON violations")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"audit_legacy_residue: root not a directory: {root}", file=sys.stderr)
        return 2
    violations = audit_tree(root)
    if args.json:
        print(json.dumps([asdict(v) for v in violations], ensure_ascii=False, indent=2))
    else:
        if not violations:
            print("LEGACY_RESIDUE_CLEAN")
        else:
            print(f"LEGACY_RESIDUE_VIOLATIONS={len(violations)}")
            for v in violations:
                print(v.line())
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
