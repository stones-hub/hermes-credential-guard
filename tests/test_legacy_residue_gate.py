"""R5 Slice A: legacy residue gate — current tree RED; auditor unit mutations."""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_auditor():
    import sys

    path = REPO / "scripts" / "audit_legacy_residue.py"
    spec = importlib.util.spec_from_file_location("audit_legacy_residue", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Python 3.9 dataclasses require the module to be present in sys.modules
    # before exec_module when using from __future__ import annotations.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def auditor():
    return _load_auditor()


def _kinds(violations) -> set:
    return {v.kind for v in violations}


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def _clean_tree(tmp_path: Path) -> Path:
    """Minimal synthetic tree with no legacy residue."""
    root = tmp_path / "clean"
    _write(
        root / "plugin.yaml",
        """
        name: credential-guard
        provides_tools:
          - http_credential_request
          - credential_process_run
        """,
    )
    _write(root / "requirements.txt", "\n")
    _write(
        root / "pyproject.toml",
        """
        [project]
        name = "hermes-credential-guard"
        version = "0.3.1"
        dependencies = []

        [tool.setuptools.packages.find]
        include = ["credential_guard*"]
        """,
    )
    _write(root / "MANIFEST.in", "include plugin.yaml\nrecursive-include credential_guard *.py\n")
    _write(root / "release-metadata.json", "{}\n")
    _write(
        root / "credential_guard" / "__init__.py",
        """
        from .constants import TOOLSET_NAME
        from .reference_tools import HTTP_REFERENCE_TOOL, handle_http_credential_request
        from .process_tools import PROCESS_REFERENCE_TOOL, handle_credential_process_run

        def register(ctx):
            ctx.register_tool(name=HTTP_REFERENCE_TOOL, toolset=TOOLSET_NAME, schema={}, handler=handle_http_credential_request, check_fn=lambda: True, description="")
            ctx.register_tool(name=PROCESS_REFERENCE_TOOL, toolset=TOOLSET_NAME, schema={}, handler=handle_credential_process_run, check_fn=lambda: True, description="")
        """,
    )
    _write(root / "credential_guard" / "constants.py", 'TOOLSET_NAME = "credential_guard"\n')
    _write(
        root / "credential_guard" / "reference_tools.py",
        'HTTP_REFERENCE_TOOL = "http_credential_request"\ndef handle_http_credential_request(args, **kw): return ""\n',
    )
    _write(
        root / "credential_guard" / "process_tools.py",
        'PROCESS_REFERENCE_TOOL = "credential_process_run"\ndef handle_credential_process_run(args, **kw): return ""\n',
    )
    _write(
        root / "credential_guard" / "migration.py",
        """
        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        def migrate_config(store_dir):
            cred = store_dir / CREDENTIALS_FILENAME
            tgt = store_dir / TARGETS_FILENAME
            return cred, tgt
        """,
    )
    _write(
        root / "credential_guard" / "sensitive_paths.py",
        """
        _STORE_BASENAMES = frozenset({"credentials.json", "targets.json", "credential-guard.json"})

        def path_is_protected(raw_path: str) -> bool:
            return any(name in raw_path for name in _STORE_BASENAMES)
        """,
    )
    _write(
        root / "credential_guard" / "runtime_config.py",
        '''
        """Formal runtime: does not read credentials.json / targets.json."""

        def load_runtime():
            return "credential-guard.json"
        ''',
    )
    _write(
        root / "docs" / "historical.md",
        "Old layout used credentials.json and targets.json as dual files.\n",
    )
    return root


# R5 outcome: these residue classes must be gone from the live tree for good.
_ELIMINATED_RESIDUE_KINDS = frozenset(
    {
        "old_registration",
        "old_module",
        "vendored_pymysql",
        "pymysql_dependency",
        "pymysql_import",
        "pymysql_package_data",
    }
)

# Classes that legitimately survive R5, each explainable in place:
#   dual_file_runtime      — migration-domain code and the tests that exercise
#                            it must still name credentials.json / targets.json.
#   unresolved_dynamic_sink — fail-closed reports at dynamic sinks the auditor
#                            cannot resolve statically; by design, not residue.
_SURVIVING_RESIDUE_KINDS = frozenset({"dual_file_runtime", "unresolved_dynamic_sink"})

# Every file still allowed to carry a surviving-class finding, with its reason.
_EXPLAINED_RESIDUE_PATHS = {
    # register_tool(name=) resolves through a runtime constant — fail-closed.
    "credential_guard/__init__.py",
    # handler identity resolution imports by computed module name — fail-closed.
    "credential_guard/cli.py",
    # builder discovers its own interpreter path dynamically — fail-closed.
    "scripts/build_release_artifacts.py",
    # R2 e2e runner names the dual files it migrates from.
    "scripts/run_r2_e2e.py",
    # Migration / dual-file / sensitive-path test domain.
    "tests/companions/credential_guard_test/__init__.py",
    "tests/test_legacy_residue_gate.py",
    "tests/test_runtime_config_v2.py",
    "tests/test_tool_request_analysis.py",
    "tests/test_config_migration.py",
    "tests/test_target_catalog_boundary.py",
}


def test_live_tree_residue_clean_is_red(auditor):
    """R5 outcome: no legacy residue class survives on the live tree.

    Retired as a TDD RED anchor. Before the atomic delete this asserted that
    ``old_registration`` / ``old_module`` / vendored PyMySQL were *present*, to
    prove the auditor could see the old architecture. Those classes are now
    gone, so the anchor is inverted into the positive post-cleanup contract and
    a copy-tree mutation keeps it load-bearing.
    """
    violations = auditor.audit_tree(REPO)
    kinds = _kinds(violations)
    # The auditor itself must still be working (not silently failing to parse).
    assert "syntax_error" not in kinds, [v.line() for v in violations]
    assert "io_error" not in kinds, [v.line() for v in violations]

    eliminated = sorted(kinds & _ELIMINATED_RESIDUE_KINDS)
    assert eliminated == [], [
        v.line() for v in violations if v.kind in _ELIMINATED_RESIDUE_KINDS
    ]

    unexplained_kinds = sorted(kinds - _SURVIVING_RESIDUE_KINDS)
    assert unexplained_kinds == [], [
        v.line() for v in violations if v.kind not in _SURVIVING_RESIDUE_KINDS
    ]

    unexplained_paths = sorted(
        {v.path for v in violations} - _EXPLAINED_RESIDUE_PATHS
    )
    assert unexplained_paths == [], [
        v.line() for v in violations if v.path not in _EXPLAINED_RESIDUE_PATHS
    ]


def _copy_live_tree(tmp_path: Path) -> Path:
    """Temporary copy of the live workspace (skips venv / caches / VCS)."""
    import shutil

    dest = tmp_path / "live_copy"
    shutil.copytree(
        REPO,
        dest,
        ignore=shutil.ignore_patterns(
            ".venv", ".git", "__pycache__", ".pytest_cache", "*.pyc"
        ),
        symlinks=True,
    )
    return dest


def test_mutation_restored_legacy_module_in_copy_tree_is_red(auditor, tmp_path):
    """Copy tree: restoring an old module / old registration must go RED again.

    Keeps the post-cleanup contract above load-bearing — it can only stay green
    because the residue is really absent, not because the auditor stopped
    looking at the live layout.
    """
    root = _copy_live_tree(tmp_path)
    before = auditor.audit_tree(root)
    assert not (_kinds(before) & _ELIMINATED_RESIDUE_KINDS), [
        v.line() for v in before if v.kind in _ELIMINATED_RESIDUE_KINDS
    ]

    _write(
        root / "credential_guard" / "tools.py",
        """
        MYSQL_TOOL = "mysql_credential_action"

        def register_legacy(ctx):
            ctx.register_tool(name=MYSQL_TOOL, schema={}, handler=None)
        """,
    )
    after = auditor.audit_tree(root)
    kinds = _kinds(after)
    assert "old_module" in kinds, [v.line() for v in after]
    assert "old_registration" in kinds, [v.line() for v in after]


def test_clean_synthetic_tree_is_green(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    violations = auditor.audit_tree(root)
    assert violations == [], [v.line() for v in violations]


def test_mutation_quoted_block_yaml_old_registration_is_red(auditor, tmp_path):
    """Quoted block / flow YAML scalars must be caught via audit_tree()."""
    root = _clean_tree(tmp_path)
    (root / "plugin.yaml").write_text(
        "name: credential-guard\n"
        "provides_tools:\n"
        '  - "mysql_credential_action"\n'
        "  - 'ssh_credential_action'\n",
        encoding="utf-8",
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "old_registration" and "mysql_credential_action" in v.summary
        for v in violations
    ), [v.line() for v in violations]
    assert any(
        v.kind == "old_registration" and "ssh_credential_action" in v.summary
        for v in violations
    ), [v.line() for v in violations]

    root2 = _clean_tree(tmp_path / "flowq")
    (root2 / "plugin.yaml").write_text(
        "name: credential-guard\n"
        'provides_tools: ["http_credential_request", "mysql_credential_action"]\n',
        encoding="utf-8",
    )
    violations2 = auditor.audit_tree(root2)
    assert any(
        v.kind == "old_registration" and "mysql_credential_action" in v.summary
        for v in violations2
    ), [v.line() for v in violations2]


def test_mutation_name_binding_register_tool_is_red(auditor, tmp_path):
    """Lexical Name binding into register_tool(name=...) must be caught."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "__init__.py",
        """
        OLD = "mysql_credential_action"

        def register(ctx):
            ctx.register_tool(
                name=OLD,
                toolset="credential_guard",
                schema={},
                handler=lambda *a, **k: None,
                check_fn=lambda: True,
                description="",
            )
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "old_registration" for v in violations), [
        v.line() for v in violations
    ]


def test_mutation_stem_ext_name_binding_dual_file_read_is_red(auditor, tmp_path):
    """STEM/EXT name bindings + concat Path read must be dual_file_runtime."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        from pathlib import Path

        STEM = "credentials"
        EXT = ".json"

        def load_runtime():
            return Path(STEM + EXT).read_text()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "dual_file_runtime" for v in violations), [
        v.line() for v in violations
    ]


def test_mutation_concat_name_binding_dynamic_import_is_red(auditor, tmp_path):
    """MOD = a+b; importlib.import_module(MOD) must catch legacy module."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_dyn2.py",
        """
        import importlib

        MOD = "credential_guard." + "mysql_executor"
        importlib.import_module(MOD)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "old_import" for v in violations), [
        v.line() for v in violations
    ]


def test_mutation_builder_member_constant_is_red(auditor, tmp_path):
    """Builder candidate/member containers must flag legacy module paths."""
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "build_release_artifacts.py",
        """
        CANDIDATES = ["credential_guard/mysql_executor.py", "credential_guard/ok.py"]
        MEMBERS = ("credential_guard/tools.py",)

        def build_all():
            return list(CANDIDATES) + list(MEMBERS)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "builder_legacy_dependency" for v in violations), [
        v.line() for v in violations
    ]


def test_mutation_unresolved_dynamic_sinks_fail_closed(auditor, tmp_path):
    """Unresolved dynamics at critical sinks fail closed without leaking values."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "dyn_sinks.py",
        """
        import importlib
        from pathlib import Path

        def register(ctx, name, mod, path):
            ctx.register_tool(
                name=name,
                toolset="credential_guard",
                schema={},
                handler=lambda *a, **k: None,
                check_fn=lambda: True,
                description="",
            )
            importlib.import_module(mod)
            Path(path).read_text()
            open(path).read()
        """,
    )
    violations = auditor.audit_tree(root)
    kinds = {v.kind for v in violations}
    assert "unresolved_dynamic_sink" in kinds, [v.line() for v in violations]
    blob = "\n".join(v.line() for v in violations)
    # Must not echo source/parameter values into the report.
    assert "secret" not in blob.lower()
    assert "password" not in blob.lower()
    for v in violations:
        if v.kind == "unresolved_dynamic_sink":
            assert "register_tool" in v.summary or "dynamic_import" in v.summary or "path_read" in v.summary


def test_mutation_sensitive_paths_dual_file_read_is_red(auditor, tmp_path):
    """sensitive_paths may declare basenames; Path.read_text of dual-file must RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "sensitive_paths.py",
        """
        from pathlib import Path

        _STORE_BASENAMES = frozenset({"credentials.json", "targets.json", "credential-guard.json"})

        def path_is_protected(raw_path: str) -> bool:
            Path("credentials.json").read_text()
            return any(name in raw_path for name in _STORE_BASENAMES)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/sensitive_paths.py"
        and v.kind == "dual_file_runtime"
        and "path_is_protected" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_if_else_maybe_old_registration_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "branch_reg.py",
        """
        def register(ctx, flag):
            name = "http_credential_request"
            if flag:
                name = "mysql_credential_action"
            else:
                name = "http_credential_request"
            ctx.register_tool(
                name=name,
                toolset="credential_guard",
                schema={},
                handler=lambda *a, **k: None,
                check_fn=lambda: True,
                description="",
            )
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "unresolved_dynamic_sink" and "register_tool" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_if_else_maybe_dual_file_read_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "branch_read.py",
        """
        from pathlib import Path

        def load(flag):
            p = "safe.txt"
            if flag:
                p = "credentials.json"
            else:
                p = "safe.txt"
            return Path(p).read_text()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"} for v in violations
    ), [v.line() for v in violations]


def test_mutation_if_else_maybe_dynamic_import_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "branch_imp.py",
        """
        import importlib

        def load(flag):
            m = "credential_guard.constants"
            if flag:
                m = "credential_guard.mysql_executor"
            else:
                m = "credential_guard.constants"
            return importlib.import_module(m)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind in {"old_import", "unresolved_dynamic_sink"} for v in violations
    ), [v.line() for v in violations]


def test_mutation_closure_nonlocal_mutates_tool_name_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "closure_mut.py",
        """
        def outer(ctx):
            name = "http_credential_request"

            def mut():
                nonlocal name
                name = "mysql_credential_action"

            mut()
            ctx.register_tool(
                name=name,
                toolset="credential_guard",
                schema={},
                handler=lambda *a, **k: None,
                check_fn=lambda: True,
                description="",
            )
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind in {"old_registration", "unresolved_dynamic_sink"} for v in violations
    ), [v.line() for v in violations]


def test_mutation_global_mutation_before_sink_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "global_mut.py",
        """
        NAME = "http_credential_request"

        def mut():
            global NAME
            NAME = "mysql_credential_action"

        def register(ctx):
            mut()
            ctx.register_tool(
                name=NAME,
                toolset="credential_guard",
                schema={},
                handler=lambda *a, **k: None,
                check_fn=lambda: True,
                description="",
            )
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind in {"old_registration", "unresolved_dynamic_sink"} for v in violations
    ), [v.line() for v in violations]


def test_mutation_loop_try_walrus_reassignment_before_sink_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "loop_try.py",
        """
        import importlib
        from pathlib import Path

        def via_loop(items):
            name = "http_credential_request"
            for _ in items:
                name = "mysql_credential_action"
            register_tool(name=name)

        def via_try(raw):
            name = "http_credential_request"
            try:
                if (name := raw):
                    pass
            except Exception:
                name = "mysql_credential_action"
            register_tool(name=name)

        def via_walrus_import(raw):
            mod = "credential_guard.constants"
            if (mod := raw):
                pass
            importlib.import_module(mod)

        def via_loop_read(items):
            p = "safe.txt"
            for _ in items:
                p = "credentials.json"
            Path(p).read_text()
        """,
    )
    violations = auditor.audit_tree(root)
    kinds = {v.kind for v in violations}
    assert "unresolved_dynamic_sink" in kinds or "dual_file_runtime" in kinds, [
        v.line() for v in violations
    ]
    assert any("register_tool" in v.summary or "dynamic_import" in v.summary or "path_read" in v.summary or "runtime-reads" in v.summary for v in violations)


def test_mutation_param_shadows_safe_module_constant_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "shadow_param.py",
        """
        SAFE = "http_credential_request"

        def register(ctx, SAFE):
            ctx.register_tool(
                name=SAFE,
                toolset="credential_guard",
                schema={},
                handler=lambda *a, **k: None,
                check_fn=lambda: True,
                description="",
            )
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "unresolved_dynamic_sink" and "register_tool" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_builder_discover_members_call_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "build_release_artifacts.py",
        """
        def discover_members():
            import os
            return os.listdir(".")

        CANDIDATE_MEMBERS = discover_members()

        def build_all():
            return CANDIDATE_MEMBERS
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "unresolved_dynamic_sink" and "builder_member" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_builder_branch_assignment_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "build_release_artifacts.py",
        """
        def build_all(flag):
            members = ["credential_guard/constants.py"]
            if flag:
                members = ["credential_guard/mysql_executor.py"]
            else:
                members = ["credential_guard/constants.py"]
            return members
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind in {"unresolved_dynamic_sink", "builder_legacy_dependency"}
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_builder_append_extend_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "build_release_artifacts.py",
        """
        def build_all(extra, more):
            members = ["credential_guard/constants.py"]
            members.append(extra)
            members.extend(more)
            return members
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "unresolved_dynamic_sink" and "builder_member" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_builder_reassignment_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "build_release_artifacts.py",
        """
        def build_all(other):
            members = ["credential_guard/constants.py"]
            members = other
            return members
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "unresolved_dynamic_sink" and "builder_member" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_build_v2_document_direct_read_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        def _read_secure_bytes(path):
            return path.read_bytes()

        def _read_secure_json(path):
            return path.read_text()

        def _build_v2_document(store):
            return Path("credentials.json").read_text()

        def migrate_config(store_dir):
            return True
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/migration.py"
        and v.kind == "dual_file_runtime"
        and "_build_v2_document" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_bound_method_alias_sensitive_paths_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "sensitive_paths.py",
        """
        from pathlib import Path

        _STORE_BASENAMES = frozenset({"credentials.json", "targets.json"})

        def path_is_protected(raw_path: str) -> bool:
            p = Path("credentials.json")
            reader = p.read_text
            reader()
            return True
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/sensitive_paths.py"
        and v.kind == "dual_file_runtime"
        and "path_is_protected" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_bound_method_alias_migration_helper_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        def _read_secure_bytes(path):
            return path.read_bytes()

        def _read_secure_json(path):
            return path.read_text()

        def _assert_source_identity(path):
            reader = Path("credentials.json").read_text
            return reader()

        def migrate_config(store_dir):
            return True
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/migration.py"
        and "_assert_source_identity" in v.summary
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_private_reader_bound_alias_stays_green(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        def _read_secure_bytes(path: Path):
            return path.read_bytes()

        def _read_secure_json(path: Path):
            p = Path("credentials.json")
            reader = p.read_text
            return reader()

        def migrate_config(store_dir):
            return _read_secure_json(store_dir / CREDENTIALS_FILENAME)
        """,
    )
    violations = auditor.audit_tree(root)
    assert not any(
        v.path == "credential_guard/migration.py"
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_old_registration_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    plugin = root / "plugin.yaml"
    text = plugin.read_text(encoding="utf-8")
    plugin.write_text(
        text.replace(
            "  - credential_process_run\n",
            "  - credential_process_run\n  - mysql_credential_action\n",
        ),
        encoding="utf-8",
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "old_registration" for v in violations)


def test_mutation_flow_yaml_old_registration_is_red(auditor, tmp_path):
    """Reviewer probe: flow-style provides_tools must be caught via audit_tree()."""
    root = _clean_tree(tmp_path)
    (root / "plugin.yaml").write_text(
        "name: credential-guard\n"
        "provides_tools: [http_credential_request, mysql_credential_action]\n",
        encoding="utf-8",
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "old_registration" and "mysql_credential_action" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_old_import_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_prod.py",
        "from .mysql_executor import execute_action\n",
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "old_import" for v in violations)


def test_mutation_dynamic_old_import_is_red(auditor, tmp_path):
    """Reviewer probe: compile-time-derivable importlib/__import__ legacy loads."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_dyn.py",
        """
        import importlib
        m = importlib.import_module("credential_guard.mysql_executor")
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "old_import" for v in violations), [v.line() for v in violations]


def _old_import_hits(violations, module: str):
    return [
        v
        for v in violations
        if v.kind == "old_import" and v.summary.endswith(f"legacy module {module}")
    ]


def test_mutation_qualified_credential_guard_tools_import_is_red(auditor, tmp_path):
    """``from credential_guard.tools import X`` names the deleted plugin module."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_prod.py",
        "from credential_guard.tools import TOOL_NAME\n",
    )
    violations = auditor.audit_tree(root)
    assert _old_import_hits(violations, "tools"), [v.line() for v in violations]


def test_mutation_relative_tools_import_is_red(auditor, tmp_path):
    """Both relative forms of the deleted module must stay RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_prod.py",
        "from .tools import TOOL_NAME\n",
    )
    violations = auditor.audit_tree(root)
    assert _old_import_hits(violations, "tools"), [v.line() for v in violations]

    root2 = _clean_tree(tmp_path / "from_dot_import")
    _write(
        root2 / "credential_guard" / "extra_prod.py",
        "from . import tools\n",
    )
    violations2 = auditor.audit_tree(root2)
    assert _old_import_hits(violations2, "tools"), [v.line() for v in violations2]


def test_mutation_plain_import_credential_guard_tools_is_red(auditor, tmp_path):
    """``import credential_guard.tools`` must be RED via the Import statement path."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_prod.py",
        "import credential_guard.tools\n",
    )
    violations = auditor.audit_tree(root)
    assert _old_import_hits(violations, "tools"), [v.line() for v in violations]


def test_hermes_host_tools_package_import_is_not_residue(auditor, tmp_path):
    """``tools.*`` is the Hermes host approval interface — never legacy residue.

    Guards the false-positive class that made `approval.py`, `cli.py`,
    `injection_plan.py` and `scripts/run_r2_e2e.py` report `old_import` for the
    host package they legitimately depend on.
    """
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_prod.py",
        """
        def posture():
            from tools.approval import request_tool_approval
            from tools.registry import registry
            return request_tool_approval, registry
        """,
    )
    violations = auditor.audit_tree(root)
    assert violations == [], [v.line() for v in violations]


def test_mutation_other_legacy_module_import_still_red(auditor, tmp_path):
    """Modules without a host homonym keep unconditional bare-segment matching."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "extra_prod.py",
        "from credential_guard.mysql_executor import execute_action\n",
    )
    violations = auditor.audit_tree(root)
    assert _old_import_hits(violations, "mysql_executor"), [
        v.line() for v in violations
    ]


def test_mutation_pymysql_dependency_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    (root / "pyproject.toml").write_text(
        (root / "pyproject.toml").read_text(encoding="utf-8")
        + '\ndependencies = ["PyMySQL==1.2.0"]\n',
        encoding="utf-8",
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "pymysql_dependency" for v in violations)


def test_mutation_package_data_deps_is_red(auditor, tmp_path):
    """Package-data / MANIFEST deps membership must be residue."""
    root = _clean_tree(tmp_path)
    (root / "MANIFEST.in").write_text("recursive-include deps *\n", encoding="utf-8")
    violations = auditor.audit_tree(root)
    assert any(v.kind == "pymysql_package_data" for v in violations), [
        v.line() for v in violations
    ]


def test_mutation_vendored_pymysql_member_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(root / "deps" / "pymysql" / "__init__.py", "__version__ = '1.2.0'\n")
    violations = auditor.audit_tree(root)
    assert any(v.kind == "vendored_pymysql" for v in violations)


def test_mutation_arbitrary_vendored_member_is_red(auditor, tmp_path):
    """Any deps/pymysql/ member or pymysql-*.dist-info/ is residue (no __init__ needed)."""
    root = _clean_tree(tmp_path)
    _write(root / "deps" / "pymysql" / "connections.py", "x = 1\n")
    violations = auditor.audit_tree(root)
    assert any(v.kind == "vendored_pymysql" for v in violations), [
        v.line() for v in violations
    ]

    root2 = _clean_tree(tmp_path / "distinfo")
    _write(
        root2 / "deps" / "pymysql-9.9.9.dist-info" / "METADATA",
        "Name: PyMySQL\n",
    )
    violations2 = auditor.audit_tree(root2)
    assert any(v.kind == "vendored_pymysql" for v in violations2), [
        v.line() for v in violations2
    ]


def test_mutation_unauthorized_dual_file_runtime_is_red(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        def load_runtime():
            # Unauthorized fallback to dual-file runtime.
            path = "credentials.json"
            return path
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "dual_file_runtime" for v in violations)


def test_mutation_concatenated_dual_file_read_is_red(auditor, tmp_path):
    """AST constant folding must catch Path('credentials'+'.json').read_text()."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        from pathlib import Path

        def load_runtime():
            return Path("credentials" + ".json").read_text()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(v.kind == "dual_file_runtime" for v in violations), [
        v.line() for v in violations
    ]


def test_mutation_test_allowlist_abuse_is_red(auditor, tmp_path):
    """Whole-file test allowlisting forbidden: unrelated loader in allowed module is RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "tests" / "test_config_migration.py",
        """
        from pathlib import Path

        def test_ok():
            assert True

        def sneaky_loader():
            return Path("credentials.json").read_text()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind == "dual_file_runtime"
        and "sneaky_loader" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_migration_module_scope_read_is_red(auditor, tmp_path):
    """Migration may declare filename constants; module-scope Path.read_text must RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"
        _BOOT = Path("credentials.json").read_text()

        def migrate_config(store_dir):
            return store_dir / CREDENTIALS_FILENAME
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/migration.py"
        and v.kind == "dual_file_runtime"
        and "runtime-reads" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_mutation_builder_legacy_dependency_is_red(auditor, tmp_path):
    """Builder/release code dynamically loading legacy deps_integrity must RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "build_release_artifacts.py",
        """
        import importlib

        def build_all():
            importlib.import_module("credential_guard.deps_integrity")
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.kind in {"old_import", "builder_legacy_dependency"} for v in violations
    ), [v.line() for v in violations]


def test_mutation_remove_migration_allowlist_makes_migration_red(
    auditor, tmp_path, monkeypatch
):
    """Deleting migration symbol allowlist must RED migration dual-file retention."""
    root = _clean_tree(tmp_path)
    # Sanity: with allowlist, clean tree including migration is green.
    assert auditor.audit_tree(root) == []

    cleared = dict(auditor.ALLOWED_DUAL_FILE_SYMBOLS)
    cleared.pop("credential_guard/migration.py", None)
    monkeypatch.setattr(auditor, "ALLOWED_DUAL_FILE_SYMBOLS", cleared)

    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/migration.py" and v.kind == "dual_file_runtime"
        for v in violations
    ), [v.line() for v in violations]


_MIGRATION_READ_ALLOWLIST = frozenset(
    {
        "_read_secure_json",
        "_read_secure_bytes",
        "_capture_owned_artifact",
        "_matches_artifact_identity",
        "_file_sha256_if_regular",
    }
)


def test_migration_read_allowlist_is_a_closed_set_of_named_readers(auditor):
    """The migration read allowlist must stay an exact, literal symbol set.

    Every entry is a private helper that lstat-guards the path (reject symlink /
    non-regular / wrong mode / wrong owner) before reading and hands back only a
    digest, a bool, or identity metadata. Prefix, regex or whole-module matching
    would authorize any future reader in the module, so the shape is pinned.
    """
    shipped = auditor.ALLOWED_DUAL_FILE_READ_SYMBOLS["credential_guard/migration.py"]
    assert isinstance(shipped, frozenset)
    assert shipped == _MIGRATION_READ_ALLOWLIST, sorted(shipped)
    for symbol in shipped:
        assert isinstance(symbol, str) and symbol
        assert "*" not in symbol
        assert symbol != "<module>"
    # ``<module>`` can never be read-allowed regardless of allowlist contents.
    assert not auditor._dual_file_read_allowed(
        "credential_guard/migration.py", "<module>"
    )


def test_mutation_wildcard_migration_read_allowlist_is_red(
    auditor, tmp_path, monkeypatch
):
    """Mutation: a wildcard read allowlist must hide a planted unauthorized read.

    Proves the closed-set assertion above is load-bearing — if the allowlist were
    widened to match anything, an arbitrary new reader inside migration.py would
    stop being reported and the residue gate would go silently green.
    """
    root = _clean_tree(tmp_path)
    # Dual-file names come from the auditor so this test's own source stays free
    # of them — no test-side allowlist entry is needed to host the fixture.
    cred = next(n for n in sorted(auditor.DUAL_FILE_NAMES) if n.startswith("cred"))
    tgt = next(n for n in sorted(auditor.DUAL_FILE_NAMES) if n.startswith("tar"))
    _write(
        root / "credential_guard" / "migration.py",
        f"""
        from pathlib import Path

        CREDENTIALS_FILENAME = "{cred}"
        TARGETS_FILENAME = "{tgt}"

        def _read_secure_bytes(path: Path):
            return path.read_bytes()

        def _sneaky_reader(store_dir):
            return (store_dir / CREDENTIALS_FILENAME).read_bytes()

        def migrate_config(store_dir):
            return _read_secure_bytes(store_dir / CREDENTIALS_FILENAME)
        """,
    )

    def _migration_hits(vs):
        return [
            v
            for v in vs
            if v.path == "credential_guard/migration.py"
            and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        ]

    strict = auditor.audit_tree(root)
    assert _migration_hits(strict), [v.line() for v in strict]

    class _MatchAnything(frozenset):
        def __contains__(self, item):  # noqa: D105
            return True

    widened = dict(auditor.ALLOWED_DUAL_FILE_READ_SYMBOLS)
    widened["credential_guard/migration.py"] = _MatchAnything()
    monkeypatch.setattr(auditor, "ALLOWED_DUAL_FILE_READ_SYMBOLS", widened)
    widened_syms = dict(auditor.ALLOWED_DUAL_FILE_SYMBOLS)
    widened_syms["credential_guard/migration.py"] = _MatchAnything()
    monkeypatch.setattr(auditor, "ALLOWED_DUAL_FILE_SYMBOLS", widened_syms)

    loosened = auditor.audit_tree(root)
    assert _migration_hits(loosened) == [], [v.line() for v in loosened]


def test_historical_docs_dual_file_names_allowed(auditor, tmp_path):
    root = _clean_tree(tmp_path)
    violations = auditor.audit_tree(root)
    assert not any(v.path.startswith("docs/") for v in violations)


def test_auditor_reports_relative_path_kind_and_safe_summary(auditor):
    violations = auditor.audit_tree(REPO)
    assert violations
    for v in violations[:5]:
        assert v.path and not v.path.startswith("/")
        assert v.kind
        assert v.summary
        # Safe summary: no Profile path leakage.
        assert "profiles" not in v.summary.lower()
        assert "/.ssh" not in v.summary


# ---------------------------------------------------------------------------
# Round 1E mutations — one per must-fix item in
# docs/R5-门禁收口方案与绕过清单.md §3. Every case goes through the formal
# audit_tree() entry point and asserts a specific violation kind.
# ---------------------------------------------------------------------------


def test_1e_loop_back_edge_register_tool_second_iteration_is_red(auditor, tmp_path):
    """§3.1 — value written by iteration N-1 must be UNKNOWN at the sink."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "loop_reg.py",
        """
        def install(reg):
            tool = "http_credential_request"
            for _ in range(2):
                reg.register_tool(name=tool)
                tool = "mysql_credential_action"
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/loop_reg.py"
        and v.kind == "unresolved_dynamic_sink"
        and "register_tool" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_loop_back_edge_dual_file_read_second_iteration_is_red(auditor, tmp_path):
    """§3.1 — Path rebinding across the loop back edge at a read sink."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "loop_read.py",
        """
        from pathlib import Path

        def load(items):
            p = Path("safe.txt")
            for _ in items:
                p.read_text()
                p = Path("credentials.json")
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/loop_read.py"
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_1e_loop_back_edge_dynamic_import_second_iteration_is_red(auditor, tmp_path):
    """§3.1 — dynamic import name rebound on the loop back edge."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "loop_imp.py",
        """
        import importlib

        def load(items):
            mod = "credential_guard.constants"
            for _ in items:
                importlib.import_module(mod)
                mod = "credential_guard.mysql_executor"
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/loop_imp.py"
        and v.kind in {"old_import", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_1e_while_true_break_back_edge_is_red(auditor, tmp_path):
    """§3.1 — while True + break must obey the same back-edge rule."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "while_reg.py",
        """
        def install(reg, flag):
            tool = "http_credential_request"
            while True:
                reg.register_tool(name=tool)
                tool = "mysql_credential_action"
                if flag:
                    break
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/while_reg.py"
        and v.kind == "unresolved_dynamic_sink"
        and "register_tool" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_nested_loop_back_edge_is_red(auditor, tmp_path):
    """§3.1 — inner loop rebinding must invalidate for the outer sink too."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "nested_loop.py",
        """
        from pathlib import Path

        def load(outer, inner):
            name = "safe.txt"
            for _ in outer:
                for _ in inner:
                    Path(name).read_text()
                    name = "credentials.json"
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/nested_loop.py"
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_1e_bound_read_alias_with_arguments_is_red(auditor, tmp_path):
    """§3.2 — reader(encoding=...) must not escape via the zero-arg check."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "sensitive_paths.py",
        """
        from pathlib import Path

        _STORE_BASENAMES = frozenset({"credentials.json", "targets.json"})

        def path_is_protected(raw_path: str) -> bool:
            p = Path("credentials.json")
            reader = p.read_text
            reader(encoding="utf-8")
            return True
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/sensitive_paths.py"
        and v.kind == "dual_file_runtime"
        and "path_is_protected" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_bound_open_alias_positional_arg_is_red(auditor, tmp_path):
    """§3.2 — opener("rb") positional form is still a dual-file read."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "sensitive_paths.py",
        """
        from pathlib import Path

        _STORE_BASENAMES = frozenset({"credentials.json", "targets.json"})

        def path_is_protected(raw_path: str) -> bool:
            opener = Path("credentials.json").open
            opener("rb")
            return True
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/sensitive_paths.py"
        and v.kind == "dual_file_runtime"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_read_alias_stored_in_container_is_red(auditor, tmp_path):
    """§3.2 — alias escaping into a dict/list must fail closed."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "sensitive_paths.py",
        """
        from pathlib import Path

        _STORE_BASENAMES = frozenset({"credentials.json", "targets.json"})

        def path_is_protected(raw_path: str) -> bool:
            holder = {}
            holder["r"] = Path("credentials.json").read_text
            return bool(holder)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/sensitive_paths.py"
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_1e_register_tool_positional_name_is_red(auditor, tmp_path):
    """§3.3 — positional tool name must be caught."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "pos_reg.py",
        """
        def install(reg, fn):
            reg.register_tool("mysql_credential_action", fn)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/pos_reg.py" and v.kind == "old_registration"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_register_tool_kwargs_unpack_is_red(auditor, tmp_path):
    """§3.3 — register_tool(**opts) must fail closed, not be skipped."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "kw_reg.py",
        """
        def install(reg, extra):
            opts = dict(extra)
            reg.register_tool(**opts)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/kw_reg.py"
        and v.kind == "unresolved_dynamic_sink"
        and "register_tool" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_register_tool_kwargs_literal_dict_legacy_is_red(auditor, tmp_path):
    """§3.3 — literal mapping carrying a legacy name is a real registration."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "kw_lit_reg.py",
        """
        def install(reg):
            reg.register_tool(**{"name": "ssh_credential_action"})
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/kw_lit_reg.py" and v.kind == "old_registration"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_register_tool_imported_constant_is_red(auditor, tmp_path):
    """§3.3 — a legacy name imported from another in-tree module resolves."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "legacy_names.py",
        'LEGACY_NAME = "mysql_credential_action"\n',
    )
    _write(
        root / "credential_guard" / "const_reg.py",
        """
        from .legacy_names import LEGACY_NAME

        def install(reg):
            reg.register_tool(name=LEGACY_NAME)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/const_reg.py" and v.kind == "old_registration"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_register_tool_bound_alias_is_red(auditor, tmp_path):
    """§3.3 — rt = reg.register_tool; rt(name=legacy)."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "alias_reg.py",
        """
        def install(reg):
            rt = reg.register_tool
            rt(name="mysql_credential_action")
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/alias_reg.py" and v.kind == "old_registration"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_register_tool_in_comprehension_is_red(auditor, tmp_path):
    """§3.3 — comprehension target names must fail closed at the sink."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "comp_reg.py",
        """
        def install(reg, names):
            return [reg.register_tool(name=n) for n in names]
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/comp_reg.py"
        and v.kind == "unresolved_dynamic_sink"
        and "register_tool" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_shadow_nested_reader_name_cannot_borrow_allowlist(auditor, tmp_path):
    """§3.4 — a nested function copying a private reader's name is still RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        def _read_secure_bytes(path: Path):
            return path.read_bytes()

        def migrate_config(base):
            def _read_secure_bytes(_):
                return (base / "credentials.json").read_bytes()
            return _read_secure_bytes(None)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/migration.py"
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        and "migrate_config" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_shadow_method_reader_name_cannot_borrow_allowlist(auditor, tmp_path):
    """§3.4 — a method of an arbitrary class may not inherit the allowlist."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        class Shim:
            def _read_secure_bytes(self):
                return open("credentials.json", "rb").read()

        def migrate_config(store_dir):
            return Shim()._read_secure_bytes()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/migration.py"
        and v.kind == "dual_file_runtime"
        and "Shim" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_qualified_symbol_reported_for_nested_definitions(auditor, tmp_path):
    """§3.4 — reports carry the qualified owner chain, not just the inner name."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        from pathlib import Path

        def load_runtime():
            def _inner():
                return Path("credentials.json").read_text()
            return _inner()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/runtime_config.py"
        and "load_runtime._inner" in v.summary
        for v in violations
    ), [v.line() for v in violations]


def test_1e_non_build_named_packaging_script_members_are_red(auditor, tmp_path):
    """§3.5 — scripts/package_dist.py member list must not be silent."""
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "package_dist.py",
        """
        MEMBERS = ["credential_guard/tools.py", "deps/pymysql"]

        def assemble():
            return list(MEMBERS)
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "scripts/package_dist.py"
        and v.kind == "builder_legacy_dependency"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_arbitrary_script_legacy_member_literal_is_red(auditor, tmp_path):
    """§3.5 — any scripts/*.py naming a legacy module member is RED."""
    root = _clean_tree(tmp_path)
    _write(
        root / "scripts" / "ship_it.py",
        """
        PAYLOAD_FILES = ("credential_guard/mysql_executor.py",)

        def go():
            return PAYLOAD_FILES
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "scripts/ship_it.py" and v.kind == "builder_legacy_dependency"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_function_default_argument_dual_file_read_is_red(auditor, tmp_path):
    """§3.6 — defaults execute at def time and must be visited."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        from pathlib import Path

        def load_runtime():
            def inner(data=Path("credentials.json").read_bytes()):
                return data
            return inner()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/runtime_config.py"
        and v.kind == "dual_file_runtime"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_keyword_only_default_dual_file_read_is_red(auditor, tmp_path):
    """§3.6 — kw_defaults must be visited as well."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        from pathlib import Path

        def load_runtime(*, data=Path("targets.json").read_text()):
            return data
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/runtime_config.py"
        and v.kind == "dual_file_runtime"
        for v in violations
    ), [v.line() for v in violations]


def test_1e_ordinary_derived_path_read_is_not_flagged(auditor, tmp_path):
    """§3.7 — a plain parameter-derived read is not a residue signal."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "adapters" / "__init__.py",
        "",
    )
    _write(
        root / "credential_guard" / "adapters" / "io_helper.py",
        """
        from pathlib import Path

        def copy_payload(src, dest):
            data = Path(src).read_bytes()
            Path(dest).write_bytes(data)
            with open(dest, "rb") as fh:
                return fh.read()
        """,
    )
    violations = auditor.audit_tree(root)
    assert not any(
        v.path == "credential_guard/adapters/io_helper.py" for v in violations
    ), [v.line() for v in violations]


def test_1e_dual_file_taint_still_flags_derived_dual_path(auditor, tmp_path):
    """§3.7 — narrowing must not lose a read derived from a dual-file name."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "runtime_config.py",
        """
        from pathlib import Path

        def _pick(base, flag):
            name = "credentials.json" if flag else "credentials.json"
            return base / name

        def load_runtime(base, flag):
            target = _pick(base, flag)
            return target.read_text()
        """,
    )
    violations = auditor.audit_tree(root)
    assert any(
        v.path == "credential_guard/runtime_config.py"
        and v.kind in {"dual_file_runtime", "unresolved_dynamic_sink"}
        for v in violations
    ), [v.line() for v in violations]


def test_1e_private_reader_nested_helper_stays_green(auditor, tmp_path):
    """§3.7 — the H4 false positive: nested helper inside an allowed reader."""
    root = _clean_tree(tmp_path)
    _write(
        root / "credential_guard" / "migration.py",
        """
        from pathlib import Path

        CREDENTIALS_FILENAME = "credentials.json"
        TARGETS_FILENAME = "targets.json"

        def _read_secure_bytes(path: Path):
            def _slurp(p):
                return p.read_bytes()
            return _slurp(path)

        def migrate_config(store_dir):
            return _read_secure_bytes(store_dir / CREDENTIALS_FILENAME)
        """,
    )
    violations = auditor.audit_tree(root)
    assert not any(
        v.path == "credential_guard/migration.py" for v in violations
    ), [v.line() for v in violations]


def test_1e_live_tree_noise_is_bounded(auditor):
    """§3.7 — clean production modules must no longer be flagged on the live tree."""
    violations = auditor.audit_tree(REPO)
    noisy = [
        v
        for v in violations
        if v.kind == "unresolved_dynamic_sink"
        and (
            v.path.startswith("credential_guard/adapters/")
            or v.path in {"credential_guard/config.py", "credential_guard/config_lock.py"}
        )
    ]
    assert noisy == [], [v.line() for v in noisy]
