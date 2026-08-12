#!/usr/bin/env python3
"""R5 no-build pytest runner.

Two hard boundaries (Round 1E), not a growing static-detection allowlist:

Boundary one — the runner owns test selection. Callers may not pass any
selection at all: no paths, no nodeids, no directories, no ``-k``, no
``--ignore``/``--deselect``. Only a small display-option allowlist is
forwarded (``-q``/``-v``/``-s``/``--tb=``/``--maxfail=``/``-x``/
``--collect-only``/``-p no:cacheprovider``). Anything else fails closed with
a nonzero exit *before* pytest starts.

Boundary two — runtime tripwire. The runner exports
``CG_NO_BUILD_TRIPWIRE=1`` into the pytest subprocess environment and
``scripts/build_release_artifacts.py`` refuses to build while that flag is
set. Whatever syntax a payload uses to smuggle a build past static analysis,
the build itself fails at the moment it is attempted.

The static transitive scan (``preflight_no_build``) is kept as a
defence-in-depth preflight over the fixed corpus; it is no longer the only
guarantee.

This runner never invokes a release build.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

REPO = Path(__file__).resolve().parents[1]

# Whole-module excludes for tests that would trigger a release build. The R5
# corpus has no such member: the dual-build cases moved to R6, so the list is
# retired to the empty set and the runner emits no --ignore at all. The
# mechanism below stays wired so R6 can repopulate it without redesign.
DEFAULT_IGNORE: Tuple[str, ...] = ()

# Runtime tripwire: exported into the pytest subprocess; the release builder
# refuses to build while this is set (boundary two).
TRIPWIRE_ENV_VAR = "CG_NO_BUILD_TRIPWIRE"
TRIPWIRE_ENV_VALUE = "1"

# Display-only pytest options the runner may forward. Deliberately excludes
# every selection mechanism (paths, nodeids, -k, --ignore, --deselect,
# --pyargs, --last-failed, ...). Values follow separately where allowed.
SAFE_OPTION_FLAGS = frozenset(
    {
        "-q",
        "-v",
        "-vv",
        "-x",
        "-s",
        "-p",
        "--tb",
        "--collect-only",
        "--maxfail",
        "-pno:cacheprovider",
    }
)
SAFE_OPTION_WITH_VALUE = frozenset({"-p", "--tb", "--maxfail"})
# -p no:cacheprovider is always injected; bare -p requires a value from allowlist.
SAFE_P_VALUES = frozenset({"no:cacheprovider"})
SAFE_TB_VALUES = frozenset({"auto", "long", "short", "line", "native", "no"})

# Selection options are refused by name so the error explains the boundary.
SELECTION_OPTIONS = frozenset(
    {
        "-k",
        "-m",
        "--ignore",
        "--ignore-glob",
        "--deselect",
        "--pyargs",
        "--last-failed",
        "--lf",
        "--failed-first",
        "--ff",
        "--new-first",
        "--nf",
        "--stepwise",
        "--sw",
        "--rootdir",
        "--confcutdir",
        "--co",
    }
)


class RunnerArgError(ValueError):
    """Fail-closed argv validation error."""


def list_allowed_corpus(
    repo: Path = REPO,
    *,
    ignore: Tuple[str, ...] = DEFAULT_IGNORE,
) -> Tuple[str, ...]:
    """Fixed selected corpus: tests/test_*.py minus ignored build modules."""
    out: List[str] = []
    tests_root = repo / "tests"
    ignore_set = set(ignore)
    for path in sorted(tests_root.rglob("test_*.py")):
        rel = path.relative_to(repo).as_posix()
        if rel in ignore_set:
            continue
        out.append(rel)
    return tuple(out)


def _normalize_token_path(token: str, repo: Path = REPO) -> Optional[str]:
    """Map a pytest path/nodeid token to a repo-relative test module, if any."""
    raw = token
    if "::" in raw:
        raw = raw.split("::", 1)[0]
    if not raw or raw.startswith("-"):
        return None
    # Strip leading ./
    while raw.startswith("./"):
        raw = raw[2:]
    p = Path(raw)
    if p.suffix == ".py" or raw.startswith("tests/"):
        rel = raw
        # If absolute under repo, relativize.
        try:
            abs_p = Path(raw)
            if abs_p.is_absolute():
                rel = abs_p.resolve().relative_to(repo.resolve()).as_posix()
        except (ValueError, OSError):
            pass
        return rel
    return None


def validate_forwarded_args(
    forward: Sequence[str],
    *,
    repo: Path = REPO,
    ignore: Tuple[str, ...] = DEFAULT_IGNORE,
    corpus: Optional[Sequence[str]] = None,
) -> List[str]:
    """Validate caller argv under boundary one and return safe display options.

    The runner owns selection: any path, nodeid, directory or selection option
    (``-k``/``-m``/``--ignore``/``--deselect``/``--pyargs``/...) is refused.
    Only display-class options survive. Raises RunnerArgError on any violation
    (fail closed before pytest starts).
    """
    del corpus  # Selection is never caller-controlled; corpus is internal.
    ignore_set = set(ignore)
    options: List[str] = []
    i = 0
    tokens = list(forward)
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            # ``--`` cannot re-open selection: everything after it is validated
            # by exactly the same rules.
            i += 1
            continue
        if tok.startswith("-"):
            base = tok
            val_inline: Optional[str] = None
            if "=" in tok:
                base, val_inline = tok.split("=", 1)
            if base in SELECTION_OPTIONS or tok in SELECTION_OPTIONS:
                raise RunnerArgError(
                    "test selection is owned by the runner; option forbidden: "
                    f"{tok}"
                )
            if base not in SAFE_OPTION_FLAGS and tok not in SAFE_OPTION_FLAGS:
                raise RunnerArgError(f"unsafe or unknown pytest option: {tok}")
            if base in SAFE_OPTION_WITH_VALUE:
                if val_inline is None:
                    if i + 1 >= len(tokens):
                        raise RunnerArgError(f"option {base} requires a value")
                    val = tokens[i + 1]
                    if val.startswith("-"):
                        raise RunnerArgError(f"option {base} requires a value")
                    _validate_option_value(base, val)
                    options.extend([base, val])
                    i += 2
                    continue
                _validate_option_value(base, val_inline)
                options.append(tok)
                i += 1
                continue
            options.append(tok)
            i += 1
            continue
        # Any bare token is a selection attempt — always refused. Ignored build
        # modules keep their dedicated message.
        rel = _normalize_token_path(tok, repo)
        if rel is not None and rel in ignore_set:
            raise RunnerArgError(
                f"explicit selection of ignored build module forbidden: {rel}"
            )
        raise RunnerArgError(
            "test selection is owned by the runner; path/nodeid forbidden: "
            f"{tok}"
        )
    return options


def _validate_option_value(option: str, value: str) -> None:
    """Value allowlist for the few options that take one."""
    if option == "-p":
        if value not in SAFE_P_VALUES:
            raise RunnerArgError(f"unsafe -p plugin value: {value}")
        return
    if option == "--tb":
        if value not in SAFE_TB_VALUES:
            raise RunnerArgError(f"unsafe --tb value: {value}")
        return
    if option == "--maxfail":
        if not value.isdigit():
            raise RunnerArgError(f"--maxfail requires a non-negative integer: {value}")
        return
    raise RunnerArgError(f"option {option} does not take a value")


def build_pytest_argv(
    extra: Optional[Sequence[str]] = None,
    *,
    ignore: Tuple[str, ...] = DEFAULT_IGNORE,
    repo: Path = REPO,
    validate: bool = True,
) -> List[str]:
    """Construct pytest argv: fixed internal corpus + validated display options.

    Selection is never taken from ``extra``; the corpus is always the full
    fixed list from :func:`list_allowed_corpus`.
    """
    forward = list(extra) if extra else []
    if validate:
        options = validate_forwarded_args(forward, repo=repo, ignore=ignore)
    else:
        options = [t for t in forward if t != "--" and t.startswith("-")]
    argv: List[str] = ["-p", "no:cacheprovider", "--noconftest"]
    for path in ignore:
        argv.extend(["--ignore", path])
    argv.extend(options)
    argv.extend(list_allowed_corpus(repo, ignore=ignore))
    return argv


def _fold_str_const(node: ast.AST, env: Optional[Dict[str, Optional[str]]] = None) -> Optional[str]:
    """Compile-time string fold with optional Name bindings (no exec)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and env is not None and node.id in env:
        return env[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str_const(node.left, env)
        right = _fold_str_const(node.right, env)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                inner = _fold_str_const(v.value, env)
                if inner is None:
                    return None
                parts.append(inner)
            else:
                piece = _fold_str_const(v, env)
                if piece is None:
                    return None
                parts.append(piece)
        return "".join(parts)
    if isinstance(node, ast.IfExp):
        body = _fold_str_const(node.body, env)
        orelse = _fold_str_const(node.orelse, env)
        if body is not None and body == orelse:
            return body
        return None
    return None


def _env_bind(env: Dict[str, Optional[str]], name: str, value: Optional[str]) -> None:
    env[name] = value


def _env_merge(
    base: Dict[str, Optional[str]], branches: Sequence[Dict[str, Optional[str]]]
) -> Dict[str, Optional[str]]:
    out = dict(base)
    keys: Set[str] = set()
    for b in branches:
        keys |= set(b)
    for name in keys:
        vals = []
        for b in branches:
            if name in b:
                vals.append(b[name])
            elif name in base:
                vals.append(base[name])
            else:
                vals.append(None)
        if len(set(vals)) == 1 and vals[0] is not None:
            out[name] = vals[0]
        else:
            out[name] = None
    return out


def _apply_stmt_bindings(
    stmt: ast.AST, env: Dict[str, Optional[str]]
) -> Dict[str, Optional[str]]:
    """Conservative binding update for one statement (control-flow aware)."""
    if isinstance(stmt, ast.Assign):
        cur = dict(env)
        if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            _env_bind(cur, stmt.targets[0].id, _fold_str_const(stmt.value, cur))
        else:
            for t in stmt.targets:
                for n in _assign_names(t):
                    cur[n] = None
        return cur
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        cur = dict(env)
        if stmt.value is not None:
            _env_bind(cur, stmt.target.id, _fold_str_const(stmt.value, cur))
        else:
            cur[stmt.target.id] = None
        return cur
    if isinstance(stmt, ast.AugAssign):
        cur = dict(env)
        for n in _assign_names(stmt.target):
            cur[n] = None
        return cur
    if isinstance(stmt, ast.Delete):
        cur = dict(env)
        for t in stmt.targets:
            for n in _assign_names(t):
                cur[n] = None
        return cur
    if isinstance(stmt, ast.If):
        then_env = dict(env)
        for s in stmt.body:
            then_env = _apply_stmt_bindings(s, then_env)
        else_env = dict(env)
        for s in stmt.orelse:
            else_env = _apply_stmt_bindings(s, else_env)
        return _env_merge(env, [then_env, else_env])
    if isinstance(stmt, (ast.For, ast.While)):
        # zero-iteration + body: anything assigned in loop becomes unknown
        body_env = dict(env)
        if isinstance(stmt, ast.For):
            for n in _assign_names(stmt.target):
                body_env[n] = None
        for s in stmt.body:
            body_env = _apply_stmt_bindings(s, body_env)
        for s in stmt.orelse:
            body_env = _apply_stmt_bindings(s, body_env)
        assigned = set()
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    assigned.update(_assign_names(t))
            elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                assigned.add(sub.target.id)
            elif isinstance(sub, ast.AugAssign):
                assigned.update(_assign_names(sub.target))
        for n in assigned:
            body_env[n] = None
        return _env_merge(env, [dict(env), body_env])
    if isinstance(stmt, ast.Try):
        body_env = dict(env)
        for s in stmt.body:
            body_env = _apply_stmt_bindings(s, body_env)
        branches = [body_env]
        for h in stmt.handlers:
            henv = dict(env)
            if h.name:
                henv[h.name] = None
            for s in h.body:
                henv = _apply_stmt_bindings(s, henv)
            branches.append(henv)
        if stmt.orelse:
            eenv = dict(body_env)
            for s in stmt.orelse:
                eenv = _apply_stmt_bindings(s, eenv)
            branches.append(eenv)
        merged = _env_merge(env, branches)
        for s in stmt.finalbody:
            merged = _apply_stmt_bindings(s, merged)
        return merged
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        # Nested defs don't update outer string bindings except by name bind of the def.
        cur = dict(env)
        cur[stmt.name] = None  # callable, not a string
        return cur
    return env


def _assign_names(target: ast.AST) -> List[str]:
    names: List[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_assign_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_assign_names(target.value))
    return names


def _collect_scope_string_bindings(tree: ast.AST) -> Dict[str, Optional[str]]:
    """Module-level simple immutable string bindings; None = invalidated."""
    env: Dict[str, Optional[str]] = {}
    body = tree.body if isinstance(tree, ast.Module) else []
    for node in body:
        env = _apply_stmt_bindings(node, env)
    return env


def _function_local_envs(tree: ast.AST) -> Dict[int, Dict[str, Optional[str]]]:
    """Map function node id -> bindings visible at end of function (params invalid)."""
    out: Dict[int, Dict[str, Optional[str]]] = {}
    module_env = _collect_scope_string_bindings(tree)

    def walk_fn(node: ast.AST, parent_env: Dict[str, Optional[str]]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local = dict(parent_env)
            args = node.args
            for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
                local[arg.arg] = None
            if args.vararg:
                local[args.vararg.arg] = None
            if args.kwarg:
                local[args.kwarg.arg] = None
            for stmt in node.body:
                local = _apply_stmt_bindings(stmt, local)
            out[id(node)] = local
            for stmt in node.body:
                for child in ast.walk(stmt):
                    if child is stmt:
                        continue
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        walk_fn(child, local)
        elif isinstance(node, ast.Module):
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    walk_fn(stmt, module_env)

    if isinstance(tree, ast.Module):
        walk_fn(tree, module_env)
    return out


def _local_import_targets(tree: ast.AST, module_rel: str) -> Set[str]:
    """Resolve local test helper / relative / package / same-dir imports."""
    targets: Set[str] = set()
    mod_dir = str(Path(module_rel).parent).replace("\\", "/")
    env = _collect_scope_string_bindings(tree)
    fn_envs = _function_local_envs(tree)

    def add_module_rel(rel_no_suffix: str) -> None:
        rel_no_suffix = rel_no_suffix.replace(".", "/").replace("\\", "/")
        targets.add(rel_no_suffix + ".py")
        targets.add(rel_no_suffix + "/__init__.py")

    def consider_folded(folded: Optional[str]) -> None:
        if folded is None:
            return
        rel = folded.replace(".", "/")
        if rel.startswith(
            ("tests/", "credential_guard/", "scripts/")
        ) or folded.startswith(("tests.", "credential_guard.", "scripts.")):
            add_module_rel(rel)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None and node.level:
                for alias in node.names:
                    cand = f"{mod_dir}/{alias.name}.py"
                    targets.add(cand)
                    pkg = f"{mod_dir}/{alias.name}/__init__.py"
                    targets.add(pkg)
            elif node.module:
                parts = node.module.split(".")
                if node.level:
                    base = Path(module_rel).parent
                    for _ in range(node.level - 1):
                        base = base.parent
                    rel = (base / "/".join(parts)).as_posix()
                    add_module_rel(rel)
                elif parts[0] in {"tests", "credential_guard", "scripts"}:
                    add_module_rel("/".join(parts))
                    for alias in node.names:
                        if alias.name != "*":
                            add_module_rel("/".join(parts + [alias.name]))
                else:
                    same = f"{mod_dir}/{parts[0]}"
                    add_module_rel(same)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] in {"tests", "credential_guard", "scripts"}:
                    add_module_rel("/".join(parts))
                else:
                    same = f"{mod_dir}/{parts[0]}"
                    add_module_rel(same)
        elif isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in {"import_module", "__import__"} and node.args:
                # Prefer nearest function-local env for Name bindings.
                local = env
                # Walk to find enclosing function env by scanning fn_envs values —
                # use module env + all fn envs' folded attempts.
                consider_folded(_fold_str_const(node.args[0], env))
                for fen in fn_envs.values():
                    consider_folded(_fold_str_const(node.args[0], fen))
            if isinstance(func, ast.Attribute) and func.attr == "spec_from_file_location":
                for arg in node.args[:2]:
                    folded = _fold_str_const(arg, env)
                    if folded and "build_release_artifacts" in folded:
                        targets.add("scripts/build_release_artifacts.py")
                    for fen in fn_envs.values():
                        folded = _fold_str_const(arg, fen)
                        if folded and "build_release_artifacts" in folded:
                            targets.add("scripts/build_release_artifacts.py")
                for kw in node.keywords:
                    folded = _fold_str_const(kw.value, env)
                    if folded and "build_release_artifacts" in folded:
                        targets.add("scripts/build_release_artifacts.py")
                    for fen in fn_envs.values():
                        folded = _fold_str_const(kw.value, fen)
                        if folded and "build_release_artifacts" in folded:
                            targets.add("scripts/build_release_artifacts.py")
    return targets


def build_all_hits_in_source(
    text: str,
    *,
    filename: str = "<src>",
    fail_closed_unresolved: bool = True,
) -> List[str]:
    """AST hits for executable build_all reachability (not mere path strings)."""
    tree = ast.parse(text, filename=filename)
    env = _collect_scope_string_bindings(tree)
    fn_envs = _function_local_envs(tree)
    hits: List[str] = []
    # Unresolved import/exec/spec fail-closed uniformly for tests/scripts/
    # and credential_guard/ selected graphs.
    rel = filename.replace("\\", "/")
    allow_unresolved_fc = fail_closed_unresolved and (
        rel.startswith("tests/")
        or rel.startswith("scripts/")
        or rel.startswith("credential_guard/")
        or rel == "<src>"
        or "/tests/" in rel
        or "/scripts/" in rel
        or "/credential_guard/" in rel
    )

    def env_for(node: ast.AST) -> Dict[str, Optional[str]]:
        # Walk parents via enclosing function if recorded — approximate by
        # checking all function envs that contain this node id range is hard;
        # use module env plus any function env (caller passes via walk stack).
        return env

    # Attribute aliases: alias = mod.build_all; alias()
    attr_aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Attribute):
                if node.value.attr == "build_all":
                    attr_aliases[t.id] = "build_all"

    # Build per-function body scan with local env
    def scan_call(
        node: ast.Call,
        local_env: Dict[str, Optional[str]],
        param_names: Optional[Set[str]] = None,
    ) -> None:
        params = param_names or set()
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "build_all":
            hits.append("call:build_all")
        if isinstance(func, ast.Name) and func.id == "build_all":
            hits.append("call:build_all")
        if isinstance(func, ast.Name) and func.id in attr_aliases:
            hits.append("call:build_all")
        if isinstance(func, ast.Attribute) and func.attr == "spec_from_file_location":
            for arg in list(node.args[:2]) + [kw.value for kw in node.keywords]:
                folded = _fold_str_const(arg, local_env)
                if folded is not None:
                    if "build_release_artifacts" in folded:
                        hits.append("load:build_release_artifacts")
                    continue
                # Path(...)/locals are opaque; only stringy dynamics fail closed.
                if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    if allow_unresolved_fc:
                        hits.append("unresolved:spec_loader")
                elif isinstance(arg, ast.Name):
                    if (
                        arg.id in local_env
                        and local_env[arg.id] is not None
                        and "build_release_artifacts" in local_env[arg.id]
                    ):
                        hits.append("load:build_release_artifacts")
                    elif allow_unresolved_fc and arg.id in params:
                        hits.append("unresolved:spec_loader")
                elif isinstance(arg, ast.Call) and allow_unresolved_fc:
                    # str()/format dynamics — not Path(...)
                    cf = arg.func
                    cname = cf.id if isinstance(cf, ast.Name) else (
                        cf.attr if isinstance(cf, ast.Attribute) else ""
                    )
                    if cname in {"str", "format", "join"}:
                        hits.append("unresolved:spec_loader")
        fname = ""
        if isinstance(func, ast.Name):
            fname = func.id
        elif isinstance(func, ast.Attribute):
            fname = func.attr
        if fname in {"import_module", "__import__"} and node.args:
            folded = _fold_str_const(node.args[0], local_env)
            if folded is None and allow_unresolved_fc:
                arg0 = node.args[0]
                if isinstance(arg0, (ast.BinOp, ast.JoinedStr)):
                    hits.append("unresolved:dynamic_import")
                elif isinstance(arg0, ast.Name):
                    # Parameter-sourced module names fail closed (incl. cg helpers).
                    # In tests/scripts, UNKNOWN (None) bindings also fail closed
                    # so conditional/reassigned module names cannot hide builders.
                    if arg0.id in params or arg0.id not in local_env:
                        hits.append("unresolved:dynamic_import")
                    elif local_env[arg0.id] is None and (
                        arg0.id in params
                        or rel.startswith("tests/")
                        or rel.startswith("scripts/")
                        or "/tests/" in rel
                        or "/scripts/" in rel
                    ):
                        hits.append("unresolved:dynamic_import")
                elif isinstance(arg0, ast.Call):
                    hits.append("unresolved:dynamic_import")
        if fname in {"exec", "eval"} and node.args:
            folded = _fold_str_const(node.args[0], local_env)
            _dot = "." + "build_all" + "("
            if folded is not None:
                if "build_all" in folded or _dot in folded:
                    hits.append("str-payload:build_all")
            elif allow_unresolved_fc:
                arg0 = node.args[0]
                if isinstance(arg0, (ast.BinOp, ast.JoinedStr, ast.Call)):
                    hits.append("unresolved:exec")
                elif isinstance(arg0, ast.Name) and (
                    arg0.id in params or arg0.id not in local_env
                ):
                    hits.append("unresolved:exec")

    def _fn_params(fn: ast.AST) -> Set[str]:
        args = getattr(fn, "args", None)
        if args is None:
            return set()
        names = {a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)}
        if args.vararg:
            names.add(args.vararg.arg)
        if args.kwarg:
            names.add(args.kwarg.arg)
        return names

    # Scan every function with its local env + parameter set; module-level with env.
    seen_fns: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if id(node) in seen_fns:
                continue
            seen_fns.add(id(node))
            local = fn_envs.get(id(node), env)
            params = _fn_params(node)
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    scan_call(sub, local, params)
    if isinstance(tree, ast.Module):
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    scan_call(sub, env, set())

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if "build_release_artifacts" in node.module:
                hits.append("import:build_release_artifacts")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "build_release_artifacts" in alias.name:
                    hits.append("import:build_release_artifacts")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "build_all":
                hits.append("def:build_all")
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "build_all":
                    hits.append("import:build_all")
    _dot = "." + "build_all" + "("
    _mod = "mod." + "build_all" + "("
    _bmod = "build_mod." + "build_all" + "("
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            if _dot in s or _mod in s or _bmod in s:
                hits.append("str-payload:build_all")
    return sorted(set(hits))


def transitive_build_reachability(
    entry_modules: Sequence[str],
    *,
    repo: Path = REPO,
) -> List[str]:
    """Scan selected modules and local helpers/support/fixtures they import."""
    all_hits: List[str] = []
    seen: Set[str] = set()
    queue: List[str] = list(entry_modules)
    while queue:
        rel = queue.pop(0)
        if rel in seen:
            continue
        seen.add(rel)
        path = repo / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            continue
        for h in build_all_hits_in_source(text, filename=rel):
            all_hits.append(f"{rel}:{h}")
        if "scripts/build_release_artifacts.py" in rel or rel.endswith(
            "build_release_artifacts.py"
        ):
            all_hits.append(f"{rel}:module:build_release_artifacts")
        for tgt in _local_import_targets(tree, rel):
            if tgt.startswith(("tests/", "scripts/", "credential_guard/")) and tgt not in seen:
                if (repo / tgt).is_file():
                    queue.append(tgt)
    return sorted(set(all_hits))


def extract_selected_modules(
    py_argv: Sequence[str],
    *,
    repo: Path = REPO,
    ignore: Tuple[str, ...] = DEFAULT_IGNORE,
) -> List[str]:
    """Modules pytest will collect from a constructed argv.

    Under boundary one the argv is always built by :func:`build_pytest_argv`,
    so this reduces to the fixed corpus; the argv walk stays as a consistency
    check (``--ignore`` values are never treated as selections).
    """
    ignore_set = set(ignore)
    selected: List[str] = []
    i = 0
    tokens = list(py_argv)
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            base = tok.split("=", 1)[0]
            if "=" not in tok and base in (
                set(SAFE_OPTION_WITH_VALUE) | {"--ignore", "--deselect"}
            ):
                i += 2
                continue
            i += 1
            continue
        rel = _normalize_token_path(tok, repo)
        if rel and rel not in ignore_set:
            selected.append(rel)
        i += 1
    if not selected:
        selected = list(list_allowed_corpus(repo, ignore=ignore))
    # Dedupe preserving order
    out: List[str] = []
    seen: Set[str] = set()
    for s in selected:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def preflight_no_build(
    selected_modules: Sequence[str],
    *,
    repo: Path = REPO,
) -> None:
    """Fail closed before pytest if selected graph can reach build_all."""
    hits = transitive_build_reachability(selected_modules, repo=repo)
    if hits:
        raise RunnerArgError(
            "build_all reachable from selected corpus: " + "; ".join(hits[:8])
        )


_PYTEST_ENV_BLOCKLIST = frozenset(
    {
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTEST_DEBUG",
        "PYTEST_DEBUG_CONFIG",
        "PYTEST_CURRENT_TEST",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    }
)


def sanitize_pytest_env(base: Optional[dict] = None) -> dict:
    """Strip inherited pytest bootstrap injection; arm the runtime tripwire.

    Boundary two: ``CG_NO_BUILD_TRIPWIRE=1`` is exported so that any actual
    release build attempted from inside the pytest subprocess aborts at the
    moment it runs, regardless of how it evaded static analysis.

    Ambient R6 build-authorization exports are stripped so a caller shell that
    happens to export the bypass cannot silently disarm the tripwire's second
    layer. The name is composed (not a single literal) so source scans that
    forbid *introducing* the authorization channel stay accurate.
    """
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key in _PYTEST_ENV_BLOCKLIST or key.startswith("PYTEST_"):
            env.pop(key, None)
    # Strip ambient build authorization (see tests/test_r6_build_optin_gate.py).
    env.pop("CG_R6_BUILD" + "_AUTHORIZED", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env[TRIPWIRE_ENV_VAR] = TRIPWIRE_ENV_VALUE
    return env


_USAGE = (
    "usage: run_r5_nobuild_pytest.py [--collect-only] [display options]\n"
    "\n"
    "Runs the fixed R5 no-build corpus. Test selection is owned by the runner:\n"
    "paths, nodeids, -k, -m, --ignore, --deselect and --pyargs are refused.\n"
    "Allowed display options: -q -v -vv -s -x --collect-only --tb=<style>\n"
    "--maxfail=<n> -p no:cacheprovider\n"
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw: List[str] = list(argv) if argv is not None else list(sys.argv[1:])
    if "-h" in raw or "--help" in raw:
        print(_USAGE)
        return 0
    # No argparse: every token must pass the runner's own fail-closed
    # validation so the rejection message is always R5_NOBUILD_REJECT.
    forward: List[str] = raw
    if "--collect-only" in raw:
        forward = ["-q", *raw]
    # Boundary one (argv) and the static preflight report distinctly so an
    # audit can tell "selection refused" from "reachability scan refused".
    try:
        py_argv = build_pytest_argv(forward or None, validate=True)
    except RunnerArgError as exc:
        print(f"R5_NOBUILD_ARGREJECT {exc}", file=sys.stderr)
        return 2
    try:
        selected = extract_selected_modules(py_argv)
        preflight_no_build(selected)
    except RunnerArgError as exc:
        print(f"R5_NOBUILD_REJECT {exc}", file=sys.stderr)
        return 2
    cmd = [sys.executable, "-m", "pytest", *py_argv]
    env = sanitize_pytest_env()
    print("R5_NOBUILD_RUNNER", " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=str(REPO), env=env)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
