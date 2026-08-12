"""R1B: execute_code static Python read of protected paths (strict TDD)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME
from credential_guard.sensitive_paths import python_code_reads_protected


def _assert_block(result) -> None:
    assert isinstance(result, dict)
    assert result.get("action") == "block"


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    cfg = store / CONFIG_FILENAME
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    ssh = home / ".ssh"
    ssh.mkdir()
    (ssh / "config").write_text("Host decoy\n", encoding="utf-8")
    (ssh / "id_ed25519").write_text("DECOY_KEY\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    return {
        "home": home,
        "hermes": hermes,
        "store": store,
        "config": cfg,
        "ssh": ssh,
    }


# ---------------------------------------------------------------------------
# Slice A: minimal explicit Python file-read calls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code_fmt",
    [
        "open({path!r}).read()",
        "from pathlib import Path\nPath({path!r}).read_text()",
        "from pathlib import Path\nPath({path!r}).read_bytes()",
        "from pathlib import Path\nPath({path!r}).open().read()",
        "import os\nos.open({path!r}, os.O_RDONLY)",
    ],
)
def test_slice_a_minimal_calls_blocked(isolated_store, code_fmt):
    path = str(isolated_store["config"])
    code = code_fmt.format(path=path)
    result = on_pre_tool_call(tool_name="execute_code", args={"code": code})
    _assert_block(result)


# ---------------------------------------------------------------------------
# Slice B: protected path variants + static evaluation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "basename",
    [
        "credential-guard.json",
        "credentials.json",
        "targets.json",
        "credentials.json.v1.bak",
        "targets.json.v1.bak",
        ".cg-migrate.journal",
        ".cg-migrate.lock",
        ".credential-guard.runtime.lock",
        ".cg-migrate-abc.tmp",
    ],
)
def test_slice_b_store_basenames_blocked(isolated_store, basename):
    target = isolated_store["store"] / basename
    if not target.exists():
        target.write_text("{}", encoding="utf-8")
        os.chmod(target, 0o600)
    code = f"from pathlib import Path\nPath({str(target)!r}).read_text()"
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code}))


def test_slice_b_ssh_files_blocked(isolated_store):
    ssh = isolated_store["ssh"]
    for name in ("config", "id_ed25519"):
        path = str(ssh / name)
        code = f"open({path!r}).read()"
        _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code}))
    home_form = (
        "from pathlib import Path\n"
        "(Path.home() / '.ssh' / 'config').read_text()"
    )
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": home_form}))


def test_slice_b_relative_and_dotdot(isolated_store, monkeypatch):
    hermes = isolated_store["hermes"]
    monkeypatch.chdir(hermes)
    rel = "credential-guard/credential-guard.json"
    code = f"open({rel!r}).read()"
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code}))
    dotdot = "credential-guard/../credential-guard/credential-guard.json"
    code2 = f"from pathlib import Path\nPath({dotdot!r}).read_text()"
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code2}))


def test_slice_b_home_and_environ_static(isolated_store):
    code_home = (
        "from pathlib import Path\n"
        "(Path.home() / '.ssh' / 'id_ed25519').read_bytes()"
    )
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code_home}))

    code_env = (
        "import os\n"
        "from pathlib import Path\n"
        "p = Path(os.environ['HERMES_HOME']) / 'credential-guard' / 'credential-guard.json'\n"
        "p.read_text()"
    )
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code_env}))

    code_get = (
        "import os\n"
        "from pathlib import Path\n"
        "base = os.environ.get('HERMES_HOME')\n"
        "Path(base, 'credential-guard', 'targets.json').read_text()"
    )
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code_get}))


def test_slice_b_const_binding_concat_fstring(isolated_store):
    store = str(isolated_store["store"])
    code_bind = (
        f"base = {store!r}\n"
        "path = base + '/credentials.json'\n"
        "open(path).read()"
    )
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code_bind}))

    code_f = (
        f"base = {store!r}\n"
        "open(f'{base}/targets.json').read()"
    )
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code_f}))

    # Dynamic expression in f-string: honest non-claim when not statically resolvable.
    dynamic = "x = input()\nopen(f'{x}/credentials.json').read()"
    assert python_code_reads_protected(dynamic) is False


# ---------------------------------------------------------------------------
# Slice C: non-interference
# ---------------------------------------------------------------------------


def test_slice_c_ordinary_project_reads_allowed(isolated_store, tmp_path):
    src = tmp_path / "app.py"
    src.write_text("print('hi')\n", encoding="utf-8")
    md = tmp_path / "README.md"
    md.write_text("# ok\n", encoding="utf-8")
    fixture = tmp_path / "fixture.json"
    fixture.write_text('{"ok": true}', encoding="utf-8")
    for path in (src, md, fixture):
        code = f"open({str(path)!r}).read()"
        assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_slice_c_ordinary_python_compute_allowed(isolated_store):
    code = "x = 1 + 2\nprint(x * 3)"
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_slice_c_mention_in_string_or_comment_allowed(isolated_store):
    code = (
        "# do not touch credentials.json or credential-guard.json\n"
        "msg = 'targets.json is a catalog name'\n"
        "print(msg)"
    )
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_slice_c_exists_stat_not_blocked(isolated_store):
    path = str(isolated_store["config"])
    exists_code = (
        f"from pathlib import Path\n"
        f"print(Path({path!r}).exists())"
    )
    assert on_pre_tool_call(tool_name="execute_code", args={"code": exists_code}) is None
    stat_code = (
        f"from pathlib import Path\n"
        f"print(Path({path!r}).stat())"
    )
    assert on_pre_tool_call(tool_name="execute_code", args={"code": stat_code}) is None


def test_slice_c_syntax_error_without_read_intent_allowed(isolated_store):
    # Parse fails but no file-read intent → must not blanket-block.
    code = "1 + "
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_slice_c_syntax_error_with_read_intent_fail_closed(isolated_store):
    path = str(isolated_store["config"])
    # Unclosed paren — parse fails, but open + protected path → fail closed.
    code = f"open({path!r}"
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code}))


# ---------------------------------------------------------------------------
# Slice D: transform_tool_result secondary gate
# ---------------------------------------------------------------------------


_SAFE_ERROR = "tool result blocked by credential-guard"


def test_slice_d_result_gate_blocks_protected_execute_code(isolated_store):
    from credential_guard.hooks import on_transform_tool_result

    path = str(isolated_store["config"])
    code = f"from pathlib import Path\nPath({path!r}).read_text()"
    canary = "CG_R1B_EXECUTE_CODE_CANARY_META_alias=ops-box host=10.9.9.9"
    # Pre-gate must be a strict block (not None / approve).
    pre = on_pre_tool_call(tool_name="execute_code", args={"code": code})
    _assert_block(pre)

    out = on_transform_tool_result(
        tool_name="execute_code",
        args={"code": code},
        result=canary,
    )
    assert json.loads(out)["error"] == _SAFE_ERROR
    assert "CG_R1B_EXECUTE_CODE_CANARY" not in out
    assert "ops-box" not in out
    assert "10.9.9.9" not in out


def test_slice_d_result_gate_blocks_without_registry_secret(isolated_store):
    """Secondary gate must not depend on registry secrets (SSH meta may not be secret)."""
    from credential_guard.hooks import on_transform_tool_result

    ssh_cfg = str(isolated_store["ssh"] / "config")
    code = f"open({ssh_cfg!r}).read()"
    meta = "Host cg-r1b-ssh-alias\nIdentityFile /tmp/decoy_id\n"
    out = on_transform_tool_result(
        tool_name="execute_code",
        args={"code": code},
        result=meta,
    )
    assert json.loads(out)["error"] == _SAFE_ERROR
    assert "cg-r1b-ssh-alias" not in out
    assert "IdentityFile" not in out


def test_slice_d_ordinary_execute_code_result_unaffected(isolated_store, tmp_path):
    from credential_guard.hooks import on_transform_tool_result

    ordinary = tmp_path / "notes.txt"
    ordinary.write_text("hello", encoding="utf-8")
    code = f"open({str(ordinary)!r}).read()"
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None
    body = "ordinary compute result 42"
    out = on_transform_tool_result(
        tool_name="execute_code",
        args={"code": "print(1+1)"},
        result=body,
    )
    assert body in out
    assert "blocked" not in out


# ---------------------------------------------------------------------------
# Round 2: import aliases, kwargs, const control-flow (Hermes probe bypasses)
# ---------------------------------------------------------------------------


def _assert_ast_and_pre_block(code: str) -> None:
    """Require AST helper hit (not shell-token coincidence) plus pre-tool block."""
    assert python_code_reads_protected(code) is True
    _assert_block(on_pre_tool_call(tool_name="execute_code", args={"code": code}))


@pytest.mark.parametrize(
    "code_fmt",
    [
        "from pathlib import Path as P\nP({path!r}).read_text()",
        "import pathlib\npathlib.Path({path!r}).read_text()",
        "import pathlib as pl\npl.Path({path!r}).read_text()",
        "from builtins import open as o\no({path!r}).read()",
    ],
)
def test_r2a_import_alias_and_qualified_blocked(isolated_store, code_fmt):
    path = str(isolated_store["config"])
    code = code_fmt.format(path=path)
    _assert_ast_and_pre_block(code)


@pytest.mark.parametrize(
    "code_fmt",
    [
        "from pathlib import Path as P\nP({path!r}).read_text()",
        "import pathlib\npathlib.Path({path!r}).read_text()",
        "import pathlib as pl\npl.Path({path!r}).read_text()",
        "from builtins import open as o\no({path!r}).read()",
    ],
)
def test_r2a_import_alias_ordinary_not_blocked(isolated_store, tmp_path, code_fmt):
    ordinary = tmp_path / "notes.txt"
    ordinary.write_text("ok", encoding="utf-8")
    code = code_fmt.format(path=str(ordinary))
    assert python_code_reads_protected(code) is False
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_r2b_open_file_keyword_blocked(isolated_store):
    path = str(isolated_store["config"])
    code = f"open(file={path!r}).read()"
    _assert_ast_and_pre_block(code)


def test_r2b_os_open_path_keyword_blocked(isolated_store):
    path = str(isolated_store["config"])
    code = f"import os\nos.open(path={path!r}, flags=os.O_RDONLY)"
    _assert_ast_and_pre_block(code)


def test_r2b_keyword_ordinary_not_blocked(isolated_store, tmp_path):
    ordinary = tmp_path / "notes.txt"
    ordinary.write_text("ok", encoding="utf-8")
    path = str(ordinary)
    for code in (
        f"open(file={path!r}).read()",
        f"import os\nos.open(path={path!r}, flags=os.O_RDONLY)",
    ):
        assert python_code_reads_protected(code) is False
        assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_r2c_ternary_const_true_protected_blocked(isolated_store, tmp_path):
    protected = str(isolated_store["config"])
    ordinary = str(tmp_path / "ordinary.txt")
    code = f"open({protected!r} if True else {ordinary!r}).read()"
    _assert_ast_and_pre_block(code)


def test_r2c_ternary_const_false_protected_blocked(isolated_store, tmp_path):
    protected = str(isolated_store["config"])
    ordinary = str(tmp_path / "ordinary.txt")
    code = f"open({ordinary!r} if False else {protected!r}).read()"
    _assert_ast_and_pre_block(code)


def test_r2c_if_false_must_not_overwrite_reachable_binding(isolated_store, tmp_path):
    protected = str(isolated_store["config"])
    ordinary = str(tmp_path / "ordinary.txt")
    code = (
        f"p = {protected!r}\n"
        "if False:\n"
        f"    p = {ordinary!r}\n"
        "open(p).read()"
    )
    _assert_ast_and_pre_block(code)


def test_r2c_if_true_uses_body_only(isolated_store, tmp_path):
    protected = str(isolated_store["config"])
    ordinary = str(tmp_path / "ordinary.txt")
    # body binds protected; orelse would bind ordinary but is unreachable.
    code = (
        f"p = {ordinary!r}\n"
        "if True:\n"
        f"    p = {protected!r}\n"
        "else:\n"
        f"    p = {ordinary!r}\n"
        "open(p).read()"
    )
    _assert_ast_and_pre_block(code)


def test_r2c_dynamic_condition_conservative_block_if_any_branch_protected(
    isolated_store, tmp_path
):
    protected = str(isolated_store["config"])
    ordinary = str(tmp_path / "ordinary.txt")
    code = (
        "cond = (1 == 1)  # not a Constant node for the If.test\n"
        f"p = {ordinary!r}\n"
        "if cond:\n"
        f"    p = {protected!r}\n"
        "else:\n"
        f"    p = {ordinary!r}\n"
        "open(p).read()"
    )
    # Dynamic condition: either branch may bind protected → conservative block.
    _assert_ast_and_pre_block(code)


def test_r2c_dynamic_condition_all_ordinary_allowed(isolated_store, tmp_path):
    ordinary_a = str(tmp_path / "a.txt")
    ordinary_b = str(tmp_path / "b.txt")
    Path(ordinary_a).write_text("a", encoding="utf-8")
    Path(ordinary_b).write_text("b", encoding="utf-8")
    code = (
        "cond = (1 == 1)\n"
        f"p = {ordinary_a!r}\n"
        "if cond:\n"
        f"    p = {ordinary_a!r}\n"
        "else:\n"
        f"    p = {ordinary_b!r}\n"
        "open(p).read()"
    )
    assert python_code_reads_protected(code) is False
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_r2c_honest_nonclaim_runtime_dynamic(isolated_store):
    # Runtime-decrypted / input-driven path: still not claimed as protected detection.
    code = "p = input()\nopen(p).read()"
    assert python_code_reads_protected(code) is False


def test_r2d_result_gate_blocks_round2_protected_variants(isolated_store):
    from credential_guard.hooks import on_transform_tool_result

    path = str(isolated_store["config"])
    canary = "CG_R1B_R2_CANARY_META_alias=ops-box host=10.9.9.9"
    variants = [
        f"from pathlib import Path as P\nP({path!r}).read_text()",
        f"import pathlib\npathlib.Path({path!r}).read_text()",
        f"open(file={path!r}).read()",
        (
            f"p = {path!r}\n"
            "if False:\n"
            "    p = '/tmp/ordinary'\n"
            "open(p).read()"
        ),
        f"open({path!r} if True else '/tmp/ordinary').read()",
    ]
    for code in variants:
        assert python_code_reads_protected(code) is True
        pre = on_pre_tool_call(tool_name="execute_code", args={"code": code})
        _assert_block(pre)
        out = on_transform_tool_result(
            tool_name="execute_code",
            args={"code": code},
            result=canary,
        )
        assert json.loads(out)["error"] == _SAFE_ERROR
        assert "CG_R1B_R2_CANARY" not in out
        assert "ops-box" not in out
        assert "10.9.9.9" not in out


# ---------------------------------------------------------------------------
# Round 3: dynamic-branch multi-candidate concat / f-string propagation
# ---------------------------------------------------------------------------


def _publish_empty_runtime_view(isolated_store) -> None:
    """Establish a valid empty v2 runtime view so result-gate tests are not false-green."""
    from credential_guard.runtime_config import load_and_publish_runtime
    from credential_guard.state import get_egress_registry_snapshot

    view = load_and_publish_runtime()
    assert view is not None
    # Empty credentials → empty egress secrets; must not raise / fail closed.
    reg = get_egress_registry_snapshot()
    assert list(reg.values()) == []


def _r3_dynamic_concat_code(
    *,
    protected_first: bool,
    both_ordinary: bool = False,
    ordinary_root: str | None = None,
) -> str:
    """Dynamic if binds name; then root + '/' + name (multi-candidate concat)."""
    a = "credential-guard.json"
    b = "ordinary.txt"
    if both_ordinary:
        left, right = "ordinary-a.txt", "ordinary-b.txt"
        # Must not use the credential-guard store root: any path under store is protected.
        root_expr = f"{ordinary_root!r}"
        assert ordinary_root is not None
    elif protected_first:
        left, right = a, b
        root_expr = "os.environ['HERMES_HOME'] + '/credential-guard'"
    else:
        left, right = b, a
        root_expr = "os.environ['HERMES_HOME'] + '/credential-guard'"
    return (
        "import os\n"
        f"root = {root_expr}\n"
        "cond = (1 == 1)\n"
        "if cond:\n"
        f"    name = {left!r}\n"
        "else:\n"
        f"    name = {right!r}\n"
        "print(open(root + '/' + name).read())\n"
    )


def test_r3a_concat_dynamic_name_protected_first_blocked(isolated_store):
    code = _r3_dynamic_concat_code(protected_first=True)
    _assert_ast_and_pre_block(code)


def test_r3a_concat_dynamic_name_ordinary_first_still_blocked(isolated_store):
    code = _r3_dynamic_concat_code(protected_first=False)
    _assert_ast_and_pre_block(code)


def test_r3a_concat_dynamic_name_all_ordinary_allowed(isolated_store, tmp_path):
    work = tmp_path / "workdir"
    work.mkdir()
    (work / "ordinary-a.txt").write_text("a", encoding="utf-8")
    (work / "ordinary-b.txt").write_text("b", encoding="utf-8")
    code = _r3_dynamic_concat_code(
        protected_first=True, both_ordinary=True, ordinary_root=str(work)
    )
    assert python_code_reads_protected(code) is False
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_r3a_multi_segment_concat_any_combo_protected_blocked(isolated_store):
    code = (
        "import os\n"
        "root = os.environ['HERMES_HOME'] + '/credential-guard'\n"
        "cond = (1 == 1)\n"
        "if cond:\n"
        "    subdir = '.'\n"
        "    name = 'credential-guard.json'\n"
        "else:\n"
        "    subdir = 'notes'\n"
        "    name = 'ordinary.txt'\n"
        "print(open(root + '/' + subdir + '/' + name).read())\n"
    )
    _assert_ast_and_pre_block(code)


def test_r3a_pre_gate_strict_block_action(isolated_store):
    code = _r3_dynamic_concat_code(protected_first=True)
    assert python_code_reads_protected(code) is True
    pre = on_pre_tool_call(tool_name="execute_code", args={"code": code})
    assert isinstance(pre, dict)
    assert pre.get("action") == "block"


def _r3_dynamic_fstring_code(
    *,
    protected_first: bool,
    both_ordinary: bool = False,
    multi_segment: bool = False,
    ordinary_root: str | None = None,
) -> str:
    a = "credential-guard.json"
    b = "ordinary.txt"
    if both_ordinary:
        left, right = "ordinary-a.txt", "ordinary-b.txt"
        assert ordinary_root is not None
        root_expr = f"{ordinary_root!r}"
    elif protected_first:
        left, right = a, b
        root_expr = "os.environ['HERMES_HOME'] + '/credential-guard'"
    else:
        left, right = b, a
        root_expr = "os.environ['HERMES_HOME'] + '/credential-guard'"
    if multi_segment:
        return (
            "import os\n"
            f"root = {root_expr}\n"
            "cond = (1 == 1)\n"
            "if cond:\n"
            "    subdir = '.'\n"
            f"    name = {left!r}\n"
            "else:\n"
            "    subdir = 'notes'\n"
            f"    name = {right!r}\n"
            "print(open(f'{root}/{subdir}/{name}').read())\n"
        )
    return (
        "import os\n"
        f"root = {root_expr}\n"
        "cond = (1 == 1)\n"
        "if cond:\n"
        f"    name = {left!r}\n"
        "else:\n"
        f"    name = {right!r}\n"
        "print(open(f'{root}/{name}').read())\n"
    )


def test_r3b_fstring_dynamic_name_blocked(isolated_store):
    code = _r3_dynamic_fstring_code(protected_first=True)
    _assert_ast_and_pre_block(code)


def test_r3b_fstring_multi_segment_blocked(isolated_store):
    code = _r3_dynamic_fstring_code(protected_first=True, multi_segment=True)
    _assert_ast_and_pre_block(code)


def test_r3b_fstring_ordinary_first_still_blocked(isolated_store):
    code = _r3_dynamic_fstring_code(protected_first=False)
    _assert_ast_and_pre_block(code)


def test_r3b_fstring_all_ordinary_allowed(isolated_store, tmp_path):
    work = tmp_path / "workdir"
    work.mkdir()
    (work / "ordinary-a.txt").write_text("a", encoding="utf-8")
    (work / "ordinary-b.txt").write_text("b", encoding="utf-8")
    code = _r3_dynamic_fstring_code(
        protected_first=True, both_ordinary=True, ordinary_root=str(work)
    )
    assert python_code_reads_protected(code) is False
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None


def test_r3c_result_gate_blocks_concat_fstring_variants(isolated_store):
    from credential_guard.hooks import on_transform_tool_result

    _publish_empty_runtime_view(isolated_store)
    canary = "CG_R1B_R3_CANARY_META_alias=ops-box host=10.9.9.9"
    variants = [
        _r3_dynamic_concat_code(protected_first=True),
        _r3_dynamic_concat_code(protected_first=False),
        _r3_dynamic_fstring_code(protected_first=True),
        _r3_dynamic_fstring_code(protected_first=True, multi_segment=True),
        (
            "import os\n"
            "root = os.environ['HERMES_HOME'] + '/credential-guard'\n"
            "cond = (1 == 1)\n"
            "if cond:\n"
            "    subdir = '.'\n"
            "    name = 'credential-guard.json'\n"
            "else:\n"
            "    subdir = 'notes'\n"
            "    name = 'ordinary.txt'\n"
            "print(open(root + '/' + subdir + '/' + name).read())\n"
        ),
    ]
    for code in variants:
        assert python_code_reads_protected(code) is True
        pre = on_pre_tool_call(tool_name="execute_code", args={"code": code})
        _assert_block(pre)
        out = on_transform_tool_result(
            tool_name="execute_code",
            args={"code": code},
            result=canary,
        )
        assert json.loads(out)["error"] == _SAFE_ERROR
        assert "CG_R1B_R3_CANARY" not in out
        assert "ops-box" not in out
        assert "10.9.9.9" not in out


def test_r3c_result_gate_ordinary_unaffected(isolated_store, tmp_path):
    from credential_guard.hooks import on_transform_tool_result

    _publish_empty_runtime_view(isolated_store)
    work = tmp_path / "workdir"
    work.mkdir()
    (work / "ordinary-a.txt").write_text("a", encoding="utf-8")
    (work / "ordinary-b.txt").write_text("b", encoding="utf-8")
    code = _r3_dynamic_concat_code(
        protected_first=True, both_ordinary=True, ordinary_root=str(work)
    )
    assert python_code_reads_protected(code) is False
    assert on_pre_tool_call(tool_name="execute_code", args={"code": code}) is None
    body = "ordinary r3 compute result 99"
    out = on_transform_tool_result(
        tool_name="execute_code",
        args={"code": code},
        result=body,
    )
    assert body in out
    assert "blocked" not in out


# ---------------------------------------------------------------------------
# Evidence: candidate product over MAX_PATH_CANDIDATE_COMBOS=64 fail closed
# ---------------------------------------------------------------------------


def _over_limit_seven_branch_concat_code() -> str:
    """7 dynamic binary segments → 2^7=128 concat candidates (exceeds bound 64).

    No segment points at a protected path; the hit is combinatorial fail-closed.
    """
    from credential_guard.sensitive_paths import MAX_PATH_CANDIDATE_COMBOS

    assert MAX_PATH_CANDIDATE_COMBOS == 64  # real constant; do not monkeypatch
    parts: list[str] = []
    for i in range(7):
        parts.append(
            "cond = (1 == 1)\n"
            "if cond:\n"
            f"    s{i} = 'a{i}'\n"
            "else:\n"
            f"    s{i} = 'b{i}'\n"
        )
    return "".join(parts) + "print(open(s0 + s1 + s2 + s3 + s4 + s5 + s6).read())\n"


def test_r3d_candidate_limit_over_limit_fail_closed(isolated_store):
    from credential_guard.hooks import on_transform_tool_result

    code = _over_limit_seven_branch_concat_code()
    assert python_code_reads_protected(code) is True
    pre = on_pre_tool_call(tool_name="execute_code", args={"code": code})
    assert isinstance(pre, dict)
    assert pre.get("action") == "block"

    _publish_empty_runtime_view(isolated_store)
    canary = "CG_R1B_OVERLIMIT_CANARY_META_alias=ops-box host=10.9.9.9"
    out = on_transform_tool_result(
        tool_name="execute_code",
        args={"code": code},
        result=canary,
    )
    assert json.loads(out)["error"] == _SAFE_ERROR
    assert "CG_R1B_OVERLIMIT_CANARY" not in out
    assert "ops-box" not in out
    assert "10.9.9.9" not in out

    # Ordinary code still unaffected under the same isolated runtime.
    ordinary = "x = 1 + 2\nprint(x * 3)"
    assert python_code_reads_protected(ordinary) is False
    assert on_pre_tool_call(tool_name="execute_code", args={"code": ordinary}) is None
    body = "ordinary over_limit neighbor result 7"
    plain = on_transform_tool_result(
        tool_name="execute_code",
        args={"code": ordinary},
        result=body,
    )
    assert body in plain
    assert "blocked" not in plain
