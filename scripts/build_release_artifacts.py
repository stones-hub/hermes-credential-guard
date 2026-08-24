"""Offline release artifact builder (real setuptools wheel/sdist + Hermes plugin zip).

Hermes installs a *directory plugin*, not a bare PEP 427 wheel. A real wheel
carries ``credential_guard/``; root ``plugin.yaml`` /
``requirements.txt`` / ``release-metadata.json`` / ``__init__.py`` cannot
naturally live at wheel root. Final user-facing artifact is therefore:

  credential-guard-<ver>-hermes-plugin.zip

built from the real wheel plus those root files. Never hand-zip a fake wheel.

Builds are byte-reproducible: fixed SOURCE_DATE_EPOCH, stable member order,
normalized zip/tar metadata (mtime/uid/gid/uname/gname/mode).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_VERSION = "0.4.6"
WHEEL_NAME = f"hermes_credential_guard-{PLUGIN_VERSION}-py3-none-any.whl"
SDIST_NAME = f"hermes_credential_guard-{PLUGIN_VERSION}.tar.gz"
PLUGIN_ZIP_NAME = f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"
# Versioned filename: coexists with frozen historical dist/artifact-manifest.json
# (0.3.1). Must stay in lockstep with release_identity.ARTIFACT_MANIFEST_FILENAME.
ARTIFACT_MANIFEST_NAME = f"artifact-manifest-{PLUGIN_VERSION}.json"

# Fixed build identity — not machine-private. Override via env for experiments.
DEFAULT_SOURCE_DATE_EPOCH = 1704067200  # 2024-01-01T00:00:00Z

_REQUIRED_PLUGIN_ROOT = (
    "plugin.yaml",
    "requirements.txt",
    "release-metadata.json",
    "__init__.py",
)


class ReleaseBuildError(RuntimeError):
    """Fail-loud offline build failure — never forge artifacts."""


# --- R5 Round 1E boundary two: runtime no-build tripwire -------------------
#
# ``scripts/run_r5_nobuild_pytest.py`` exports CG_NO_BUILD_TRIPWIRE=1 into the
# pytest subprocess. Every real build entry point checks it *before* touching
# the filesystem, so a payload that evades static reachability analysis still
# fails at the moment the build is attempted. The value is also captured at
# import time, so popping the variable after this module is imported does not
# disarm the tripwire.
TRIPWIRE_ENV_VAR = "CG_NO_BUILD_TRIPWIRE"
_TRIPWIRE_AT_IMPORT = os.environ.get(TRIPWIRE_ENV_VAR)

# --- R6 slice 1: explicit build-authorization channel ----------------------
#
# The tripwire stays intact — it is the reusable mechanism any future
# "no build this round" milestone re-arms verbatim. R6 must actually build, so
# rather than deleting the gate we add a second variable that must be declared
# on purpose. Default remains fail-closed; only an explicitly truthy value
# opens the gate, and every bypass is audited on stderr so a later reviewer can
# tell an authorized build from a broken tripwire.
BUILD_AUTHORIZED_ENV_VAR = "CG_R6_BUILD_AUTHORIZED"

_FALSEY_ENV_VALUES = {"", "0", "false", "False"}


class NoBuildTripwireError(RuntimeError):
    """Raised when a build is attempted inside a declared no-build run."""


def _env_flag_true(raw: Optional[str]) -> bool:
    return raw is not None and raw.strip() not in _FALSEY_ENV_VALUES


def _tripwire_armed() -> bool:
    for raw in (_TRIPWIRE_AT_IMPORT, os.environ.get(TRIPWIRE_ENV_VAR)):
        if _env_flag_true(raw):
            return True
    return False


def _build_authorized() -> bool:
    """True only when the bypass variable is explicitly set to a truthy value."""
    return _env_flag_true(os.environ.get(BUILD_AUTHORIZED_ENV_VAR))


def assert_no_build_tripwire(entry: str) -> None:
    """Fail closed when the no-build tripwire is armed and unauthorized."""
    if not _tripwire_armed():
        return
    if not _build_authorized():
        raise NoBuildTripwireError(
            f"{TRIPWIRE_ENV_VAR} is armed: release build forbidden (entry={entry})"
        )
    print(
        f"RELEASE_BUILD_TRIPWIRE_BYPASS: {TRIPWIRE_ENV_VAR} armed but bypassed "
        f"under explicit {BUILD_AUTHORIZED_ENV_VAR} authorization (entry={entry})",
        file=sys.stderr,
    )


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None or raw.strip() == "":
        return DEFAULT_SOURCE_DATE_EPOCH
    try:
        return int(raw)
    except ValueError as exc:
        raise ReleaseBuildError(f"invalid SOURCE_DATE_EPOCH={raw!r}") from exc


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _zip_date_time(epoch: int) -> Tuple[int, int, int, int, int, int]:
    t = time.gmtime(epoch)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def find_build_python() -> Path:
    """Locate an interpreter that can build wheels offline (setuptools+wheel)."""
    env = os.environ.get("CREDENTIAL_GUARD_BUILD_PYTHON")
    candidates: List[Path] = []
    if env:
        candidates.append(Path(env))
    candidates.extend(
        [
            Path("/Users/yelei/.hermes/hermes-agent/venv/bin/python"),
            Path(
                "/Users/yelei/.cache/codex-runtimes/codex-primary-runtime/"
                "dependencies/python/bin/python"
            ),
            ROOT / ".venv" / "bin" / "python",
            Path(sys.executable),
        ]
    )
    seen = set()
    for py in candidates:
        key = str(py)
        if key in seen or not py.is_file():
            continue
        seen.add(key)
        if _python_can_build(py):
            return py
    raise ReleaseBuildError(
        "offline wheel build requires an interpreter with setuptools>=61 and "
        "importable wheel; neither 'build' nor 'wheel' may be fetched from PyPI. "
        "Set CREDENTIAL_GUARD_BUILD_PYTHON to a suitable local interpreter."
    )


def _python_can_build(py: Path) -> bool:
    probe = r"""
import importlib.util
import sys
ok = True
try:
    import setuptools
    from packaging.version import Version
    if Version(setuptools.__version__.split()[0]) < Version("61"):
        # packaging may be missing; fall back to tuple compare
        raise SystemExit(2)
except Exception:
    try:
        import setuptools
        parts = [int(x) for x in setuptools.__version__.split(".")[:2]]
        if tuple(parts) < (61, 0):
            raise SystemExit(2)
    except Exception:
        raise SystemExit(2)
# wheel: top-level or setuptools vendored
if importlib.util.find_spec("wheel") is None:
    import setuptools as st
    from pathlib import Path
    vendor = Path(st.__file__).resolve().parent / "_vendor"
    sys.path.insert(0, str(vendor))
    if importlib.util.find_spec("wheel") is None:
        raise SystemExit(3)
print("ok")
"""
    proc = subprocess.run(
        [str(py), "-c", probe],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc.returncode == 0 and "ok" in (proc.stdout or "")


def _build_env(py: Path, *, epoch: int) -> Dict[str, str]:
    env = os.environ.copy()
    # Prefer hermes/setuptools vendored wheel when top-level wheel is absent.
    proc = subprocess.run(
        [
            str(py),
            "-c",
            "import importlib.util,setuptools,sys\n"
            "from pathlib import Path\n"
            "if importlib.util.find_spec('wheel') is None:\n"
            "  v=Path(setuptools.__file__).resolve().parent/'_vendor'\n"
            "  print(v)\n",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    vendor = (proc.stdout or "").strip()
    if vendor:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = vendor + (os.pathsep + existing if existing else "")
    # Never hit PyPI.
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["SOURCE_DATE_EPOCH"] = str(epoch)
    env["PYTHONHASHSEED"] = "0"
    env["TZ"] = "UTC"
    return env


def _clamp_tree_mtime(root: Path, epoch: int) -> None:
    """Clamp all file/dir mtimes under root to epoch (best-effort for builders)."""
    paths = [root]
    paths.extend(sorted(root.rglob("*"), key=lambda p: p.as_posix()))
    for path in reversed(paths):
        try:
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        except OSError:
            try:
                os.utime(path, (epoch, epoch))
            except OSError:
                pass


def _clean_src_copy(dest: Path, *, epoch: int) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        ROOT,
        dest,
        ignore=shutil.ignore_patterns(
            ".venv",
            ".pytest_cache",
            "__pycache__",
            "tests",
            "scripts",
            "docs",
            "build",
            "dist",
            "*.egg-info",
            ".eggs",
            ".m0-*",
            ".m2-*",
            "*.md",
        ),
    )
    _clamp_tree_mtime(dest, epoch)
    return dest


def clean_prior_artifacts(out_dir: Path) -> None:
    """Remove *this version's* prior artifacts so glob cannot pick stale files.

    Deliberately version-scoped. An earlier revision globbed ``*.whl`` /
    ``*.tar.gz`` / ``*-hermes-plugin.zip`` unconditionally, which silently
    deleted every retained historical release artifact whenever ``out_dir`` was
    the repository ``dist/`` (measured 2026-08-21: building 0.4.5 into a copy of
    the repo took dist/ from 12 files to 7, destroying the nine git-tracked
    0.4.2/0.4.3/0.4.4 artifacts that four gates hash-freeze). Previous releases
    only survived because they were built into a temp dir and hand-copied.

    Stale-file safety is preserved: the four current-version names are removed
    explicitly, and any same-version leftovers (e.g. ``.tmp`` partials from an
    interrupted normalize step) are swept by version-anchored patterns. Other
    versions' artifacts are never touched — clearing them is a release decision,
    not a build-step side effect.
    """
    assert_no_build_tripwire("clean_prior_artifacts")
    out_dir.mkdir(parents=True, exist_ok=True)
    named = (WHEEL_NAME, SDIST_NAME, PLUGIN_ZIP_NAME, ARTIFACT_MANIFEST_NAME)
    for name in named:
        path = out_dir / name
        if path.is_file():
            path.unlink()
    # Version-anchored sweep: partial/renamed leftovers for THIS version only.
    version_patterns = (
        f"hermes_credential_guard-{PLUGIN_VERSION}-*.whl",
        f"hermes_credential_guard-{PLUGIN_VERSION}.tar.gz*",
        f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip*",
        f"artifact-manifest-{PLUGIN_VERSION}.json*",
    )
    for pattern in version_patterns:
        for path in out_dir.glob(pattern):
            if path.is_file():
                path.unlink()


def normalize_zip_file(src: Path, dest: Path, *, epoch: int) -> None:
    """Rewrite a zip with stable order, date_time, Unix mode, and compression."""
    date_time = _zip_date_time(epoch)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    with zipfile.ZipFile(src, "r") as zin:
        names = sorted(zin.namelist())
        with zipfile.ZipFile(tmp, "w") as zout:
            for name in names:
                info = zin.getinfo(name)
                data = zin.read(name)
                out = zipfile.ZipInfo(filename=name, date_time=date_time)
                out.create_system = 3  # Unix
                out.create_version = 20
                out.extract_version = 20
                if name.endswith("/") or info.is_dir():
                    out.external_attr = (0o755 << 16) | 0x10
                    out.compress_type = zipfile.ZIP_STORED
                    zout.writestr(out, b"")
                else:
                    out.external_attr = 0o644 << 16
                    out.compress_type = zipfile.ZIP_DEFLATED
                    zout.writestr(out, data)
    tmp.replace(dest)


def normalize_sdist_tarball(src: Path, dest: Path, *, epoch: int) -> None:
    """Rewrite sdist tar.gz with fixed mtime/uid/gid/uname/gname/mode + gzip mtime."""
    entries: List[Tuple[tarfile.TarInfo, Optional[bytes]]] = []
    with tarfile.open(src, "r:gz") as tf:
        for member in sorted(tf.getmembers(), key=lambda m: m.name):
            data: Optional[bytes] = None
            if member.isfile():
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise ReleaseBuildError(f"sdist member unreadable: {member.name}")
                data = extracted.read()
            elif member.isdir():
                data = None
            else:
                # Skip non-regular / non-dir (should not appear in our sdist).
                continue
            entries.append((member, data))

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for member, data in entries:
            new = tarfile.TarInfo(name=member.name)
            new.mtime = int(epoch)
            new.uid = 0
            new.gid = 0
            new.uname = "root"
            new.gname = "root"
            if member.isdir() or member.name.endswith("/"):
                new.type = tarfile.DIRTYPE
                new.mode = 0o755
                new.size = 0
                tf.addfile(new)
            else:
                assert data is not None
                new.type = tarfile.REGTYPE
                new.mode = 0o644
                new.size = len(data)
                tf.addfile(new, io.BytesIO(data))

    tar_bytes = tar_buf.getvalue()
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    with open(tmp, "wb") as raw:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw,
            mtime=int(epoch),
            compresslevel=9,
        ) as gz:
            gz.write(tar_bytes)
    tmp.replace(dest)


def build_sdist_and_wheel(out_dir: Path, *, py: Optional[Path] = None) -> Dict[str, Path]:
    """Build real sdist + wheel offline in a clean source copy, then normalize."""
    assert_no_build_tripwire("build_sdist_and_wheel")
    out_dir.mkdir(parents=True, exist_ok=True)
    builder = py or find_build_python()
    epoch = source_date_epoch()
    with tempfile.TemporaryDirectory(prefix="cg-release-src-") as tmp:
        work = _clean_src_copy(Path(tmp) / "src", epoch=epoch)
        env = _build_env(builder, epoch=epoch)

        # Build into an isolated staging dir, then normalize into out_dir.
        staging = Path(tmp) / "staging"
        staging.mkdir()

        wheel_proc = subprocess.run(
            [
                str(builder),
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--no-index",
                "-w",
                str(staging),
                ".",
            ],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env=env,
        )
        if wheel_proc.returncode != 0:
            raise ReleaseBuildError(
                "real wheel build failed (offline):\n"
                + (wheel_proc.stderr or "")[-1200:]
                + "\n"
                + (wheel_proc.stdout or "")[-400:]
            )

        sdist_proc = subprocess.run(
            [str(builder), "setup.py", "sdist", "--dist-dir", str(staging)],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env=env,
        )
        if sdist_proc.returncode != 0:
            raise ReleaseBuildError(
                "real sdist build failed:\n"
                + (sdist_proc.stderr or "")[-1200:]
                + "\n"
                + (sdist_proc.stdout or "")[-400:]
            )

        wheels = sorted(staging.glob("*.whl"))
        if len(wheels) != 1:
            raise ReleaseBuildError(f"expected one wheel in staging, found {wheels}")
        sdists = sorted(staging.glob("*.tar.gz"))
        if len(sdists) != 1:
            raise ReleaseBuildError(f"expected one sdist in staging, found {sdists}")

        wheel_out = out_dir / WHEEL_NAME
        sdist_out = out_dir / SDIST_NAME
        normalize_zip_file(wheels[0], wheel_out, epoch=epoch)
        normalize_sdist_tarball(sdists[0], sdist_out, epoch=epoch)

    if not wheel_out.is_file() or not sdist_out.is_file():
        raise ReleaseBuildError("normalized wheel/sdist missing after build")
    return {"wheel": wheel_out, "sdist": sdist_out, "build_python": builder}  # type: ignore[dict-item]


def build_hermes_plugin_zip(
    out_dir: Path,
    *,
    wheel: Path,
    py: Optional[Path] = None,
) -> Path:
    """Assemble final Hermes-installable plugin zip from a real wheel + root files."""
    assert_no_build_tripwire("build_hermes_plugin_zip")
    del py  # reserved for API compatibility
    out_dir.mkdir(parents=True, exist_ok=True)
    epoch = source_date_epoch()
    date_time = _zip_date_time(epoch)
    zip_path = out_dir / PLUGIN_ZIP_NAME
    with tempfile.TemporaryDirectory(prefix="cg-plugin-zip-") as tmp:
        staging = Path(tmp) / "credential-guard"
        staging.mkdir()
        with zipfile.ZipFile(wheel) as zf:
            zf.extractall(staging)
        # Drop the Python distribution metadata — Hermes loads a directory plugin.
        for dist_info in staging.glob("*.dist-info"):
            shutil.rmtree(dist_info)
        if not (staging / "credential_guard").is_dir():
            raise ReleaseBuildError("wheel missing credential_guard/")
        for name in _REQUIRED_PLUGIN_ROOT:
            src = ROOT / name
            if not src.is_file():
                raise ReleaseBuildError(f"missing release root file: {name}")
            shutil.copy2(src, staging / name)
        _clamp_tree_mtime(staging, epoch)

        if zip_path.exists():
            zip_path.unlink()
        # Write with fully fixed ZipInfo (not Path.write which embeds file mtime).
        with zipfile.ZipFile(zip_path, "w") as zf:
            for path in sorted(p for p in staging.rglob("*") if p.is_file()):
                arc = (Path("credential-guard") / path.relative_to(staging)).as_posix()
                info = zipfile.ZipInfo(filename=arc, date_time=date_time)
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.external_attr = 0o644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, path.read_bytes())
    return zip_path


def extract_plugin_zip(plugin_zip: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(plugin_zip) as zf:
        zf.extractall(dest)
    plugin_dir = dest / "credential-guard"
    if not plugin_dir.is_dir():
        raise ReleaseBuildError("plugin zip missing credential-guard/")
    return plugin_dir


def _compute_identity_hashes() -> Dict[str, str]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from credential_guard.release_identity import candidate_manifest_sha256

    return {"candidate_manifest_sha256": candidate_manifest_sha256(ROOT)}


def write_artifact_manifest(out_dir: Path, built: Dict[str, Any]) -> Path:
    """Write versioned artifact-manifest-<ver>.json from actual build results."""
    identity = _compute_identity_hashes()
    epoch = source_date_epoch()
    payload = {
        "version": PLUGIN_VERSION,
        "candidate_manifest_sha256": identity["candidate_manifest_sha256"],
        "wheel": {
            "filename": Path(built["wheel"]).name,
            "sha256": built["wheel_sha256"],
            "size": Path(built["wheel"]).stat().st_size,
        },
        "sdist": {
            "filename": Path(built["sdist"]).name,
            "sha256": built["sdist_sha256"],
            "size": Path(built["sdist"]).stat().st_size,
        },
        "plugin_zip": {
            "filename": Path(built["plugin_zip"]).name,
            "sha256": built["plugin_zip_sha256"],
            "size": Path(built["plugin_zip"]).stat().st_size,
        },
        "build": {
            "source_date_epoch": epoch,
            "pythonhashseed": "0",
            "tz": "UTC",
            "normalized_archives": True,
            "build_python": str(built.get("build_python") or ""),
        },
    }
    path = out_dir / ARTIFACT_MANIFEST_NAME
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def build_all(out_dir: Path) -> Dict[str, Any]:
    """Build wheel, sdist, and final Hermes plugin zip; return paths + hashes."""
    # Boundary two: first statement of the build entry point — before any
    # filesystem effect — so no-build runs fail even if static gates were bypassed.
    assert_no_build_tripwire("build_all")
    clean_prior_artifacts(out_dir)
    built = build_sdist_and_wheel(out_dir)
    plugin_zip = build_hermes_plugin_zip(out_dir, wheel=built["wheel"])
    result: Dict[str, Any] = {
        "wheel": built["wheel"],
        "sdist": built["sdist"],
        "plugin_zip": plugin_zip,
        "build_python": str(built["build_python"]),
        "wheel_sha256": _sha256(built["wheel"]),
        "sdist_sha256": _sha256(built["sdist"]),
        "plugin_zip_sha256": _sha256(plugin_zip),
        "source_date_epoch": source_date_epoch(),
    }
    manifest = write_artifact_manifest(out_dir, result)
    result["artifact_manifest"] = manifest
    result["artifact_manifest_sha256"] = _sha256(manifest)
    return result


def main() -> int:
    out = ROOT / "dist"
    try:
        result = build_all(out)
    except NoBuildTripwireError as exc:
        print(f"RELEASE_BUILD_TRIPWIRE: {exc}", file=sys.stderr)
        return 3
    except ReleaseBuildError as exc:
        print(f"RELEASE_BUILD_FAIL: {exc}", file=sys.stderr)
        return 2
    print("RELEASE_BUILD_OK")
    for key in ("wheel", "sdist", "plugin_zip"):
        path = result[key]
        print(f"{key}={path}")
        print(f"{key}_sha256={result[key + '_sha256']}")
    print(f"artifact_manifest={result['artifact_manifest']}")
    print(f"source_date_epoch={result['source_date_epoch']}")
    print(f"build_python={result['build_python']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
