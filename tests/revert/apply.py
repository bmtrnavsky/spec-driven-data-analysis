"""AST-based whole-function replacement for revert scenarios, isolated (I16).

Reverts NEVER touch the source checkout (SPEC-34478d1 NEW-5 / I16). Every
reverted arm runs inside a private sandbox copy of the working tree:

    with revert_sandbox(REPO) as sbx:
        restore = apply_unit(sbx, "scripts/ddalib/chain.py",
                             "_append_locked", "tests/revert/impl/....py")
        try:
            ...run probes / conformance against sbx...
        finally:
            restore()

Guarantees:
  * isolation:     apply_unit / apply_patch_unit / apply_units refuse any
                   root that is not a sandbox (RevertIsolationError). The
                   source checkout is read, never written, by a revert.
  * exclusion:     an exclusive OS lock on <git-common-dir>/dda-revert.lock
                   (msvcrt / fcntl; the OS drops it when the holder dies, so
                   a killed run never wedges the next one) is held for the
                   whole sandbox lifetime: concurrent runs cannot interleave
                   revert sessions or race the self-check repair.
  * exact restore: restore() writes back the PRISTINE bytes captured the
                   first time a file is touched in the sandbox, with
                   write_bytes. Interleaved restores (rA, rB, rA(), rB())
                   cannot strand a mutated file, and line endings are never
                   rewritten (no LF->CRLF churn).
  * cleanup:       try/finally, plus SIGTERM/SIGBREAK/SIGHUP -> SystemExit so
                   the finally runs on a catchable signal. A hard kill
                   (TerminateProcess / SIGKILL) can only orphan a temp
                   sandbox, never a product file; the next startup sweeps it.
  * startup self-check: once per process, under the lock, startup_selfcheck()
                   detects product modules left stripped by an earlier run
                   (current text == HEAD with one or more known revert units
                   applied, e.g. by a pre-I16 harness killed mid-arm or two
                   overlapping legacy runs), backs each up, restores it from
                   HEAD, and has the premise validator re-validate every
                   record the strip left STALE.

Any structural problem raises :class:`IncoherentRevert` and leaves the
target file untouched.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path


# Reference impl -> conformance check run WHILE the revert is applied
# (SPEC-504ed55 §3). A check exits 0 only when the reverted unit behaves
# like its pre-fix self; anything else is INCOHERENT-REVERT, never a pass.
CONFORMANCE = {
    "tests/revert/impl/chain_append_locked_historic_d135783.py":
        "tests/revert/conformance/check_chain_append_locked_historic.py",
    "tests/revert/impl/chain_append_locked_no_M7.py":
        "tests/revert/conformance/check_chain_append_locked_no_M7.py",
    "tests/revert/impl/ledger_checkpoint_problems_none.py":
        "tests/revert/conformance/check_ledger_checkpoint_problems_none.py",
    "tests/revert/impl/lineage_lineage_no_pin.py":
        "tests/revert/conformance/check_lineage_lineage_no_pin.py",
    "tests/revert/impl/review_existing_calls_preN2.py":
        "tests/revert/conformance/check_review_existing_calls_preN2.py",
}

SANDBOX_PREFIX = "dda-revert-sbx-"
SANDBOX_MARKER = ".dda-revert-sandbox.json"
LOCK_NAME = "dda-revert.lock"
LOCK_TIMEOUT = float(os.environ.get("DDA_REVERT_LOCK_TIMEOUT", "7200"))
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", "*.pyc", ".pytest_cache", ".venv", "out")


class IncoherentRevert(Exception):
    """The reverted unit cannot be applied coherently: report, never run probes."""


class RevertIsolationError(RuntimeError):
    """A revert was aimed at a non-sandbox root, the lock could not be had,
    or the source tree is in a state the self-check will not auto-repair."""


def _log(msg: str) -> None:
    print(f"[revert-harness] {msg}", file=sys.stderr, flush=True)


def normalize_eol(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def _read_lf(path: Path) -> str:
    return normalize_eol(Path(path).read_bytes()).decode("utf-8")


# ---------------------------------------------------------------------------
# Repo-level exclusive lock
# ---------------------------------------------------------------------------

def _git_common_dir(repo: Path) -> Path | None:
    try:
        p = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0 or not p.stdout.strip():
        return None
    d = Path(p.stdout.strip())
    return d if d.is_absolute() else (Path(repo) / d).resolve()


def lock_path(repo: Path) -> Path:
    gd = _git_common_dir(repo)
    return (gd if gd is not None else Path(repo)) / LOCK_NAME


_LOCK_GUARD = threading.RLock()
_HELD: dict[str, list] = {}  # lock path -> [fileobj, depth]


def _try_os_lock(fh) -> bool:
    fh.seek(0)
    if os.name == "nt":
        import msvcrt
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _os_unlock(fh) -> None:
    fh.seek(0)
    if os.name == "nt":
        import msvcrt
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


@contextmanager
def repo_lock(repo: Path, timeout: float | None = None):
    """Exclusive, process-reentrant, released-by-the-OS-on-death repo lock."""
    path = lock_path(repo)
    key = str(path)
    with _LOCK_GUARD:
        held = _HELD.get(key)
        if held is not None:
            held[1] += 1
        else:
            fh = open(path, "a+b")
            deadline = time.monotonic() + (LOCK_TIMEOUT if timeout is None else timeout)
            waited = False
            while not _try_os_lock(fh):
                if not waited:
                    _log(f"waiting for revert lock {path} (another run holds it)")
                    waited = True
                if time.monotonic() > deadline:
                    fh.close()
                    raise RevertIsolationError(
                        f"timed out waiting for the revert lock {path}")
                time.sleep(0.2)
            if waited:
                _log(f"acquired revert lock {path}")
            _HELD[key] = [fh, 1]
    try:
        yield path
    finally:
        with _LOCK_GUARD:
            entry = _HELD[key]
            entry[1] -= 1
            if entry[1] == 0:
                _HELD.pop(key, None)
                _os_unlock(entry[0])
                entry[0].close()


# ---------------------------------------------------------------------------
# Sandboxes
# ---------------------------------------------------------------------------

_PRISTINE: dict[str, dict[str, bytes]] = {}  # sandbox root -> relpath -> bytes


def is_sandbox(root: Path) -> bool:
    return (Path(root) / SANDBOX_MARKER).is_file()


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def sweep_orphan_sandboxes() -> list[str]:
    """Remove sandboxes whose owning process is gone (hard-killed runs)."""
    swept = []
    for d in Path(tempfile.gettempdir()).glob(SANDBOX_PREFIX + "*"):
        meta = d / "repo" / SANDBOX_MARKER
        try:
            pid = int(json.loads(meta.read_text(encoding="utf-8")).get("pid", 0))
        except (OSError, ValueError):
            # Half-created sandbox: sweep only when clearly abandoned.
            try:
                if time.time() - d.stat().st_mtime < 3600:
                    continue
            except OSError:
                continue
            pid = 0
        if pid == os.getpid() or (pid and _pid_alive(pid)):
            continue
        shutil.rmtree(d, ignore_errors=True)
        swept.append(str(d))
    return swept


def _install_signal_handlers():
    """SIGTERM/SIGBREAK/SIGHUP -> SystemExit so `finally` cleanup runs."""
    if threading.current_thread() is not threading.main_thread():
        return []
    saved = []

    def _raise(signum, _frame):
        raise SystemExit(128 + signum)
    for name in ("SIGTERM", "SIGBREAK", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            prev = signal.getsignal(sig)
            if prev in (signal.SIG_DFL, None):
                signal.signal(sig, _raise)
                saved.append((sig, prev))
        except (ValueError, OSError):
            pass
    return saved


def _restore_signal_handlers(saved) -> None:
    for sig, prev in saved:
        try:
            signal.signal(sig, prev)
        except (ValueError, OSError):
            pass


@contextmanager
def revert_sandbox(repo: Path, selfcheck: bool = True):
    """Private copy of the working tree (minus .git) for one revert session.

    Holds the repo lock for its whole lifetime and runs the once-per-process
    startup self-check first. Yields the sandbox root.
    """
    repo = Path(repo).resolve()
    if is_sandbox(repo):
        raise RevertIsolationError(f"{repo} is already a sandbox")
    with repo_lock(repo):
        if selfcheck:
            startup_selfcheck(repo)
        saved_sigs = _install_signal_handlers()
        tmp = Path(tempfile.mkdtemp(prefix=SANDBOX_PREFIX))
        root = tmp / "repo"
        try:
            shutil.copytree(repo, root, ignore=_COPY_IGNORE)
            (root / SANDBOX_MARKER).write_text(json.dumps(
                {"origin": str(repo), "pid": os.getpid(),
                 "created": time.time()}), encoding="utf-8")
            _PRISTINE[str(root)] = {}
            yield root
        finally:
            _PRISTINE.pop(str(root), None)
            shutil.rmtree(tmp, ignore_errors=True)
            _restore_signal_handlers(saved_sigs)


def _require_sandbox(root: Path) -> None:
    if not is_sandbox(root):
        raise RevertIsolationError(
            f"refusing to apply a revert to {root}: reverts never touch the "
            f"source checkout (I16) — use `with revert_sandbox(REPO) as sbx`")


def _capture(root: Path, relpath: str) -> tuple[Path, bytes]:
    """Target path + its PRISTINE bytes (first sight in this sandbox)."""
    target = Path(root) / relpath
    store = _PRISTINE.setdefault(str(Path(root)), {})
    if relpath not in store:
        store[relpath] = target.read_bytes()
    return target, store[relpath]


def _restorer(target: Path, pristine: bytes):
    def restore():
        # Interleave-safe: always the pristine bytes, never a snapshot of a
        # sibling arm's mutation; write_bytes never rewrites line endings.
        target.write_bytes(pristine)
    return restore


def _eol_of(raw: bytes) -> str:
    return "\r\n" if b"\r\n" in raw else "\n"


def _write_text_eol(target: Path, text_lf: str, eol: str) -> None:
    data = text_lf.replace("\n", eol) if eol != "\n" else text_lf
    target.write_bytes(data.encode("utf-8"))


# ---------------------------------------------------------------------------
# Pure text transforms (shared by apply and by the self-check)
# ---------------------------------------------------------------------------

def _single_function(tree: ast.Module, func_name: str, where: str):
    matches = [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == func_name]
    if len(matches) != 1:
        raise IncoherentRevert(
            f"{where}: found {len(matches)} definitions of {func_name!r}, "
            f"need exactly 1 for a whole-function revert")
    return matches[0]


def _span(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, int]:
    start = node.lineno - 1
    if node.decorator_list:
        start = min(d.lineno for d in node.decorator_list) - 1
    end = node.end_lineno  # 1-based inclusive -> slice-exclusive as-is
    if end is None:
        raise IncoherentRevert(f"{node.name}: cannot locate function end")
    return start, end


def splice_function(src: str, func_name: str, impl_src: str,
                    relpath: str = "<target>", impl_relpath: str = "<impl>") -> str:
    """`src` (LF text) with `func_name` replaced by the impl. Raises
    IncoherentRevert on any structural problem."""
    if not impl_src.endswith("\n"):
        impl_src += "\n"
    try:
        target_tree = ast.parse(src)
    except SyntaxError as e:
        raise IncoherentRevert(f"{relpath}: target does not parse: {e}") from None
    try:
        impl_tree = ast.parse(impl_src)
    except SyntaxError as e:
        raise IncoherentRevert(f"{impl_relpath}: impl does not parse: {e}") from None
    _single_function(target_tree, func_name, relpath)
    _single_function(impl_tree, func_name, impl_relpath)
    if [n.name for n in impl_tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] != [func_name]:
        raise IncoherentRevert(
            f"{impl_relpath}: must contain exactly the {func_name!r} function")
    t_start, t_end = _span(_single_function(target_tree, func_name, relpath))
    lines = src.splitlines(keepends=True)
    patched = "".join(lines[:t_start]) + impl_src + "".join(lines[t_end:])
    try:
        compile(patched, relpath, "exec")
    except SyntaxError as e:
        raise IncoherentRevert(f"{relpath}: patched module does not compile: {e}") from None
    return patched


def apply_patches(text: str, patches, module: str = "<target>") -> str:
    for old, new in patches:
        if old not in text:
            raise IncoherentRevert(f"{module}: revert anchor not found: {old[:80]!r}")
        text = text.replace(old, new, 1)
    return text


# ---------------------------------------------------------------------------
# Applying reverts (sandbox only)
# ---------------------------------------------------------------------------

def apply_unit(repo_root: Path, relpath: str, func_name: str, impl_relpath: str):
    """Replace `func_name` in `relpath` with the reference `impl_relpath`,
    inside a sandbox. Returns a zero-argument `restore()` closure. The target
    is only written when the patched module compiles; otherwise
    IncoherentRevert is raised and the file is untouched."""
    _require_sandbox(repo_root)
    impl_path = Path(repo_root) / impl_relpath
    try:
        target, pristine = _capture(repo_root, relpath)
        current = target.read_bytes()
    except OSError as e:
        raise IncoherentRevert(f"{relpath}: cannot read target: {e}") from None
    try:
        impl_src = _read_lf(impl_path)
    except OSError as e:
        raise IncoherentRevert(f"{impl_relpath}: cannot read impl: {e}") from None
    patched = splice_function(normalize_eol(current).decode("utf-8"), func_name,
                              impl_src, relpath, impl_relpath)
    _write_text_eol(target, patched, _eol_of(current))
    return _restorer(target, pristine)


def apply_patch_unit(repo_root: Path, unit: dict):
    """String-substitution (patch-kind) unit, inside a sandbox."""
    _require_sandbox(repo_root)
    try:
        target, pristine = _capture(repo_root, unit["module"])
        current = target.read_bytes()
    except OSError as e:
        raise IncoherentRevert(f"{unit['module']}: cannot read target: {e}") from None
    text = apply_patches(normalize_eol(current).decode("utf-8"), unit["patches"],
                         unit["module"])
    _write_text_eol(target, text, _eol_of(current))
    return _restorer(target, pristine)


def apply_units(repo_root: Path, units: list) -> list:
    """Apply every unit; returns restore closures (call reversed). On any
    failure the already-applied units are restored before re-raising."""
    restores = []
    try:
        for u in units:
            kind = u.get("kind", "function")
            if kind == "function":
                restores.append(apply_unit(repo_root, u["module"], u["func"], u["impl"]))
            elif kind == "patch":
                restores.append(apply_patch_unit(repo_root, u))
            else:
                raise IncoherentRevert(f"unknown unit kind: {kind!r}")
    except BaseException:
        for r in reversed(restores):
            r()
        raise
    return restores


# ---------------------------------------------------------------------------
# Startup self-check: detect + repair a source tree stripped by a crashed run
# ---------------------------------------------------------------------------

_SELFCHECKED: dict[str, dict] = {}


def _scenarios():
    try:
        from . import scenarios  # type: ignore
    except ImportError:
        import revert.scenarios as scenarios  # type: ignore
    return scenarios.SCENARIOS


def _git_head_text(repo: Path, relpath: str) -> str | None:
    p = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{relpath}"],
                       capture_output=True, timeout=60)
    if p.returncode != 0:
        return None
    return normalize_eol(p.stdout).decode("utf-8")


def _module_units(module: str) -> list[dict]:
    units, seen = [], set()
    for s in _scenarios():
        for u in s["units"]:
            if u["module"] == module and u["id"] not in seen:
                seen.add(u["id"])
                units.append(u)
    return units


def _unit_transform(repo: Path, u: dict):
    if u["kind"] == "function":
        impl = _read_lf(Path(repo) / u["impl"])
        return lambda text: splice_function(text, u["func"], impl, u["module"], u["impl"])
    return lambda text: apply_patches(text, u["patches"], u["module"])


def stripped_variants(repo: Path, module: str, head_text: str,
                      max_depth: int = 3) -> set[str]:
    """Every text reachable from HEAD by applying 1..max_depth known revert
    units of `module`, in any order (covers overlapping-run strips)."""
    transforms = [_unit_transform(repo, u) for u in _module_units(module)]
    out: set[str] = set()
    frontier = {head_text}
    for _ in range(max_depth):
        nxt = set()
        for text in frontier:
            for t in transforms:
                try:
                    r = t(text)
                except IncoherentRevert:
                    continue
                if r != head_text and r not in out:
                    nxt.add(r)
        out |= nxt
        frontier = nxt
    return out


def _has_revert_signature(repo: Path, module: str, text: str, head: str) -> bool:
    """True when `text` carries a known revert (a reference impl body or a
    patch's added line) that HEAD does not."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    for u in _module_units(module):
        if u["kind"] == "patch":
            for old, new in u["patches"]:
                added = [ln for ln in new.splitlines()
                         if ln.strip() and ln not in old.splitlines()]
                if any(ln in text and ln not in head for ln in added):
                    return True
        elif tree is not None:
            try:
                impl = ast.parse(_read_lf(Path(repo) / u["impl"]))
                inode = _single_function(impl, u["func"], u["impl"])
                tnode = _single_function(tree, u["func"], module)
            except (IncoherentRevert, OSError, SyntaxError):
                continue
            if ast.dump(inode) == ast.dump(tnode):
                return True
    return False


def refresh_premise(repo: Path, modules: list[str], revalidate: bool = True) -> list[str]:
    """Premise-validator refresh after a repair (I14): every record bound to
    a repaired module that is STALE is re-validated with the full matrix.
    Returns the pairs still stale afterwards."""
    try:
        from .premise import check_pair, find_record, load_premise  # type: ignore
    except ImportError:
        from revert.premise import check_pair, find_record, load_premise  # type: ignore
    premise = load_premise(repo)
    stale = []
    for s in _scenarios():
        if not any(u["module"] in modules for u in s["units"]):
            continue
        for probe in s["probes"]:
            if check_pair(repo, s, probe, find_record(premise, s["id"], probe)) is not None:
                stale.append((s["id"], probe))
    if not stale or not revalidate:
        return [f"{sid} :: {p}" for sid, p in stale]
    _log(f"{len(stale)} premise record(s) stale after repair; re-validating")
    try:
        from . import validate as _v  # type: ignore
    except ImportError:
        import revert.validate as _v  # type: ignore
    left = []
    for sid, probe in stale:
        if _v.main(["--scenario", sid, "--probe", probe, "--matrix"]) != 0:
            left.append(f"{sid} :: {probe}")
    return left


def startup_selfcheck(repo: Path, revalidate: bool = True, force: bool = False) -> dict:
    """Once per process: sweep orphan sandboxes, repair product modules left
    stripped by an earlier (crashed / overlapping pre-I16) run, refresh the
    premise records the strip invalidated. Raises RevertIsolationError when
    a module carries a revert signature mixed with unknown edits."""
    repo = Path(repo).resolve()
    key = str(repo)
    if key in _SELFCHECKED and not force:
        return _SELFCHECKED[key]
    report = {"swept": [], "repaired": [], "backups": [], "stale_after": []}
    _SELFCHECKED[key] = report  # set first: refresh_premise re-enters sandboxes
    try:
        with repo_lock(repo):
            report["swept"] = sweep_orphan_sandboxes()
            modules = sorted({u["module"] for s in _scenarios() for u in s["units"]})
            refused = []
            stamp = time.strftime("%Y%m%d-%H%M%S")
            for module in modules:
                path = repo / module
                if not path.is_file():
                    continue
                cur = _read_lf(path)
                head = _git_head_text(repo, module)
                if head is None or cur == head:
                    continue
                if cur in stripped_variants(repo, module, head):
                    bdir = Path(_git_common_dir(repo) or repo) / "dda-revert-backups" / stamp
                    (bdir / module).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, bdir / module)
                    p = subprocess.run(["git", "-C", str(repo), "checkout", "HEAD",
                                        "--", module], capture_output=True,
                                       text=True, timeout=60)
                    if p.returncode != 0 or _read_lf(path) != head:
                        refused.append(f"{module}: repair from HEAD failed: "
                                       f"{(p.stdout + p.stderr)[-200:]}")
                        continue
                    report["repaired"].append(module)
                    report["backups"].append(str(bdir / module))
                    _log(f"STRIPPED-TREE-REPAIRED: {module} carried a known revert "
                         f"left by an earlier run; restored from HEAD "
                         f"(backup: {bdir / module})")
                elif _has_revert_signature(repo, module, cur, head):
                    refused.append(
                        f"{module}: carries a revert signature mixed with other "
                        f"edits — not auto-repairable; inspect `git diff -- {module}`")
            if refused:
                raise RevertIsolationError("revert self-check refused:\n  - "
                                           + "\n  - ".join(refused))
            if report["repaired"]:
                report["stale_after"] = refresh_premise(
                    repo, report["repaired"], revalidate=revalidate)
    except BaseException:
        _SELFCHECKED.pop(key, None)
        raise
    return report


def run_selfcheck_cli(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m tests.revert selfcheck",
                                 description="Revert-harness startup self-check.")
    ap.add_argument("--no-revalidate", action="store_true",
                    help="report stale premise records instead of re-validating")
    args = ap.parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    try:
        rep = startup_selfcheck(repo, revalidate=not args.no_revalidate)
    except RevertIsolationError as e:
        print(f"SELFCHECK-REFUSED: {e}")
        return 2
    print("SELFCHECK:", json.dumps(rep))
    return 1 if rep["stale_after"] else 0
