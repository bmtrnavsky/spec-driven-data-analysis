"""AST-based whole-function replacement for revert scenarios.

Usage: ``restore = apply_unit(REPO, "scripts/ddalib/chain.py",
"_append_locked", "tests/revert/impl/....py")`` then ``restore()`` in a
``finally``. Any structural problem raises :class:`IncoherentRevert` and
leaves the target file untouched.
"""
from __future__ import annotations

import ast
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


class IncoherentRevert(Exception):
    """The reverted unit cannot be applied coherently: report, never run probes."""


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


def apply_unit(repo_root: Path, relpath: str, func_name: str, impl_relpath: str):
    """Replace `func_name` in `relpath` with the reference `impl_relpath`.

    Returns a zero-argument `restore()` closure. The target file is only
    written when the patched module compiles; otherwise IncoherentRevert
    is raised and the file is untouched.
    """
    target = Path(repo_root) / relpath
    impl_path = Path(repo_root) / impl_relpath
    try:
        src = target.read_text(encoding="utf-8")
    except OSError as e:
        raise IncoherentRevert(f"{relpath}: cannot read target: {e}") from None
    try:
        impl_src = impl_path.read_text(encoding="utf-8")
    except OSError as e:
        raise IncoherentRevert(f"{impl_relpath}: cannot read impl: {e}") from None
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
    node = _single_function(impl_tree, func_name, impl_relpath)
    if [n.name for n in impl_tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] != [func_name]:
        raise IncoherentRevert(
            f"{impl_relpath}: must contain exactly the {func_name!r} function")
    t_start, t_end = _span(_single_function(target_tree, func_name, relpath))
    lines = src.splitlines(keepends=True)
    patched = "".join(lines[:t_start]) + impl_src + "".join(lines[t_end:])
    try:
        compile(patched, str(target), "exec")
    except SyntaxError as e:
        raise IncoherentRevert(f"{relpath}: patched module does not compile: {e}") from None

    def restore():
        target.write_text(src, encoding="utf-8")

    target.write_text(patched, encoding="utf-8")
    return restore
