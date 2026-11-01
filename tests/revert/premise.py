"""PREMISE.json helpers and the refusal-reason oracle audit (SPEC-504ed55 §2).

Hashes pin the exact code a validation run certified:
  probe:        sha256 of the probe file bytes.
  probelib:     sha256 of tests/probes/probelib.py.
  fixed_units:  per unit, sha256 of the AST dump of the fixed function
                (function units) or of the target file (patch units).
  revert_units: per unit, sha256 of the reference impl file (function
                units) or of the patch anchor strings (patch units).

Any drift in the probe, its harness, or the code it targets makes the
record STALE-PREMISE: the pair must be re-validated, never trusted.

Oracle rule (makes I13 enforceable): a bound probe's containment verdict
(the manifest `expected` token) must be decided by the REFUSAL REASON —
a check on step-output content, the guard's verdict, or the attack's
observable effect. Two verdict shapes are rejected:
  * "any nonzero exit": the expected token guarded by a bare `rc != 0`
    (or equivalent) with no content check alongside it. A crash then
    reads as containment.
  * disjunctive oracles (`A or B`): an `or` across DIFFERENT signals in
    the verdict condition. Alternative phrasings of the SAME refusal
    from the SAME step output (`"older prefix" in out or
    "heads mirror records" in out`) are one refusal reason, not two
    layers, and are allowed.
Vuln-token findings are the attack-succeeded observation (covered by the
flip test's exact-token requirement) and are not audited here.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

PREMISE_NAME = "tests/revert/PREMISE.json"

GATE_CALLS = {"g3_verdict", "evaluate", "verify_all", "lineage", "chain_checkpoints"}


def sha_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def func_ast_hash(repo: Path, module: str, func: str) -> str:
    """sha256 of the AST dump of `func` in the current tree (whitespace- and
    comment-insensitive; any semantic edit changes the hash)."""
    tree = ast.parse((Path(repo) / module).read_text(encoding="utf-8"))
    matches = [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == func]
    if len(matches) != 1:
        raise ValueError(f"{module}: found {len(matches)} definitions of {func!r}")
    return hashlib.sha256(ast.dump(matches[0]).encode()).hexdigest()


def patch_unit_hash(repo: Path, unit: dict) -> str:
    """sha256 of the target file bytes plus the patch anchor strings."""
    h = hashlib.sha256()
    h.update((Path(repo) / unit["module"]).read_bytes())
    for old, new in unit["patches"]:
        h.update(b"\x00OLD\x00" + old.encode())
        h.update(b"\x00NEW\x00" + new.encode())
    return h.hexdigest()


def unit_fixed_hash(repo: Path, unit: dict) -> str:
    if unit["kind"] == "function":
        return func_ast_hash(repo, unit["module"], unit["func"])
    return patch_unit_hash(repo, unit)


def unit_revert_hash(repo: Path, unit: dict) -> str:
    if unit["kind"] == "function":
        return sha_file(Path(repo) / unit["impl"])
    h = hashlib.sha256()
    for old, new in unit["patches"]:
        h.update(b"\x00OLD\x00" + old.encode())
        h.update(b"\x00NEW\x00" + new.encode())
    return h.hexdigest()


def pair_hashes(repo: Path, scenario: dict) -> dict:
    return {
        "probelib": sha_file(Path(repo) / "tests/probes/probelib.py"),
        "fixed_units": {u["id"]: unit_fixed_hash(repo, u) for u in scenario["units"]},
        "revert_units": {u["id"]: unit_revert_hash(repo, u) for u in scenario["units"]},
    }


def load_premise(repo: Path) -> dict:
    path = Path(repo) / PREMISE_NAME
    if not path.is_file():
        return {"version": 1, "records": []}
    return json.loads(path.read_text(encoding="utf-8"))


def find_record(premise: dict, scenario_id: str, probe: str) -> dict | None:
    for r in premise.get("records", []):
        if r.get("scenario") == scenario_id and r.get("probe") == probe:
            return r
    return None


def check_pair(repo: Path, scenario: dict, probe: str, record: dict | None) -> str | None:
    """None when the record is fresh; otherwise the failure line.

    Missing record -> NO-RECORD (a probe bound to an anchor with no
    validation record is rejected). Hash drift -> STALE-PREMISE.
    """
    if record is None:
        return (f"NO-RECORD: {probe} is bound to [{scenario['id']}] but has no "
                f"PREMISE record — run: python -m tests.revert validate")
    want_probe = sha_file(Path(repo) / "tests/probes" / probe)
    if record.get("probe_hash") != want_probe:
        return (f"STALE-PREMISE: {probe} changed after validation "
                f"(probe hash drift) — re-run: python -m tests.revert validate")
    cur = pair_hashes(repo, scenario)
    if record.get("hashes", {}).get("probelib") != cur["probelib"]:
        return (f"STALE-PREMISE: {scenario['id']} :: {probe} — probelib.py "
                f"changed after validation — re-run: python -m tests.revert validate")
    for uid, h in cur["fixed_units"].items():
        if record.get("hashes", {}).get("fixed_units", {}).get(uid) != h:
            return (f"STALE-PREMISE: {scenario['id']} :: {probe} — target unit "
                    f"{uid} changed after validation — re-run: python -m tests.revert validate")
    for uid, h in cur["revert_units"].items():
        if record.get("hashes", {}).get("revert_units", {}).get(uid) != h:
            return (f"STALE-PREMISE: {scenario['id']} :: {probe} — reference "
                    f"impl {uid} changed after validation — re-run: python -m tests.revert validate")
    return None


# ---------------------------------------------------------------------------
# Oracle audit
# ---------------------------------------------------------------------------

class _Scope:
    """One-level name resolution inside a probe function/module."""

    # Names that carry step content: the raw step output, parsed verdicts,
    # and guard-verdict lists. A verdict condition that consults any of
    # these (after assignment resolution) is reading the refusal, not
    # just the exit code.
    CONTENT_NAMES = {"out", "err", "stderr", "stdout", "output", "msg",
                     "message", "action", "rec", "data", "probs",
                     "problems", "verdicts", "failed_bound"}

    def __init__(self, tree: ast.Module):
        self.assigns: dict[str, list[ast.AST]] = {}
        self.append_conds: dict[str, list[ast.AST]] = {}
        parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents.setdefault(id(child), node)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif node.target is not None:
                    targets = [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        self.assigns.setdefault(t.id, []).append(node.value)
            elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute)
                    and node.value.func.attr == "append"
                    and isinstance(node.value.func.value, ast.Name)):
                name = node.value.func.value.id
                up: ast.AST | None = node
                while up is not None:
                    up = parents.get(id(up))
                    if isinstance(up, ast.If):
                        self.append_conds.setdefault(name, []).append(up.test)
                        break
                    if isinstance(up, (ast.FunctionDef, ast.AsyncFunctionDef,
                                       ast.Module)):
                        break

    def parents_of(self, tree: ast.Module) -> dict[int, ast.AST]:
        parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents.setdefault(id(child), node)
        return parents


def _expanded(node: ast.AST, scope: _Scope, depth: int = 0) -> list[ast.AST]:
    """The node plus, for bare Names, their assigned RHS and the guards of
    their .append() sites (bounded)."""
    out = [node]
    if depth < 3 and isinstance(node, ast.Name):
        if node.id in scope.assigns:
            for rhs in scope.assigns[node.id]:
                out.extend(_expanded(rhs, scope, depth + 1))
        for cond in scope.append_conds.get(node.id, []):
            out.extend(_expanded(cond, scope, depth + 1))
    return out


def audit_oracle(probe_path: Path, expected_token: str) -> list[str]:
    """Refusal-reason audit for one bound probe. Returns error lines ([] = pass).

    Only findings that print the manifest `expected` (containment) token are
    audited; vuln-token findings are the attack-succeeded observation and are
    constrained by the flip test's exact-token requirement instead.
    """
    src = Path(probe_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    scope = _Scope(tree)
    parents = scope.parents_of(tree)
    errors: list[str] = []

    findings = [n for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                if isinstance(n.func, ast.Name) and n.func.id == "finding"]
    for call in findings:
        if not call.args:
            continue
        # A finding argument may itself be a ternary (the common probe
        # shape: finding(EXPECTED if <verdict> else <other>)). Collect
        # (token-node, condition) branches; a bare token takes the
        # enclosing If/IfExp condition instead.
        branches: list[tuple[ast.AST, ast.AST | None]] = []
        stack: list[tuple[ast.AST, ast.AST | None]] = [(call.args[0], None)]
        while stack:
            arg, given = stack.pop()
            if isinstance(arg, ast.IfExp):
                pos = arg.test if given is None else ast.BoolOp(
                    op=ast.And(), values=[given, arg.test])
                neg = ast.UnaryOp(op=ast.Not(), operand=arg.test) \
                    if given is None else ast.BoolOp(
                        op=ast.And(), values=[given, ast.UnaryOp(
                            op=ast.Not(), operand=arg.test)])
                stack.append((arg.body, pos))
                stack.append((arg.orelse, neg))
            else:
                branches.append((arg, given))

        for tok, branch_cond in branches:
            token_is_expected = False
            if isinstance(tok, ast.Constant) and isinstance(tok.value, str):
                token_is_expected = (tok.value == expected_token)
            elif isinstance(tok, ast.Name) and tok.id in scope.assigns:
                vals = [v.value for v in scope.assigns[tok.id]
                        if isinstance(v, ast.Constant)
                        and isinstance(v.value, str)]
                token_is_expected = (expected_token in vals)
            if not token_is_expected:
                continue  # vuln/diagnostic token: flip test owns it
            # Verdict condition: the ternary branch condition, else the
            # nearest enclosing If / IfExp test.
            cond: ast.AST | None = branch_cond
            if cond is None:
                node: ast.AST | None = call
                while node is not None:
                    parent = parents.get(id(node))
                    if isinstance(parent, ast.IfExp):
                        cond = parent.test
                        break
                    if isinstance(parent, ast.If):
                        cond = parent.test
                        if node not in parent.body:
                            cond = ast.UnaryOp(op=ast.Not(), operand=parent.test)
                        break
                    node = parent
            if cond is None:
                errors.append(f"{Path(probe_path).name}: unconditional "
                              f"{expected_token} finding — containment verdict "
                              f"with no guard")
                continue
            expanded: list[ast.AST] = []
            for part in ([cond] if not isinstance(cond, ast.BoolOp) else [cond]):
                expanded.append(part)
                for n in ast.walk(part):
                    if isinstance(n, ast.Name):
                        expanded.extend(_expanded(n, scope))
            # Transitive closure: also resolve names discovered inside
            # guards and assignments (e.g. `not ok` -> ok -> action check).
            closure: list[ast.AST] = list(expanded)
            seen: set[int] = {id(x) for x in closure}
            queue: list[ast.AST] = list(expanded)
            while queue:
                cur = queue.pop()
                for sub in ast.walk(cur):
                    if isinstance(sub, ast.Name):
                        for extra in _expanded(sub, scope):
                            if id(extra) not in seen:
                                seen.add(id(extra))
                                closure.append(extra)
                                queue.append(extra)
            # Disjunctive oracle check: an `or` across different signals.
            for n in closure:
                for sub in ast.walk(n):
                    if isinstance(sub, ast.BoolOp) and isinstance(sub.op, ast.Or):
                        operands = []
                        for v in sub.values:
                            atoms = [v] if not isinstance(v, ast.Name) \
                                else _expanded(v, scope)
                            operands.append(atoms)
                        flat_vars: list[str] = []
                        same_var_in = True
                        for atoms in operands:
                            ins = [a for x in atoms for a in ast.walk(x)
                                   if isinstance(a, ast.Compare)
                                   and any(isinstance(o, ast.In) for o in a.ops)]
                            if len(ins) != 1:
                                same_var_in = False
                                break
                            comp = ins[0].comparators[0]
                            flat_vars.append(ast.dump(comp))
                        if not (same_var_in and len(set(flat_vars)) == 1):
                            errors.append(
                                f"{Path(probe_path).name}: disjunctive oracle "
                                f"(A or B across different signals) guards "
                                f"{expected_token} — verdicts must come from one "
                                f"refusal reason")
                            break
            # Refusal-reason check: the expanded condition must reference step
            # content — a refusal-text substring, a string-verdict comparison,
            # a guard call, or parsed-output access — and a bare exit-code
            # comparison alone is never enough.
            has_content = False
            for n in closure:
                for sub in [n, *list(ast.walk(n))]:
                    if isinstance(sub, ast.Compare) and any(
                            isinstance(o, (ast.In, ast.NotIn)) for o in sub.ops):
                        has_content = True
                    if (isinstance(sub, ast.Compare)
                            and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in sub.ops)
                            and any(isinstance(e, ast.Constant) and isinstance(e.value, str)
                                    for e in [sub.left, *sub.comparators])):
                        has_content = True
                    if (isinstance(sub, ast.Call)
                            and ((isinstance(sub.func, ast.Name)
                                  and sub.func.id in GATE_CALLS)
                                 or (isinstance(sub.func, ast.Attribute)
                                     and sub.func.attr in GATE_CALLS))):
                        has_content = True
                    if isinstance(sub, ast.Subscript):
                        has_content = True
                    if (isinstance(sub, ast.Name)
                            and sub.id in _Scope.CONTENT_NAMES):
                        has_content = True
            # A top-level lone exit-code comparison deciding the finding is
            # caught by the no-content rule above (an rc-only condition has
            # no refusal-text, verdict-string, guard-call, or output access).
            if not has_content:
                errors.append(f"{Path(probe_path).name}: {expected_token} verdict is "
                              f"not decided by a refusal reason (bare exit code?) "
                              f"— assert on the refusal text or guard verdict")
    return errors
