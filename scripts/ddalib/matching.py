"""Tool-input analysis shared by the hooks (spec §6).

Hooks string-match tool inputs: they prevent slips, not determined evasion
(§0.1). Everything here is deliberately conservative and cheap: no file
reads, no hashing, stdlib only.
"""
from __future__ import annotations

import os
import re

# ---------- text and path normalisation ----------

_MSYS_RE = re.compile(r"^/([a-z])/")
_DRIVE_RE = re.compile(r"^[a-z]:/")
_TOKEN_SPLIT = re.compile(r"[\s'\"`=(),;|&<>\[\]{}]+")


def string_leaves(obj, limit: int = 2000) -> list[str]:
    """Every string value (not key) in a JSON-like structure, depth-first."""
    out: list[str] = []
    stack = [obj]
    while stack and len(out) < limit:
        cur = stack.pop()
        if isinstance(cur, str):
            out.append(cur)
        elif isinstance(cur, dict):
            stack.extend(reversed(list(cur.values())))
        elif isinstance(cur, (list, tuple)):
            stack.extend(reversed(cur))
    return out


def norm_text(s: str) -> str:
    """Lower-case, forward slashes, file:// prefixes reduced to the path."""
    s = s.replace("\\\\", "/").replace("\\", "/").lower()
    s = re.sub(r"file:/{2,3}", "", s)
    return s


def canon(p: str, cwd: str | None = None) -> str | None:
    """Canonical absolute path text (lower, forward slashes) or None if `p` is not path-like."""
    if not p or len(p) > 1024 or "\n" in p or "\x00" in p:
        return None
    p = norm_text(p.strip())
    m = _MSYS_RE.match(p)
    if m:
        p = f"{m.group(1)}:/" + p[3:]
    if not (_DRIVE_RE.match(p) or p.startswith("/")):
        if not cwd:
            return None
        base = canon(cwd)
        if not base:
            return None
        p = base.rstrip("/") + "/" + p
    try:
        p = os.path.normpath(p).replace("\\", "/")
    except ValueError:
        return None
    return p.lower().rstrip("/") or "/"


def norm_root(p: str) -> str:
    return canon(p, os.getcwd()) or norm_text(p)


def path_candidates(texts: list[str], cwd: str | None) -> set[str]:
    """Canonical absolute paths for every path-ish token in `texts` (relative ones joined to cwd)."""
    out: set[str] = set()
    for t in texts:
        whole = canon(t, cwd) if len(t) < 1024 and not any(c in t for c in " \t\n'\"") else None
        if whole:
            out.add(whole)
        for tok in _TOKEN_SPLIT.split(t):
            if not tok or len(tok) > 1024:
                continue
            if not (("/" in tok) or ("\\" in tok) or "." in tok):
                continue
            c = canon(tok, cwd)
            if c:
                out.add(c)
    return out


def under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _boundary_contains(hay: str, needle: str) -> bool:
    """`needle` occurs in `hay` not followed by a name character (so /data/raw ≠ /data/raw2)."""
    if not needle:
        return False
    start = 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return False
        j = i + len(needle)
        if j >= len(hay) or not (hay[j].isalnum() or hay[j] in "_-."):
            return True
        if needle.endswith("/"):
            return True
        start = i + 1


def _path_variants(root: str) -> list[str]:
    r = norm_root(root)
    out = [r]
    m = re.match(r"^([a-z]):/(.*)$", r)
    if m:
        out.append(f"/{m.group(1)}/{m.group(2)}")
    return out


_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_\-])([A-Za-z0-9+/_\-]{16,}={0,2})(?![A-Za-z0-9+/=_\-])")


def decoded_tokens(texts: list[str], limit: int = 50) -> list[str]:
    """Printable decodings of base64-looking tokens: a cheap catch for the commonest path obfuscation
    (§0.1: hooks stop slips; a runtime-built path still gets through to the kernel audit hook)."""
    import base64
    import binascii
    out: list[str] = []
    for t in texts:
        if len(t) > 100_000:
            continue
        for m in _B64_TOKEN.finditer(t):
            tok = m.group(1)
            if tok.isalnum() and (tok.isalpha() or tok.isdigit()):
                continue  # plain words / numbers
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    raw = dec(tok + "=" * (-len(tok) % 4))
                    txt = raw.decode("utf-8")
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    continue
                if txt.isprintable() and ("/" in txt or "\\" in txt or "." in txt):
                    out.append(txt)
                    break
            if len(out) >= limit:
                return out
    return out


# ---------- tool-input view ----------

class ToolView:
    """Pre-computed view of one tool call: texts, normalised blob, path candidates."""

    def __init__(self, tool_name: str, tool_input, cwd: str | None):
        self.tool = tool_name or ""
        self.input = tool_input if isinstance(tool_input, dict) else {}
        if isinstance(tool_input, dict) and isinstance(tool_input.get("workdir"), str):
            cwd = tool_input["workdir"] or cwd
        self.cwd = cwd
        self.texts = string_leaves(tool_input)
        self.texts += decoded_tokens(self.texts)
        self.blob = "\n".join(norm_text(t) for t in self.texts)
        self._paths: set[str] | None = None

    @property
    def paths(self) -> set[str]:
        if self._paths is None:
            self._paths = path_candidates(self.texts, self.cwd)
        return self._paths

    def inner_tool_names(self) -> list[str]:
        names = [self.tool]
        calls = self.input.get("calls")
        if isinstance(calls, list):
            for c in calls:
                if isinstance(c, dict) and isinstance(c.get("name"), str):
                    names.append(c["name"])
        if isinstance(self.input.get("name"), str) and self.tool in ("tool_call", "tool_describe"):
            names.append(self.input["name"])
        return names

    def target_path(self) -> str | None:
        """Exact target of a file-writing tool (write_file / patch)."""
        p = self.input.get("path") or self.input.get("file_path")
        return canon(p, self.cwd) if isinstance(p, str) else None

    def mentions_path(self, prefix: str) -> bool:
        pre = canon(prefix) or norm_text(prefix)
        if any(under(p, pre) for p in self.paths):
            return True
        return any(_boundary_contains(self.blob, v) for v in _path_variants(prefix))


def referenced_aliases(view: ToolView, roots: dict) -> set[str]:
    """Aliases whose locators (paths, hosts, URL prefixes, tool-name patterns) the call touches."""
    hits: set[str] = set()
    names = view.inner_tool_names()
    for alias, loc in roots.items():
        if not isinstance(loc, dict):
            continue
        if any(re.search(p, n) for p in loc.get("tool_patterns") or [] for n in names):
            hits.add(alias)
            continue
        if any(_boundary_contains(view.blob, h.lower()) for h in loc.get("hosts") or []):
            hits.add(alias)
            continue
        if any(norm_text(u) in view.blob for u in loc.get("url_prefixes") or []):
            hits.add(alias)
            continue
        if any(view.mentions_path(p) for p in loc.get("paths") or []):
            hits.add(alias)
    return hits


def connector_aliases(view: ToolView, roots: dict) -> set[str]:
    """Aliases reached through a declared connector tool (tool-name pattern match)."""
    names = view.inner_tool_names()
    return {a for a, loc in roots.items() if isinstance(loc, dict)
            and any(re.search(p, n) for p in loc.get("tool_patterns") or [] for n in names)}


# ---------- write intent ----------

FILE_WRITERS = ("write_file", "patch")
CODE_TOOLS = ("terminal", "execute_code")

_SHELL_WRITE = re.compile(
    r"(?:^|[\s;&|(`])(?:sudo\s+)?(?:tee|cp|mv|rm|rmdir|del|erase|move|copy|ren|rename|truncate|touch|dd|ln|"
    r"chmod|chown|install|rsync|unzip|tar|shred|"
    r"set-content|add-content|out-file|remove-item|move-item|copy-item|new-item|clear-content|rename-item)"
    r"(?:\.exe)?(?=\s|$)"
    r"|\bsed\s+(?:-[a-z]*\s+)*-[a-z]*i|\bperl\s+-[a-z]*i"
    r"|\bgit\s+(?:-c\s+\S+\s+)*(?:checkout|restore|rm|mv|reset|clean|stash|apply|am|switch)\b",
    re.IGNORECASE,
)
_PY_WRITE = re.compile(
    r"open\s*\([^)]*?,\s*(?:mode\s*=\s*)?[rbt]*['\"][rbt]*[wax+]"
    r"|\.write_(?:text|bytes)\s*\(|\.unlink\s*\(|\.touch\s*\(|\.rmdir\s*\(|\.rename\s*\(|\.symlink_to\s*\("
    r"|\bos\.(?:remove|unlink|rename|replace|rmdir|removedirs|truncate|makedirs|mkdir|symlink|link|chmod)\s*\("
    r"|\bshutil\.(?:copy\w*|move|rmtree)\s*\(|\.to_(?:csv|parquet|excel|json|feather|pickle|sql)\s*\("
    r"|\bsubprocess\.|\bos\.system\s*\(",
    re.IGNORECASE,
)
_REDIRECT = re.compile(r"(?<![<>&0-9])[0-9]?>>?(?!&)\s*(\"[^\"]+\"|'[^']+'|[^\s;&|)]+)")


def write_targets(view: ToolView) -> tuple[bool, set[str] | None]:
    """(has_write_intent, explicit_targets).

    explicit_targets is a set of canonical paths when the only write is a shell
    redirect (so only the redirect targets matter); None means 'any path the
    command mentions may be written'."""
    if view.tool in FILE_WRITERS:
        t = view.target_path()
        return True, ({t} if t else None)
    if view.tool not in CODE_TOOLS:
        return False, set()
    code = "\n".join(view.texts)
    if view.tool == "execute_code":
        if _PY_WRITE.search(code) or _SHELL_WRITE.search(code):
            return True, None
        return False, set()
    if _SHELL_WRITE.search(code) or _PY_WRITE.search(code):
        return True, None
    targets = set()
    for m in _REDIRECT.finditer(code):
        tgt = m.group(1).strip("'\"")
        if tgt.lower() in ("/dev/null", "nul", "$null"):
            continue
        c = canon(tgt, view.cwd)
        if c:
            targets.add(c)
    if targets:
        return True, targets
    return False, set()


def written_paths_under(view: ToolView, prefix: str) -> tuple[bool, list[str]]:
    """Does the call (possibly) write under `prefix`? Returns (hit, matching paths)."""
    intent, targets = write_targets(view)
    if not intent:
        return False, []
    pre = canon(prefix) or norm_text(prefix)
    if targets is not None:
        hits = [t for t in targets if under(t, pre)]
        return bool(hits), hits
    hits = sorted(p for p in view.paths if under(p, pre))
    if not hits and any(_boundary_contains(view.blob, v) for v in _path_variants(prefix)):
        hits = [pre]
    return bool(hits), hits


# ---------- signing / human-only commands (§4.5) ----------

_SIGNING = [
    (re.compile(r"\bgit\b[^\n;&|]*?\b(?:commit|merge|rebase|cherry-pick|revert|am|pull)\b[^\n;&|]*?(?:\s-S\S*|\s--gpg-sign\b)"),
     "signed git commit"),
    (re.compile(r"\bgit\b[^\n;&|]*?\btag\b[^\n;&|]*?\s(?:-[a-zA-Z]*[su][a-zA-Z]*|--sign|--local-user)\b"), "signed git tag"),
    (re.compile(r"(?:commit|tag)\.gpgsign\s*[= ]\s*['\"]?(?:true|yes|on|1)\b", re.IGNORECASE), "gpgsign=true"),
    (re.compile(r"\bgit\b[^\n;&|]*?\bconfig\b[^\n;&|]*?\b(?:user\.signingkey|gpg\.format|gpg\.program|gpg\.ssh\.program)\b",
                re.IGNORECASE), "git signing config change"),
    (re.compile(r"\bdda(?:\.py|\.cmd|\.bat|\.exe)?['\"]?\s+approve\b"), "dda approve (human-only)"),
]


def signing_violation(view: ToolView) -> str | None:
    if view.tool not in CODE_TOOLS:
        return None
    code = "\n".join(view.texts)
    for rx, label in _SIGNING:
        if rx.search(code):
            return label
    return None


# ---------- evidence path table (§6.2) ----------

_AGENT_ANALYSIS = re.compile(
    r"^(?:milestones/[a-z0-9_\-]+/)?spec\.md$"
    r"|^wayfinder\.md$"
    r"|^variants/[^/]+\.(?:py|sql)$"
    r"|^answer\.md$"
    r"|^reviews/self(?:/.*)?$"
    r"|^notes(?:/.*)?$"
    r"|^kernel\.yaml$"
)
_ANALYSIS_REF = re.compile(r"(?:^|[^a-z0-9_.\-])\.analysis(?:/([^\s'\"`;|&<>(),]*))?")


def analysis_tail(path: str) -> str | None:
    """Path inside a `.analysis/` directory ('' for the directory itself), else None."""
    p = path.rstrip("/")
    if p.endswith("/.analysis") or p == ".analysis":
        return ""
    i = p.rfind("/.analysis/")
    if i < 0:
        return None
    return p[i + len("/.analysis/"):]


def agent_writable(tail: str) -> bool:
    return bool(_AGENT_ANALYSIS.match(tail)) and ".." not in tail.split("/") and "*" not in tail


def analysis_refs(view: ToolView) -> set[str]:
    """Every `.analysis/...` tail the call mentions (canonical paths plus raw text)."""
    tails = set()
    for p in view.paths:
        t = analysis_tail(p)
        if t is not None:
            tails.add(t)
    for m in _ANALYSIS_REF.finditer(view.blob):
        tails.add((m.group(1) or "").rstrip("/").rstrip(".:"))
    return tails


__all__ = [
    "ToolView", "referenced_aliases", "connector_aliases", "write_targets", "written_paths_under",
    "signing_violation", "analysis_refs", "analysis_tail", "agent_writable", "canon", "under", "norm_text",
    "FILE_WRITERS", "CODE_TOOLS",
]
