"""Tool-input analysis shared by the hooks (spec §6).

Hooks string-match tool inputs: they prevent slips, not determined evasion
(§0.1). Everything here is deliberately conservative and cheap: no file
reads, no hashing, stdlib only.
"""
from __future__ import annotations

import os
import re
import shlex

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


def parent_dir(path: str) -> str | None:
    """Canonical parent of a canonical path, or None at the filesystem root."""
    p = (path or "").rstrip("/")
    if not p or "/" not in p:
        return None
    parent = p.rpartition("/")[0]
    if not parent or parent.endswith(":") or parent in ("/", ""):
        return None
    return parent or None


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


def _dir_token_contains(hay: str, needle: str) -> bool:
    """`needle` occurs in `hay` as a complete path token: at most one trailing
    slash may follow, then a boundary. Longer paths merely passing through the
    directory (parent/child) do not count — used for the parent-dir rule (§6.1)."""
    if not needle:
        return False
    start = 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return False
        if i > 0 and (hay[i - 1].isalnum() or hay[i - 1] in "_-."):
            start = i + 1
            continue
        j = i + len(needle)
        if j < len(hay) and hay[j] == "/":
            j += 1
        if j >= len(hay) or not (hay[j].isalnum() or hay[j] in "_-."):
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

    def mentions_path(self, prefix: str, include_parent: bool = False) -> bool:
        """Does the call mention `prefix` (or a path under it)?

        With include_parent=True the call also matches when it names the
        direct parent directory of `prefix`: listing the parent exposes the
        root itself, so it counts as a read of the root (§6.1). Callers that
        match workdir-internal prefixes (derived/, reports/) leave this off,
        because the session's own workdir token would otherwise always hit.
        """
        pre = canon(prefix) or norm_text(prefix)
        if any(under(p, pre) for p in self.paths):
            return True
        variants = list(_path_variants(prefix))
        if include_parent:
            par = parent_dir(pre)
            if par and par in self.paths:
                return True
            if par:
                par_variants = _path_variants(par)
                if any(_dir_token_contains(self.blob, v) for v in par_variants):
                    return True
        return any(_boundary_contains(self.blob, v) for v in variants)


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
        if any(view.mentions_path(p, include_parent=True) for p in loc.get("paths") or []):
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


# Keep in sync with hookentry.is_clean_dda_invocation's argv parsing.
_DDA_NAMES = frozenset({"dda", "dda.cmd", "dda.bat", "dda.exe"})
_PYTHON_RE = re.compile(r"^(python(3(\.\d+)?)?|py)(\.exe)?$")
_HUMAN_ONLY_SUBS = frozenset({"release", "abandon"})

# Shell wrappers whose `-c` / `-Command` string argument must be re-parsed
# as its own command line (§0.1: hooks stop slips, not determined evasion).
_SHELL_BASES = frozenset({
    "bash", "bash.exe", "sh", "sh.exe", "dash", "zsh", "fish", "ksh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
})
_WRAPPER_FLAGS = frozenset({
    "-c", "/c", "/k", "-k", "-command", "/command", "--command",
})
# `python -m <mod>` module invocations that run the dda CLI.
_DDA_MODULES = frozenset({"dda", "ddalib", "ddalib.cli"})

# sh-family shells accept bundled short flags (`bash -lc '...'`).
_SH_BUNDLED_C = frozenset({
    "bash", "bash.exe", "sh", "sh.exe", "dash", "zsh", "ksh",
})
_BUNDLED_C_RE = re.compile(r"^-[A-Za-z]{1,4}$")


def _is_command_flag(shell_base: str, flag: str) -> bool:
    if flag in _WRAPPER_FLAGS:
        return True
    return (shell_base in _SH_BUNDLED_C and bool(_BUNDLED_C_RE.match(flag))
            and flag.endswith("c") and flag != "-c")


def _dda_base(tok: str) -> str:
    # Quote-spliced names (`d''da`, `d"da"`, `"dd"a`) group as one argv word,
    # so every quote char is removed — not just the surrounding pair.
    tok = tok.replace("'", "").replace('"', "")
    return re.split(r"[\\/]", tok)[-1].lower()


def _unquoted_word(tok: str) -> str:
    """Subcommand-position word with all quote chars removed and lowered."""
    return tok.replace("'", "").replace('"', "").lower()


def _dda_next_words(tokens: list[str]) -> list[str]:
    """Subcommand-position word after every dda invocation in a token stream.

    Same recognition as `is_clean_dda_invocation` (bare `dda` / `dda.cmd` /
    ... or `python[.exe] <path/>dda.py`, quotes stripped) but every
    invocation in the stream is inspected, so `dda status && dda release`
    still hits.
    """
    out: list[str] = []
    n = len(tokens)
    for i, tok in enumerate(tokens):
        b = _dda_base(tok)
        if b in _DDA_NAMES:
            if i + 1 < n:
                out.append(_unquoted_word(tokens[i + 1]))
        elif _PYTHON_RE.match(b):
            for j in range(i + 1, n):
                bj = _dda_base(tokens[j])
                if bj == "dda.py" or (bj == "cli.py" and "dda" in tokens[j].lower()):
                    if j + 1 < n:
                        out.append(_unquoted_word(tokens[j + 1]))
                    break
                if tokens[j].strip("'\"").lower() == "-m" and j + 1 < n:
                    if tokens[j + 1].strip("'\"").lower() in _DDA_MODULES:
                        if j + 2 < n:
                            out.append(_unquoted_word(tokens[j + 2]))
                    break
                if tokens[j].startswith("-"):
                    continue  # `python -u dda.py ...`
                break
    return out


def _argv_tokens(text: str) -> list[str]:
    # posix=True joins quote-spliced words the way a real shell does
    # (`"dd"a` -> `dda`); posix=False is the fallback for texts whose
    # backslashes or quotes only lex in literal mode.
    for mode in (True, False):
        try:
            return [t.strip("'\"") for t in shlex.split(text, posix=mode)]
        except ValueError:
            continue
    return []


def _split_unquoted(text: str) -> list[str]:
    """Split on unquoted shell separators: `;`, `&&`, `||`, `|`, `&`,
    redirects (`>`, `<`, `2>`), newlines, and parens. Quotes
    (single/double) are respected; the separators themselves are
    discarded, so `dda release>out.txt` still parses as `dda release`."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in (";", "<", ">", "\n", "\r", "(", ")"):
            parts.append("".join(buf))
            buf = []
        elif c == "&" or c == "|":
            parts.append("".join(buf))
            buf = []
            while i + 1 < n and text[i + 1] == c:
                i += 1
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def _substitute_expansions(text: str) -> list[str]:
    """Variants of `text` with `$(...)` / backtick / `(...)` groups replaced
    by their inner content, plus the inner contents themselves.

    Catches `$(echo dda) release` (expands to `dda release`) and
    `(dda release)` without trying to emulate a real shell.
    """
    out: list[str] = []
    quote: str | None = None
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            depth = 0
            j = i + 1
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < n:
                inner = text[i + 2:j]
                out.append(inner)
                out.append(text[:i] + inner + text[j + 1:])
            i = j + 1 if j < n else n
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j > i:
                inner = text[i + 1:j]
                out.append(inner)
                out.append(text[:i] + inner + text[j + 1:])
                i = j + 1
                continue
            i += 1
            continue
        if c == "(":
            depth = 0
            j = i
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < n:
                inner = text[i + 1:j]
                out.append(inner)
                out.append(text[:i] + inner + text[j + 1:])
            i = j + 1 if j < n else n
            continue
        i += 1
    return out


def _wrapper_inners(tokens: list[str]) -> list[str]:
    """Inner command strings passed via shell `-c` / `/c` / `-Command`.

    `bash -c "dda release"` lexes as `['bash', '-c', 'dda release']` — no
    bare `dda` argv — so the string argument after the flag is re-parsed
    as its own command line. An unquoted tail (`cmd /c dda release`)
    joins the remaining tokens. `VAR=x` assignments and `sudo`/`env`
    prefixes before the shell are skipped. Bundled sh flags (`-lc`) and
    `--command` / `-command=<str>` count as command flags.
    """
    inners: list[str] = []
    start = 0
    while start < len(tokens) and (
            tokens[start].lower() in ("sudo", "env")
            or ("=" in tokens[start] and not tokens[start].startswith("-"))):
        start += 1
    for i in range(start, len(tokens)):
        if _dda_base(tokens[i]) in _SHELL_BASES and i + 1 < len(tokens):
            shell = _dda_base(tokens[i])
            # Skip pass-through flags (`powershell -NoProfile -Command ...`,
            # `bash -x -c ...`): the first `-c`/`/c`/`-Command` after the
            # shell owns the rest of the line as its command string.
            for j in range(i + 1, len(tokens)):
                flag = tokens[j].strip("'\"").lower()
                if _is_command_flag(shell, flag) and j + 1 < len(tokens):
                    if len(tokens) == j + 2:
                        inners.append(tokens[j + 1])
                    else:
                        inners.append(" ".join(tokens[j + 1:]))
                    break
                if not flag.startswith(("-", "/")) and j > i + 1:
                    break
        flag = tokens[i].strip("'\"")
        low = flag.lower()
        if low.startswith(("-command=", "/command=", "--command=")):
            _, _, val = flag.partition("=")
            if val:
                inners.append(val)
    return inners


def _unquote(s: str) -> str:
    """Strip layers of surrounding quotes left over from wrapper parsing.

    A `-c` inner arrives with its quoting intact (`'"dda release X"'`
    from nested `bash -c 'sh -c "dda release X"'`); without stripping,
    the next fixpoint round lexes it as one opaque token and the nested
    invocation is missed.
    """
    s = s.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    return s


def _expand_shell_texts(text: str, limit: int = 24) -> list[str]:
    """All command-line candidates hidden inside one shell text: segments
    split on unquoted separators, `$(...)`/backtick/paren expansions,
    and `-c`/`-Command` wrapper arguments — expanded to fixpoint."""
    seen: set[str] = {text}
    queue = [text]
    while queue and len(seen) < limit:
        cur = queue.pop(0)
        for seg in _split_unquoted(cur):
            seg = _unquote(seg)
            if seg not in seen and len(seen) < limit:
                seen.add(seg)
                queue.append(seg)
        for variant in _substitute_expansions(cur):
            variant = _unquote(variant)
            if variant not in seen and len(seen) < limit:
                seen.add(variant)
                queue.append(variant)
        try:
            # One matched quote layer only: blanket stripping would eat
            # the inner quotes of a nested wrapper
            # (`'sh -c "dda release"'` must keep its `"` pair).
            toks = [_unquote(t) for t in shlex.split(cur, posix=False)]
        except ValueError:
            continue
        for inner in _wrapper_inners(toks):
            inner = _unquote(inner)
            if inner not in seen and len(seen) < limit:
                seen.add(inner)
                queue.append(inner)
    return list(seen)


def _word_tokens(text: str) -> list[str]:
    # Backstop for non-shell texts (execute_code python API, JSON leaves):
    # `subprocess.call(["dda", "release"])` never survives shlex as argv.
    return re.findall(r"[A-Za-z0-9_.:/\\-]+", text.lower())


def human_only_violation(view: ToolView) -> str | None:
    """`dda release` / `dda abandon` are human-only (§6.0): an agent must ask Brad, never run them.

    Parses argv like `is_clean_dda_invocation` instead of regexing the blob:
    `dda "release"` (quoted subcommand) and `dda status && dda release`
    (chained) both hit; `dda lock --amend "release notes"` does not (only
    the subcommand-position word after `dda` counts, not a later flag value).
    Shell wrappers are re-parsed: `-c`/`/c`/`-Command` string arguments
    (including bundled sh flags like `-lc` and `--command`), nested
    wrappers (`bash -c 'sh -c "dda release"'`), quote-spliced names
    (`d''da`), redirect-attached words (`dda release>out.txt`), and
    `python -m ddalib.cli`, plus unquoted `;`/`&&`/`|`/`>` separators,
    parens, and `$(...)`/backtick expansions.

    The word-token backstop (for non-shell texts such as
    `subprocess.call(["dda", "release"])`, which never survives shlex as
    argv) applies to `execute_code` only. Applied to `terminal` it
    false-positives on prose that merely mentions the command
    (`git commit -m "prep for dda release"`, `echo "ask Brad to run dda
    release"`), where the argv parse correctly finds no `dda` invocation.
    """
    if view.tool not in CODE_TOOLS:
        return None
    texts = list(view.texts)
    if len(texts) > 1:
        texts.append(" ".join(texts))
    for text in texts:
        candidates = [text] if view.tool == "execute_code" else _expand_shell_texts(text)
        token_lists = [_argv_tokens(c) for c in candidates]
        if view.tool == "execute_code":
            token_lists.append(_word_tokens(text))
        for toks in token_lists:
            for nxt in _dda_next_words(toks):
                if nxt in _HUMAN_ONLY_SUBS:
                    return nxt
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
    "signing_violation", "human_only_violation", "analysis_refs", "analysis_tail", "agent_writable", "canon", "under",
    "norm_text", "parent_dir", "FILE_WRITERS", "CODE_TOOLS",
]
