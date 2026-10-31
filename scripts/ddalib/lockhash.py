"""Lock hashing (spec §4.2, §7).

lock_hash = SHA-256 over a canonical text built from:
  1. the normalized spec body (whitespace-normalized, H2 sections reordered
     into template order),
  2. sorted definition pins `name@version#contenthash` (each recomputed
     from definitions/ — a stale pin is an error, not a warning),
  3. the config.yaml hash (bytes with line endings normalized),
  4. sorted source aliases (each must exist in config).

Data contents are never part of the lock hash.
Everything here fails closed: an unknown or duplicate section, an
unresolvable pin, or an undeclared alias raises DdaError.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .layout import ALIAS_RE, RUNGS, TIERS, DdaError, Workdir, load_config, read_text_lf

LOCK_FORMAT = "dda-lock-v1"
PIN_HASH_LEN = 12

# Template order (spec §4.1). Matching is case-insensitive on the heading text.
SECTION_ORDER = (
    "Question",
    "Decision it informs",
    "Tier",
    "Rung",
    "Audience",
    "Population and time window",
    "Data sources",
    "Metrics",
    "Hypotheses",
    "Planned comparisons and cuts",
    "Method",
    "Exclusion and outlier rules",
    "Reproduction tolerance",
    "Thresholds that would change the decision",
    "Known risks",
    "Prior exposure",
    "Assumptions",
    "Out of scope",
    "Pattern tags",
)
_SECTION_KEYS = {s.lower(): s for s in SECTION_ORDER}
PREAMBLE = "__preamble__"

PIN_RE = re.compile(r"(?<![\w@#])([a-z][a-z0-9_\-]*)@([0-9][0-9A-Za-z.\-]*)#([0-9a-f]+)\b")
_H2_RE = re.compile(r"^##\s+(.+?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalize_ws(text: str) -> str:
    """LF endings, horizontal whitespace runs -> one space, trailing space stripped,
    blank-line runs collapsed to one, leading/trailing blank lines removed."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out: list[str] = []
    blank = False
    for line in text.split("\n"):
        line = re.sub(r"[ \t\f\v]+", " ", line).strip()
        if not line:
            if out and not blank:
                out.append("")
            blank = True
            continue
        blank = False
        out.append(line)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


def parse_sections(text: str) -> dict[str, str]:
    """Split a spec into {canonical section name: raw body}. Preamble kept under PREAMBLE."""
    sections: dict[str, list[str]] = {PREAMBLE: []}
    current = PREAMBLE
    in_fence = False
    for n, line in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
        m = None if in_fence else _H2_RE.match(line)
        if m:
            title = m.group(1).strip().rstrip(":").strip()
            key = _SECTION_KEYS.get(re.sub(r"\s+", " ", title).lower())
            if key is None:
                raise DdaError(f"spec line {n}: unknown section '## {title}' (allowed: {', '.join(SECTION_ORDER)})")
            if key in sections:
                raise DdaError(f"spec line {n}: duplicate section '## {key}'")
            sections[key] = []
            current = key
            continue
        sections[current].append(line)
    if in_fence:
        raise DdaError("spec: unterminated code fence")
    return {k: "\n".join(v) for k, v in sections.items()}


def normalized_spec(text: str) -> str:
    sections = parse_sections(text)
    parts = [f"{PREAMBLE}\n{normalize_ws(sections[PREAMBLE])}"]
    for name in SECTION_ORDER:
        if name in sections:
            parts.append(f"## {name}\n{normalize_ws(sections[name])}")
    return "\n\n".join(parts) + "\n"


# ---- definitions / pins (§7) ----

@dataclass(frozen=True)
class Definition:
    name: str
    version: str
    content_hash: str

    @property
    def pin(self) -> str:
        return f"{self.name}@{self.version}#{self.content_hash}"


def _front_matter(text: str, path: Path) -> dict[str, str]:
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        raise DdaError(f"{path}: definition must start with a '---' front-matter block")
    fm: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fm
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if m:
            fm[m.group(1)] = m.group(2).strip().strip("'\"")
    raise DdaError(f"{path}: unterminated front-matter block")


def load_definition(wd: Workdir, name: str) -> Definition:
    if not ALIAS_RE.match(name):
        raise DdaError(f"invalid definition name {name!r}")
    path = wd.definitions / f"{name}.md"
    if not path.is_file():
        raise DdaError(f"definition {name!r} not found at {path} (definitions are human-owned; propose in definitions/proposals/)")
    text = read_text_lf(path)
    fm = _front_matter(text, path)
    if fm.get("name") != name:
        raise DdaError(f"{path}: front-matter name {fm.get('name')!r} != file name {name!r}")
    version = fm.get("version", "")
    if not re.match(r"^[0-9][0-9A-Za-z.\-]*$", version):
        raise DdaError(f"{path}: missing or invalid 'version' in front matter")
    content_hash = sha256_hex(normalize_ws(text))[:PIN_HASH_LEN]
    return Definition(name, version, content_hash)


def resolve_pin(wd: Workdir, pin_text: str) -> Definition:
    m = PIN_RE.fullmatch(pin_text)
    if not m:
        raise DdaError(f"malformed pin {pin_text!r}; expected name@version#{'h' * PIN_HASH_LEN}")
    name, version, h = m.groups()
    d = load_definition(wd, name)
    if d.version != version:
        raise DdaError(f"pin {pin_text}: registry has version {d.version} (re-pin as {d.pin})")
    if d.content_hash != h:
        raise DdaError(f"pin {pin_text}: content hash recomputes to {d.content_hash} — "
                       f"definition changed without a version bump, or the pin is stale")
    return d


# ---- source aliases ----

def extract_aliases(sections: dict[str, str]) -> list[str]:
    body = sections.get("Data sources", "")
    aliases = []
    for line in body.split("\n"):
        m = re.match(r"^\s*[-*]\s+`?([^`\s]+)`?", line)
        if m:
            aliases.append(m.group(1).rstrip(":,"))
    return aliases


def _single(section_text: str, choices, label: str, *, case_insensitive: bool) -> str | None:
    hay = section_text.lower() if case_insensitive else section_text
    found = []
    for c in choices:
        needle = c.lower() if case_insensitive else c
        if re.search(r"(?<![\w-])" + re.escape(needle) + r"(?![\w-])", hay):
            found.append(c)
    if len(found) > 1:
        # "full analysis" contains no other rung word; "quick-cut" none either — any overlap is real ambiguity.
        raise DdaError(f"spec declares more than one {label}: {', '.join(found)}")
    return found[0] if found else None


@dataclass
class LockComponents:
    spec_hash: str
    config_hash: str
    pins: list[str]
    aliases: list[str]
    tier: str | None
    rung: str | None
    lock_hash: str
    canonical: str = field(repr=False, default="")

    def as_dict(self) -> dict:
        return {
            "lock_hash": self.lock_hash,
            "spec_hash": self.spec_hash,
            "config_hash": self.config_hash,
            "pins": self.pins,
            "aliases": self.aliases,
            "tier": self.tier,
            "rung": self.rung,
        }


def config_hash(wd: Workdir) -> str:
    return sha256_hex(read_text_lf(wd.config_path))


def compute(wd: Workdir, spec_text: str | None = None) -> LockComponents:
    """Compute the lock hash for `spec_text` (default: current spec.md) in workdir `wd`."""
    wd.require_initialized()
    cfg = load_config(wd)
    if spec_text is None:
        if not wd.spec_path.is_file():
            raise DdaError(f"missing {wd.spec_path}")
        spec_text = read_text_lf(wd.spec_path)
    sections = parse_sections(spec_text)
    norm = normalized_spec(spec_text)

    pin_texts = sorted({m.group(0) for m in PIN_RE.finditer(sections.get("Metrics", ""))})
    pins = sorted(resolve_pin(wd, p).pin for p in pin_texts)

    aliases = sorted(set(extract_aliases(sections)))
    unknown = [a for a in aliases if a not in cfg["data_roots"]]
    if unknown:
        raise DdaError(f"spec names source aliases not declared in config.yaml data_roots: {', '.join(unknown)}")

    tier = _single(sections.get("Tier", ""), TIERS, "tier", case_insensitive=False)
    rung = _single(sections.get("Rung", ""), RUNGS, "rung", case_insensitive=True)

    s_hash = sha256_hex(norm)
    c_hash = config_hash(wd)
    canonical = "\n".join([
        LOCK_FORMAT,
        "[spec]", s_hash,
        "[pins]", *pins,
        "[config]", c_hash,
        "[aliases]", *aliases,
        "",
    ])
    return LockComponents(s_hash, c_hash, pins, aliases, tier, rung, sha256_hex(canonical), canonical)
