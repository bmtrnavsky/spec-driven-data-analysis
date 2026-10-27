"""Workdir layout, dda home, and config loading (spec §4, §6.0)."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import yamlsub

__all__ = [
    "DdaError", "Workdir", "dda_home", "workdir_id", "load_config",
    "LAYOUT_DIRS", "TEMPLATES_DIR", "ALIAS_RE", "TIERS", "RUNGS",
]

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = REPO_ROOT / "templates"
ALIAS_RE = re.compile(r"^[a-z][a-z0-9_\-]{0,63}$")
TIERS = ("EXPLORE", "DECIDE", "PUBLISH")
RUNGS = ("glance", "quick-cut", "full analysis", "study")

# Directories created by `dda init` (relative to the workdir). Spec §4.
LAYOUT_DIRS = (
    ".analysis",
    ".analysis/specs",
    ".analysis/runs/blobs",
    ".analysis/variants",
    ".analysis/approvals",
    ".analysis/reviews",
    ".analysis/milestones",
    "derived",
    "derived/snapshots",
    "outputs",
    "reports",
    "definitions",
    "definitions/proposals",
    "evals/corrections",
)

# Files seeded from templates by `dda init`: workdir path -> template name.
LAYOUT_FILES = {
    ".analysis/config.yaml": "config.yaml",
    ".analysis/spec.md": "spec.md",
    ".analysis/wayfinder.md": "wayfinder.md",
    ".gitignore": "gitignore",
}


class DdaError(Exception):
    """A user-facing failure. `code` is the process exit status."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def dda_home() -> Path:
    """`$DDA_HOME`, else `$HERMES_HOME/dda`, else `~/.hermes-home/dda` (spec §4.4, §6.0)."""
    if os.environ.get("DDA_HOME"):
        return Path(os.environ["DDA_HOME"])
    hermes_home = os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes-home")
    return Path(hermes_home) / "dda"


def canonical_path(p) -> str:
    return os.path.normcase(os.path.abspath(str(p))).replace("\\", "/")


def workdir_id(path) -> str:
    return hashlib.sha256(canonical_path(path).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Workdir:
    root: Path
    milestone: str | None = None

    @classmethod
    def at(cls, path, milestone: str | None = None) -> "Workdir":
        root = Path(os.path.abspath(str(path)))
        if milestone is not None and not ALIAS_RE.match(milestone):
            raise DdaError(f"invalid milestone name {milestone!r} (lowercase, digits, - and _)")
        return cls(root, milestone)

    @property
    def analysis(self) -> Path:
        return self.root / ".analysis"

    @property
    def scope(self) -> Path:
        """Directory holding spec/lock/ledger for the active scope (milestone or top level)."""
        if self.milestone:
            return self.analysis / "milestones" / self.milestone
        return self.analysis

    @property
    def config_path(self) -> Path:
        return self.analysis / "config.yaml"

    @property
    def spec_path(self) -> Path:
        return self.scope / "spec.md"

    @property
    def lock_path(self) -> Path:
        return self.scope / "spec.lock"

    @property
    def specs_dir(self) -> Path:
        return self.scope / "specs"

    @property
    def wayfinder_path(self) -> Path:
        return self.analysis / "wayfinder.md"

    @property
    def definitions(self) -> Path:
        return self.root / "definitions"

    @property
    def id(self) -> str:
        return workdir_id(self.root)

    def require_initialized(self) -> None:
        if not self.config_path.is_file():
            raise DdaError(f"{self.root} is not a dda workdir (no .analysis/config.yaml); run `dda init`")
        if self.milestone and not self.scope.is_dir():
            raise DdaError(f"milestone {self.milestone!r} does not exist under {self.analysis / 'milestones'}")


def load_config(wd: Workdir) -> dict:
    """Parse and validate config.yaml. Fails closed on anything malformed."""
    try:
        cfg = yamlsub.load_file(wd.config_path)
    except FileNotFoundError:
        raise DdaError(f"missing {wd.config_path}") from None
    except yamlsub.YamlSubsetError as exc:
        raise DdaError(f"config.yaml: {exc}") from None
    if not isinstance(cfg, dict):
        raise DdaError("config.yaml: top level must be a mapping")
    errors = []
    if cfg.get("version") != 1:
        errors.append("version must be 1")
    tier = cfg.get("default_tier")
    if tier is not None and tier not in TIERS:
        errors.append(f"default_tier must be one of {', '.join(TIERS)}")
    roots = cfg.get("data_roots")
    if roots is None:
        roots = {}
    if not isinstance(roots, dict):
        errors.append("data_roots must be a mapping of alias -> locators")
        roots = {}
    for alias, spec in roots.items():
        if not ALIAS_RE.match(alias):
            errors.append(f"data_roots.{alias}: alias must match {ALIAS_RE.pattern}")
        if not isinstance(spec, dict):
            errors.append(f"data_roots.{alias}: must be a mapping")
            continue
        unknown = set(spec) - {"paths", "hosts", "url_prefixes", "tool_patterns", "pii", "pii_columns", "conn"}
        if unknown:
            errors.append(f"data_roots.{alias}: unknown keys {sorted(unknown)}")
        locators = 0
        for key in ("paths", "hosts", "url_prefixes", "tool_patterns", "pii_columns"):
            val = spec.get(key, [])
            if val is None:
                val = []
            if not isinstance(val, list) or not all(isinstance(v, str) and v for v in val):
                errors.append(f"data_roots.{alias}.{key}: must be a list of non-empty strings")
                continue
            if key != "pii_columns":
                locators += len(val)
        if locators == 0:
            errors.append(f"data_roots.{alias}: needs at least one of paths/hosts/url_prefixes/tool_patterns")
        for pat in spec.get("tool_patterns") or []:
            try:
                re.compile(pat)
            except re.error as exc:
                errors.append(f"data_roots.{alias}.tool_patterns: bad regex {pat!r}: {exc}")
        conn = spec.get("conn")
        if conn is not None and not (isinstance(conn, str) and re.match(r"^(env|vault):[A-Za-z_][A-Za-z0-9_]*$", conn)):
            errors.append(f"data_roots.{alias}.conn: must be env:NAME or vault:NAME (never a literal secret)")
    if errors:
        raise DdaError("config.yaml invalid:\n  - " + "\n  - ".join(errors))
    cfg["data_roots"] = roots
    return cfg


def read_text_lf(path: Path) -> str:
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read().replace("\r\n", "\n").replace("\r", "\n")
