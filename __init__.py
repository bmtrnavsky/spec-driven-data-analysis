"""spec-driven-data-analysis — registers the pack's skills with the host.

Skills live in ``skills/*/SKILL.md`` and are registered namespaced as
``spec-driven-data-analysis:<skill>``, loaded via ``skill_view``. The
pipeline itself is the ``dda`` CLI under ``scripts/``; this entry point
exists so the pack is loadable and its skills reach the host at all.
"""

from pathlib import Path


def register(ctx):
    skills_dir = Path(__file__).parent / "skills"
    if not skills_dir.is_dir():
        return
    for child in sorted(skills_dir.iterdir()):
        skill_md = child / "SKILL.md"
        if child.is_dir() and skill_md.is_file():
            ctx.register_skill(child.name, skill_md)
