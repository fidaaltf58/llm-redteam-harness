"""Load and validate the YAML attack library; render templates and payload transforms."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from redteam import mappings
from redteam.encoding import split_payload, to_base64, to_hex, to_rot13
from redteam.models import AttackCase, DetectorSpec, Document, Suite, Turn

_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z_]+)\}\}")


class LibraryError(ValueError):
    """The attack library is malformed."""


def default_attacks_dir() -> Path:
    """``./attacks`` if present, else the ``attacks/`` folder of the source checkout."""
    cwd = Path.cwd() / "attacks"
    if cwd.is_dir():
        return cwd
    return Path(__file__).resolve().parents[2] / "attacks"


def load_suite_file(path: Path) -> Suite:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    try:
        return Suite.model_validate(raw)
    except ValidationError as exc:
        raise LibraryError(f"{path.name}: {exc}") from exc


def load_library(
    directory: Path | None = None,
    suites: str = "all",
    case_ids: list[str] | None = None,
) -> list[AttackCase]:
    """Load every ``*.yaml`` suite, validate cross-references and filter.

    ``suites`` is ``all`` or a comma-separated list of suite names (file stems or the
    ``suite:`` field), e.g. ``jailbreak,excessive_agency``.
    """
    directory = directory or default_attacks_dir()
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise LibraryError(f"no *.yaml suites found in {directory}")
    wanted = None if suites == "all" else {s.strip() for s in suites.split(",") if s.strip()}

    known_atlas = set(mappings.atlas()["techniques"])
    known_owasp = set(mappings.owasp()["entries"])
    cases: list[AttackCase] = []
    seen: set[str] = set()
    found_suites: set[str] = set()
    for path in files:
        suite = load_suite_file(path)
        found_suites.update({suite.suite, path.stem})
        if wanted and not ({suite.suite, path.stem} & wanted):
            continue
        for case in suite.cases:
            if case.id in seen:
                raise LibraryError(f"duplicate case id {case.id}")
            seen.add(case.id)
            unknown = [t for t in case.atlas if t not in known_atlas]
            if unknown:
                raise LibraryError(
                    f"{case.id}: ATLAS ids not in mappings/mitre_atlas.yaml: {unknown}"
                )
            for oid in [case.owasp_llm, *case.owasp_secondary]:
                if oid not in known_owasp:
                    raise LibraryError(f"{case.id}: unknown OWASP id {oid}")
            cases.append(case)
    if wanted and (missing := wanted - found_suites):
        raise LibraryError(
            f"unknown suite(s): {sorted(missing)}; available: {sorted(found_suites)}"
        )
    if case_ids:
        ids = set(case_ids)
        cases = [c for c in cases if c.id in ids]
        if missing_ids := ids - {c.id for c in cases}:
            raise LibraryError(f"unknown case id(s): {sorted(missing_ids)}")
    return cases


def render(text: str, variables: dict[str, str]) -> str:
    """Replace ``{{NAME}}`` placeholders. Unknown placeholders are an error, not a silent miss."""

    def sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if name == "PAYLOAD":
            return match.group(0)
        if name not in variables:
            raise LibraryError(f"unknown template variable {{{{{name}}}}}")
        return variables[name]

    return _PLACEHOLDER_RE.sub(sub, text)


_TRANSFORMS = {
    "none": lambda s: s,
    "base64": to_base64,
    "rot13": to_rot13,
    "hex": to_hex,
    "reverse": lambda s: s[::-1],
    "split": split_payload,
}


def build_turn_text(turn: Turn, variables: dict[str, str]) -> str:
    """The exact text sent for a turn: templates rendered, then the payload transformed."""
    content = render(turn.content, variables)
    transform = _TRANSFORMS[turn.transform]
    if turn.payload is not None:
        return content.replace("{{PAYLOAD}}", transform(render(turn.payload, variables)))
    return transform(content)


def render_documents(docs: list[Document], variables: dict[str, str]) -> list[Document]:
    return [d.model_copy(update={"content": render(d.content, variables)}) for d in docs]


def render_detector(spec: DetectorSpec, variables: dict[str, str]) -> DetectorSpec:
    return spec.model_copy(
        update={
            "value": render(spec.value, variables),
            "pattern": render(spec.pattern, variables) if spec.pattern else None,
            "args_match": {k: render(v, variables) for k, v in spec.args_match.items()},
        }
    )
