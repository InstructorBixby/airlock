"""Validate a policy file.

Two layers, and the split matters.

The **schema** describes the syntax and needs `jsonschema`, which is an
optional extra. If it is missing, lint says so and carries on.

The **invariants** are the control -- confidential cannot leave the
machine, undecided has no route, every tier must be stated -- and they
are enforced by the loader itself, with or without the extra. A build
where the fail-closed behaviour depends on an optional dependency is
not a control, so the layers can never be collapsed.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from airlock.policy import PolicyError, load

SCHEMA_PATH = Path(__file__).parent / "schema" / "policy-v1.json"


def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def schema_available() -> bool:
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return False
    return True


def check_schema(path) -> list[str]:
    """Schema errors, or [] when clean. Empty also when unavailable."""
    if not schema_available():
        return []
    import jsonschema

    raw = yaml.safe_load(Path(path).read_text()) or {}
    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(raw),
                      key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in err.path) or "(root)"
        out.append(f"{where}: {err.message}")
    return out


def lint(path) -> tuple[list[str], list[str]]:
    """(errors, notes)."""
    errors = check_schema(path)
    notes = []
    if not schema_available():
        notes.append("jsonschema is not installed, so only the "
                     "invariants were checked; uv pip install "
                     "-e '.[schema]' for the full check")
    try:
        pol = load(path)
    except PolicyError as exc:
        errors.append(str(exc))
        return errors, notes
    local = [n for n, be in pol.backends.items() if be.is_local]
    notes.append(f"{len(pol.backends)} backend(s), "
                 f"{len(local)} local: {', '.join(sorted(local))}")
    if not local:
        errors.append("no local backend, so client-confidential "
                      "material has nowhere to go")
    if pol.max_outbound_chars == 0:
        notes.append("no max_outbound_chars, so an arbitrarily large "
                     "request will be classified and sent")
    return errors, notes
