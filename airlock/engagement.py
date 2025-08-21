"""Per-engagement configuration, found rather than configured.

Every engagement already has a directory on this machine with the
statement of work, the scope, the evidence and the notes in it. Adding
a second place to declare the same engagement to the gateway would
guarantee the two disagree, so the gateway reads the directory.

    engagements/halberd/
        scope.yaml            # hosts and URLs in scope
        scrubkit.toml         # scrubkit's engagement profile
        engagement.key        # the key its placeholders derive from
        halberd.mapping.json  # scrubkit's reverse map
        airlock.yaml          # optional: overrides for this engagement

Three of those five are scrubkit's and are read rather than written:
the profile names the key file, the key is what makes a placeholder a
function of the value, and the mapping is the assignments made so far.
airlock has no opinion about any of them.

`airlock.yaml` is optional and small. It cannot widen anything: the
loader only accepts keys that tighten, which is why there is no
`routes` key in it. Loosening is a policy edit, and a policy edit is a
thing I want to notice myself doing.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class EngagementError(Exception):
    pass


#: Keys an engagement file may set. Everything here either adds
#: detection or lowers a ceiling; nothing here can permit a call the
#: base policy refuses.
ALLOWED_KEYS = {"id", "scope", "map", "extra_terms", "max_cost_usd",
                "deny_hosted", "notes"}

#: scrubkit/profile.py
SCRUBKIT_PROFILE = "scrubkit.toml"
DEFAULT_KEY_FILE = "engagement.key"


@dataclass
class Engagement:
    id: str
    root: Path
    scope: Path | None = None
    map: Path | None = None
    #: strings specific to this engagement that the roster does not
    #: have: a product codename, an acquired brand, a ticket prefix
    extra_terms: tuple[str, ...] = ()
    max_cost_usd: float | None = None
    #: hard off switch. Some engagement letters are explicit that no
    #: third party processes anything, and then the answer to every
    #: tier is local.
    deny_hosted: bool = False
    notes: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def map_path(self) -> Path:
        return self.map or (self.root / f"{self.id}.mapping.json")

    @property
    def key_path(self) -> Path:
        """Where scrubkit's engagement key lives, per its profile.

        Read, never written, and never logged. Without it airlock can
        reuse the assignments already in the mapping and cannot make
        new ones, which costs recall on the hosted path and nothing
        else.
        """
        profile = self.root / SCRUBKIT_PROFILE
        if profile.is_file():
            try:
                doc = tomllib.loads(profile.read_text())
            except (OSError, tomllib.TOMLDecodeError) as exc:
                raise EngagementError(f"{profile}: {exc}") from exc
            named = (doc.get("engagement") or {}).get("key_file")
            if named:
                p = Path(named)
                return p if p.is_absolute() else self.root / p
        return self.root / DEFAULT_KEY_FILE

    @property
    def preserve_structure(self) -> bool:
        """scrubkit's `[detect] preserve_structure`, if it is set.

        It changes what a placeholder looks like for an address, so
        airlock has to agree with it or the two tools would assign
        differently for the same engagement.
        """
        profile = self.root / SCRUBKIT_PROFILE
        if not profile.is_file():
            return False
        try:
            doc = tomllib.loads(profile.read_text())
        except (OSError, tomllib.TOMLDecodeError):
            return False
        return bool((doc.get("detect") or {}).get(
            "preserve_structure"))


def load(path) -> Engagement:
    root = Path(path)
    if not root.is_dir():
        raise EngagementError(f"{root} is not a directory")
    cfg = root / "airlock.yaml"
    raw = {}
    if cfg.exists():
        raw = yaml.safe_load(cfg.read_text()) or {}
        unknown = set(raw) - ALLOWED_KEYS
        if unknown:
            raise EngagementError(
                f"{cfg}: unknown key(s) {sorted(unknown)}. An "
                f"engagement file can only tighten; routes live in "
                f"the policy.")
    scope = raw.get("scope") or ("scope.yaml"
                                 if (root / "scope.yaml").exists()
                                 else None)
    return Engagement(
        id=raw.get("id") or root.name,
        root=root,
        scope=(root / scope) if scope else None,
        map=(root / raw["map"]) if raw.get("map") else None,
        extra_terms=tuple(raw.get("extra_terms") or ()),
        max_cost_usd=(float(raw["max_cost_usd"])
                      if raw.get("max_cost_usd") is not None else None),
        deny_hosted=bool(raw.get("deny_hosted")),
        notes=str(raw.get("notes") or ""),
        raw=raw,
    )


def discover(root) -> dict:
    """Every engagement directory under `root`, by id."""
    base = Path(root)
    if not base.is_dir():
        raise EngagementError(f"{base} is not a directory")
    out = {}
    for child in sorted(base.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        eng = load(child)
        out[eng.id] = eng
    return out
