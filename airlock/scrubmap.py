"""scrubkit's mapping file.

The file that makes a redaction reversible. scrubkit owns the format
and owns the assignments; this reads it, uses what is in it, and adds
to it only through scrubkit's own aliaser. Nothing here invents a
placeholder.

The format, from scrubkit/mapping.py:

    {"version": 1,
     "engagement": "acme-q3-external",
     "entries": {"host": {"jump01.corp.example": "CLIENT-HOST-11"},
                 "ip4":  {"10.40.1.9": "CLIENT-IP-04"}}}

Value to placeholder, keyed by span kind, both levels sorted so the
file does not churn in a diff. `reverse()` inverts it for the trip
back.

## why this does not mint

scrubkit assigns placeholders from an HMAC of the value under the
engagement key, so the map from value to placeholder is a *function*:
the same host is `CLIENT-HOST-11` in every file, on every day, on a
rebuilt machine. Collisions are resolved by probing and the resolution
is recorded in the mapping, which is why the mapping is an input to
the next file and not only an output.

If airlock minted its own placeholders it would be choosing indices
scrubkit has not seen, in a namespace scrubkit also allocates in, and
the first collision would mean the same host had two placeholders
across one engagement's evidence. That breaks the one property the
whole redaction exists to provide.

So: a value already in the mapping is redacted using the placeholder
the mapping gives. A value that is not can be minted **by scrubkit**,
when scrubkit is installed and the engagement has a key -- it is an
optional extra, `airlock[scrubkit]`. When it cannot be minted, the
finding is not redactable, redaction is incomplete, and the call goes
to the local model. That is the right answer anyway.

## encryption

scrubkit can encrypt a mapping at rest and that is the normal way to
write one. An encrypted mapping is refused here with a clear message
rather than decrypted: the gateway would have to hold a passphrase for
the length of an engagement to serve a request, which is a worse trade
than routing the call locally.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

#: scrubkit/mapping.py
VERSION = 1
#: scrubkit/crypt.py
MAGIC = b"SKMAP1"

#: scrubkit/alias.py FAMILIES. Writing a kind scrubkit does not have
#: would produce a mapping its own tooling cannot read back.
KINDS = frozenset((
    "host", "ip4", "ip6", "email", "user", "term", "bucket",
    "account", "jwt", "bearer", "awskey", "uuid",
))


class MapError(Exception):
    pass


class EncryptedMap(MapError):
    pass


@dataclass
class ScrubMap:
    path: Path | None = None
    engagement: str = ""
    #: kind -> {value: placeholder}
    entries: dict = field(default_factory=dict)
    #: how many assignments this process added, via scrubkit
    minted: int = 0
    dirty: bool = False
    #: scrubkit's Aliaser, when it is installed and keyed
    minter: object = None

    # -- lookup ----------------------------------------------------
    def placeholder_for(self, kind: str, value: str) -> str | None:
        """The assignment for `value`, or None if there is not one."""
        if kind not in KINDS:
            raise MapError(f"{kind!r} is not a scrubkit span kind; "
                           f"known kinds are {sorted(KINDS)}")
        existing = self.entries.get(kind, {}).get(value)
        if existing is not None:
            return existing
        if self.minter is None:
            return None
        placeholder = self.minter.alias(kind, value)
        self.entries.setdefault(kind, {})[value] = placeholder
        self.minted += 1
        self.dirty = True
        return placeholder

    def reverse(self) -> dict:
        """placeholder -> value, for un-redacting."""
        out = {}
        for values in self.entries.values():
            for value, placeholder in values.items():
                out[placeholder] = value
        return out

    def assigned(self) -> dict:
        """(kind, value) -> placeholder, scrubkit's own shape."""
        out = {}
        for kind, values in self.entries.items():
            for value, placeholder in values.items():
                out[(kind, value)] = placeholder
        return out

    def substitutions(self) -> list:
        """(value, placeholder) pairs, longest value first.

        The file is sorted, which puts `corp.example` before
        `jump01.corp.example`. Substituting in that order leaves
        `jump01.CLIENT-HOST-11` in the request, so the order has to
        be imposed here rather than inherited from the file.
        """
        pairs = [(value, placeholder)
                 for values in self.entries.values()
                 for value, placeholder in values.items()]
        return sorted(pairs, key=lambda kv: len(kv[0]), reverse=True)

    def __len__(self) -> int:
        return sum(len(v) for v in self.entries.values())

    # -- serialisation ---------------------------------------------
    def to_json(self) -> dict:
        return {
            "version": VERSION,
            "engagement": self.engagement,
            # Sorted at both levels, as scrubkit writes it.
            "entries": {
                kind: dict(sorted(values.items()))
                for kind, values in sorted(self.entries.items())
            },
        }

    def save(self, path=None) -> None:
        target = Path(path or self.path) if (path or self.path) \
            else None
        if target is None:
            raise MapError("no path to save to")
        target.parent.mkdir(parents=True, exist_ok=True)
        # Atomic: a half-written mapping is an engagement's worth of
        # evidence that can no longer be read back.
        fd, tmp = tempfile.mkstemp(dir=str(target.parent),
                                   prefix=".mapping.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.to_json(), fh, indent=1)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self.path = target
        self.dirty = False


def loads(raw: bytes, *, path=None) -> ScrubMap:
    if raw.startswith(MAGIC):
        raise EncryptedMap(
            f"{path or 'mapping'} is an encrypted scrubkit mapping. "
            f"airlock will not hold a passphrase for the length of an "
            f"engagement; decrypt it with `scrubkit restore` or point "
            f"at a plaintext copy, or accept that these calls route "
            f"local.")
    data = json.loads(raw.decode("utf-8"))
    if data.get("version") != VERSION:
        raise MapError(f"{path or 'mapping'}: unsupported scrubkit "
                       f"mapping version {data.get('version')!r}")
    entries = {}
    for kind, values in (data.get("entries") or {}).items():
        if kind not in KINDS:
            raise MapError(f"{path or 'mapping'}: unknown span kind "
                           f"{kind!r}")
        entries[kind] = dict(values)
    return ScrubMap(path=Path(path) if path else None,
                    engagement=data.get("engagement", ""),
                    entries=entries)


def load(path, *, engagement: str = "", key: bytes | None = None,
         preserve_structure: bool = False) -> ScrubMap:
    p = Path(path)
    if p.exists():
        smap = loads(p.read_bytes(), path=p)
    else:
        smap = ScrubMap(path=p, engagement=engagement)
    smap.minter = aliaser(smap, key=key,
                          preserve_structure=preserve_structure)
    return smap


def aliaser(smap: ScrubMap, *, key: bytes | None,
            preserve_structure: bool = False):
    """scrubkit's Aliaser, loaded with what the mapping already has.

    None when scrubkit is not installed or the engagement has no key.
    Both of those mean airlock can reuse assignments and not make new
    ones, which costs recall on the hosted path and nothing else.
    """
    if not key:
        return None
    try:
        from scrubkit.alias import Aliaser
    except ImportError:
        return None
    al = Aliaser(key, preserve_structure=preserve_structure)
    al.load(smap.assigned())
    return al


def engagement_key(path) -> bytes | None:
    p = Path(path)
    if not p.exists():
        return None
    return p.read_bytes().strip()
