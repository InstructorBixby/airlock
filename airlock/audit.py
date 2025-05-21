"""The record of what happened.

This file is the reason the whole project is worth maintaining. The
question it has to answer, months later, in writing, is: did any client
material reach a hosted provider. Not "I was careful" -- a list of
calls, each with what it was classified as, where it went, and what was
removed before it went.

Two constraints that follow from that:

**Append-only.** Open in append mode, write one line, flush. No
rewriting, no compaction, no in-place edit. A record that can be
amended is not evidence.

**No client material in the log.** The log is the artefact most likely
to be read by someone who should not see the engagement. So: reason
ids, not matched values; counts, not strings; a hash of the outbound
body, not the body.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 1


def call_id() -> str:
    return secrets.token_hex(8)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def body_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass
class Record:
    id: str
    ts: str
    path: str = ""
    tier: str = ""
    reasons: list = field(default_factory=list)
    engagements: list = field(default_factory=list)
    decision: str = "refuse"
    backend: str | None = None
    model: str | None = None
    redactions: int = 0
    request_sha256: str = ""
    status: int | None = None
    tokens: dict = field(default_factory=dict)
    #: None means no price was declared for this model, which is not
    #: the same as a cost of zero. Both are meaningful; conflating
    #: them makes a monthly total quietly wrong.
    cost_usd: float | None = None
    refusal: str = ""

    def to_json(self) -> dict:
        out = {"v": SCHEMA}
        skip = (None, "", [], {})
        for k, v in asdict(self).items():
            if k == "cost_usd":
                if v is not None:
                    out[k] = v
                continue
            if v not in skip:
                out[k] = v
        return out


class Log:
    """Append-only JSONL. One instance per process is fine."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, rec: Record) -> Record:
        line = json.dumps(rec.to_json(), sort_keys=True,
                          ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return rec

    def records(self):
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)


def default_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "airlock" / "calls.jsonl"
