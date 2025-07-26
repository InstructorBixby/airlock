"""The record of what happened.

This file is the reason the whole project is worth maintaining. The
question it has to answer, months later, in writing, is: did any client
material reach a hosted provider. Not "I was careful" -- a list of
calls, each with what it was classified as, where it went, and what was
removed before it went.

Three constraints follow from that:

**Append-only.** Open in append mode, write one line, flush. No
rewriting, no compaction, no in-place edit. A record that can be
amended is not evidence.

**No client material in the log.** The log is the artefact most likely
to be read by someone who should not see the engagement. So: reason
ids, not matched values; counts, not strings; a hash of the outbound
body, not the body.

**Enough to reconstruct the decision.** Which routes were considered
and why each was rejected, not just the one that won. Without that, the
only time the reasoning is visible is while the process is still alive,
which is never when the question gets asked.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 2


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
    restored: int = 0
    request_sha256: str = ""
    status: int | None = None
    tokens: dict = field(default_factory=dict)
    cost_usd: float | None = None
    refusal: str = ""
    #: one line per route considered, winner included. Contains route
    #: names and requirement names, never matched text.
    considered: list = field(default_factory=list)
    #: identifier of the policy that produced the decision, so a
    #: record stays interpretable after the policy changes
    policy_sha256: str = ""

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

    def explain(self) -> str:
        lines = [f"{self.id}  {self.ts}  {self.path}",
                 f"tier: {self.tier}"]
        if self.reasons:
            lines.append("because: " + ", ".join(self.reasons))
        for line in self.considered:
            lines.append("  " + line)
        if self.decision == "allow":
            lines.append(f"decision: allow via {self.backend} "
                         f"as {self.model}")
            if self.redactions:
                lines.append(f"redactions: {self.redactions} out, "
                             f"{self.restored} restored")
        else:
            lines.append(f"decision: refuse -- {self.refusal}")
        if self.policy_sha256:
            lines.append(f"policy: {self.policy_sha256[:19]}")
        return "\n".join(lines)


def from_json(raw: dict) -> Record:
    fields = {f for f in Record.__dataclass_fields__}
    return Record(**{k: v for k, v in raw.items() if k in fields})


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

    def find(self, call_id_prefix: str) -> Record | None:
        hit = None
        for raw in self.records():
            if str(raw.get("id", "")).startswith(call_id_prefix):
                hit = raw
        return from_json(hit) if hit else None


def default_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "airlock" / "calls.jsonl"
