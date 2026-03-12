"""The record of what happened.

This file is the reason the whole project is worth maintaining. The
question it has to answer, months later, in writing, is: did any client
material reach a hosted provider. Not "I was careful" -- a list of
calls, each with what it was classified as, where it went, and what was
removed before it went.

Four constraints follow from that:

**Append-only.** Open in append mode, write one line, flush, fsync. No
rewriting, no compaction, no in-place edit.

**Chained.** Each record carries the hash of the line before it. That
does not make the log tamper-proof -- anything on this disk can be
rewritten by whoever holds the disk -- it makes a *silent* edit
impossible. A deleted line, a reordered line or an altered field breaks
the chain at a known point, and `airlock verify` says where. The
distinction that matters for a record like this is between "cannot be
changed" and "cannot be changed without the change being visible", and
only the second one is achievable here.

**No client material in the log.** The log is the artefact most likely
to be read by someone who should not see the engagement. So: reason
ids, not matched values; counts, not strings; a hash of the outbound
body, not the body.

**Enough to reconstruct the decision.** Which routes were considered
and why each was rejected, not just the one that won.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 4

#: First record's `prev`. Any constant would do; a recognisable one
#: makes a truncated-from-the-front log obvious.
GENESIS = "sha256:" + "0" * 64


def call_id() -> str:
    return secrets.token_hex(8)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def body_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def line_digest(line: str) -> str:
    return "sha256:" + hashlib.sha256(line.encode("utf-8")).hexdigest()


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
    considered: list = field(default_factory=list)
    policy_sha256: str = ""
    response_tier: str = ""
    reserialised: bool = False
    #: position in the chain, and the hash of the previous line
    seq: int = 0
    prev: str = ""

    def to_json(self) -> dict:
        out = {"v": SCHEMA}
        skip = (None, "", [], {}, False)
        for k, v in asdict(self).items():
            if k == "cost_usd":
                if v is not None:
                    out[k] = v
                continue
            if k == "seq":
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
            if self.response_tier:
                lines.append(f"answer classified {self.response_tier}")
        else:
            lines.append(f"decision: refuse -- {self.refusal}")
        if self.policy_sha256:
            lines.append(f"policy: {self.policy_sha256[:19]}")
        return "\n".join(lines)


def from_json(raw: dict) -> Record:
    fields = set(Record.__dataclass_fields__)
    return Record(**{k: v for k, v in raw.items() if k in fields})


@dataclass
class ChainBreak:
    seq: int
    line_no: int
    why: str

    def __str__(self) -> str:
        return f"line {self.line_no} (seq {self.seq}): {self.why}"


class Log:
    """Append-only, hash-chained JSONL."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._head = None
        self._seq = None

    # -- chain state -----------------------------------------------
    def _tail(self):
        """(seq, digest) of the last line, read once per process."""
        if self._head is not None:
            return self._seq, self._head
        seq, digest = 0, GENESIS
        if self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    digest = line_digest(line)
                    try:
                        seq = int(json.loads(line).get("seq", seq + 1))
                    except ValueError:
                        seq += 1
        self._seq, self._head = seq, digest
        return seq, digest

    @property
    def head(self) -> str:
        return self._tail()[1]

    # -- writing ---------------------------------------------------
    def write(self, rec: Record) -> Record:
        seq, prev = self._tail()
        rec.seq = seq + 1
        rec.prev = prev
        line = json.dumps(rec.to_json(), sort_keys=True,
                          ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._seq, self._head = rec.seq, line_digest(line)
        return rec

    # -- reading ---------------------------------------------------
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

    def verify(self, *, expect_head: str | None = None) -> list:
        """Every break in the chain, in order. Empty means intact."""
        breaks = []
        prev = GENESIS
        seq = 0
        digest = GENESIS
        if self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                for line_no, raw in enumerate(fh, start=1):
                    stripped = raw.rstrip("\n")
                    if not stripped.strip():
                        continue
                    try:
                        obj = json.loads(stripped)
                    except ValueError:
                        breaks.append(ChainBreak(seq + 1, line_no,
                                                 "not json"))
                        return breaks
                    got_prev = obj.get("prev", "")
                    got_seq = int(obj.get("seq", 0))
                    if got_prev != prev:
                        breaks.append(ChainBreak(
                            got_seq, line_no,
                            f"prev is {got_prev[:19]}, expected "
                            f"{prev[:19]}"))
                    if got_seq != seq + 1:
                        breaks.append(ChainBreak(
                            got_seq, line_no,
                            f"seq jumped from {seq} to {got_seq}"))
                    seq = got_seq
                    digest = line_digest(stripped)
                    prev = digest
        if expect_head is not None and digest != expect_head:
            breaks.append(ChainBreak(
                seq, -1, f"head is {digest[:19]}, the recorded head "
                         f"was {expect_head[:19]}"))
        return breaks


def default_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "airlock" / "calls.jsonl"


def head_path(log_path) -> Path:
    return Path(str(log_path) + ".head")
