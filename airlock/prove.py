"""Answer the question in writing.

The question, exactly as it gets asked: did anything belonging to this
client reach a third party. The answer has to be a count and a list,
derived from the log, with the cases it cannot speak to named
explicitly rather than folded into the clean number.

Three outcomes, and the third is the honest one:

- `clean`   -- no call carrying material for this engagement went to a
               non-local backend.
- `exposed` -- at least one did. Here they are.
- `partial` -- the log contains calls whose classification was
               undecided, or whose records predate a schema change, so
               the clean answer cannot be given for the whole period.

A tool that only ever says "clean" is not evidence of anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CLEAN = "clean"
EXPOSED = "exposed"
PARTIAL = "partial"


@dataclass
class Proof:
    engagement: str
    verdict: str = CLEAN
    total: int = 0
    local: int = 0
    hosted: int = 0
    redacted: int = 0
    refused: int = 0
    exposures: list = field(default_factory=list)
    caveats: list = field(default_factory=list)
    first_ts: str = ""
    last_ts: str = ""

    def text(self) -> str:
        lines = [
            f"engagement: {self.engagement}",
            f"period: {self.first_ts or '-'} .. {self.last_ts or '-'}",
            f"calls: {self.total} ({self.local} local, "
            f"{self.hosted} hosted, {self.refused} refused)",
        ]
        if self.redacted:
            lines.append(f"of the hosted calls, {self.redacted} were "
                         f"sent redacted")
        lines.append(f"verdict: {self.verdict}")
        for e in self.exposures:
            lines.append(f"  exposure: {e}")
        for c in self.caveats:
            lines.append(f"  caveat: {c}")
        return "\n".join(lines)


def prove(records, engagement: str, *, local_backends=()) -> Proof:
    """`local_backends` comes from the policy, not from guessing."""
    local = set(local_backends)
    out = Proof(engagement=engagement)
    undecided = 0
    old_schema = 0
    for rec in records:
        if engagement not in (rec.get("engagements") or []):
            continue
        out.total += 1
        ts = rec.get("ts") or ""
        out.first_ts = out.first_ts or ts
        out.last_ts = ts or out.last_ts
        if rec.get("v", 1) < 3:
            old_schema += 1
        if rec.get("decision") != "allow":
            out.refused += 1
            if rec.get("tier") == "undecided":
                undecided += 1
            continue
        backend = rec.get("backend")
        if backend in local:
            out.local += 1
            continue
        out.hosted += 1
        if rec.get("redactions"):
            out.redacted += 1
            continue
        out.exposures.append(
            f"{rec.get('id')} {ts} tier={rec.get('tier')} "
            f"backend={backend} reasons="
            f"{','.join(rec.get('reasons') or []) or '-'}")

    if out.exposures:
        out.verdict = EXPOSED
    if undecided:
        out.caveats.append(
            f"{undecided} call(s) were refused as undecided; the log "
            f"records that nothing was sent, not what they contained")
    if old_schema:
        out.caveats.append(
            f"{old_schema} record(s) predate schema 3 and do not carry "
            f"a response classification")
    if out.caveats and out.verdict == CLEAN:
        out.verdict = PARTIAL
    return out
