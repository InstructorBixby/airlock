"""What a classification is.

A `Finding` is one thing a detector noticed. An `Assessment` is the
whole verdict on one request. Both are deliberately boring records: the
interesting behaviour lives in the detectors and in the policy, and
keeping the data between them dumb is what lets either side be replaced.

The one rule with teeth: a Finding carries the matched value, an
Assessment's `reasons` do not. Findings stay in memory for the length
of one request so redaction can use them. Reasons are what gets
written to disk, and the audit log of a gateway that exists to keep
client material off disk cannot be full of client material.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from airlock import tiers


@dataclass(frozen=True)
class Finding:
    #: stable detector id, e.g. "net.private-address". A `@base64` or
    #: `~fold` suffix means it was found in a decoded or normalised
    #: view of the text rather than in the text itself.
    kind: str
    #: the text that matched, for redaction. Never serialised.
    value: str
    #: tier this finding on its own implies
    tier: str = tiers.CONFIDENTIAL
    #: which engagement it belongs to, when the detector knows
    engagement: str | None = None
    #: byte offsets in the text that was scanned, when available
    span: tuple[int, int] | None = None

    @property
    def reason(self) -> str:
        if self.engagement:
            return f"{self.engagement}:{self.kind}"
        return self.kind


@dataclass
class Assessment:
    tier: str = tiers.PUBLIC
    findings: list = field(default_factory=list)
    #: set when the classifier could not reach a confident answer
    undecided_because: str | None = None
    #: one readable line per weak finding that something else backed up
    corroborated: list = field(default_factory=list)
    #: the text contained characters that folding changed
    folded: bool = False

    @property
    def reasons(self) -> list[str]:
        return sorted({f.reason for f in self.findings})

    @property
    def engagements(self) -> list[str]:
        return sorted({f.engagement for f in self.findings
                       if f.engagement})

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.tier = tiers.worst(self.tier, finding.tier)

    def undecided(self, why: str) -> None:
        self.undecided_because = why
        self.tier = tiers.UNDECIDED

    def to_json(self) -> dict:
        out = {"tier": self.tier, "reasons": self.reasons}
        if self.engagements:
            out["engagements"] = self.engagements
        if self.corroborated:
            out["corroborated"] = list(self.corroborated)
        if self.folded:
            out["folded"] = True
        if self.undecided_because:
            out["undecided_because"] = self.undecided_because
        return out
