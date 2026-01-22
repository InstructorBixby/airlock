"""What this engagement has cost so far.

Read from the audit log rather than kept in a counter, for the same
reason the log exists at all: there is one source of truth about what
happened and it is the append-only file. A counter in memory resets
when I restart the gateway, which is the moment I am least likely to
notice it.

The ceiling is checked *before* a call, not after. Discovering that a
pipeline went over budget once it has finished is accounting; refusing
the call that would cross the line is a control.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Totals:
    usd: float = 0.0
    calls: int = 0
    #: calls whose model had no declared price. Not zero -- unknown.
    unpriced: int = 0
    by_engagement: dict = field(default_factory=dict)

    def over(self, ceiling: float | None) -> bool:
        return ceiling is not None and self.usd >= ceiling


def totals(records, *, engagement: str | None = None) -> Totals:
    out = Totals()
    for rec in records:
        if rec.get("decision") != "allow":
            continue
        engs = rec.get("engagements") or []
        if engagement is not None and engagement not in engs:
            continue
        out.calls += 1
        cost = rec.get("cost_usd")
        if cost is None:
            out.unpriced += 1
        else:
            out.usd = round(out.usd + float(cost), 6)
        for e in engs or ["(none)"]:
            slot = out.by_engagement.setdefault(
                e, {"usd": 0.0, "calls": 0})
            slot["calls"] += 1
            if cost is not None:
                slot["usd"] = round(slot["usd"] + float(cost), 6)
    return out


def would_exceed(spent: float, ceiling: float | None,
                 estimate: float = 0.0) -> bool:
    if ceiling is None:
        return False
    return spent + estimate >= ceiling


def report(t: Totals) -> str:
    lines = [f"{t.calls} call(s), ${t.usd:.4f}"]
    if t.unpriced:
        lines.append(f"{t.unpriced} call(s) had no declared price and "
                     f"are not in that total")
    for name in sorted(t.by_engagement):
        slot = t.by_engagement[name]
        lines.append(f"  {name:24} {slot['calls']:5}  "
                     f"${slot['usd']:.4f}")
    return "\n".join(lines)
