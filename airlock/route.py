"""Choose a route for an assessed request.

Returns a Decision, which is the thing the audit log records and the
thing `--why` prints. The important property is that a refusal is a
Decision too, with the same list of considered-and-rejected routes as a
success -- otherwise the only time you can see the reasoning is when
you did not need it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from airlock import backends, tiers
from airlock.model import Assessment
from airlock.policy import Policy, Route

#: How long a probe result is trusted. Short, because "the local model
#: is up" is what decides whether a confidential call can run at all,
#: and a stale yes routes a call at a backend that is not there. Long
#: enough that a pipeline of forty calls does not probe forty times.
PROBE_TTL = 15.0

_probes: dict = {}


def available(be, *, now=None) -> bool:
    now = now if now is not None else time.monotonic()
    hit = _probes.get(be.name)
    if hit is not None and now - hit[0] < PROBE_TTL:
        return hit[1]
    ok = backends.probe(be)
    _probes[be.name] = (now, ok)
    return ok


def forget_probes() -> None:
    _probes.clear()


@dataclass
class Considered:
    route: Route
    ok: bool
    why: str

    def line(self) -> str:
        mark = "->" if self.ok else "  "
        return f"{mark} {self.route.describe()}: {self.why}"


@dataclass
class Decision:
    tier: str
    allowed: bool = False
    route: Route | None = None
    considered: list = field(default_factory=list)
    refusal: str = ""

    @property
    def backend(self) -> str | None:
        return self.route.backend if self.route else None

    def explain(self) -> str:
        out = [f"tier: {self.tier}"]
        if not self.considered:
            out.append("no routes declared for this tier")
        for c in self.considered:
            out.append(c.line())
        if self.allowed:
            out.append(f"decision: allow via {self.route.describe()}")
        else:
            out.append(f"decision: refuse -- {self.refusal}")
        return "\n".join(out)


def decide(pol: Policy, assessment: Assessment, *,
           redaction_complete: bool = False,
           check_available: bool = True,
           deny_hosted: bool = False) -> Decision:
    tier = assessment.tier
    dec = Decision(tier=tier)

    if tier == tiers.UNDECIDED:
        dec.refusal = (assessment.undecided_because
                       or "classifier reached no verdict")
        return dec

    candidates = pol.candidates(tier)
    if not candidates:
        dec.refusal = f"policy declares no route for {tier}"
        return dec

    for route in candidates:
        be = pol.backend(route.backend)
        unmet = []
        if deny_hosted and not be.is_local:
            unmet.append("engagement denies hosted")
        if "redacted" in route.require and not redaction_complete:
            unmet.append("redaction incomplete")
        if "local" in route.require and not be.is_local:
            unmet.append("backend is not local")
        if ("available" in route.require and check_available
                and not available(be)):
            unmet.append("backend not answering")
        if unmet:
            dec.considered.append(
                Considered(route, False, "; ".join(unmet)))
            continue
        dec.considered.append(Considered(route, True,
                                         "requirements met"))
        dec.allowed = True
        dec.route = route
        return dec

    dec.refusal = (f"all {len(candidates)} route(s) for {tier} were "
                   f"unusable")
    return dec
