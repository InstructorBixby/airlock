"""A suite I point at the policy file I am actually running.

The reason this exists: the policy is the control, not this code. The
example in the repository is covered by the test suite and is not the
file in front of me. The file in front of me is one of a dozen in
engagement directories, most of them edited in a hurry, none of them
tested by anything -- and a control I have not tested is not a
control, it is a thing I believe about my own setup.

So the cases are data rather than tests, and the runner takes a path.
Every case is a request and an expectation, loaded from `cases.yaml`.
No case asserts a tier -- that would be testing my detectors against
my own regexes. Each one asserts something about the *behaviour*:
refused, or routed to a local backend, or never reaching a socket.

Two ways a case can lie, both handled:

1. **Passing for the wrong reason.** A refusal case records the reason
   it expects to see, and the runner checks the message contains it.
2. **Passing vacuously.** A `local` case against a policy with no
   hosted backend at all proves nothing -- there was nowhere else for
   the request to go. Those cases are reported as `n/a`, not as passes,
   and the report says how many were skipped so a wall of green cannot
   be mistaken for a wall of proof.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from airlock import audit, policy, server, tiers

CASES = Path(__file__).parent / "cases.yaml"


class NoSocket(Exception):
    """Raised if a case reaches a backend when it should not."""


@dataclass
class Case:
    id: str
    why: str
    body: dict
    #: "refused" | "local" | "any"
    expect: str = "refused"
    because: str = ""
    raw: str | None = None

    def payload(self) -> bytes:
        if self.raw is not None:
            return self.raw.encode()
        return json.dumps(self.body).encode()


@dataclass
class Outcome:
    case: Case
    ok: bool
    detail: str = ""
    #: the case could not say anything about this policy
    vacuous: bool = False

    def line(self) -> str:
        mark = "n/a " if self.vacuous else ("pass" if self.ok
                                            else "FAIL")
        return f"{mark}  {self.case.id:34} {self.detail}"


@dataclass
class Report:
    outcomes: list = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes
                   if not o.ok and not o.vacuous)

    @property
    def skipped(self) -> int:
        return sum(1 for o in self.outcomes if o.vacuous)

    def text(self) -> str:
        lines = [o.line() for o in self.outcomes]
        tail = (f"{len(self.outcomes)} case(s), "
                f"{self.failed} failed")
        if self.skipped:
            tail += (f", {self.skipped} said nothing about this "
                     f"policy")
        lines.append(tail)
        if self.skipped and not self.failed:
            lines.append("a skipped case is not a passing case; this "
                         "policy has no hosted backend for those "
                         "cases to prove anything against")
        if self.failed:
            lines.append("a failure here means the loaded policy does "
                         "not fail closed; do not serve with it")
        return "\n".join(lines)


def load_cases(path=None) -> list:
    raw = yaml.safe_load(Path(path or CASES).read_text()) or {}
    out = []
    for item in raw.get("cases") or []:
        out.append(Case(
            id=item["id"], why=item.get("why", ""),
            body=item.get("body") or {},
            expect=item.get("expect", "refused"),
            because=item.get("because", ""),
            raw=item.get("raw"),
        ))
    if not out:
        raise ValueError(f"{path or CASES} declares no cases")
    return out


def run(pol: policy.Policy, cases=None, *, detectors=(),
        log_path=None) -> Report:
    cases = cases or load_cases()
    local = {n for n, be in pol.backends.items() if be.is_local}
    hosted = set(pol.backends) - local
    report = Report()
    for case in cases:
        if case.expect == "local" and not hosted:
            report.outcomes.append(Outcome(
                case, True, "policy declares no hosted backend",
                vacuous=True))
            continue
        report.outcomes.append(
            _run_one(pol, case, local, detectors, log_path))
    return report


def _run_one(pol, case, local, detectors, log_path) -> Outcome:
    reached = []

    def fake_call(be, path, body, timeout=180.0):
        reached.append(be.name)
        if be.name not in local:
            raise NoSocket(be.name)
        return {"choices": [{"message": {"content": "ok"}}],
                "usage": {}}

    real_call, real_probe = server.backends.call, server.backends.probe
    server.backends.call = fake_call
    server.backends.probe = lambda be, **kw: True
    try:
        log = audit.Log(log_path or _scratch())
        gw = server.Gateway(pol, log, detectors=list(detectors))
        try:
            status, obj, _ = gw.handle("/v1/chat/completions",
                                       case.payload())
        except NoSocket as exc:
            return Outcome(case, False,
                           f"request reached non-local backend {exc!s}")
        message = (obj.get("error") or {}).get("message", "")
        if case.expect == "refused":
            if status == 200:
                where = reached[0] if reached else "?"
                return Outcome(case, False, f"allowed via {where}")
            if case.because and case.because not in message:
                return Outcome(case, False,
                               f"refused for the wrong reason: "
                               f"{message[:70]}")
            return Outcome(case, True, f"refused ({status})")
        if case.expect == "local":
            if status != 200:
                return Outcome(case, False, f"refused: {message[:70]}")
            if not reached or reached[0] not in local:
                return Outcome(case, False,
                               f"routed to {reached or ['nothing']}")
            return Outcome(case, True, f"local ({reached[0]})")
        return Outcome(case, status in (200, 403), f"status {status}")
    finally:
        server.backends.call = real_call
        server.backends.probe = real_probe


def _scratch() -> Path:
    import tempfile
    return Path(tempfile.mkdtemp(prefix="airlock-conf.")) / "calls.jsonl"


__all__ = ["Case", "Outcome", "Report", "load_cases", "run", "tiers"]
