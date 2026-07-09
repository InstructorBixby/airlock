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

The cases that matter most are the fail-closed ones. A case whose
expectation is `refused` and which passes vacuously -- because the
request errored for an unrelated reason -- would be worse than no case,
so each records the refusal reason it expects to see and the runner
checks it.
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
    #: substring expected in the refusal, so a case cannot pass by
    #: failing for the wrong reason
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

    def line(self) -> str:
        return (f"{'pass' if self.ok else 'FAIL'}  {self.case.id:34} "
                f"{self.detail}")


@dataclass
class Report:
    outcomes: list = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.ok)

    def text(self) -> str:
        lines = [o.line() for o in self.outcomes]
        lines.append(f"{len(self.outcomes)} case(s), "
                     f"{self.failed} failed")
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
    report = Report()
    for case in cases:
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
                           f"request reached non-local backend "
                           f"{exc!s}")
        message = (obj.get("error") or {}).get("message", "")
        if case.expect == "refused":
            if status == 200:
                return Outcome(case, False,
                               f"allowed via {reached[0] if reached else '?'}")
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


__all__ = ["Case", "Report", "load_cases", "run", "tiers"]
