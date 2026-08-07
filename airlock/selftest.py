"""Run the fail-closed cases before the listener opens.

A control that starts up and hopes is a logging proxy with opinions.
The conformance cases already express the properties that have to hold;
this runs the fail-closed subset of them against the loaded policy and
the live detector set at startup, and refuses to serve if any of them
pass when they should have been refused.

It costs a few milliseconds and no network: every case is run with the
backend call replaced, so nothing leaves the machine during a selftest.

Deliberately not optional in any build. `--no-selftest` exists for
exactly one situation -- debugging a case that is itself wrong -- and it
prints a line saying the gateway is running without having proved
anything, every time, to stderr, where it cannot be missed.
"""
from __future__ import annotations

from airlock import conformance


class SelfTestFailed(Exception):
    def __init__(self, report):
        super().__init__(f"{report.failed} fail-closed case(s) did not "
                         f"hold for this policy")
        self.report = report


def fail_closed_cases(cases=None):
    """The subset whose expectation is a refusal."""
    return [c for c in (cases or conformance.load_cases())
            if c.expect == "refused"]


def run(policy, *, detectors=(), cases=None, log_path=None):
    """Returns the report, or raises SelfTestFailed."""
    subset = fail_closed_cases(cases)
    report = conformance.run(policy, subset, detectors=detectors,
                             log_path=log_path)
    if report.failed:
        raise SelfTestFailed(report)
    return report
