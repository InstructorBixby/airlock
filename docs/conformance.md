# Conformance and selftest

The policy file is the control. This code applies it. So the thing
worth testing is the configuration I am actually running, not the
example in here, which is why the cases are data in the package and
the runner takes a path.

## against the policy in front of me

    airlock conformance --policy ~/eng/CLIENT/airlock.yaml

Each case is a request and an expected behaviour -- refused, or routed
to a local backend. No case asserts a *tier*: that would test my
detectors against my own regexes. The failure I am looking for is a
case that should have been refused and was not.

Nothing leaves the machine during a run. The backend call is replaced,
and a case that reaches a non-local backend is reported as a failure
rather than being allowed to happen.

## at startup

    airlock serve              # selftest runs by default
    airlock serve --no-selftest

The selftest is the fail-closed subset of the same cases, run against
the loaded policy and the live detector set before the listener opens.
If any of them do not hold, the process exits 3 and does not serve.
Exiting is the point: a gateway that starts anyway is a gateway I will
paste into for a week.

`--no-selftest` exists for debugging a case that is itself wrong. It
prints a line to stderr saying nothing has been proved, every time,
and the unit file does not have it.

## adding cases

`airlock/conformance/cases.yaml`, or a separate file with `--cases`.
Each case needs:

- `id`, and `why` -- what failure it is defending against. A case
  without a reason is a case I will delete in a year without knowing
  what I lost.
- `body` (or `raw`, for something that is not valid JSON).
- `expect`: `refused` or `local`.
- `because`, for a refusal: a substring of the expected refusal
  message. This is not pedantry. A case that passes because the
  request failed for an unrelated reason is worse than no case, since
  it reports green while testing nothing.

A case that catches a fail-open configuration is worth more than
anything else I could add to this repository.
