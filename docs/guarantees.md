# What this guarantees

The whole claim, and it is deliberately narrow:

> For a request that reaches this process, airlock applies the loaded
> policy to it before any part of it is sent anywhere, refuses the
> request if the policy does not permit a route for its classification,
> and writes one audit record describing what it decided.

That is it. Three properties, each of which is testable, and
`airlock conformance` tests them against the policy I am actually
running rather than the example in this repository.

## the three properties

**P1. Nothing is sent before the decision.** There is one function that
produces a routing decision and both the buffered and the streaming
path call it before opening a socket. A request that is refused does
not reach a backend at all -- not truncated, not redacted, not
attempted.

**P2. No route means no call.** Every exit from classification that is
not a confident tier with a satisfiable route ends in a refusal. That
includes: a body that is not an object, a content part the reader does
not understand, a detector that raised, a tier with an empty route
list, a missing roster file, and a policy that fails to load. The
conformance suite enumerates these and asserts each one refuses.

**P3. Every call leaves exactly one record.** Allowed or refused,
success or backend error. The record contains the classification, the
reasons as codes, the route considered and taken, and a hash of the
request body.

## what it does not guarantee

**It does not guarantee classification is correct.** The detectors are
heuristic. Recall is not 100% and cannot be. `docs/limits.md` and
`docs/threat-model.md` are the honest versions of this, and the
guarantee above is carefully worded to be about *applying the policy*,
not about getting the tier right.

**It does not guarantee coverage.** It constrains calls that arrive. A
tool that does not point at it is not affected by it in any way. This
is the largest gap between what I feel when I paste something and what
is actually true, which is why it is the first section of
`docs/limits.md` and why `airlock doctor` exists.

**It does not guarantee confidentiality of anything on this machine.**
Routing to a local model keeps material off a provider. The material is
still on the disk, and so is the redaction map.

**It does not guarantee the log cannot be altered.** It guarantees an
alteration is visible. Those are different claims and only the second
one is achievable by a process writing to its own filesystem.

**It makes no claim about any specific regulation.** It is a technical
control that produces evidence. Whether that evidence satisfies the
confidentiality clause in a given contract is not a question I get to
answer by having written the control, and it is exactly the question I
would talk myself into answering.

## how I check instead of trusting

    airlock conformance --policy ~/eng/CLIENT/airlock.yaml
    airlock serve --selftest

The first proves the properties above hold for the policy in front of
me, not for the one in this repository. The second runs the same checks
at startup and refuses to serve if any of them fail -- which is why it
is the default and why the unit file has no way to turn it off.
