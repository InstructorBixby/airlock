# Decisions I keep wanting to reverse

Written down because every one of these will look reasonable again at
2am on a Thursday with a call that will not go through, and because by
then I will have forgotten which failure put it on the list.

## the thing to remember

This is a compliance control. A change that makes it quieter is a
regression even when it makes it more pleasant to use. "It refused
something it should have allowed" is a lower-severity bug than "it
allowed something it should have refused", and the second one has no
symptom. Being slow and irritating about that distinction is the
entire job.

Concretely: anything I touch in classification, routing or redaction
gets a test that fails without it, and a test for the *negative* case
-- not just that the new thing is detected, but that a request which
should still be refused still is.

## the loop

    uv pip install -e ".[dev]"
    ruff check .
    mypy
    pytest

`pytest -q` stays clean and fast; anything slow or network-touching is
marked and skipped by default, because a suite I skip is a suite I do
not have.

## worth adding, when I have the evidence

- A detector for a credential or hostname shape, with a real example
  in the test. Redacted, obviously.
- A conformance case that catches a fail-open configuration I had not
  thought of. These are worth more than any feature on the list and
  `airlock/conformance/cases.yaml` is deliberately easy to add to.
- Anything that makes a limit clearer in the docs. I am the one who
  will over-estimate this.
- Support for a client whose base-url handling is awkward, as long as
  it does not add a bypass. Awkward clients are how `doctor` happened.

## what I am not going to do, however good the reason looks

- **A route requirement the gateway cannot verify.** `require:
  [redacted]` works because redaction either covered every finding or
  it did not. A requirement that trusts a header, an env var or the
  caller's word is not a requirement, it is a note.
- **Confidence scores or thresholds in the classifier.** Tried,
  removed, `docs/aliases.md` has the write-up. A refusal has to be
  explainable in one line, and a number between 0 and 1 is not one.
- **Writing request or response content anywhere.** Including to a
  debug log behind a flag. Especially to a debug log behind a flag,
  because the flag will be on during the one engagement where it
  matters.
- **A way to override policy at call time** -- a magic header, a model
  name suffix, an env var. The policy file is the control. If it can
  be overridden per call then the control is whatever I felt like at
  the time, which is the thing this replaced.
- **A large refactor on a whim.** This code is shaped by failures that
  are not visible from reading it. If I cannot name the failure a
  piece of it is defending against, that is a reason to go and find
  out, not a reason to tidy it.

## commit messages

Say what changed and, if it is not obvious, what went wrong that made
it necessary. The log is the only place some of that is written down
at all.
