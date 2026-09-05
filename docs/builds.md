# Which build is serving

A tampered build of this would be worse than not running it at all: a
control that reports clean while doing nothing, producing a log that
is evidence of something that did not happen. Nothing here is
published, so nobody has to tamper with anything -- the realistic
version of that failure is me, not knowing which build is answering
on 8111.

That has happened. An old wheel in a venv that was earlier on `PATH`
than the one I had just installed, serving a policy loader from before
a key was renamed, quietly classifying as `public` a shape that the
current code calls `internal`.

## so

- The tag pipeline stamps the commit into the package before it
  builds, and `airlock.version.describe()` reports it.
- Anything installed out of a working tree describes itself as
  `(checkout)` instead of claiming a commit. A build whose contents I
  cannot name has to say so.
- Every record carries the policy digest, so a decision in the log can
  be re-read against the policy that actually produced it rather than
  the one on disk now.
- The tag job prints a SHA-256 per artefact and the artefacts do not
  expire, so the file on a machine either matches a line in a job log
  or came from somewhere I did not look.
- `airlock doctor` is still the answer to the different and worse
  question: not which build is serving, but what is not going through
  it at all.

## what this is not

Not a signature, and it does not need to be. The chain is a hash in a
job log on my own instance on my own network. Anybody in a position to
rewrite that has far more of mine than a wheel.

## and then

    airlock conformance --policy ~/eng/CLIENT/airlock.yaml

Knowing which build is serving says the code is the code I tested. The
conformance run says this policy fails closed. They are different
questions and I need both answers, and the second one is the one I
skip.
