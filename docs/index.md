# airlock

A local, OpenAI-compatible endpoint that classifies every model call
before it leaves the machine, routes it according to a declarative
policy, redacts reversibly when that is what makes a call allowable,
and records the decision.

It exists for one constraint: under an engagement letter, client
material does not go to a hosted provider. One gate in the path beats
a habit of being careful, and a log beats a memory.

!!! warning "Re-read the guarantee before trusting this again"
    The claim it makes is narrow and precise, and it is not "keeps
    client data safe". [What it guarantees](guarantees.md), [what it
    does not protect against](limits.md), and the
    [threat model](threat-model.md) are the three pages that say what
    I am entitled to believe. I over-estimate this tool roughly every
    time I have not read them for a month.

## install

    uv pip install -e .

## in thirty seconds

    airlock policy lint --policy policy.yaml
    airlock conformance --policy policy.yaml
    airlock serve --policy policy.yaml

    export OPENAI_BASE_URL=http://127.0.0.1:8111/v1

Every tool that honours `OPENAI_BASE_URL` now goes through the gate
with no changes of its own. `airlock serve` runs the fail-closed
conformance cases against that policy before it opens the listener and
refuses to start if any of them do not hold.

## the shape of it

    tool -> airlock -> classify -> route -> local model
                               \-> redact -> hosted model -> un-redact
                               \-> refuse
                               \-> audit record, always

## tiers

| tier | meaning | route |
| ---- | ------- | ----- |
| `public` | nothing identifying in it | hosted |
| `internal` | mine, but needs scrubbing first | hosted after redaction, else local |
| `client-confidential` | belongs to a client | local model only |

`undecided` is the fourth answer and not a tier: it is what the
classifier says when it cannot read part of a request or a detector
raised. It has no route, and the policy language cannot give it one.
