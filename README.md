# airlock

A local, OpenAI-compatible endpoint that classifies every model call
before it leaves the machine, routes it according to a declarative
policy, redacts reversibly when that is what makes a call allowable,
and records the decision.

The constraint it exists for: client material does not go to a hosted
provider. One gate in the path beats a habit of being careful, and a
log beats a memory.

## install

    uv pip install -e .

## configure

`~/.config/airlock/policy.yaml` -- what each tier may reach. Start from
`airlock/policy.yaml` in this repo. The loader refuses any policy in
which client-confidential could reach something that is not on this
machine.

`roster.yaml` -- the engagements, with the names, domains and networks
that identify each. Start from `roster.example.yaml`. The server will
not start without it, because an absent roster classifies client
material as public.

`engagements/<id>/` -- optional per-engagement directory, read rather
than configured. A `scope.yaml` becomes a detector, an `airlock.yaml`
can add engagement-specific terms and tighten limits, and the
redaction map for the engagement lives beside them.

## run

    airlock serve -e halberd

    export OPENAI_BASE_URL=http://127.0.0.1:8111/v1
    export OPENAI_API_KEY=unused-but-some-clients-insist

Every tool that honours `OPENAI_BASE_URL` now goes through the gate
with no changes of its own.

## tiers

| tier                  | meaning                         | route |
| --------------------- | ------------------------------- | ----- |
| `public`              | nothing identifying in it       | hosted |
| `internal`            | mine, but needs scrubbing first | hosted after redaction, else local |
| `client-confidential` | belongs to a client             | local model only |

There is a fourth answer, `undecided`, which is what the classifier
says when it cannot read part of a request or a detector raised. It has
no route and cannot be given one.

## the round trip

For the `internal` tier, identifying strings are replaced with the
placeholders the engagement already uses and put back on the way in,
so the model reasons about `CLIENT-HOST-07` and I read about the real
host.

The mapping is `scrubkit`'s -- the same file that reverses the
engagement's asciicasts and HARs -- and airlock reads it rather than
keeping one of its own. It does not mint placeholders either: scrubkit
derives them from the engagement key so a host is the same placeholder
everywhere, and a value with no assignment is simply not redactable,
which routes the call locally. See `docs/redaction.md`.

## ask it things

    airlock check notes.md --why      # would this be allowed out, and why
    airlock why 9f2c                  # why did that call go where it went
    airlock engagements               # what profiles were found

## what this does not protect against

`docs/limits.md`. Read it before trusting this with anything.
