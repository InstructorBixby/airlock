# airlock

A local, OpenAI-compatible endpoint that classifies every model call
before it leaves the machine, routes it according to a declarative
policy, and records the decision.

The constraint it exists for: client material does not go to a hosted
provider. One gate in the path beats a habit of being careful, and a
log beats a memory.

## install

    uv pip install -e .

## configure

Two files. Neither is in this repository.

`~/.config/airlock/policy.yaml` -- what each tier is allowed to reach.
Start from `airlock/policy.yaml` in this repo.

`roster.yaml` -- the engagements, with the names, domains and networks
that identify each. Start from `roster.example.yaml`. The server will
not start without it, because an absent roster classifies client
material as public.

## run

    airlock serve

    export OPENAI_BASE_URL=http://127.0.0.1:8111/v1
    export OPENAI_API_KEY=unused-but-some-clients-insist

Every tool that honours `OPENAI_BASE_URL` now goes through the gate
with no changes of its own.

## tiers

| tier                  | meaning                            | route |
| --------------------- | ---------------------------------- | ----- |
| `public`              | nothing identifying in it          | hosted |
| `internal`            | mine, but needs scrubbing first    | hosted after redaction, else local |
| `client-confidential` | belongs to a client                | local model only |

There is a fourth answer, `undecided`, which is what the classifier
says when it cannot read part of a request or a detector raised. It has
no route and cannot be given one.

## check something without sending it

    airlock check notes.md
    pbpaste | airlock check -

Prints the routing decision and every route it considered. Exits
non-zero if the material would not be allowed out.

## what this does not protect against

See `docs/limits.md`. Read it before trusting this with anything.
