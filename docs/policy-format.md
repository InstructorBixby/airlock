# The policy file

A policy file is the control. Not this code -- this code applies what
the file says.

There is one of these per engagement, in each engagement directory,
and the oldest ones predate about half the keys. That is the reason
the format has a version and a schema rather than being whatever the
loader happened to accept: I am not going to rewrite every policy on
this disk when I change my mind about a key name, and if I tried I
would do the three I am working in and leave the rest loading under a
reader that means something slightly different by the same words.

Schema: `airlock/schema/policy-v1.json`. The editor picks it up from
there, which is the only reason it is a file and not a docstring.

## version

`version: 1` is required. A file with a version this build does not
know is refused, not best-effort parsed. Within version 1:

- New optional keys may be added.
- No existing key will change meaning or default.
- No key will be removed.
- A key will not become required.

Anything that cannot be done under those rules becomes version 2, and a
version 1 file will keep loading for at least two minor releases after
version 2 exists, with a deprecation warning naming the key.

## strictness

Unknown keys are an error, both at the top level and inside a backend.
That is unusual for a config format and deliberate here: a misspelled
`preseve_model` silently doing nothing is a control behaving differently
from how its file reads, which is the failure this whole document
exists to prevent.

## invariants the loader enforces

These are checked whether or not `jsonschema` is installed, because
they are the control rather than the syntax:

1. `client-confidential` may only route to a backend whose `base_url`
   is on this machine. The loader rejects anything else; there is no
   flag.
2. `undecided` has no routes and cannot be given any.
3. Every tier must appear. Omitting one is not a permissive default, it
   is an error -- silence is not a policy.
4. Every route must name a declared backend.
5. Every `require` entry must be one the router knows how to check.

## validating

    airlock policy lint                       # the configured policy
    airlock policy lint --policy ./policy.yaml

Exits non-zero with the reason on stderr. Schema validation runs when
the `schema` extra is installed; the invariants above run regardless.
It is a pre-commit hook in the engagement template, so a policy I edit
at 1am does not get committed broken and then loaded in the morning.
