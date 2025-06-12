# Redaction, and reading the answer afterwards

The `internal` tier is the one that earns its keep. Most of what I want
a hosted model for is not secret in itself -- why does this response
header combination mean what it means, what is wrong with this nginx
block, is this really a path traversal -- but the text I have in front
of me is full of names that cannot leave.

One-way redaction does not solve that. If I send

    GET /admin HTTP/1.1
    Host: CLIENT-HOST-07

and the answer comes back talking about `CLIENT-HOST-07`, the answer is
correct and unreadable, and I end up doing the substitution in my head,
badly, while reading. Three turns later I have lost track of which
placeholder was which.

So the mapping has to be kept and applied in reverse on the way back.
The model reasons about `CLIENT-HOST-07`; I read about the real host.
Nothing identifying crossed the wire in either direction, and the
transcript I keep locally is in the vocabulary of the engagement.

## it is scrubkit's mapping, not a second one

The engagement already has one. `scrubkit` wrote it while redacting the
asciicasts and the HARs and the request pairs that went into the
evidence folder, and it is the file that reverses all of that. A
placeholder means the same thing in the report, in the terminal capture
and in a model's answer, or it means nothing.

The file, from scrubkit/mapping.py:

    {"version": 1,
     "engagement": "halberd",
     "entries": {"host": {"jump01.corp.example": "CLIENT-HOST-11"},
                 "ip4":  {"10.40.1.9": "CLIENT-IP-04"}}}

Value to placeholder, keyed by scrubkit's span kind, sorted at both
levels so the file does not churn in a diff. airlock reads it, and the
kinds it maps its own findings onto are scrubkit's twelve and nothing
else.

One consequence of the file being sorted is worth writing down because
it is the kind of bug that produces a half-redacted request: the
mapping lists `corp.example` before `jump01.corp.example`. Substituting
in file order leaves `jump01.CLIENT-HOST-11` in the body. Longest value
first, always, in both directions.

## airlock does not mint placeholders

scrubkit assigns an index from an HMAC of the value under the
engagement key, so the map from value to placeholder is a *function*:
the same host comes out as `CLIENT-HOST-11` in every file, on every
day, on a rebuilt machine. Collisions are resolved by probing and the
resolution is recorded in the mapping, which is why the mapping is an
input to the next file rather than only an output.

If airlock chose its own indices it would be allocating in a namespace
scrubkit also allocates in, without the key, and the first collision
would mean one host had two placeholders across one engagement's
evidence. That breaks the only property this is for.

So, in order:

1. A value already in the mapping is redacted with the placeholder the
   mapping gives.
2. A value that is not can be minted **by scrubkit** -- `uv pip
   install -e '.[scrubkit]'`, plus the engagement key named in the
   engagement's `scrubkit.toml`. The assignment is recorded in the
   mapping and the file is rewritten.
3. Otherwise the finding is not redactable, which makes redaction
   incomplete, which sends the call to the local model.

Three is the common case on a new engagement and it is the right
answer. A gateway that cannot name a host safely should not be sending
a sentence about it.

## an encrypted mapping

scrubkit can encrypt the mapping at rest and that is the normal way to
write one. airlock refuses an encrypted mapping with a message that
says so, rather than asking for a passphrase: a long-running gateway
holding an engagement's mapping passphrase in memory for a week is a
worse trade than routing those calls locally.

## the placeholders are ugly on purpose

An earlier version of this -- before scrubkit existed and when airlock
was substituting its own strings -- used plausible-looking fake
hostnames, on the theory that the model would reason better about
something that looked real. It did, slightly. It also meant that when I
forgot the substitution was on, I read an answer about
`web-04.example.net` as if it were a real finding.

scrubkit's `CLIENT-HOST-11` cannot be read that way, which is the point
of it, and its address placeholders land in the benchmarking ranges for
the same reason.

## what is never redacted

Credentials. There is no useful placeholder for a secret: the model
cannot reason about a token it cannot see, and sending a redacted token
is pure risk with no return. A credential finding makes redaction
incomplete by definition, which under the default policy sends the
whole call to the local model. That is the right answer and it required
no new mechanism.
