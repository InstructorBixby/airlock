# Weak aliases

One engagement's short name is an ordinary English word. It appeared in
the roster as an alias, which is correct -- it *is* how that client is
referred to -- and the consequence was that every call containing that
word anywhere classified as client-confidential and went to the local
model. Including "what does the vantage point of the attacker look
like here", which has nothing to do with anybody.

The failure is in the safe direction, which is why it took a few days
to notice rather than being an incident. It is still a failure: a gate
that refuses everything gets switched off, and a gate that is switched
off protects nothing.

## what it is not

Not a scoring system. I tried a confidence number first and threw it
away: every threshold was either too low to help or high enough to let
a real client name through, and there was no principled way to pick
one. A number also makes the log harder to read, because "0.62" does
not tell me what to fix.

## what it is

A second list. `aliases` are unambiguous -- a full client name, a
domain, a ticker, an internal project code with a prefix that occurs
nowhere else. `weak_aliases` are the ones that are also words.

A weak alias on its own produces an `internal` finding: the call is
still not sent as-is, it is redacted first. A weak alias *plus any
other finding for the same engagement* is corroborated and the whole
assessment becomes confidential.

That rule is explainable in one line in the log, which was the
requirement:

    halberd:roster.weak-name (corroborated by halberd:scope.host)

## the honest part

This is a deliberate reduction in recall. A sentence that mentions a
weak-aliased client and nothing else now gets redacted-and-sent rather
than kept local. The redaction still removes the name, so what leaves
is a sentence about `CLIENT-03`. I am content with that trade; it is
written down here so that it stays a decision rather than becoming an
assumption.
