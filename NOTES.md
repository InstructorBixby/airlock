# Design notes

## the actual requirement

Three kinds of text go into a model in a working week:

1. Things that are public. A vendor advisory, an RFC, a question about
   a protocol. No restriction at all.
2. Things that are mine and internal. Methodology, a draft of a report
   section with the client scrubbed out, my own notes. Fine to send if
   the identifying material is gone.
3. Things that belong to a client. Hostnames, addresses, the contents
   of a scan, a request and response pair, a customer record that
   turned up in a response, the engagement itself. These do not leave
   the machine.

Nobody can reliably sort text into those three buckets at the moment of
typing, including me, which is the whole reason for a gate. The gate
does not have to be clever. It has to be in the path, and it has to
default to the restrictive answer when it does not know.

## shape

Everything on this box that talks to a model honours `OPENAI_BASE_URL`
or a `--base-url` flag. So: be that URL. Speak enough of the API to be
indistinguishable upstream of a provider, and make the decision in the
middle.

    tool -> airlock -> classify -> route -> (local | redact + hosted)
                                      \-> audit

## tiers

Three, matching the three kinds above:

- `public` -- goes anywhere.
- `internal` -- hosted is allowed, but only after redaction.
- `client-confidential` -- local model only, no exceptions encoded
  anywhere in the config language.

## fail closed

If the classifier raises, times out, or returns a tier it does not have
a route for, the call does not go out. An error at the tool is an
annoyance. A silent pass-through is the one failure mode that makes the
whole thing a liability.

There are more ways to be fail-open than to be fail-closed, and they
are all shaped like an absent input. No roster file. An empty roster
file. A content part the request reader does not understand, skipped
instead of refused. A classifier exception caught too broadly. Each of
those produced a confident `public` on text that was nothing of the
kind, which is why the default branch of every one of them is now a
refusal and why the server will not start without a roster.

## what it is not

It is not a DLP product and it is not a guarantee. I am still a person
typing into a terminal; if I paste a hostname into a browser this does
nothing. The honest claim is narrower: every call made through the
tooling I actually use goes through one decision point, and that point
keeps a record.
