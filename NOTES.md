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

## what it is not

It is not a DLP product and it is not a guarantee. I am still a person
typing into a terminal; if I paste a hostname into a browser this does
nothing. The honest claim is narrower: every call made through the
tooling I actually use goes through one decision point, and that point
keeps a record.
