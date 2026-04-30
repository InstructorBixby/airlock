# The bugs that would cost me something

A list to read before I merge my own work, because this is a control
and the dangerous bugs in a control are the ones that make it quieter
rather than louder. A crash is fine. A crash is the best outcome
available. These are the ones that are not.

## the five that matter

- **Any path that sends a request to a non-local backend when the
  policy says it should not.** Everything else on this page is a
  category. This one is the event.
- **Any way to make the gateway fail open** -- a request shape, a
  config shape, a race, an exception path -- where the call goes out
  instead of being refused. Every `except` in the decision path is a
  candidate and they get read individually.
- **A classifier bypass that is cheap and general.** An encoding, a
  normalisation, a request field the reader does not look at. Not
  "this specific hostname does not match a regex": the detectors are
  heuristic and `docs/limits.md` says so. The ones that matter are the
  ones that work on every engagement at once.
- **Client material in the audit log**, in a refusal message, or in
  anything I might paste into a report. The log is the artefact I
  would hand over to show the control worked; it cannot itself be a
  disclosure.
- **Anything that makes the audit chain claim intact when it is not.**
  The chain is the difference between evidence and a story I tell
  afterwards.

Plus one that is not a leak but is worse than it sounds: **a redaction
map that reverses to the wrong original.** That does not expose
anything, it corrupts evidence, and I would not find out until a
finding said the wrong hostname in a report that had already gone out.

## what I keep mistaking for one of the above

- **A missed detection that needs knowledge of a specific
  engagement.** The roster is maintained by hand and its recall is a
  documented limit, not a bug. Add the roster entry.
- **Anything that needs code execution as me.** At that point the
  material is already readable on this disk and the gateway is not the
  layer that was supposed to stop it.
- **Denial of service against a loopback listener that one person
  uses.** If it will not start, I will notice within one command.
- **"A local model is not a guarantee of confidentiality."** Correct,
  and `docs/limits.md` section 3 already says so. Local means the text
  did not leave the machine. It does not mean the machine is safe.

## the habit

Before I trust it again after touching it: `airlock conformance`
against the engagement policy I am actually running, not the example
in here, and `airlock serve --selftest`, which is the default and
stays the default. `docs/threat-model.md` and `docs/guarantees.md` are
the two pages that say what I am entitled to believe.
