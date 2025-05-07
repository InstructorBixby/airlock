# What airlock does not protect against

A gate that is oversold is worse than no gate, because the overselling
is what makes you stop paying attention. So, explicitly:

## 1. It only covers calls that go through it

Anything that talks to a provider over a hardcoded URL, a browser tab,
a phone, a desktop app with its own networking -- none of that touches
this. The coverage claim is "every call made by the tooling that
honours `OPENAI_BASE_URL`", which is most of what I use and not all of
what exists on this machine. `egress-ledger` is the complement: it
records what a process tree actually connected to, which is how you
find the tool that bypassed the gateway rather than assuming there
isn't one.

## 2. Classification is heuristic and recall is not 100%

It finds private addresses, internal hostname shapes, credentials in
known formats, and strings from a roster I maintain by hand. It will
miss: a client's public hostname that is genuinely public, a product
name I did not list, a description of an architecture with no
identifiers in it at all, a screenshot, a paraphrase. Nothing in the
design even tries to catch the last two.

The roster is the part with the worst recall, because it depends on me
remembering to add an alias. Every miss I have found so far has been a
roster miss, not a detector miss.

## 3. A local model on a laptop is still data on a laptop

Routing client material to a model on this machine keeps it off a
provider. It does nothing about the machine. Full-disk encryption, a
short lock timeout and not losing the thing are still the controls that
matter, and they are not in this repository.

## 4. The log is evidence of decisions, not of content

It records the tier, the reasons, the route and a hash of the request.
It does not record the request. That is deliberate -- a log full of
client prompts is the exact disclosure this exists to prevent -- but it
means the log cannot prove *what* was sent, only that it was classified
and where it went. If you need the content, you need the content
somewhere else, with the handling that implies.

## 5. Redaction is reversible, which is the point and also the risk

The mapping that turns `CLIENT-HOST-07` back into the real name has to
live somewhere. That somewhere is scrubkit's mapping file, which is
as sensitive as all the evidence it reverses and accumulates for the
length of an engagement. scrubkit can encrypt it; airlock refuses an
encrypted one rather than holding the passphrase, which means the
convenient configuration is the unencrypted one. That is a real
tension and it is not resolved.

## 6. I am still a person typing

No tool in this repository prevents me pasting a hostname into a web
form. The honest scope is the automated path, and the automated path is
where I make the mistakes I cannot see.
