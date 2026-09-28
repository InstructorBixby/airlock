# airlock

A local, OpenAI-compatible endpoint that classifies every model call
before it leaves the machine, routes it according to a declarative
policy, redacts reversibly when that is what makes a call allowable,
and records what it decided.

It exists for one constraint. Under an engagement letter, client
material does not go to a hosted provider -- and no amount of being
careful is a control. One gate in the path is.

## install

    uv pip install -e .

## standing it up again

    # 1. a policy. start from the one in here and edit it.
    cp airlock/policy.yaml ~/eng/CLIENT/airlock.yaml

    # 2. check it fails closed BEFORE trusting it
    airlock policy lint --policy ~/eng/CLIENT/airlock.yaml
    airlock conformance --policy ~/eng/CLIENT/airlock.yaml

    # 3. run it
    airlock serve --policy ~/eng/CLIENT/airlock.yaml

    # 4. point everything at it
    export OPENAI_BASE_URL=http://127.0.0.1:8111/v1

Nothing needs modifying. Anything that honours `OPENAI_BASE_URL` is
now behind the gate. Step 2 is the one I skip and should not.

## a worked example

A finding is being written up. The notes contain a real hostname.

    $ cat notes.md
    The admin interface on dc-01.hq.corp accepted a blank password
    for the service account. Response headers suggest IIS 8.5.

    $ airlock check notes.md --why
    tier: client-confidential
      hosted (requires redacted, available): redaction incomplete
    -> local: requirements met
    decision: allow via local

Confidential, so a local model answers it and nothing leaves. Now the
same question with the hostname as an internal shortname instead:

    $ echo "why would web-01 return 401 on a HEAD but 200 on GET" \
        | airlock check - --why
    tier: internal
    -> hosted (requires redacted, available): requirements met
    decision: allow via hosted (requires redacted)

Internal, so it goes to the hosted model with the name replaced, and
the answer comes back in my vocabulary:

    $ curl -s localhost:8111/v1/chat/completions -d @q.json | jq -r .choices[0].message.content
    web-01 is probably running a WAF rule that only inspects GET...

What crossed the wire was `CLIENT-HOST-01`. The mapping is
[scrubkit](http://git.c01n31.net/c01n31pan1c/scrubkit)'s map format, kept
per engagement, and the reversal happens here -- including across
streaming chunk boundaries. Then:

    $ airlock prove halberd
    engagement: halberd
    calls: 214 (189 local, 25 hosted, 0 refused)
    of the hosted calls, 25 were sent redacted
    verdict: clean

That last command is the reason for all of it. It is the difference
between knowing and remembering.

## what it guarantees

Exactly this:

> For a request that reaches this process, airlock applies the loaded
> policy before any part of it is sent anywhere, refuses the request if
> the policy permits no route for its classification, and writes one
> audit record describing what it decided.

Three testable properties, and `airlock conformance` tests them
against the policy I am actually running rather than the example in
here. `airlock serve` runs the fail-closed subset at startup and
refuses to serve if any of them do not hold.

## what it does not do

Read [docs/limits.md](docs/limits.md) again before relying on this.
The short version:

- **It only covers calls that reach it.** A tool with a hardcoded URL,
  a browser tab, a phone -- none of that is affected. This is the
  biggest gap between what I feel when I paste something and what is
  actually true.
  [`egress-ledger`](http://git.c01n31.net/c01n31pan1c/egress-ledger) is the
  complement that answers "what did it connect to".
- **Classification is heuristic.** Recall is not 100%. It will miss a
  client's genuinely public hostname, a product name not in the
  roster, and any description with no identifiers in it at all.
- **A local model on a laptop is still data on a laptop.** Disk
  encryption is a different control and it is not in here.
- **The log proves decisions, not content.** It records that a call
  was classified and where it went. It does not record the request, on
  purpose.
- **The audit chain makes an edit visible, not impossible.** Anything
  on this disk can be rewritten by whoever holds the disk.
- **It makes no claim about any regulation.** It is a technical
  control that produces evidence. Whether that evidence satisfies the
  confidentiality clause in a given contract is not a question I get
  to answer by having written the control.

## why not one of the existing things

| | what it is | why it did not do this |
| --- | --- | --- |
| **A commercial DLP or AI-gateway product** | Network-wide coverage, managed rules, a dashboard, an audit trail somebody else operates | They terminate traffic on infrastructure I do not control. For work under an NDA that is the problem rather than the solution, and the audit trail I need to be able to show is one that lives on my own disk. |
| **litellm, or another routing proxy** | Far better at routing, retries, budgets and provider coverage | Routing is a feature there and the whole point here. Nothing in a general proxy decides *whether* a call may leave, fails closed when it cannot tell, or produces evidence afterwards. Pointing one at the other works and is what I do for the model fan-out. |
| **A provider's zero-retention tier** | A contractual promise, often a good one | A promise is not a control and it is not mine to show. I can have both; this is the part that produces the artefact. |
| **Being careful** | Free | Worked until the day it did not, and left no record of which day that was. That is the whole origin of this repository. |

## the notes

The docs build with `mkdocs serve` and that is where I read them,
because search beats grep across two dozen pages. The ones worth
re-reading before trusting this: [the
guarantee](docs/guarantees.md), [the threat
model](docs/threat-model.md), [the limits](docs/limits.md), and [on
relying on this](docs/relying.md). The write-ups of the failures that
shaped it: [weak aliases](docs/aliases.md),
[folding](docs/folding.md), [coverage](docs/coverage.md),
[caching](docs/caching.md).

## which build is serving

A gateway that reports clean while doing nothing is worse than no
gateway, and the realistic way that happens here is a stale install
answering on 8111. `airlock --version` names the commit a tag build
came from and says `(checkout)` when it cannot know.
[docs/builds.md](docs/builds.md).

## licence

MIT. [docs/failure-modes.md](docs/failure-modes.md) is the list of
bugs in here that would actually cost me something, which is the page
to read before merging my own work.
