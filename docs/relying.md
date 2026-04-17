# On relying on this

It works, and so I have stopped checking. That is the point of it --
a gate I audit by hand every time is not a gate, it is a second habit,
and habits are the thing this replaces. But it means I now paste
without thinking, because I believe the decision has already been
made. That belief is the whole problem.

Everything else I have built is a research tool or a diagnostic. If
`promptfuzz` has a bug, a run of mine is wrong and I find out, because
the output stops making sense. If this has a bug, I sent client
material to a third party while believing I had a control that
prevented it -- and I would not know. Not "would find out late". Would
not know, at all, unless somebody on the other side noticed first. A
gateway that has quietly stopped classifying looks exactly like a
gateway that is working: same latency, same answers, same log lines
saying `public`.

So the bar for this one is not the bar I use for the rest of them.
Everything below is a thing that has to stay true for me to be allowed
to keep not checking.

## what has to stay true

**The guarantee written down precisely, and small.** Not "keeps client
data off hosted models" -- that is a sentence I would like to believe
and it is false. Something closer to: for requests that reach this
process, the classification and routing behaviour is exactly what the
policy says, it fails closed on every path, and it records what it
did. Everything outside that sentence goes in the limits document,
loudly, because the limits are what I will forget first.
`docs/guarantees.md`.

**A threat model, in the repository.** Who the adversary is, what they
control, and what this does and does not do about it. Most of the
honest answers are "nothing", and that is fine as long as it is
written down where I will read it again rather than remembered as
"handled". `docs/threat-model.md`.

**I have to be able to test my own policy.** The policy file is the
control. My code is only the thing that reads it. So: a conformance
suite I point at the policy I am actually running, that proves it
fails closed and that client-confidential material cannot reach a
non-local backend under it. Without that I am trusting defaults I
wrote a long time ago and have not re-read since, which is
indistinguishable from trusting nothing. A control I have not tested
is not a control.

**The policy format needs a version and a schema.** There is a policy
file per engagement, in each engagement directory, going back further
than I can remember the shape of. I am not rewriting all of them every
time the loader changes, and worse, I would not rewrite all of them --
I would rewrite the three I touched this month and the rest would load
under a reader that means something slightly different by the same
keys. An old policy silently becoming a different control is the worst
outcome available here.

**It has to prove itself before it serves anything.** A `--selftest`
that runs the fail-closed cases against the loaded policy and refuses
to start if any of them pass. Starting up and hoping is what the
logging proxy at the bottom of this repository's history did. This is
supposed to be a control, and a control that cannot demonstrate itself
on startup is a claim.

**The thing running has to be the thing I tested.** On my own machine
the risk is not a tampered build, it is me: `airlock serve` out of a
checkout with uncommitted edits in it, or a stale install in a venv I
forgot I had, or a policy file I edited at 1am and never re-ran the
conformance suite against. Hence the policy digest on every record,
`airlock verify` over the chain, and `airlock doctor` for the tool that
is not pointed at the gateway at all. A control that reports clean
while doing nothing is worse than no control, and nothing about that
needs nobody else to be involved.

## what it is not going to become

It runs here, on this machine, bound to loopback, for me. The moment it
runs anywhere else -- a box I do not own, a container on somebody's
orchestrator, a host that happens to have a GPU -- the word "local" in
the policy stops meaning what the policy invariant means by it, and the
question of who is processing the client material gets a different and
much worse answer. If I ever find myself wanting that, the thing to
change is the policy vocabulary, not the deployment.
