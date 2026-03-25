# The shell that was already open

A play came back with a cost on it, which it should not have: the
pipeline was client material and should have run entirely on the local
model. The audit log had no record of the call at all, which is the
part that mattered -- a refusal would have been fine, an absence meant
the call had not come through the gateway.

The tmux pane had been open since before I restarted the gateway with a
new port. `OPENAI_BASE_URL` in that pane still pointed at the old one,
the old one was not listening, and the client fell back to its
compiled-in default. Which is sensible behaviour for the client and a
hole in the control.

Three things came out of it.

**`airlock doctor`**, which looks at the environment it is handed and
says what would bypass the gateway. Run it in the pane you are about to
work in, not in a fresh one, or it tells you about a shell you are not
using.

**A fixed port.** The gateway listens on 8111 and nowhere else now.
Moving it was never worth the cost of every open shell being wrong.

**No silent fallback in the client.** Where a client supports it, the
base URL is set in its config file as well as the environment, so a
stale variable produces an error instead of a successful call to
somewhere else. Where it does not support it, that tool is on the list
in `docs/limits.md` of things this does not cover.

The general version of the lesson: a gateway can only report on calls
that reach it, so an absence in the log is a signal and not a silence.
`egress-ledger` is what turns that from a thing I have to remember into
a thing that gets recorded, because it watches connections rather than
requests.
