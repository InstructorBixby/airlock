# Streaming through the gate

Half the tools I use set `stream: true`, and until now the gateway
refused those because the response reader expected one JSON object. The
workaround was setting `stream: false` in each tool, which is exactly
the kind of per-tool change the whole design exists to avoid.

Three things make it more than a flag.

## 1. The request is still the request

Classification and routing happen before anything is sent, identically.
Nothing about streaming changes the outbound decision, which is worth
stating because it is the part that must not get a second code path.

## 2. Framing

`text/event-stream` is simple and everybody implements a slightly
different simple. Events are separated by a blank line, a line may be a
comment starting with `:`, `data:` may appear more than once in one
event and the payloads concatenate with a newline, and the terminator
is a `data: [DONE]` line that is not JSON and not part of the spec.
A chunk boundary can fall anywhere, including inside a UTF-8 sequence.

This is the same parser as `sse-intercept`, and it exists there for the
same reason: a framing bug in a proxy looks exactly like a model
producing truncated output, so it is the most expensive kind of bug to
diagnose from the far end.

## 3. Reversal across chunks

The hard part. On the redacted path the answer arrives as deltas, and
`CLIENT-HOST-01` will be split across two of them -- that is not an
edge case, token boundaries have no reason to respect it. Substituting
per-delta turns the answer into `CLIENT-HOS` followed by `T-01`, which
then does not match anything and reaches me as a placeholder I have to
resolve by hand.

So the reverser is stateful and holds back a tail: anything that could
still become a placeholder stays in the buffer until the next delta
proves it either way. Holdback is bounded by the longest placeholder in
the map, which is small, so the latency cost is one token at worst.

Flush at end of stream, or the last word of every answer goes missing.
That one cost me an afternoon.
