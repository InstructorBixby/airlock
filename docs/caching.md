# Not breaking the cache on the way through

Prompt caching (announced 2024-08-14) charges less for a request whose
leading messages are byte-identical to a recent one. My longest system
blocks -- house style, methodology, a schema -- are exactly the kind of
prefix that benefits, and after a week of streaming work the hit rate
on the hosted path was nearly zero.

It was the gateway. The body was decoded to a dict and re-encoded
before forwarding, and `json.dumps` is not the inverse of whatever the
client used: key order survives, but escaping does not. A client that
sends a literal `é` gets `\u00e9` back out, separators differ by a
space, and the prefix is no longer the prefix.

## fix

When nothing was changed, forward the original bytes. Not a
reconstruction of them -- the actual bytes that arrived. The gateway
only needs to re-encode when it has edited the body, which is the
redacted path and the case where the model name has to be rewritten
for the chosen backend.

`preserve_model: true` on a backend says the client already asks for a
model this backend serves, so the gateway should leave the field alone
and forward verbatim. That is the configuration I use for the local
backend, where the tools name the model directly.

## and on the redacted path

Re-encoding is unavoidable there, so the cache depends on the
substitution being *stable*: the same host must become the same
placeholder on every call, or every call has a different prefix. That
was already true for a different reason -- a conversation spanning
several calls has to stay coherent -- and it turns out to be what makes
caching work on the redacted path at all. Two requirements, one
property.

The audit record carries `reserialised` so a run of cache misses has a
visible cause rather than being a mystery about somebody else's
infrastructure.
