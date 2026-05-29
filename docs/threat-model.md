# Threat model

Who this is defending against, what they control, and what it actually
does about it. Most of the honest answers are narrow.

## assets

1. Client material: hostnames, addresses, scan output, requests and
   responses, customer records that turned up in a response, the
   existence and identity of the engagement.
2. The redaction map, which is as sensitive as the material it came
   from because it reverses it.
3. The audit log, which is less sensitive by design but still names
   engagements and timings.

## what counts as a loss

Client material reaching a party not covered by the engagement letter.
A hosted provider is the case this was built for; a second client, a
subcontractor and a public paste are the same loss with different
plumbing.

Secondary: the audit log being wrong. A control that cannot describe
its own behaviour is not a control, and a log that says clean when it
is not is worse than no log.

## adversaries

### A1. Me, in a hurry

The primary one, and the reason this exists. Controls nothing except
what I type. Mitigated by being in the path by default, by failing
closed, and by `airlock doctor` making a bypass visible rather than
silent. Not mitigated at all for anything I paste outside the tooling.

### A2. A tool that is not using the gateway

No intent, same effect. A client with a compiled-in default, a stale
shell, a plugin with its own HTTP stack. Mitigated by one fixed port, by
setting the base URL in client config as well as the environment, by an
absence in the log being a signal, and properly by `egress-ledger`,
which watches connections rather than requests. This is the largest
residual risk in the model and I do not think the gateway can close it.

### A3. Content in the request that is shaped to evade the classifier

The interesting one. A hostname in base64, a zero-width space inside a
name, a gzipped payload, a tool-call argument the reader did not look
at. Partly mitigated: encoded payloads are decoded to a depth limit,
text is folded before matching, and the request reader raises on any
shape it does not understand rather than skipping it. Not fully
mitigated and cannot be -- a paraphrase has no identifiers in it at all.
The design response is that every one of these makes redaction
incomplete and therefore routes local.

Note that this adversary is usually not an adversary. It is a scanner
export, a copied web page, a terminal capture. The mitigations are the
same.

### A4. A hosted provider

Controls what happens to anything that reaches it, including retention
I cannot verify. Mitigated only by material not reaching it: that is
the whole product. Nothing here is a defence against a provider that
has already received the text.

### A5. Someone with the machine

Full read access to the material, the map and the log; able to rewrite
any of them. Not mitigated. The audit chain makes a silent edit
impossible, not an edit impossible, and that distinction is the only
claim being made. Disk encryption and a lock timeout are the controls
for this adversary and they are not in this repository.

### A6. Me, later, editing this

A tampered gateway is a control that reports clean while doing nothing,
which is strictly worse than having no gateway. Nobody has to tamper
with this one -- I change it. A refactor that quietly drops a detector,
a policy key renamed in the loader but not in the engagement policies
already on disk, a `serve` run out of a working tree with uncommitted
edits in it. Mitigated by the conformance suite running against the
policy actually in use rather than the example, by `--selftest`
refusing to serve when a fail-closed case passes, and by the policy
digest on every record so a decision can be re-read against the policy
that produced it. Not mitigated: I am the only person who reads the
diff, and the suite tests only the cases I thought of.

## assumptions

- The local backend is on loopback and is what it claims to be. The
  policy loader checks the URL is local; it does not check what is
  listening. A malicious process bound to 8080 would receive everything
  classified confidential.
- The policy file and roster are trusted input. They are the control.
- The clock is roughly right, since audit timestamps depend on it.
- `yaml.safe_load` is safe load. Nothing in this repository ever uses
  the unsafe loader.

## out of scope

Multi-user deployments, network-exposed listeners, authentication of
callers. The listener binds loopback and there is no authentication
because there is no second user and there is not going to be one. If I
ever put this on a network I have built something else, and this
document stops describing it.
