# Reason codes

Every finding has a stable id. They appear in the audit log, in
`airlock why`, and in the message of a 403, and they are the only
vocabulary in which a refusal is described -- the matched text is never
written down anywhere.

A kind may carry a suffix describing where it was found rather than
what was found:

| suffix        | meaning |
| ------------- | ------- |
| none          | in the text as it arrived |
| `@base64`     | inside a base64 payload. `@base64@base64` means two layers |
| `@base64url`  | inside a url-safe base64 payload |
| `@hex`        | inside a hex payload |
| `+gzip`       | the payload was compressed as well as encoded |
| `~fold`       | only visible after unicode normalisation, see docs/folding.md |

A suffixed kind is never redactable, so it routes the call local.

## net

| code | what it matches | tier |
| ---- | --------------- | ---- |
| `net.private-address` | an address in a private range, excluding loopback and link-local | confidential |
| `net.internal-hostname` | a name under `.local`, `.internal`, `.corp`, `.lan`, `.intranet`, `home.arpa` | confidential |
| `net.internal-shortname` | a digit-suffixed shortname: `dc-01`, `sql03`, `jump2` | internal |

## secrets

All confidential, and none of them redactable.

| code | what it matches |
| ---- | --------------- |
| `secrets.private-key` | a PEM private key header |
| `secrets.aws-access-key` | an `AKIA`/`ASIA` key id |
| `secrets.bearer` | an `authorization:` header with a bearer or basic value |
| `secrets.jwt` | three base64url segments separated by dots |
| `secrets.ntlm-hash` | an LM:NT pair |
| `secrets.connection-string` | a URI with inline credentials |

## roster

Carry an engagement id, so they read as `halberd:roster.client-name`.

| code | what it matches | tier |
| ---- | --------------- | ---- |
| `roster.client-name` | a strong alias | confidential |
| `roster.weak-name` | a weak alias, see docs/aliases.md | internal, confidential once corroborated |
| `roster.client-domain` | a domain listed for the engagement, on suffix | confidential |
| `roster.client-net` | an address inside a network listed for the engagement | confidential |

## engagement and scope

| code | what it matches | tier |
| ---- | --------------- | ---- |
| `engagement.term` | a term from the engagement's own `extra_terms` | confidential |
| `scope.host` | a host in the engagement's scope file | confidential |
| `scope.address` | an address in a scoped network, private or not | confidential |

## not a finding

`undecided` is not in this table because it is not something that was
found. It is the absence of a verdict: an unreadable content part, a
detector that raised, a body that is not an object. It has no route and
the call does not go out.
