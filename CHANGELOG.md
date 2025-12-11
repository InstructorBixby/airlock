# Changelog

Keep a Changelog format, semver versions.

## [0.3.0]

### Added
- Streaming passthrough. `stream: true` goes through the gate
  instead of being refused, which removes the last reason to set
  a per-tool workaround.
- SSE framing shared in shape with sse-intercept: incremental,
  byte-oriented, correct across a chunk boundary anywhere
  including mid-character.
- Stateful un-redaction for streamed answers: a placeholder split
  across two deltas is still restored, with a holdback bounded by
  the longest placeholder in the map.
- Weak aliases, for client names that are also ordinary words,
  promoted to confidential only when something else in the same
  text corroborates them. `docs/aliases.md`.
- The classifier decodes base64, base64url, hex and gzip payloads
  and runs the text detectors over the result, to a depth limit
  and a byte budget. Findings from inside a payload are not
  redactable, so they route local.

### Fixed
- An alias that is also an English word classified every call
  containing it as client-confidential, which sent unrelated
  questions to the local model.
- A hostname inside a base64 parameter was invisible to every
  detector and the call was classified public.

## [0.2.0]

### Added
- Reversible redaction in scrubkit's map v1 format: identifying
  strings become stable placeholders on the way out and are
  restored on the way back, so an answer arrives in the vocabulary
  of the engagement.
- `require: [redacted]` on a route is enforced rather than
  advisory: a partial redaction does not satisfy it.
- Credentials are deliberately not redactable, which routes any
  call containing one to the local model.
- Per-engagement profiles discovered from the engagement
  directory: scope file as a detector, engagement-specific terms,
  a cost ceiling, and `deny_hosted` for letters that forbid third
  party processing entirely.
- Every route considered, and why each was rejected, is on the
  audit record. `airlock why <call>` prints it; `airlock check
  --why` prints it before sending anything.
- The policy file's hash is recorded with every decision.

### Changed
- The gateway takes a list of detectors instead of a single
  roster, since which detectors apply depends on the engagement.

## [0.1.0]

### Added
- OpenAI-compatible endpoint, so existing tools reach the gateway
  by changing `OPENAI_BASE_URL` and nothing else.
- Three tiers (`public`, `internal`, `client-confidential`) plus
  `undecided`, which is the classifier's no-verdict answer and has
  no route.
- Detectors for private addresses, internal hostname shapes and
  credential formats; an engagement roster loaded from a file
  outside the repository.
- Declarative routing policy with a loader that refuses any
  configuration where client-confidential could reach a non-local
  backend.
- Append-only audit log: tier, reasons, route, model, token counts,
  cost, and a hash of the request body. No prompt text.
- `airlock check` to classify material without sending it.
- `docs/limits.md`, which is the part to read first.
