# Changelog

Keep a Changelog format, semver versions.

## [1.0.0]

### Added
- A stability policy (`docs/stability.md`). Three surfaces are
  covered: the policy file format, the command line including
  exit codes, and `airlock.api`. Everything else is internal.
  Detector behaviour is deliberately not covered, but its
  direction is: a patch release never makes the classifier
  quieter.
- Deprecation shims with a stated removal release, warning once
  per process and never silently ignoring a renamed key.
- A README that states the guarantee, the limits, and why none of
  the existing things did this.

### Changed
- `airlock --version` names the build, not just the release: the
  commit for a tag build, `(checkout)` for anything run out of a
  working tree.
- `--map` is now `--scrubmap`. The old spelling works until 2.0.
- A backend's default model is `default_model`; the old
  `models.default` works until 2.0, and setting both to different
  values is an error rather than a silent preference.

## [0.9.0]

### Added
- `airlock conformance`: a suite that runs against the policy I
  am actually running and proves it fails closed. Cases assert
  behaviour, never a tier, and a refusal case pins the expected
  reason so it cannot pass by failing for an unrelated cause. A
  control I have not tested is not a control.
- `airlock serve --selftest`, on by default: the fail-closed
  subset of those cases runs against the loaded policy before the
  listener opens, and the process exits 3 rather than serving if
  any of them do not hold.
- `airlock policy lint`, with a JSON schema for the policy format
  at `airlock/schema/policy-v1.json`. The invariants that make
  the control a control are enforced by the loader with or
  without the optional `schema` extra.
- `docs/guarantees.md` -- the whole claim, deliberately narrow --
  and `docs/threat-model.md`, `docs/policy-format.md`,
  `docs/conformance.md`, `docs/builds.md`, `docs/container.md`,
  which is the one that says containerising this silently changes
  what the policy means by local.
- `airlock.api` as the import surface my other scripts use, plus
  `py.typed`.
- Proper packaging: full metadata, extras, a searchable docs
  build, mypy and coverage in the pipeline, and a Monday schedule
  that says what has moved instead of opening branches at me.
- A tag pipeline gated on the suite and the conformance cases,
  producing the wheel and the image I install from and nothing
  else. The build carries the commit it was made from; anything
  run out of a working tree describes itself as a checkout
  instead of claiming one. `docs/builds.md`.

## [0.5.0]

### Added
- Every detector runs over a folded view of the text as well as
  the raw text: NFKC, invisible characters removed, bidi controls
  removed, ANSI escapes removed. A finding only visible in the
  folded form is marked `~fold` and is not redactable.
- `airlock doctor`, which lists what in the current environment
  would bypass the gateway, including the specific case of a
  shell older than the running gateway.
- `docs/reasons.md`, the full reason-code vocabulary, and
  `docs/folding.md` and `docs/coverage.md` for the two incidents
  behind this release.

### Fixed
- A hostname containing a zero-width space matched no detector
  and classified as public.
- ANSI colour codes in piped terminal output split tokens the
  detectors were matching on.
- Corroboration compared raw kinds, so a weak alias found only in
  the folded pass was never promoted.

## [0.4.0]

### Added
- The audit log is hash-chained. A deleted, reordered or edited
  line breaks the chain at a known point and `airlock verify`
  says where. This makes a silent edit impossible, not an edit
  impossible; the README is explicit about the difference.
- `airlock prove <engagement>` answers the question the log
  exists for, and reports `partial` rather than `clean` when the
  log contains calls it cannot speak to.
- `airlock spend`, with per-engagement totals read from the log
  rather than from a counter that resets on restart.
- Spend ceilings per engagement, checked before the call rather
  than discovered after it.
- `require: [available]` probes a backend before routing to it,
  so a hosted provider being down falls through to the local
  model instead of hanging until the request timeout. Probe
  results are cached briefly so a long pipeline does not probe
  once per call.
- The answer is classified too, and its tier is on the record and
  in an `x-airlock-tier` response header, for the pipeline case
  where one call's output becomes the next call's input.
- `preserve_model` and a per-backend `timeout`.

### Fixed
- The gateway decoded and re-encoded every request body, which
  changed its byte prefix and cost essentially every prompt cache
  hit on the hosted path. Unmodified bodies are now forwarded
  verbatim; `reserialised` on the record says when they were not.

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
