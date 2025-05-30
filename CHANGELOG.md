# Changelog

Keep a Changelog format, semver versions.

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
