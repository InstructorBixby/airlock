# Folding before matching

A hostname copied out of a rendered web page had a zero-width space
inside it. Every detector missed it, the call classified public, and
the gateway did exactly what it was told.

Nothing adversarial happened. The page had a soft break in a long
hostname and the break survived the copy. But the same shape is the
trivial bypass for any string matcher, and `glyphstop` exists in my
toolchain precisely because this class of character keeps turning up in
places that matter, so there was no excuse for not handling it here.

## what folding does

- NFKC normalisation, which collapses the compatibility forms and the
  fullwidth Latin block.
- Removes the default-ignorable set that is invisible by design: zero
  width space, joiner, non-joiner, word joiner, soft hyphen, the bidi
  overrides and isolates, the variation selectors, the Unicode tag
  block.
- Removes ANSI escape sequences.
- Lowercases nothing. Matching already handles case where it should.

## why findings from folded text are not redactable

Folding changes offsets. A finding located in the folded text cannot be
mapped back to a span in the original with any confidence, and
substituting into the original by value would leave the invisible
characters behind -- producing a "redacted" request that still contains
the hostname with a joiner in the middle of it.

So a finding that appears *only* in the folded text is marked `~fold`
and is not redactable, which routes the call to the local model. That
is the conservative answer and it is also the useful one: text with
invisible characters in the middle of a hostname is text I want to look
at myself before sending anywhere.

## cost

Two passes over the request instead of one, and a handful of duplicate
findings where a string matches in both forms. Deduplication is by
(kind, value), so the duplicate collapses and only the suffixed kind
survives when the raw pass missed it.
