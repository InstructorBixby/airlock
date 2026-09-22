# Stability

1.0 is not a statement that this is finished. It is a statement about
what I will and will not change under myself without a warning, which
is the only thing a version number can usefully mean for something I
have wired into everything I do.

## what is covered

Three surfaces, and nothing else:

1. **The policy file format.** Version 1 keeps loading, with the
   compatibility rules in [the policy format
   document](policy-format.md). This is the important one: the policy
   file is the control, and there is one per engagement going back
   further than I would want to re-edit.
2. **The command line.** Subcommand names, flag names, exit codes and
   the meaning of the output. Exit codes specifically: 0 allow / clean,
   1 refuse / dirty / chain broken, 2 configuration error, 3 selftest
   failed.
3. **`airlock.api`.** The names in its `__all__` and their behaviour.
   Importing anything else from the package is not covered, and the
   internals do move.

## what is not covered

Everything else. The detector registry, the module layout, the server
internals, the on-disk layout of a scrub map beyond what scrubkit's
format guarantees, the exact wording of a refusal message, the audit
record's schema beyond the fields documented in
[guarantees](guarantees.md).

Detector *behaviour* is explicitly not covered, and this is deliberate.
A detector getting better means text that used to classify as public
now classifies as confidential, and that is a change I will notice
mid-engagement. It is also exactly the change this should be free to
make at any time. The direction is constrained instead: a patch
release never makes the classifier *quieter*. If a detector has to
stop matching something, that is a minor release with a changelog
entry saying what will now be allowed out that previously was not --
because that is the sentence I will want in front of me later, and I
will not remember it.

## what the numbers mean

- **patch** -- fixes, new detectors, new conformance cases, docs. May
  make the classifier stricter. Never looser.
- **minor** -- new features, new optional policy keys, a detector that
  stops matching something, a deprecation. Always with a shim and a
  changelog entry.
- **major** -- policy format version 2, a removed flag, a removed API
  name, or a change to one of the three guaranteed properties.

## deprecations

A renamed flag or policy key keeps working for at least two minor
releases, warns once per process with the new spelling and the release
in which it stops being accepted, and never silently does nothing. A
policy key that quietly stopped being read would be a control that
stopped working without saying so, which is the one failure mode this
whole project is organised against.

Current deprecations are in `airlock/deprecations.py`, which is a short
file on purpose.

## how long

I use this every working day, so it is maintained for as long as that
is true. If it stops being true, the thing to do is stop pointing
tools at it rather than leave a control running that nobody is reading
the log of. No long-term support branch, no backports: whatever is on
`main` is what is serving.
