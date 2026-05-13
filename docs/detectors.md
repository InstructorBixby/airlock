# Before I add a detector

Detectors are the part of this I will reach for first and should
reach for last. Three questions, in order.

## 1. is it a detector or a roster entry?

A shape that is recognisable without knowing the specific
organisation is a detector: a private address, a credential prefix, an
internal-looking suffix, a digit-suffixed shortname. A thing that is
only identifying because of who the client is belongs in that
engagement's roster, where it will also be removed when the engagement
ends.

Getting this wrong in the detector direction is how a detector ends up
carrying a client's name in a repository that outlives the
engagement.

## 2. where will it match something it should not?

Required, written down, before the detector goes in. Every detector
trades recall against routing more things to the local model, and the
second failure is the dangerous one: a gateway that sends everything
local is a gateway I will start working around, and the day I work
around it is the day it stops being a control. `docs/aliases.md` is
the long version of exactly this, and it cost me a week.

## 3. what tier does it imply, and can I say why in one line?

`internal` or `client-confidential`. If I cannot say which in one
line, the detector is really two detectors or it is a roster entry.

## when it misbehaves

The thing to capture is `airlock why <call id>`, not the request. The
reason codes are the useful part, they are stable, and they never
contain the material -- which is the only reason that output is safe
to paste into a note, a ticket, or a page like this one.

The second thing to capture is the relevant few lines of the policy
file that was loaded, and the policy digest off the record, because
half of what looks like a detector bug is a policy I edited and never
re-ran the conformance suite against.
