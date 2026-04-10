"""Run every detector over the request and produce one Assessment.

Detectors are independent and know nothing about each other. Two pieces
of cross-detector reasoning live here.

**Folding.** Every detector runs twice: once over the text as it
arrived, once over the folded form (see airlock.fold). A finding that
only appears in the folded pass gets a `~fold` suffix on its kind,
which makes it unredactable and therefore routes the call to the local
model. Findings present in both passes collapse, so the normal case
costs nothing but the second pass.

**Corroboration.** A weak finding is promoted when something else in
the same text points at the same engagement. See docs/aliases.md for
why that rule exists and what it costs.
"""
from __future__ import annotations

from airlock import detect, fold, request, tiers
from airlock.detect.roster import WEAK_KINDS
from airlock.model import Assessment, Finding


def _corroborate(a: Assessment) -> None:
    """Promote weak findings that something else backs up.

    Conclusive here means: another finding, for the same engagement,
    of a kind that is not itself weak. A second weak alias for the
    same client is not corroboration -- two ordinary words are still
    two ordinary words.
    """
    base = [f for f in a.findings if _base_kind(f.kind) not in WEAK_KINDS]
    strong_by_engagement = {f.engagement for f in base if f.engagement}
    global_strong = [f for f in base if not f.engagement]
    promoted = []
    for i, f in enumerate(a.findings):
        if _base_kind(f.kind) not in WEAK_KINDS:
            continue
        backer = None
        if f.engagement in strong_by_engagement:
            backer = next(g for g in base
                          if g.engagement == f.engagement)
        elif global_strong:
            backer = global_strong[0]
        if backer is not None:
            promoted.append((i, Finding(
                f.kind, f.value, tiers.CONFIDENTIAL,
                engagement=f.engagement, span=f.span)))
            a.corroborated.append(
                f"{f.reason} (corroborated by {backer.reason})")
    for i, f in promoted:
        a.findings[i] = f
    if promoted:
        a.tier = tiers.worst(a.tier, tiers.CONFIDENTIAL)


def _base_kind(kind: str) -> str:
    for sep in ("@", fold.MARKER):
        if sep in kind:
            return kind.split(sep, 1)[0]
    return kind


def _run(detectors, text: str, assessment: Assessment,
         *, suffix: str = "", seen=None):
    """Returns False if a detector failed, in which case stop."""
    for name, fn in detectors:
        try:
            for finding in fn(text):
                key = (finding.kind, finding.value)
                if seen is not None and key in seen:
                    continue
                if seen is not None:
                    seen.add(key)
                if suffix:
                    finding = Finding(
                        finding.kind + suffix, finding.value,
                        finding.tier, engagement=finding.engagement,
                        span=None)
                assessment.add(finding)
        except Exception as exc:                      # noqa: BLE001
            # A broken detector is a hole in the gate, so it becomes
            # an undecided verdict rather than a missing opinion.
            assessment.undecided(f"detector {name} failed: "
                                 f"{type(exc).__name__}")
            return False
    return True


def classify_text(text: str, *, extra=()) -> Assessment:
    out = Assessment()
    detectors = list(detect.all_detectors().items()) + list(extra)
    seen: set = set()
    if not _run(detectors, text, out, seen=seen):
        return out
    folded = fold.fold(text)
    if folded != text:
        out.folded = True
        if not _run(detectors, folded, out, suffix=fold.MARKER,
                    seen=seen):
            return out
    _corroborate(out)
    return out


def classify_request(body: dict, *, extra=()) -> Assessment:
    try:
        text = request.joined(body)
    except request.Unreadable as exc:
        out = Assessment()
        out.undecided(str(exc))
        return out
    return classify_text(text, extra=extra)


def is_sendable(assessment: Assessment) -> bool:
    """Only a confident public verdict is sendable without a route."""
    return (assessment.tier == tiers.PUBLIC
            and assessment.undecided_because is None)


__all__ = ["Assessment", "Finding", "classify_text",
           "classify_request", "is_sendable"]
