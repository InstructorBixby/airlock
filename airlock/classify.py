"""Run every detector over the request and produce one Assessment.

Detectors are independent and know nothing about each other. The one
piece of cross-detector reasoning lives here: corroboration, which
promotes a weak finding when something else in the same text points at
the same engagement. See docs/aliases.md for why that rule exists and
what it costs.
"""
from __future__ import annotations

from airlock import detect, request, tiers
from airlock.detect.roster import WEAK_KINDS
from airlock.model import Assessment, Finding


def _corroborate(a: Assessment) -> None:
    """Promote weak findings that something else backs up.

    Conclusive here means: another finding, for the same engagement,
    of a kind that is not itself weak. A second weak alias for the
    same client is not corroboration -- two ordinary words are still
    two ordinary words.
    """
    strong_by_engagement = {
        f.engagement for f in a.findings
        if f.kind not in WEAK_KINDS and f.engagement
    }
    global_strong = any(f.kind not in WEAK_KINDS and not f.engagement
                        for f in a.findings)
    promoted = []
    for i, f in enumerate(a.findings):
        if f.kind not in WEAK_KINDS:
            continue
        backer = None
        if f.engagement in strong_by_engagement:
            backer = next(
                g for g in a.findings
                if g.engagement == f.engagement
                and g.kind not in WEAK_KINDS)
        elif global_strong:
            backer = next(g for g in a.findings
                          if g.kind not in WEAK_KINDS
                          and not g.engagement)
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


def classify_text(text: str, *, extra=()) -> Assessment:
    out = Assessment()
    for name, fn in list(detect.all_detectors().items()) + list(extra):
        try:
            for finding in fn(text):
                out.add(finding)
        except Exception as exc:                      # noqa: BLE001
            # A broken detector is a hole in the gate, so it becomes
            # an undecided verdict rather than a missing opinion.
            out.undecided(f"detector {name} failed: "
                          f"{type(exc).__name__}")
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
