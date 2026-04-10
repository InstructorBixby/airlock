from airlock import classify, redact, tiers


def test_hostname_with_a_zero_width_space_is_caught():
    a = classify.classify_text("talking to dc-01.hq\u200b.corp")
    assert a.tier == tiers.CONFIDENTIAL
    assert a.folded
    assert any(r.endswith("~fold") for r in a.reasons)


def test_fullwidth_address_is_caught():
    a = classify.classify_text("ping \uff11\uff10.40.1.9")
    assert a.tier == tiers.CONFIDENTIAL


def test_a_folded_only_finding_is_not_redactable():
    a = classify.classify_text("dc-01.hq\u200b.corp")
    assert all(not redact.is_redactable(f.kind) for f in a.findings)


def test_plain_text_findings_are_still_redactable():
    a = classify.classify_text("dc-01.hq.corp")
    assert all(redact.is_redactable(f.kind) for f in a.findings)
    assert not a.folded


def test_a_value_present_in_both_passes_is_not_duplicated():
    a = classify.classify_text("dc-01.hq.corp and \x1b[31mred\x1b[0m")
    kinds = [f.kind for f in a.findings]
    assert kinds == ["net.internal-hostname"]


def test_ansi_only_difference_still_folds():
    a = classify.classify_text("\x1b[32mall clear\x1b[0m")
    assert a.folded
    assert a.tier == tiers.PUBLIC


def test_corroboration_still_works_on_folded_kinds():
    from airlock.detect import roster
    eng = roster.Engagement.from_raw(
        {"id": "vantage", "weak_aliases": ["vantage"],
         "nets": ["10.9.0.0/16"]})
    extra = [("roster", roster.detector([eng]))]
    a = classify.classify_text("vantage\u200b at 10.9.1.1", extra=extra)
    assert a.tier == tiers.CONFIDENTIAL
