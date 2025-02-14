from airlock import classify, tiers


def test_private_address_is_confidential():
    a = classify.classify_text("try 10.40.3.7 next")
    assert a.tier == tiers.CONFIDENTIAL
    assert a.reasons == ["net.private-address"]


def test_public_text_is_sendable():
    a = classify.classify_text("what does RFC 5280 say about CRLs")
    assert classify.is_sendable(a)


def test_shortname_is_internal():
    a = classify.classify_text("dc-02 refused the bind")
    assert a.tier == tiers.INTERNAL
    assert not classify.is_sendable(a)


def test_private_key_block():
    a = classify.classify_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert "secrets.private-key" in a.reasons


def test_worst_tier_wins():
    a = classify.classify_text("web-01 at 10.40.3.7")
    assert a.tier == tiers.CONFIDENTIAL


def test_unreadable_request_is_undecided():
    a = classify.classify_request({"messages": "not a list"})
    assert a.tier == tiers.UNDECIDED
    assert not classify.is_sendable(a)


def test_broken_detector_makes_it_undecided():
    def boom(_text):
        raise RuntimeError("nope")
    a = classify.classify_text("hello", extra=[("boom", boom)])
    assert a.tier == tiers.UNDECIDED


def test_reasons_do_not_contain_matched_values():
    a = classify.classify_text("10.40.3.7")
    assert all("10.40" not in r for r in a.reasons)
