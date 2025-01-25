import classify


def test_private_address_is_confidential():
    assert classify.tier("try 10.40.3.7 next") == classify.CONFIDENTIAL


def test_public_address_is_not():
    assert classify.tier("8.8.8.8 answers") == classify.PUBLIC


def test_loopback_is_not_interesting():
    assert classify.tier("bound on 127.0.0.1:8111") == classify.PUBLIC


def test_internal_suffix():
    t = classify.tier("mail01.hq.corp was unauthenticated")
    assert t == classify.CONFIDENTIAL


def test_shortname_is_internal_not_confidential():
    assert classify.tier("dc-02 refused the bind") == classify.INTERNAL


def test_findings_are_kind_and_value():
    kinds = {k for k, _ in classify.findings("10.40.3.7 and sql03")}
    assert kinds == {"private-address", "internal-shortname"}


def test_prose_about_versions_is_not_an_address():
    assert classify.tier("upgraded to 1.2.3.4-rc1") == classify.PUBLIC
