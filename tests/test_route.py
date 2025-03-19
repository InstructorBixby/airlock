from airlock import policy, route, tiers
from airlock.model import Assessment, Finding


def pol(tmp_path, body=None):
    from tests.test_policy import GOOD, write
    return policy.load(write(tmp_path, body or GOOD))


def conf():
    a = Assessment()
    a.add(Finding("net.private-address", "10.40.1.1",
                  tiers.CONFIDENTIAL))
    return a


def internal():
    a = Assessment()
    a.add(Finding("net.internal-shortname", "web-01", tiers.INTERNAL))
    return a


def test_public_goes_hosted(tmp_path):
    d = route.decide(pol(tmp_path), Assessment(), check_available=False)
    assert d.allowed and d.backend == "hosted"


def test_confidential_goes_local(tmp_path):
    d = route.decide(pol(tmp_path), conf(), check_available=False)
    assert d.allowed and d.backend == "local"


def test_internal_falls_through_to_local_without_redaction(tmp_path):
    d = route.decide(pol(tmp_path), internal(), check_available=False)
    assert d.backend == "local"
    assert "redaction incomplete" in d.considered[0].why


def test_internal_goes_hosted_once_redacted(tmp_path):
    d = route.decide(pol(tmp_path), internal(),
                     redaction_complete=True, check_available=False)
    assert d.backend == "hosted"


def test_undecided_is_refused(tmp_path):
    a = Assessment()
    a.undecided("content part type 'image_url'")
    d = route.decide(pol(tmp_path), a, check_available=False)
    assert not d.allowed
    assert "image_url" in d.refusal


def test_explain_lists_rejected_routes(tmp_path):
    text = route.decide(pol(tmp_path), internal(),
                        check_available=False).explain()
    assert "hosted (requires redacted)" in text
    assert "decision: allow via local" in text


def test_explain_works_for_a_refusal(tmp_path):
    a = Assessment()
    a.undecided("no readable text found")
    text = route.decide(pol(tmp_path), a, check_available=False).explain()
    assert "decision: refuse" in text
