import pytest

from airlock import conformance, policy, selftest
from tests.test_policy import GOOD, write


def pol(tmp_path, body=None):
    return policy.load(write(tmp_path, body or GOOD))


def test_the_shipped_policy_passes(tmp_path):
    report = selftest.run(pol(tmp_path), log_path=tmp_path / "s.jsonl")
    assert report.failed == 0


def test_only_the_fail_closed_cases_run():
    subset = selftest.fail_closed_cases()
    assert subset
    assert all(c.expect == "refused" for c in subset)
    assert len(subset) < len(conformance.load_cases())


def test_a_case_that_should_refuse_but_does_not_stops_startup(tmp_path):
    # A case whose expectation cannot hold: a plainly public request
    # that the policy will allow.
    bad = conformance.Case(
        id="public-allowed", why="deliberately impossible",
        body={"model": "m", "messages": [
            {"role": "user", "content": "what is RFC 5280"}]},
        expect="refused", because="classified")
    with pytest.raises(selftest.SelfTestFailed):
        selftest.run(pol(tmp_path), cases=[bad],
                     log_path=tmp_path / "s.jsonl")


def test_the_exception_carries_the_report(tmp_path):
    bad = conformance.Case(id="x", why="w", body={}, expect="refused",
                           because="definitely not this")
    try:
        selftest.run(pol(tmp_path), cases=[bad],
                     log_path=tmp_path / "s.jsonl")
    except selftest.SelfTestFailed as exc:
        assert exc.report.failed == 1
    else:
        raise AssertionError("should have raised")


def test_nothing_leaves_during_a_selftest(tmp_path, monkeypatch):
    import airlock.backends as backends

    def explode(*a, **k):
        raise AssertionError("a socket was opened during selftest")

    monkeypatch.setattr(backends.requests, "post", explode)
    monkeypatch.setattr(backends.requests, "get", explode)
    selftest.run(pol(tmp_path), log_path=tmp_path / "s.jsonl")
