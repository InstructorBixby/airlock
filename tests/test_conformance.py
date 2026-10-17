import pytest

from airlock import conformance, policy
from tests.test_policy import GOOD, write


def pol(tmp_path, body=None):
    return policy.load(write(tmp_path, body or GOOD))


def test_the_shipped_cases_pass_against_the_shipped_policy(tmp_path):
    report = conformance.run(pol(tmp_path),
                             log_path=tmp_path / "c.jsonl")
    assert report.failed == 0, report.text()
    assert report.skipped == 0


def test_every_case_declares_why_it_exists():
    for case in conformance.load_cases():
        assert case.why, case.id


def test_refusal_cases_pin_the_reason():
    for case in conformance.load_cases():
        if case.expect == "refused":
            assert case.because, case.id


def test_a_fail_open_policy_is_caught(tmp_path):
    body = GOOD.replace("    - backend: hosted\n      require: [redacted]",
                        "    - backend: hosted")
    report = conformance.run(pol(tmp_path, body),
                             log_path=tmp_path / "c.jsonl")
    assert report.failed > 0


def test_a_case_cannot_pass_for_the_wrong_reason(tmp_path):
    case = conformance.Case(id="x", why="w", body={},
                            expect="refused",
                            because="something else entirely")
    report = conformance.run(pol(tmp_path), [case],
                             log_path=tmp_path / "c.jsonl")
    assert report.failed == 1
    assert "wrong reason" in report.outcomes[0].detail


def test_local_cases_are_vacuous_without_a_hosted_backend(tmp_path):
    # Local-only policy: every "must stay local" case is trivially
    # satisfied and proves nothing, so it must not read as a pass.
    body = GOOD.replace("https://api.example/v1",
                        "http://127.0.0.1:9000/v1")
    report = conformance.run(pol(tmp_path, body),
                             log_path=tmp_path / "c.jsonl")
    assert report.skipped > 0
    assert report.failed == 0
    assert "not a passing case" in report.text()


def test_report_says_not_to_serve_on_failure(tmp_path):
    case = conformance.Case(id="x", why="w", body={}, expect="local")
    report = conformance.run(pol(tmp_path), [case],
                             log_path=tmp_path / "c.jsonl")
    assert "do not serve" in report.text()


def test_an_empty_cases_file_is_an_error(tmp_path):
    p = tmp_path / "cases.yaml"
    p.write_text("cases: []\n")
    with pytest.raises(ValueError):
        conformance.load_cases(p)
