from airlock import policylint
from tests.test_policy import GOOD, write


def test_a_good_policy_lints_clean(tmp_path):
    errors, _ = policylint.lint(write(tmp_path, GOOD))
    assert errors == []


def test_the_invariants_are_reported_as_errors(tmp_path):
    body = GOOD.replace("  client-confidential:\n    - backend: local",
                        "  client-confidential:\n    - backend: hosted")
    errors, _ = policylint.lint(write(tmp_path, body))
    assert any("does not permit" in e for e in errors)


def test_a_policy_with_no_local_backend_is_an_error(tmp_path):
    body = GOOD.replace("http://127.0.0.1:8080/v1",
                        "https://other.example/v1")
    errors, _ = policylint.lint(write(tmp_path, body))
    assert any("nowhere to go" in e for e in errors)


def test_notes_mention_the_local_backends(tmp_path):
    _, notes = policylint.lint(write(tmp_path, GOOD))
    assert any("1 local" in n for n in notes)


def test_schema_is_valid_json():
    assert policylint.schema()["properties"]["version"]["const"] == 1


def test_schema_check_is_skipped_cleanly_when_unavailable(tmp_path,
                                                          monkeypatch):
    monkeypatch.setattr(policylint, "schema_available", lambda: False)
    errors, notes = policylint.lint(write(tmp_path, GOOD))
    assert errors == []
    assert any("jsonschema is not installed" in n for n in notes)
