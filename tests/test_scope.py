import pytest

from airlock.detect import scope

SCOPE = """\
hosts:
  - app.example-client.invalid
nets:
  - 198.51.100.0/24
urls:
  - https://portal.example-client.invalid/login
"""


def write(tmp_path, body=SCOPE):
    p = tmp_path / "scope.yaml"
    p.write_text(body)
    return p


def test_host_in_scope_is_confidential(tmp_path):
    fn = scope.from_file(write(tmp_path), "example")
    found = list(fn("curl https://app.example-client.invalid/x"))
    assert [f.kind for f in found] == ["scope.host"]
    assert found[0].engagement == "example"


def test_hosts_are_taken_from_urls_too(tmp_path):
    fn = scope.from_file(write(tmp_path), "example")
    assert list(fn("portal.example-client.invalid timed out"))


def test_public_address_in_scope_still_counts(tmp_path):
    fn = scope.from_file(write(tmp_path), "example")
    # 198.51.100.0/24 is documentation space and not private, so the
    # net detector would never see it. In scope means client material.
    assert [f.kind for f in fn("198.51.100.9")] == ["scope.address"]


def test_out_of_scope_host_is_not_cleared_by_this(tmp_path):
    fn = scope.from_file(write(tmp_path), "example")
    # Says nothing either way, which is the point: other detectors
    # still get their say.
    assert list(fn("other.example-client.invalid")) == []


def test_empty_scope_is_an_error(tmp_path):
    with pytest.raises(scope.ScopeError):
        scope.from_file(write(tmp_path, "hosts: []\n"), "example")


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(scope.ScopeError):
        scope.from_file(tmp_path / "nope.yaml", "example")
