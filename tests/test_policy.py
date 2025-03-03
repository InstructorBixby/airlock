import pytest

from airlock import policy, tiers

GOOD = """\
version: 1
routes:
  public:
    - backend: hosted
  internal:
    - backend: hosted
      require: [redacted]
    - backend: local
  client-confidential:
    - backend: local
  undecided: []
backends:
  hosted:
    kind: openai
    base_url: https://api.example/v1
    models: {default: m}
  local:
    kind: openai
    base_url: http://127.0.0.1:8080/v1
    models: {default: n}
"""


def write(tmp_path, body=GOOD):
    p = tmp_path / "policy.yaml"
    p.write_text(body)
    return p


def test_loads(tmp_path):
    pol = policy.load(write(tmp_path))
    assert [r.backend for r in pol.candidates(tiers.INTERNAL)] == \
        ["hosted", "local"]


def test_local_backend_detected_by_url(tmp_path):
    pol = policy.load(write(tmp_path))
    assert pol.backend("local").is_local
    assert not pol.backend("hosted").is_local


def test_confidential_to_hosted_is_rejected(tmp_path):
    body = GOOD.replace("  client-confidential:\n    - backend: local",
                        "  client-confidential:\n    - backend: hosted")
    with pytest.raises(policy.PolicyError, match="does not permit"):
        policy.load(write(tmp_path, body))


def test_undecided_cannot_have_a_route(tmp_path):
    body = GOOD.replace("  undecided: []",
                        "  undecided:\n    - backend: local")
    with pytest.raises(policy.PolicyError, match="cannot have one"):
        policy.load(write(tmp_path, body))


def test_missing_tier_is_an_error(tmp_path):
    body = GOOD.replace("  public:\n    - backend: hosted\n", "")
    with pytest.raises(policy.PolicyError, match="silence is not"):
        policy.load(write(tmp_path, body))


def test_unknown_requirement(tmp_path):
    body = GOOD.replace("require: [redacted]", "require: [vibes]")
    with pytest.raises(policy.PolicyError, match="unknown requirement"):
        policy.load(write(tmp_path, body))


def test_route_to_undeclared_backend(tmp_path):
    body = GOOD.replace("    - backend: hosted\n      require",
                        "    - backend: ghost\n      require")
    with pytest.raises(policy.PolicyError, match="undeclared"):
        policy.load(write(tmp_path, body))


def test_version_must_be_one(tmp_path):
    with pytest.raises(policy.PolicyError, match="version"):
        policy.load(write(tmp_path, "version: 2\n"))
