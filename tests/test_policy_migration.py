import pytest

from airlock import deprecations, policy
from tests.test_policy import GOOD, write


def setup_function():
    deprecations._warned.clear()


def test_the_shipped_policy_uses_the_new_key():
    text = (policy.Path(policy.__file__).parent
            / "policy.yaml").read_text()
    assert "default_model:" in text
    assert "models.default" not in text


def test_a_legacy_policy_still_loads(tmp_path, capsys):
    pol = policy.load(write(tmp_path, GOOD))
    assert pol.backend("local").model_for(None) == "n"
    assert "deprecated" in capsys.readouterr().err


def test_the_new_key_loads_quietly(tmp_path, capsys):
    body = GOOD.replace("models: {default: m}", "default_model: m") \
               .replace("models: {default: n}", "default_model: n")
    pol = policy.load(write(tmp_path, body))
    assert pol.backend("hosted").model_for(None) == "m"
    assert "deprecated" not in capsys.readouterr().err


def test_both_keys_disagreeing_is_a_policy_error(tmp_path):
    body = GOOD.replace("models: {default: m}",
                        "default_model: a\n            "
                        "models: {default: b}")
    with pytest.raises(policy.PolicyError, match="disagree"):
        policy.load(write(tmp_path, body))


def test_a_model_alias_still_works(tmp_path):
    body = GOOD.replace("models: {default: m}",
                        "default_model: m\n            "
                        "models: {small: m-small}")
    pol = policy.load(write(tmp_path, body))
    assert pol.backend("hosted").model_for("small") == "m-small"


def test_the_digest_is_of_the_file_not_the_migration(tmp_path):
    p = write(tmp_path, GOOD)
    import hashlib
    want = "sha256:" + hashlib.sha256(
        p.read_text().encode()).hexdigest()
    assert policy.load(p).digest == want
