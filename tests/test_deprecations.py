import pytest

from airlock import deprecations


def setup_function():
    deprecations._warned.clear()


def test_old_flag_is_translated():
    assert deprecations.rewrite_argv(["serve", "--map", "m.json"]) == \
        ["serve", "--scrubmap", "m.json"]


def test_equals_form_is_translated():
    assert deprecations.rewrite_argv(["--map=m.json"]) == \
        ["--scrubmap=m.json"]


def test_new_flag_is_untouched():
    argv = ["serve", "--scrubmap", "m.json"]
    assert deprecations.rewrite_argv(argv) == argv


def test_warning_happens_once(capsys):
    deprecations.rewrite_argv(["--map", "a"])
    deprecations.rewrite_argv(["--map", "b"])
    assert capsys.readouterr().err.count("deprecated") == 1


def test_warning_names_the_removal_release(capsys):
    deprecations.rewrite_argv(["--map", "a"])
    assert "stops being accepted in 2.0" in capsys.readouterr().err


def test_legacy_default_model_key_is_migrated():
    out = deprecations.migrate_backend(
        "local", {"kind": "openai", "base_url": "http://127.0.0.1/v1",
                  "models": {"default": "n"}})
    assert out["default_model"] == "n"
    assert "models" not in out


def test_other_model_aliases_survive_the_migration():
    out = deprecations.migrate_backend(
        "local", {"models": {"default": "n", "small": "s"}})
    assert out["models"] == {"small": "s"}
    assert out["default_model"] == "n"


def test_both_spellings_disagreeing_is_an_error():
    with pytest.raises(ValueError, match="disagree"):
        deprecations.migrate_backend(
            "local", {"default_model": "a",
                      "models": {"default": "b"}})


def test_both_spellings_agreeing_is_fine():
    out = deprecations.migrate_backend(
        "local", {"default_model": "a", "models": {"default": "a"}})
    assert out["default_model"] == "a"
