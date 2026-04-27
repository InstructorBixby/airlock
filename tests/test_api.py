import airlock.api as api


def test_everything_exported_exists():
    for name in api.__all__:
        assert hasattr(api, name), name


def test_tier_vocabulary_is_exported():
    assert api.CONFIDENTIAL == "client-confidential"


def test_classify_is_reachable_from_the_api_alone():
    assert api.classify_text("10.40.1.9").tier == api.CONFIDENTIAL


def test_the_surface_is_small():
    # If this number grows, that is a decision, not an accident.
    assert len(api.__all__) <= 20
