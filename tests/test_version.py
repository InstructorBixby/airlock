from airlock import __version__
from airlock.version import describe


def test_a_working_tree_admits_it_is_one():
    # _build.py is written by the tag pipeline and by nothing else.
    assert describe() == f"{__version__} (checkout)"


def test_the_description_always_starts_with_the_version():
    assert describe().startswith(__version__)
