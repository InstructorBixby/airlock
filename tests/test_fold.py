from airlock import fold


def test_zero_width_space_inside_a_hostname():
    assert fold.fold("dc-01.hq\u200b.corp") == "dc-01.hq.corp"


def test_soft_hyphen():
    assert fold.fold("sql\u00ad03") == "sql03"


def test_fullwidth_digits_collapse():
    assert fold.fold("\uff11\uff10.\uff14\uff10.1.9") == "10.40.1.9"


def test_bidi_override_is_removed():
    assert fold.fold("\u202eabc\u202c") == "abc"


def test_tag_characters_are_removed():
    assert fold.fold("host\U000e0061\U000e0062") == "host"


def test_variation_selectors_are_removed():
    assert fold.fold("a\ufe0fb") == "ab"


def test_ansi_colour_is_removed():
    assert fold.fold("\x1b[31m10.40.1.9\x1b[0m") == "10.40.1.9"


def test_osc_sequence_is_removed():
    assert fold.fold("\x1b]0;title\x07text") == "text"


def test_case_is_untouched():
    assert fold.fold("DC-01.HQ.corp") == "DC-01.HQ.corp"


def test_differs_is_false_for_plain_text():
    assert not fold.differs("ordinary ascii text")
