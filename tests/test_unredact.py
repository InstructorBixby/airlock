from airlock.unredact import Reverser

TABLE = {"CLIENT-HOST-01": "dc-01.hq.corp",
         "CLIENT-HOST-02": "sql03.hq.corp",
         "CLIENT-01": "Halberd Industrial"}


def stream(*chunks):
    r = Reverser(TABLE)
    out = "".join(r.feed(c) for c in chunks)
    return out + r.flush(), r.count


def test_whole_in_one_chunk():
    text, n = stream("CLIENT-HOST-01 is slow")
    assert text == "dc-01.hq.corp is slow"
    assert n == 1


def test_split_at_every_offset():
    raw = "the host CLIENT-HOST-01 looks fine"
    want = "the host dc-01.hq.corp looks fine"
    for cut in range(len(raw) + 1):
        text, n = stream(raw[:cut], raw[cut:])
        assert text == want, cut
        assert n == 1


def test_split_into_single_characters():
    raw = "CLIENT-HOST-02 then CLIENT-01"
    text, n = stream(*list(raw))
    assert text == "sql03.hq.corp then Halberd Industrial"
    assert n == 2


def test_prefix_that_never_completes_is_emitted():
    text, n = stream("CLIENT-HO", "ME is not in the map")
    assert text == "CLIENT-HOME is not in the map"
    assert n == 0


def test_longer_placeholder_wins_over_its_prefix():
    text, _ = stream("CLIENT-HOST-01")
    assert text == "dc-01.hq.corp"


def test_flush_is_required_for_the_tail():
    r = Reverser(TABLE)
    assert r.feed("ends with CLIENT") == "ends with "
    assert r.flush() == "CLIENT"


def test_empty_table_passes_through():
    r = Reverser({})
    assert r.feed("anything at all") == "anything at all"
