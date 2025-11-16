from airlock import sse


def events(*chunks):
    p = sse.Parser()
    out = []
    for c in chunks:
        out += list(p.feed(c))
    tail = p.flush()
    if tail is not None:
        out.append(tail)
    return out


def test_single_event():
    assert [e.data for e in events(b'data: {"a":1}\n\n')] == \
        ['{"a":1}']


def test_split_anywhere():
    raw = b'data: {"a":1}\n\ndata: {"b":2}\n\n'
    for cut in range(1, len(raw)):
        got = events(raw[:cut], raw[cut:])
        assert [e.data for e in got] == ['{"a":1}', '{"b":2}'], cut


def test_split_inside_a_utf8_sequence():
    raw = 'data: {"t":"\u00e9t\u00e9"}\n\n'.encode()
    cut = raw.index(b"\xc3") + 1
    got = events(raw[:cut], raw[cut:])
    assert "été" in got[0].data


def test_multiple_data_lines_join_with_newline():
    got = events(b"data: one\ndata: two\n\n")
    assert got[0].data == "one\ntwo"


def test_comment_keepalive_is_preserved():
    got = events(b": ping\n\n")
    assert got[0].comments == (" ping",)


def test_crlf_framing():
    got = events(b'data: {"a":1}\r\n\r\n')
    assert got[0].data == '{"a":1}'


def test_done_is_recognised_and_not_json():
    got = events(b"data: [DONE]\n\n")
    assert got[0].is_done


def test_unterminated_last_event_is_flushed():
    got = events(b"data: tail")
    assert [e.data for e in got] == ["tail"]


def test_render_round_trips():
    ev = sse.Event(data="one\ntwo", event="delta", id="7")
    assert [e.data for e in events(ev.render())] == ["one\ntwo"]
