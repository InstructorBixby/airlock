import json

from airlock import streaming
from airlock.unredact import Reverser


class FakeResponse:
    status_code = 200

    def __init__(self, chunks):
        self.chunks = chunks

    def iter_content(self, chunk_size=None):
        return iter(self.chunks)


def deltas(*texts):
    out = []
    for t in texts:
        out.append(("data: " + json.dumps({"choices": [
            {"index": 0, "delta": {"content": t}}]})
            + "\n\n").encode())
    out.append(b"data: [DONE]\n\n")
    return out


class Backend:
    name = "hosted"
    base_url = "https://api.example/v1"

    def api_key(self):
        return ""


def run(monkeypatch, chunks, reverser=None):
    monkeypatch.setattr(streaming.requests, "post",
                        lambda *a, **k: FakeResponse(chunks))
    out = b""
    info = {}
    for payload, info in streaming.relay(Backend(), "/chat/completions",
                                         {"stream": True},
                                         reverser=reverser):
        out += payload
    return out.decode(), info


def test_passthrough_preserves_the_frames(monkeypatch):
    text, _ = run(monkeypatch, deltas("hel", "lo"))
    assert text.count("data: ") == 3
    assert text.endswith("data: [DONE]\n\n")


def test_placeholder_split_across_deltas_is_restored(monkeypatch):
    r = Reverser({"CLIENT-HOST-01": "dc-01.hq.corp"})
    text, info = run(monkeypatch,
                     deltas("the host CLIENT-HO", "ST-01 is slow"), r)
    joined = "".join(
        json.loads(line[6:])["choices"][0]["delta"]["content"]
        for line in text.splitlines()
        if line.startswith("data: ") and "[DONE]" not in line)
    assert joined == "the host dc-01.hq.corp is slow"
    assert info["restored"] == 1


def test_usage_from_the_final_chunk_is_captured(monkeypatch):
    chunks = deltas("hi")[:-1] + [
        b'data: ' + json.dumps({"choices": [], "usage": {
            "prompt_tokens": 9, "completion_tokens": 2}}).encode()
        + b"\n\n", b"data: [DONE]\n\n"]
    _, info = run(monkeypatch, chunks)
    assert info["usage"]["prompt_tokens"] == 9


def test_keepalive_comments_survive(monkeypatch):
    chunks = [b": ping\n\n"] + deltas("x")
    text, _ = run(monkeypatch, chunks)
    assert ": ping" in text


def test_wants_stream():
    assert streaming.wants_stream({"stream": True})
    assert not streaming.wants_stream({})
