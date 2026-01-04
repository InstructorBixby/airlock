import json

from airlock import backends


class Backend:
    name = "hosted"
    base_url = "https://api.example/v1"

    def api_key(self):
        return ""


def capture(monkeypatch):
    seen = {}

    class Resp:
        status_code = 200

        def json(self):
            return {}

    def post(url, data=None, headers=None, timeout=None):
        seen["data"] = data
        return Resp()

    monkeypatch.setattr(backends.requests, "post", post)
    return seen


def test_raw_bytes_are_forwarded_verbatim(monkeypatch):
    seen = capture(monkeypatch)
    raw = '{"model":"m","messages":[{"role":"user","content":"caf\u00e9"}]}'
    backends.call(Backend(), "/chat/completions", raw.encode())
    assert seen["data"] == raw.encode()


def test_a_dict_is_encoded(monkeypatch):
    seen = capture(monkeypatch)
    backends.call(Backend(), "/chat/completions", {"model": "m"})
    assert json.loads(seen["data"]) == {"model": "m"}


def test_unicode_survives_the_verbatim_path(monkeypatch):
    seen = capture(monkeypatch)
    raw = '{"t":"caf\u00e9"}'.encode()
    backends.call(Backend(), "/chat/completions", raw)
    # The point of the whole exercise: byte-identical in, byte-identical
    # out, because a changed prefix is a cache miss.
    assert seen["data"] == raw
