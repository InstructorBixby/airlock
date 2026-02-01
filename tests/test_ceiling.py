import json

from airlock import audit, engagement, policy, server
from tests.test_policy import GOOD, write


class Fake:
    def __init__(self, cost_tokens=1_000_000):
        self.calls = 0
        self.cost_tokens = cost_tokens

    def call(self, be, path, body, timeout=180.0):
        self.calls += 1
        return {"choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": self.cost_tokens,
                          "completion_tokens": 0}}


PRICED = GOOD.replace(
    "            models: {default: m}",
    "            models: {default: m}\n"
    "            prices:\n"
    "              m: {prompt: 1.0, completion: 1.0}")

PROFILE = "id: halberd\nmax_cost_usd: 2.5\n"


def setup(tmp_path, monkeypatch, fake=None):
    fake = fake or Fake()
    monkeypatch.setattr(server.backends, "call", fake.call)
    monkeypatch.setattr(server.backends, "probe", lambda be, **k: True)
    root = tmp_path / "engagements" / "halberd"
    root.mkdir(parents=True)
    (root / "airlock.yaml").write_text(PROFILE)
    eng = engagement.load(root)
    gw = server.Gateway(policy.load(write(tmp_path, PRICED)),
                        audit.Log(tmp_path / "calls.jsonl"),
                        engagement=eng)
    return gw, fake


def chat(text="what is RFC 5280"):
    return json.dumps({"model": "m", "messages": [
        {"role": "user", "content": text}]}).encode()


def test_calls_run_until_the_ceiling(tmp_path, monkeypatch):
    gw, fake = setup(tmp_path, monkeypatch)
    for _ in range(3):
        gw.handle("/v1/chat/completions", chat())
    assert fake.calls == 3


def test_the_call_that_would_cross_it_is_refused(tmp_path, monkeypatch):
    gw, fake = setup(tmp_path, monkeypatch)
    codes = [gw.handle("/v1/chat/completions", chat())[0]
             for _ in range(5)]
    assert 402 in codes
    assert fake.calls < 5


def test_the_refusal_says_the_numbers(tmp_path, monkeypatch):
    gw, _ = setup(tmp_path, monkeypatch)
    msg = ""
    for _ in range(5):
        status, obj, _ = gw.handle("/v1/chat/completions", chat())
        if status == 402:
            msg = obj["error"]["message"]
            break
    assert "ceiling" in msg and "2.50" in msg


def test_a_local_only_call_is_unaffected(tmp_path, monkeypatch):
    gw, fake = setup(tmp_path, monkeypatch)
    for _ in range(8):
        gw.handle("/v1/chat/completions", chat("ping 10.40.1.9"))
    assert fake.calls == 8


def test_spend_survives_a_restart(tmp_path, monkeypatch):
    gw, _ = setup(tmp_path, monkeypatch)
    for _ in range(2):
        gw.handle("/v1/chat/completions", chat())
    again = server.Gateway(gw.policy,
                           audit.Log(tmp_path / "calls.jsonl"),
                           engagement=gw.engagement)
    assert again.spent() >= 2.0
