import json

from airlock import audit, policy, server
from tests.test_policy import GOOD, write


class FakeBackend:
    def __init__(self):
        self.seen = []

    def call(self, be, path, body, timeout=180.0):
        self.seen.append((be.name, body))
        return {"choices": [{"message": {"role": "assistant",
                                         "content": "ok"}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 2}}


def gateway(tmp_path, monkeypatch, fake=None):
    fake = fake or FakeBackend()
    monkeypatch.setattr(server.backends, "call", fake.call)
    monkeypatch.setattr(server.backends, "probe", lambda be, **k: True)
    pol = policy.load(write(tmp_path, GOOD))
    log = audit.Log(tmp_path / "calls.jsonl")
    return server.Gateway(pol, log), fake, log


def chat(text):
    return json.dumps({"model": "gpt-4o-mini", "messages": [
        {"role": "user", "content": text}]}).encode()


def test_public_call_goes_to_hosted(tmp_path, monkeypatch):
    gw, fake, log = gateway(tmp_path, monkeypatch)
    status, _ = gw.handle("/v1/chat/completions",
                          chat("what is RFC 5280"))
    assert status == 200
    assert fake.seen[0][0] == "hosted"


def test_confidential_call_goes_local(tmp_path, monkeypatch):
    gw, fake, log = gateway(tmp_path, monkeypatch)
    status, _ = gw.handle("/v1/chat/completions",
                          chat("why is 10.40.1.9 refusing"))
    assert status == 200
    assert fake.seen[0][0] == "local"


def test_model_is_rewritten_for_the_chosen_backend(tmp_path, monkeypatch):
    gw, fake, _ = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions", chat("10.40.1.9"))
    assert fake.seen[0][1]["model"] == "n"


def test_unreadable_request_is_refused_not_forwarded(tmp_path,
                                                     monkeypatch):
    gw, fake, _ = gateway(tmp_path, monkeypatch)
    body = json.dumps({"messages": [{"role": "user", "content": [
        {"type": "image_url"}]}]}).encode()
    status, obj = gw.handle("/v1/chat/completions", body)
    assert status == 403
    assert fake.seen == []
    assert "image_url" in obj["error"]["message"]


def test_garbage_body_is_refused(tmp_path, monkeypatch):
    gw, fake, _ = gateway(tmp_path, monkeypatch)
    status, _ = gw.handle("/v1/chat/completions", b"not json")
    assert status == 400
    assert fake.seen == []


def test_every_call_leaves_exactly_one_audit_record(tmp_path,
                                                    monkeypatch):
    gw, _, log = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions", chat("hello"))
    gw.handle("/v1/chat/completions", b"junk")
    gw.handle("/v1/chat/completions", chat("10.40.1.9"))
    assert len(list(log.records())) == 3


def test_audit_record_has_no_prompt_text(tmp_path, monkeypatch):
    gw, _, log = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions", chat("host dc-01 at 10.40.1.9"))
    blob = (tmp_path / "calls.jsonl").read_text()
    assert "dc-01" not in blob
    assert "10.40" not in blob
