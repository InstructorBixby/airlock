import json

from airlock import audit, policy, server
from tests.test_policy import GOOD, write


class Fake:
    def call(self, be, path, body, timeout=180.0):
        return {"usage": {"prompt_tokens": 1, "completion_tokens": 1}}


def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(server.backends, "call", Fake().call)
    monkeypatch.setattr(server.backends, "probe", lambda be, **k: True)
    log = audit.Log(tmp_path / "calls.jsonl")
    return server.Gateway(policy.load(write(tmp_path, GOOD)), log), log


def chat(text):
    return json.dumps({"model": "m", "messages": [
        {"role": "user", "content": text}]}).encode()


def test_considered_routes_are_recorded(tmp_path, monkeypatch):
    g, log = gw(tmp_path, monkeypatch)
    g.handle("/v1/chat/completions", chat("web-01 is slow"))
    rec = list(log.records())[0]
    assert any("requires redacted" in line
               for line in rec["considered"])


def test_explain_reads_back_from_the_log(tmp_path, monkeypatch):
    g, log = gw(tmp_path, monkeypatch)
    _, out = g.handle("/v1/chat/completions", chat("10.40.1.9"))
    rec = list(log.records())[0]
    text = audit.from_json(rec).explain()
    assert "tier: client-confidential" in text
    assert "decision: allow via local" in text


def test_find_by_id_prefix(tmp_path, monkeypatch):
    g, log = gw(tmp_path, monkeypatch)
    g.handle("/v1/chat/completions", chat("hello"))
    rec = list(log.records())[0]
    assert log.find(rec["id"][:4]).id == rec["id"]


def test_refusal_explains_too(tmp_path, monkeypatch):
    g, log = gw(tmp_path, monkeypatch)
    g.handle("/v1/chat/completions", b"{}")
    text = audit.from_json(list(log.records())[0]).explain()
    assert "decision: refuse" in text


def test_policy_digest_is_on_the_record(tmp_path, monkeypatch):
    g, log = gw(tmp_path, monkeypatch)
    g.handle("/v1/chat/completions", chat("hello"))
    assert list(log.records())[0]["policy_sha256"].startswith("sha256:")
