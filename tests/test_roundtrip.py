import json

from airlock import audit, policy, scrubmap, server
from tests.test_policy import GOOD, write

ASSIGNED = {
    "version": 1,
    "engagement": "halberd",
    "entries": {
        "host": {"web-01": "CLIENT-HOST-23"},
        "ip4": {"10.40.1.9": "CLIENT-IP-04"},
    },
}


class Echo:
    """A backend that answers using whatever placeholder it was given."""

    def __init__(self):
        self.seen = []

    def call(self, be, path, body, timeout=180.0):
        self.seen.append((be.name, json.dumps(body, default=str)))
        text = json.dumps(body, default=str)
        host = [w.strip('"\\, ') for w in text.split()
                if "CLIENT-HOST" in w]
        reply = (f"{host[0]} looks misconfigured" if host
                 else "no idea")
        return {"choices": [{"message": {"role": "assistant",
                                         "content": reply}}],
                "usage": {"prompt_tokens": 20,
                          "completion_tokens": 5}}


def gateway(tmp_path, monkeypatch):
    echo = Echo()
    monkeypatch.setattr(server.backends, "call", echo.call)
    monkeypatch.setattr(server.backends, "probe", lambda be, **k: True)
    pol = policy.load(write(tmp_path, GOOD))
    log = audit.Log(tmp_path / "calls.jsonl")
    mpath = tmp_path / "halberd.mapping.json"
    mpath.write_text(json.dumps(ASSIGNED))
    smap = scrubmap.load(mpath)
    return server.Gateway(pol, log, scrubmap=smap), echo, log, smap


def chat(text):
    return json.dumps({"model": "m", "messages": [
        {"role": "user", "content": text}]}).encode()


def test_internal_material_goes_hosted_redacted(tmp_path, monkeypatch):
    gw, echo, log, _ = gateway(tmp_path, monkeypatch)
    status, out = gw.handle("/v1/chat/completions",
                            chat("why is web-01 timing out"))
    assert status == 200
    backend, sent = echo.seen[0]
    assert backend == "hosted"
    assert "web-01" not in sent
    assert "CLIENT-HOST-23" in sent


def test_the_answer_comes_back_in_my_vocabulary(tmp_path, monkeypatch):
    gw, _, _, _ = gateway(tmp_path, monkeypatch)
    _, out = gw.handle("/v1/chat/completions",
                       chat("why is web-01 timing out"))
    said = out["choices"][0]["message"]["content"]
    assert said == "web-01 looks misconfigured"


def test_confidential_material_is_not_redacted_and_goes_local(
        tmp_path, monkeypatch):
    gw, echo, _, _ = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions", chat("10.40.1.9 is unreachable"))
    backend, sent = echo.seen[0]
    assert backend == "local"
    # Local means local: no reason to obscure anything from a model
    # running on this machine, and a redacted local answer would be
    # strictly worse.
    assert "10.40.1.9" in sent


def test_an_unassigned_host_routes_local_rather_than_minting(
        tmp_path, monkeypatch):
    # Nothing in the mapping for this host and no engagement key, so
    # airlock cannot redact it and must not invent a placeholder.
    gw, echo, _, smap = gateway(tmp_path, monkeypatch)
    before = len(smap)
    gw.handle("/v1/chat/completions", chat("sql03 is slow"))
    assert echo.seen[0][0] == "local"
    assert len(smap) == before


def test_a_credential_forces_the_call_local(tmp_path, monkeypatch):
    gw, echo, _, _ = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions",
              chat("is this token valid: Authorization: Bearer "
                   "aaaabbbbccccdddd"))
    assert echo.seen[0][0] == "local"


def test_the_placeholder_is_the_same_on_every_call(tmp_path,
                                                   monkeypatch):
    gw, echo, _, smap = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions", chat("web-01 is slow"))
    gw.handle("/v1/chat/completions", chat("web-01 again"))
    assert "CLIENT-HOST-23" in echo.seen[1][1]
    assert len(smap) == 2


def test_the_mapping_is_not_rewritten_when_nothing_was_minted(
        tmp_path, monkeypatch):
    gw, _, _, smap = gateway(tmp_path, monkeypatch)
    mpath = tmp_path / "halberd.mapping.json"
    before = mpath.read_text()
    gw.handle("/v1/chat/completions", chat("web-01 is slow"))
    assert not smap.dirty
    assert mpath.read_text() == before


def test_audit_counts_both_directions(tmp_path, monkeypatch):
    gw, _, log, _ = gateway(tmp_path, monkeypatch)
    gw.handle("/v1/chat/completions", chat("web-01 is slow"))
    rec = list(log.records())[0]
    assert rec["redactions"] == 1
    assert rec["restored"] == 1
