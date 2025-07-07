import json

from airlock import classify, redact, scrubmap, tiers
from airlock.model import Finding

#: An engagement's mapping, as scrubkit would have written it after
#: scrubbing the evidence this request came out of.
ASSIGNED = {
    "version": 1,
    "engagement": "halberd",
    "entries": {
        "host": {"corp.example": "CLIENT-HOST-02",
                 "dc-01.hq.corp": "CLIENT-HOST-07",
                 "jump01.corp.example": "CLIENT-HOST-11",
                 "web-01": "CLIENT-HOST-23"},
        "ip4": {"10.40.1.9": "CLIENT-IP-04"},
        "term": {"Halberd Industrial": "CLIENT-TERM-05"},
    },
}


def smap(tmp_path, data=None):
    p = tmp_path / "halberd.mapping.json"
    p.write_text(json.dumps(data if data is not None else ASSIGNED))
    return scrubmap.load(p)


def body(text):
    return {"messages": [{"role": "user", "content": text}]}


def test_hostname_is_replaced_with_scrubkits_placeholder(tmp_path):
    text = "GET /admin on dc-01.hq.corp"
    a = classify.classify_text(text)
    r = redact.apply(body(text), a.findings, smap(tmp_path))
    sent = r.body["messages"][0]["content"]
    assert "dc-01.hq.corp" not in sent
    assert "CLIENT-HOST-07" in sent
    assert r.complete


def test_round_trip_restores_the_original(tmp_path):
    m = smap(tmp_path)
    text = "timeout talking to dc-01.hq.corp"
    a = classify.classify_text(text)
    redact.apply(body(text), a.findings, m)
    answer = {"choices": [{"message": {
        "content": "CLIENT-HOST-07 is probably filtering it"}}]}
    back, n = redact.reverse(answer, m)
    assert n == 1
    assert back["choices"][0]["message"]["content"] == \
        "dc-01.hq.corp is probably filtering it"


def test_a_value_with_no_assignment_is_not_redactable(tmp_path):
    # No keyed aliaser here, so airlock cannot mint one, and it must
    # not invent an index of its own.
    text = "and also sql03.hq.corp"
    a = classify.classify_text(text)
    r = redact.apply(body(text), a.findings, smap(tmp_path))
    assert not r.complete
    assert [f.value for f in r.unredactable] == ["sql03.hq.corp"]


def test_secret_is_not_redactable(tmp_path):
    text = "authorization: Bearer abcd1234efgh5678"
    a = classify.classify_text(text)
    r = redact.apply(body(text), a.findings, smap(tmp_path))
    assert not r.complete
    assert [f.kind for f in r.unredactable] == ["secrets.bearer"]


def test_a_longer_value_is_replaced_before_a_suffix_of_it(tmp_path):
    # scrubkit writes the mapping sorted, so corp.example comes first
    # in the file. Substituting in file order would leave
    # jump01.CLIENT-HOST-02 in the request.
    m = smap(tmp_path)
    findings = [Finding("net.internal-hostname", "jump01.corp.example",
                        tiers.CONFIDENTIAL),
                Finding("net.internal-hostname", "corp.example",
                        tiers.CONFIDENTIAL)]
    r = redact.apply(body("ssh to jump01.corp.example"), findings, m)
    sent = r.body["messages"][0]["content"]
    assert sent == "ssh to CLIENT-HOST-11"


def test_a_shortname_uses_the_host_family(tmp_path):
    findings = [Finding("net.internal-shortname", "web-01",
                        tiers.INTERNAL)]
    r = redact.apply(body("web-01 is slow"), findings, smap(tmp_path))
    assert "CLIENT-HOST-23" in str(r.body)


def test_a_client_name_uses_the_term_family(tmp_path):
    findings = [Finding("roster.client-name", "Halberd Industrial",
                        tiers.CONFIDENTIAL, engagement="halberd")]
    r = redact.apply(body("for Halberd Industrial"), findings,
                     smap(tmp_path))
    assert "CLIENT-TERM-05" in str(r.body)


def test_the_same_value_is_counted_but_mapped_once(tmp_path):
    text = "dc-01.hq.corp talks to dc-01.hq.corp"
    a = classify.classify_text(text)
    m = smap(tmp_path)
    before = len(m)
    r = redact.apply(body(text), a.findings, m)
    assert r.replacements == 2
    assert len(m) == before


def test_nested_structures_are_walked(tmp_path):
    b = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "ping 10.40.1.9"}]}]}
    a = classify.classify_text("ping 10.40.1.9")
    r = redact.apply(b, a.findings, smap(tmp_path))
    assert "10.40.1.9" not in str(r.body)
    assert "CLIENT-IP-04" in str(r.body)


def test_every_kind_in_the_table_is_one_scrubkit_has():
    assert set(redact.KINDS.values()) <= scrubmap.KINDS
