import base64
import gzip

from airlock import classify, redact, tiers


def b64(text):
    return base64.b64encode(text.encode()).decode()


def test_hostname_inside_base64_is_found():
    blob = b64("Host: dc-01.hq.corp\nCookie: " + "a" * 40)
    a = classify.classify_text("what is this parameter: " + blob)
    assert any(r.startswith("net.internal-hostname@base64")
               for r in a.reasons)
    assert a.tier == tiers.CONFIDENTIAL


def test_two_layers():
    inner = b64("ping 10.40.1.9 and pad this out a bit more")
    blob = b64(inner)
    a = classify.classify_text(blob)
    assert any("@base64@base64" in r for r in a.reasons)


def test_gzipped_then_base64():
    raw = gzip.compress(b"GET / HTTP/1.1\r\nHost: sql03.hq.corp\r\n")
    blob = base64.b64encode(raw).decode()
    a = classify.classify_text(blob)
    assert any("+gzip" in r for r in a.reasons)


def test_hex_payloads_too():
    blob = b"Host: exch-02.hq.corp padding padding".hex()
    a = classify.classify_text(blob)
    assert any("@hex" in r for r in a.reasons)


def test_binary_payload_is_ignored():
    blob = base64.b64encode(bytes(range(256)) * 2).decode()
    a = classify.classify_text(blob)
    assert a.tier == tiers.PUBLIC


def test_ordinary_prose_decodes_to_nothing_interesting():
    a = classify.classify_text(
        "the response header was unusually long but readable")
    assert a.tier == tiers.PUBLIC


def test_encoded_findings_are_not_redactable():
    blob = b64("Host: dc-01.hq.corp" + " padding" * 5)
    a = classify.classify_text(blob)
    kinds = {f.kind for f in a.findings}
    assert all(not redact.is_redactable(k) for k in kinds
               if "@" in k)


def test_budget_stops_runaway_decoding():
    from airlock.detect import encoded
    blob = b64("a" * 4096)
    found = list(encoded.layers(blob * 40, budget=4096))
    assert len(found) < 40
