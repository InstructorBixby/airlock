import json

from airlock import audit


def test_record_omits_empty_fields(tmp_path):
    log = audit.Log(tmp_path / "calls.jsonl")
    log.write(audit.Record(id="aa", ts="t", tier="public",
                           decision="allow", backend="hosted"))
    line = json.loads((tmp_path / "calls.jsonl").read_text())
    assert "refusal" not in line
    assert line["v"] == audit.SCHEMA


def test_append_only(tmp_path):
    log = audit.Log(tmp_path / "calls.jsonl")
    for i in range(3):
        log.write(audit.Record(id=str(i), ts="t"))
    assert len(list(log.records())) == 3
    log2 = audit.Log(tmp_path / "calls.jsonl")
    log2.write(audit.Record(id="3", ts="t"))
    assert [r["id"] for r in log.records()] == ["0", "1", "2", "3"]


def test_digest_is_of_bytes_not_text():
    assert audit.body_digest(b"{}").startswith("sha256:")


def test_no_request_body_field_exists():
    assert "body" not in audit.Record(id="a", ts="t").to_json()
