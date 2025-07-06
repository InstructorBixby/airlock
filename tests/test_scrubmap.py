import json

import pytest

from airlock import scrubmap

MAP = {
    "version": 1,
    "engagement": "halberd",
    "entries": {
        "host": {"corp.example": "CLIENT-HOST-02",
                 "jump01.corp.example": "CLIENT-HOST-11"},
        "ip4": {"10.40.1.9": "CLIENT-IP-04"},
    },
}


def write(tmp_path, data=MAP):
    p = tmp_path / "halberd.mapping.json"
    p.write_text(json.dumps(data, indent=1))
    return p


class FakeAliaser:
    """Stands in for scrubkit's keyed aliaser."""

    def __init__(self):
        self.loaded = {}
        self.calls = []

    def load(self, assigned):
        self.loaded = dict(assigned)

    def alias(self, kind, value):
        self.calls.append((kind, value))
        return f"CLIENT-{kind.upper()}-99"


def test_reads_scrubkits_shape(tmp_path):
    m = scrubmap.load(write(tmp_path))
    assert m.engagement == "halberd"
    assert len(m) == 3
    assert m.placeholder_for("host", "corp.example") == \
        "CLIENT-HOST-02"


def test_an_unassigned_value_is_none_without_a_minter(tmp_path):
    m = scrubmap.load(write(tmp_path))
    assert m.placeholder_for("host", "new.corp.example") is None


def test_a_kind_scrubkit_does_not_have_is_an_error(tmp_path):
    m = scrubmap.load(write(tmp_path))
    with pytest.raises(scrubmap.MapError, match="span kind"):
        m.placeholder_for("hostname", "x")


def test_reverse_is_placeholder_to_value(tmp_path):
    m = scrubmap.load(write(tmp_path))
    assert m.reverse()["CLIENT-HOST-11"] == "jump01.corp.example"


def test_substitutions_are_longest_value_first(tmp_path):
    # The file is sorted, which puts corp.example first. Substituting
    # in that order would leave jump01.CLIENT-HOST-11 behind.
    m = scrubmap.load(write(tmp_path))
    values = [v for v, _p in m.substitutions()]
    assert values.index("jump01.corp.example") < \
        values.index("corp.example")


def test_assigned_is_scrubkits_own_shape(tmp_path):
    m = scrubmap.load(write(tmp_path))
    assert m.assigned()[("ip4", "10.40.1.9")] == "CLIENT-IP-04"


def test_a_minter_is_loaded_with_what_is_already_assigned(tmp_path):
    m = scrubmap.load(write(tmp_path))
    m.minter = FakeAliaser()
    m.minter.load(m.assigned())
    assert ("host", "corp.example") in m.minter.loaded


def test_minting_records_the_assignment(tmp_path):
    m = scrubmap.load(write(tmp_path))
    m.minter = FakeAliaser()
    got = m.placeholder_for("host", "new.corp.example")
    assert got == "CLIENT-HOST-99"
    assert m.minted == 1
    assert m.dirty


def test_an_existing_assignment_does_not_reach_the_minter(tmp_path):
    m = scrubmap.load(write(tmp_path))
    m.minter = FakeAliaser()
    m.placeholder_for("host", "corp.example")
    assert m.minter.calls == []


def test_round_trip_through_disk_keeps_scrubkits_layout(tmp_path):
    p = write(tmp_path)
    m = scrubmap.load(p)
    m.minter = FakeAliaser()
    m.placeholder_for("term", "Project Kestrel")
    m.save()
    doc = json.loads(p.read_text())
    assert sorted(doc) == ["engagement", "entries", "version"]
    assert doc["version"] == 1
    assert list(doc["entries"]) == sorted(doc["entries"])
    assert list(doc["entries"]["host"]) == \
        sorted(doc["entries"]["host"])
    assert scrubmap.load(p).placeholder_for(
        "term", "Project Kestrel") == "CLIENT-TERM-99"


def test_an_encrypted_mapping_is_refused_clearly(tmp_path):
    p = tmp_path / "halberd.mapping.json.enc"
    p.write_bytes(scrubmap.MAGIC + b"\x00\x10" + b"x" * 64)
    with pytest.raises(scrubmap.EncryptedMap, match="scrubkit restore"):
        scrubmap.load(p)


def test_a_future_mapping_version_is_refused(tmp_path):
    data = dict(MAP, version=2)
    with pytest.raises(scrubmap.MapError, match="version"):
        scrubmap.load(write(tmp_path, data))


def test_an_unknown_span_kind_in_the_file_is_refused(tmp_path):
    data = dict(MAP, entries={"hostname": {"a": "b"}})
    with pytest.raises(scrubmap.MapError, match="span kind"):
        scrubmap.load(write(tmp_path, data))


def test_a_missing_file_is_an_empty_mapping(tmp_path):
    m = scrubmap.load(tmp_path / "nope.mapping.json",
                      engagement="halberd")
    assert len(m) == 0
    assert m.engagement == "halberd"


def test_no_key_means_no_minter(tmp_path):
    m = scrubmap.load(write(tmp_path), key=None)
    assert m.minter is None


def test_the_engagement_key_comes_from_a_file(tmp_path):
    k = tmp_path / "engagement.key"
    k.write_bytes(b"0123456789abcdef\n")
    assert scrubmap.engagement_key(k) == b"0123456789abcdef"
    assert scrubmap.engagement_key(tmp_path / "absent") is None
