import pytest

from airlock.detect import roster

ROSTER = """\
engagements:
  - id: halberd
    client: Halberd Industrial
    aliases: [halberd, HBRD]
    domains: [halberd-industrial.example]
    nets: [10.40.0.0/14]
"""


def write(tmp_path, body=ROSTER):
    p = tmp_path / "roster.yaml"
    p.write_text(body)
    return p


def one(tmp_path, body=ROSTER):
    return roster.load(write(tmp_path, body))[0]


def kinds(findings):
    return sorted({f.kind for f in findings})


def test_alias_match(tmp_path):
    eng = one(tmp_path)
    assert kinds(eng.find("the Halberd kickoff")) == \
        ["roster.client-name"]


def test_alias_is_word_bounded(tmp_path):
    assert list(one(tmp_path).find("halberdier")) == []


def test_domain_covers_subdomains(tmp_path):
    eng = one(tmp_path)
    assert "roster.client-domain" in kinds(
        eng.find("vpn.halberd-industrial.example"))


def test_net_is_containment_not_text(tmp_path):
    eng = one(tmp_path)
    assert kinds(eng.find("10.41.200.9")) == ["roster.client-net"]
    assert list(eng.find("10.44.0.1")) == []


def test_finding_reason_names_the_engagement_not_the_value(tmp_path):
    eng = one(tmp_path)
    f = next(iter(eng.find("Halberd")))
    assert f.reason == "halberd:roster.client-name"


def test_missing_file_raises(tmp_path):
    with pytest.raises(roster.RosterError):
        roster.load(tmp_path / "nope.yaml")


def test_empty_roster_raises(tmp_path):
    with pytest.raises(roster.RosterError):
        roster.load(write(tmp_path, "engagements: []\n"))


def test_bad_net_raises(tmp_path):
    with pytest.raises(roster.RosterError):
        roster.load(write(tmp_path, "engagements:\n"
                                    "  - id: x\n"
                                    "    nets: [not-a-net]\n"))
