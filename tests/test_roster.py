import textwrap

import roster


def write(tmp_path, body):
    p = tmp_path / "roster.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


ROSTER = """\
engagements:
  - id: halberd
    client: Halberd Industrial
    aliases: [halberd, HBRD]
    domains: [halberd-industrial.example]
    nets: [10.40.0.0/14]
"""


def test_alias_match(tmp_path):
    eng = roster.load(write(tmp_path, ROSTER))[0]
    assert eng.hits("the Halberd kickoff call") == ["client-name"]


def test_alias_is_word_bounded(tmp_path):
    eng = roster.load(write(tmp_path, ROSTER))[0]
    assert eng.hits("halberdier") == []


def test_domain_match_covers_subdomains(tmp_path):
    eng = roster.load(write(tmp_path, ROSTER))[0]
    assert "client-domain" in eng.hits("vpn.halberd-industrial.example")


def test_net_match_is_containment_not_text(tmp_path):
    eng = roster.load(write(tmp_path, ROSTER))[0]
    assert eng.hits("10.41.200.9") == ["client-net"]
    assert eng.hits("10.44.0.1") == []


def test_hits_never_return_the_matched_value(tmp_path):
    eng = roster.load(write(tmp_path, ROSTER))[0]
    for h in eng.hits("Halberd at 10.40.1.1"):
        assert "10.40" not in h
