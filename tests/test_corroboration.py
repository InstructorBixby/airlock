from airlock import classify, tiers
from airlock.detect import roster

ROSTER = """\
engagements:
  - id: vantage-retest
    client: Vantage Mutual
    aliases: [vantage-mutual]
    weak_aliases: [vantage]
    domains: [vantagemutual.example]
    nets: [10.9.0.0/16]
"""


def detector(tmp_path):
    p = tmp_path / "roster.yaml"
    p.write_text(ROSTER)
    return [("roster", roster.detector(roster.load(p)))]


def test_weak_alias_alone_is_internal(tmp_path):
    a = classify.classify_text(
        "what is the attacker's vantage here", extra=detector(tmp_path))
    assert a.tier == tiers.INTERNAL
    assert a.corroborated == []


def test_weak_alias_with_a_domain_is_confidential(tmp_path):
    a = classify.classify_text(
        "vantage portal at app.vantagemutual.example",
        extra=detector(tmp_path))
    assert a.tier == tiers.CONFIDENTIAL
    assert "corroborated by" in a.corroborated[0]


def test_weak_alias_with_a_private_address_is_confidential(tmp_path):
    a = classify.classify_text("vantage box at 10.9.1.1",
                               extra=detector(tmp_path))
    assert a.tier == tiers.CONFIDENTIAL


def test_corroboration_line_is_readable(tmp_path):
    a = classify.classify_text("vantage at 10.9.1.1",
                               extra=detector(tmp_path))
    assert a.corroborated[0].startswith(
        "vantage-retest:roster.weak-name (corroborated by")


def test_strong_alias_needs_no_corroboration(tmp_path):
    a = classify.classify_text("vantage-mutual sent the scope",
                               extra=detector(tmp_path))
    assert a.tier == tiers.CONFIDENTIAL
    assert a.corroborated == []


def test_two_weak_hits_are_not_corroboration(tmp_path):
    a = classify.classify_text("vantage and vantage again",
                               extra=detector(tmp_path))
    assert a.tier == tiers.INTERNAL


def test_alias_in_both_lists_is_a_config_error(tmp_path):
    import pytest
    p = tmp_path / "r.yaml"
    p.write_text("engagements:\n  - id: x\n"
                 "    aliases: [foo]\n    weak_aliases: [FOO]\n")
    with pytest.raises(roster.RosterError, match="both strong and weak"):
        roster.load(p)
