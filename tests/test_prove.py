from airlock import prove

LOCAL = ("local",)


def rec(**kw):
    base = {"v": 3, "id": "a1", "ts": "t", "decision": "allow",
            "backend": "local", "engagements": ["halberd"],
            "tier": "client-confidential"}
    base.update(kw)
    return base


def test_all_local_is_clean():
    p = prove.prove([rec(), rec()], "halberd", local_backends=LOCAL)
    assert p.verdict == prove.CLEAN
    assert p.local == 2


def test_a_hosted_call_with_no_redaction_is_an_exposure():
    p = prove.prove([rec(backend="hosted", tier="internal")],
                    "halberd", local_backends=LOCAL)
    assert p.verdict == prove.EXPOSED
    assert len(p.exposures) == 1


def test_a_redacted_hosted_call_is_not_an_exposure():
    p = prove.prove([rec(backend="hosted", tier="internal",
                         redactions=3)],
                    "halberd", local_backends=LOCAL)
    assert p.verdict == prove.CLEAN
    assert p.redacted == 1


def test_undecided_refusals_become_a_caveat():
    p = prove.prove([rec(decision="refuse", tier="undecided")],
                    "halberd", local_backends=LOCAL)
    assert p.verdict == prove.PARTIAL
    assert "undecided" in p.caveats[0]


def test_old_records_become_a_caveat():
    p = prove.prove([rec(v=1)], "halberd", local_backends=LOCAL)
    assert p.verdict == prove.PARTIAL


def test_other_engagements_are_ignored():
    p = prove.prove([rec(engagements=["vantage"])], "halberd",
                    local_backends=LOCAL)
    assert p.total == 0


def test_exposure_line_has_no_matched_values():
    p = prove.prove([rec(backend="hosted",
                         reasons=["roster.client-domain"])],
                    "halberd", local_backends=LOCAL)
    assert "roster.client-domain" in p.exposures[0]


def test_text_names_the_verdict():
    p = prove.prove([rec()], "halberd", local_backends=LOCAL)
    assert "verdict: clean" in p.text()
