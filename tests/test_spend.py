from airlock import spend

RECORDS = [
    {"decision": "allow", "cost_usd": 0.01, "engagements": ["halberd"]},
    {"decision": "allow", "cost_usd": 0.02, "engagements": ["halberd"]},
    {"decision": "allow", "cost_usd": 0.05, "engagements": ["vantage"]},
    {"decision": "refuse", "cost_usd": 9.99, "engagements": ["halberd"]},
    {"decision": "allow", "engagements": ["halberd"]},
]


def test_refused_calls_cost_nothing():
    assert spend.totals(RECORDS).usd == 0.08


def test_per_engagement():
    t = spend.totals(RECORDS)
    assert t.by_engagement["halberd"]["usd"] == 0.03
    assert t.by_engagement["halberd"]["calls"] == 3


def test_filtering_by_engagement():
    assert spend.totals(RECORDS, engagement="vantage").usd == 0.05


def test_unpriced_calls_are_counted_separately():
    assert spend.totals(RECORDS).unpriced == 1


def test_would_exceed_is_before_not_after():
    assert spend.would_exceed(24.0, 25.0, estimate=2.0)
    assert not spend.would_exceed(24.0, 25.0, estimate=0.5)


def test_no_ceiling_never_exceeds():
    assert not spend.would_exceed(1e9, None, estimate=1e9)


def test_report_mentions_the_unpriced_calls():
    assert "no declared price" in spend.report(spend.totals(RECORDS))
