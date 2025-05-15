from airlock.cost import Price, estimate


def test_per_million():
    p = Price(prompt=0.15, completion=0.6)
    assert p.of(1_000_000, 0) == 0.15
    assert p.of(0, 500_000) == 0.3


def test_unpriced_model_is_none_not_zero():
    assert estimate({}, "whatever", {"prompt": 10}) is None


def test_default_price_is_used():
    prices = {"default": Price(prompt=1.0)}
    assert estimate(prices, "unknown", {"prompt": 1_000_000}) == 1.0


def test_local_model_priced_at_zero_is_explicit():
    prices = {"qwen2.5-14b-instruct": Price()}
    assert estimate(prices, "qwen2.5-14b-instruct",
                    {"prompt": 9_000_000}) == 0.0
