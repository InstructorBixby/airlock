from airlock import policy, route, tiers
from airlock.model import Assessment
from tests.test_policy import write

POL = """\
version: 1
routes:
  public:
    - backend: hosted
      require: [available]
    - backend: local
  internal:
    - backend: local
  client-confidential:
    - backend: local
  undecided: []
backends:
  hosted:
    kind: openai
    base_url: https://api.example/v1
    models: {default: m}
  local:
    kind: openai
    base_url: http://127.0.0.1:8080/v1
    models: {default: n}
"""


def test_falls_back_when_hosted_is_down(tmp_path, monkeypatch):
    route.forget_probes()
    monkeypatch.setattr(route.backends, "probe", lambda be, **k: False)
    pol = policy.load(write(tmp_path, POL))
    d = route.decide(pol, Assessment())
    assert d.backend == "local"
    assert "not answering" in d.considered[0].why


def test_uses_hosted_when_it_is_up(tmp_path, monkeypatch):
    route.forget_probes()
    monkeypatch.setattr(route.backends, "probe", lambda be, **k: True)
    pol = policy.load(write(tmp_path, POL))
    assert route.decide(pol, Assessment()).backend == "hosted"


def test_probe_is_cached_for_a_pipeline(tmp_path, monkeypatch):
    route.forget_probes()
    calls = []

    def probe(be, **k):
        calls.append(be.name)
        return True

    monkeypatch.setattr(route.backends, "probe", probe)
    pol = policy.load(write(tmp_path, POL))
    for _ in range(20):
        route.decide(pol, Assessment())
    assert len(calls) == 1


def test_cache_expires(tmp_path, monkeypatch):
    route.forget_probes()
    monkeypatch.setattr(route.backends, "probe", lambda be, **k: True)
    pol = policy.load(write(tmp_path, POL))
    be = pol.backend("hosted")
    assert route.available(be, now=0.0)
    monkeypatch.setattr(route.backends, "probe", lambda be, **k: False)
    assert route.available(be, now=1.0)
    assert not route.available(be, now=route.PROBE_TTL + 2)


def test_confidential_never_falls_back_to_hosted(tmp_path, monkeypatch):
    route.forget_probes()
    monkeypatch.setattr(route.backends, "probe", lambda be, **k: True)
    pol = policy.load(write(tmp_path, POL))
    a = Assessment()
    a.tier = tiers.CONFIDENTIAL
    assert route.decide(pol, a).backend == "local"
