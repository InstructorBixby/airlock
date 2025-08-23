        import json

        import pytest

        from airlock import audit, engagement, policy, server
        from tests.test_policy import GOOD, write

        PROFILE = """\
        id: halberd
        extra_terms: ["project kestrel", "KSTRL-"]
        max_cost_usd: 25.0
        deny_hosted: true
        """

        SCOPE = """\
        hosts: [app.halberd-industrial.example]
        """


        def eng_dir(tmp_path, profile=PROFILE, scope=SCOPE):
            root = tmp_path / "engagements" / "halberd"
            root.mkdir(parents=True)
            (root / "airlock.yaml").write_text(profile)
            if scope is not None:
                (root / "scope.yaml").write_text(scope)
            return root


        def test_loads_a_profile(tmp_path):
            eng = engagement.load(eng_dir(tmp_path))
            assert eng.id == "halberd"
            assert eng.deny_hosted
            assert eng.max_cost_usd == 25.0
            assert eng.scope is not None


        def test_map_path_defaults_beside_the_engagement(tmp_path):
            eng = engagement.load(eng_dir(tmp_path))
            assert eng.map_path.name == "halberd.mapping.json"
            assert eng.map_path.parent == eng.root


        def test_the_key_path_defaults_next_to_the_engagement(tmp_path):
            eng = engagement.load(eng_dir(tmp_path))
            assert eng.key_path == eng.root / "engagement.key"


        def test_the_key_path_comes_from_scrubkits_profile(tmp_path):
            root = eng_dir(tmp_path)
            (root / "scrubkit.toml").write_text(
                '[engagement]
name = "halberd"
'
                'key_file = "keys/halberd.key"
')
            eng = engagement.load(root)
            assert eng.key_path == root / "keys" / "halberd.key"


        def test_preserve_structure_is_read_from_the_same_profile(tmp_path):
            root = eng_dir(tmp_path)
            (root / "scrubkit.toml").write_text(
                '[detect]
preserve_structure = true
')
            assert engagement.load(root).preserve_structure is True


        def test_no_scrubkit_profile_is_not_an_error(tmp_path):
            eng = engagement.load(eng_dir(tmp_path))
            assert eng.preserve_structure is False


        def test_unknown_key_is_refused(tmp_path):
            with pytest.raises(engagement.EngagementError, match="only tighten"):
                engagement.load(eng_dir(tmp_path, "routes: []\n"))


        def test_discover_finds_every_directory(tmp_path):
            eng_dir(tmp_path)
            (tmp_path / "engagements" / "other").mkdir()
            found = engagement.discover(tmp_path / "engagements")
            assert sorted(found) == ["halberd", "other"]


        def test_deny_hosted_refuses_when_the_only_route_is_hosted(
                tmp_path, monkeypatch):
            seen = []

            def call(be, path, body, timeout=180.0):
                seen.append(be.name)
                return {"usage": {}}

            monkeypatch.setattr(server.backends, "call", call)
            monkeypatch.setattr(server.backends, "probe", lambda be, **k: True)
            eng = engagement.load(eng_dir(tmp_path))
            gw = server.Gateway(policy.load(write(tmp_path, GOOD)),
                                audit.Log(tmp_path / "calls.jsonl"),
                                engagement=eng)
            body = json.dumps({"messages": [{"role": "user",
                                             "content": "what is RFC 5280"}]})
            status, _ = gw.handle("/v1/chat/completions", body.encode())
            assert status == 403
            assert seen == []
