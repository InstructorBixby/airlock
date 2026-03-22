from airlock import doctor


def results(env, tmp_path):
    return doctor.checks(env=env, home=tmp_path)


def ok_for(results_, name):
    return [ok for ok, n, _ in results_ if n == name]


def test_pointing_at_the_gateway_is_ok(tmp_path):
    r = results({"OPENAI_BASE_URL": "http://127.0.0.1:8111/v1",
                 "OPENAI_API_KEY": "x"}, tmp_path)
    assert ok_for(r, "OPENAI_BASE_URL") == [True]


def test_unset_base_url_is_flagged(tmp_path):
    r = results({"OPENAI_API_KEY": "x"}, tmp_path)
    assert ok_for(r, "OPENAI_BASE_URL") == [False]


def test_pointing_at_a_provider_is_flagged(tmp_path):
    r = results({"OPENAI_BASE_URL": "https://api.openai.com/v1",
                 "OPENAI_API_KEY": "x"}, tmp_path)
    assert ok_for(r, "OPENAI_BASE_URL") == [False]


def test_the_older_variable_is_flagged_even_when_the_new_one_is_right(
        tmp_path):
    r = results({"OPENAI_BASE_URL": "http://127.0.0.1:8111/v1",
                 "OPENAI_API_BASE": "https://api.openai.com/v1",
                 "OPENAI_API_KEY": "x"}, tmp_path)
    assert ok_for(r, "OPENAI_API_BASE") == [False]


def test_a_tool_config_file_is_mentioned(tmp_path):
    p = tmp_path / ".aider.conf.yml"
    p.write_text("model: gpt-4o-mini\n")
    r = results({"OPENAI_BASE_URL": "http://127.0.0.1:8111/v1",
                 "OPENAI_API_KEY": "x"}, tmp_path)
    assert any(str(p) == name for _, name, _ in r)


def test_report_points_at_egress_ledger(tmp_path):
    text = doctor.report(results({}, tmp_path))
    assert "egress-ledger" in text
