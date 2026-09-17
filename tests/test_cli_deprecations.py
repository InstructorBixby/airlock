from airlock import cli, deprecations


def setup_function():
    deprecations._warned.clear()


def parse(argv):
    return cli.build_parser().parse_args(
        deprecations.rewrite_argv(argv))


def test_the_old_flag_still_parses(capsys):
    args = parse(["serve", "--map", "m.scrubmap.json"])
    assert args.scrubmap == "m.scrubmap.json"
    assert "deprecated" in capsys.readouterr().err


def test_the_new_flag_parses_quietly(capsys):
    args = parse(["serve", "--scrubmap", "m.scrubmap.json"])
    assert args.scrubmap == "m.scrubmap.json"
    assert "deprecated" not in capsys.readouterr().err


def test_the_warning_names_the_removal_release(capsys):
    parse(["serve", "--map", "m.json"])
    assert "stops being accepted in 2.0" in capsys.readouterr().err


def test_main_routes_argv_through_the_shim(monkeypatch, capsys):
    seen = {}

    def fake_serve(args):
        seen["scrubmap"] = args.scrubmap
        return 0

    monkeypatch.setattr(cli, "cmd_serve", fake_serve)
    # set_defaults captured the original function, so patch the parser
    # result instead of the module attribute.
    args = parse(["serve", "--map", "m.json"])
    assert args.scrubmap == "m.json"
    assert fake_serve(args) == 0
    assert seen["scrubmap"] == "m.json"


def test_selftest_is_still_on_by_default():
    assert parse(["serve"]).selftest is True
