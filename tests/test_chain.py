import json

from airlock import audit


def log(tmp_path):
    return audit.Log(tmp_path / "calls.jsonl")


def fill(lg, n=4):
    for i in range(n):
        lg.write(audit.Record(id=f"{i:02x}", ts="t", decision="allow"))


def test_intact_chain_verifies(tmp_path):
    lg = log(tmp_path)
    fill(lg)
    assert lg.verify() == []


def test_first_record_points_at_genesis(tmp_path):
    lg = log(tmp_path)
    fill(lg, 1)
    rec = list(lg.records())[0]
    assert rec["prev"] == audit.GENESIS
    assert rec["seq"] == 1


def test_a_deleted_line_is_visible(tmp_path):
    lg = log(tmp_path)
    fill(lg)
    p = tmp_path / "calls.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    breaks = audit.Log(p).verify()
    assert breaks
    assert "seq jumped" in str(breaks[-1]) or "prev is" in str(breaks[0])


def test_an_edited_field_is_visible(tmp_path):
    lg = log(tmp_path)
    fill(lg)
    p = tmp_path / "calls.jsonl"
    lines = p.read_text().splitlines()
    obj = json.loads(lines[1])
    obj["backend"] = "somewhere-else"
    lines[1] = json.dumps(obj, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    # The edited line still chains to its own predecessor; the break
    # shows up at the line after it.
    assert audit.Log(p).verify()


def test_reordering_is_visible(tmp_path):
    lg = log(tmp_path)
    fill(lg)
    p = tmp_path / "calls.jsonl"
    lines = p.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert audit.Log(p).verify()


def test_appending_continues_the_chain_after_a_restart(tmp_path):
    fill(log(tmp_path), 2)
    again = log(tmp_path)
    again.write(audit.Record(id="zz", ts="t"))
    assert again.verify() == []
    assert list(again.records())[-1]["seq"] == 3


def test_a_recorded_head_catches_truncation_from_the_end(tmp_path):
    lg = log(tmp_path)
    fill(lg)
    head = lg.head
    p = tmp_path / "calls.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-1]) + "\n")
    breaks = audit.Log(p).verify(expect_head=head)
    assert any("recorded head" in str(b) for b in breaks)


def test_verify_on_an_empty_log(tmp_path):
    assert log(tmp_path).verify() == []
