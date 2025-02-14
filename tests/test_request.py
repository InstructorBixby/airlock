import pytest

from airlock import request


def test_plain_messages():
    body = {"messages": [{"role": "user", "content": "hello"}]}
    assert request.texts(body) == ["hello"]


def test_multipart_text():
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}]}
    assert request.texts(body) == ["a", "b"]


def test_image_part_refuses_rather_than_skipping():
    body = {"messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:..."}}]}]}
    with pytest.raises(request.Unreadable):
        request.texts(body)


def test_tool_call_arguments_are_model_visible():
    body = {"messages": [{"role": "assistant", "tool_calls": [
        {"function": {"name": "f", "arguments": '{"host": "dc-01"}'}}]}]}
    assert "dc-01" in request.joined(body)


def test_tool_descriptions_count():
    body = {"messages": [{"role": "user", "content": "x"}],
            "tools": [{"function": {"name": "f",
                                    "description": "query sql02"}}]}
    assert "query sql02" in request.joined(body)


def test_empty_body_is_unreadable():
    with pytest.raises(request.Unreadable):
        request.texts({})
