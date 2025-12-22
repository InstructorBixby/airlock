from airlock import response, tiers


def answer(text):
    return {"choices": [{"message": {"role": "assistant",
                                     "content": text}}]}


def test_public_answer():
    assert response.assess(answer("RFC 5280 says so")) == tiers.PUBLIC


def test_answer_about_a_private_host():
    assert response.assess(answer("10.40.1.9 is filtering it")) == \
        tiers.CONFIDENTIAL


def test_tool_call_arguments_in_the_answer_count():
    resp = {"choices": [{"message": {"tool_calls": [
        {"function": {"name": "f",
                      "arguments": '{"host": "dc-01.hq.corp"}'}}]}}]}
    assert response.assess(resp) == tiers.CONFIDENTIAL


def test_empty_answer_is_public_not_undecided():
    assert response.assess({"choices": []}) == tiers.PUBLIC


def test_embeddings_shaped_response():
    resp = {"data": [{"text": "sql03.hq.corp", "embedding": [0.1]}]}
    assert response.assess(resp) == tiers.CONFIDENTIAL
