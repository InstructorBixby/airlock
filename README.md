# airlock

A local OpenAI-compatible endpoint that sits in front of every model
call I make, decides whether that call is allowed to leave the machine,
and writes down what it decided.

The constraint it exists for: client material does not go to a hosted
provider. Not "should not" -- the engagement letter says it does not,
and I would rather have one boring gate than a habit of being careful.

The trick that makes it usable is that it speaks the API every tool I
already own speaks, so nothing has to be rewritten:

    export OPENAI_BASE_URL=http://127.0.0.1:8111/v1

Right now it forwards everything and makes no decisions, which makes it
worse than useless -- it is a false sense of one. Classification next.
