# Running it in a container

Built here, kept here, pushed nowhere. There is one reason this exists
-- the box with the GPU is not the box I type on -- and one reason to
be careful about it, which is the rest of this page.

    podman build -t airlock:1 -f Containerfile .

## what containerising changes

The policy loader's only structural check is that a
`client-confidential` route points at a `base_url` on this machine. In
a container, "this machine" is the container's network namespace, and
`127.0.0.1:8080` inside it is not the local model on the host -- it is
nothing, or worse, something else in the same namespace.

So the check still passes and no longer means what it meant. There is
no way for the gateway to tell the difference from the inside, which is
why this is a page and not a clever heuristic. It is the one place
where the invariant this whole thing is built on can be true and
useless at the same time.

Gateway in a container, local model on the host: three honest options.

1. Run both in the same network namespace (`--network container:...`
   or a pod), so loopback means what the policy thinks it means.
2. Run the gateway on the host and leave the container out of the path.
3. Accept that the local route is a network route, and treat the link
   to it accordingly -- which, for client-confidential material, is
   most of what the gateway was supposed to remove.

One is what I do. Three is what I would drift into if this page did
not exist.

## running it

    podman run --rm -it \
      --network container:llama \
      -v ./policy.yaml:/home/airlock/policy.yaml:ro \
      -v ./roster.yaml:/home/airlock/roster.yaml:ro \
      -v airlock-state:/home/airlock/.local/state \
      airlock:1 \
      serve --policy /home/airlock/policy.yaml

The audit log has to be on a volume. A log that disappears with the
container answers no questions, and answering questions afterwards is
the entire point of having it.

## which image is this

No signature and nothing to verify against: the image came off this
machine and never left it. What matters instead is that the image is
the code I tested, so the build is a CI job rather than something I do
by hand at the end of a long day, and the selftest runs on every start
-- a container that comes up without proving its policy fails closed
is a container I should not be pasting into.
