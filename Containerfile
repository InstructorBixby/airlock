# A container is a convenience, not a security boundary, and it
# changes one thing about the threat model that matters: the local
# backend is no longer on the same loopback as the gateway. Read
# docs/container.md again before running this anywhere real.

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY airlock ./airlock
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
LABEL org.opencontainers.image.title="airlock"
LABEL org.opencontainers.image.description="Policy gateway for model calls"
LABEL org.opencontainers.image.source="http://git.c01n31.net/c01n31pan1c/airlock"
LABEL org.opencontainers.image.licenses="MIT"

RUN useradd --create-home --shell /usr/sbin/nologin airlock
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER airlock
WORKDIR /home/airlock

# Loopback only. Binding 0.0.0.0 is a deliberate act and the threat
# model does not cover it, so it is not the default here either.
ENV AIRLOCK_HOST=127.0.0.1
EXPOSE 8111

# The selftest runs on every start. A container that comes up without
# proving its policy fails closed is not worth shipping.
ENTRYPOINT ["airlock"]
CMD ["serve", "--host", "127.0.0.1", "--port", "8111"]
