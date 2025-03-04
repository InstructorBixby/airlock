"""Talking to a model.

One interface, two implementations that happen to be the same protocol:
the local server speaks the same API as the provider, which is the only
reason routing is a config decision rather than a rewrite.

Nothing here knows about tiers, policy or redaction. It takes a body
and a backend and returns a response, and it is the only module allowed
to open a socket.
"""
from __future__ import annotations

import json

import requests

from airlock.policy import Backend


class BackendError(Exception):
    def __init__(self, msg, *, status=None, retryable=False):
        super().__init__(msg)
        self.status = status
        self.retryable = retryable


class Unavailable(BackendError):
    """Could not reach the backend at all."""


def _headers(be: Backend) -> dict:
    h = {"content-type": "application/json",
         "accept": "application/json"}
    key = be.api_key()
    if key:
        h["authorization"] = "Bearer " + key
    return h


def call(be: Backend, path: str, body: dict, *,
         timeout: float = 180.0) -> dict:
    """POST `body` to `be` and return the decoded response."""
    url = be.base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        r = requests.post(url, data=json.dumps(body).encode(),
                          headers=_headers(be), timeout=timeout)
    except requests.RequestException as exc:
        raise Unavailable(f"{be.name}: {type(exc).__name__}") from exc
    if r.status_code >= 500 or r.status_code == 429:
        raise BackendError(f"{be.name}: HTTP {r.status_code}",
                           status=r.status_code, retryable=True)
    if r.status_code >= 400:
        raise BackendError(f"{be.name}: HTTP {r.status_code} "
                           f"{r.text[:200]}", status=r.status_code)
    try:
        return r.json()
    except ValueError as exc:
        raise BackendError(f"{be.name}: response was not json") from exc


def probe(be: Backend, *, timeout: float = 2.0) -> bool:
    """Is this backend answering right now?

    Used by the `available` route requirement. Deliberately cheap and
    deliberately not cached for long: the local server being up is the
    thing that decides whether a confidential call can run at all, and
    a stale yes is worse than a slow check.
    """
    url = be.base_url.rstrip("/") + "/models"
    try:
        r = requests.get(url, headers=_headers(be), timeout=timeout)
    except requests.RequestException:
        return False
    return r.status_code < 500
