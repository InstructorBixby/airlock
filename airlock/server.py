"""An OpenAI-compatible endpoint.

Everything on this box that talks to a model already honours
`OPENAI_BASE_URL`, so being that URL is the entire adoption strategy.

Only the handlers live here. Classification, policy, routing, redaction
and the audit record are all somewhere else, and this module's job is
to make sure every request passes through all of them exactly once, in
that order, with no path that skips one.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from airlock import (audit, backends, classify, cost, redact, route,
                     tiers)


class Gateway:
    def __init__(self, policy, log, roster_detector=None, scrubmap=None):
        self.policy = policy
        self.log = log
        self.scrubmap = scrubmap
        self.extra = ([("roster", roster_detector)]
                      if roster_detector else [])

    def handle(self, path: str, raw: bytes) -> tuple[int, dict]:
        rec = audit.Record(id=audit.call_id(), ts=audit.now(),
                           path=path,
                           request_sha256=audit.body_digest(raw))

        def refuse(status, why, tier=tiers.UNDECIDED):
            rec.tier = rec.tier or tier
            rec.refusal = why
            self.log.write(rec)
            return status, _error(why, rec.id)

        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return refuse(400, "request body is not json")
        if not isinstance(body, dict):
            return refuse(400, "request body is not an object")

        cap = self.policy.max_outbound_chars
        if cap and len(raw) > cap:
            return refuse(413, f"request is {len(raw)} bytes, over the "
                               f"{cap} byte outbound limit; refusing "
                               f"rather than truncating")

        assessment = classify.classify_request(body, extra=self.extra)
        rec.tier = assessment.tier
        rec.reasons = assessment.reasons
        rec.engagements = assessment.engagements

        # Redaction is attempted before routing, because whether it
        # succeeded is an input to the routing decision rather than a
        # consequence of it.
        redaction = None
        if (assessment.findings and self.scrubmap is not None
                and assessment.tier != tiers.UNDECIDED):
            redaction = redact.apply(body, assessment.findings,
                                     self.scrubmap)

        decision = route.decide(
            self.policy, assessment,
            redaction_complete=bool(redaction and redaction.complete))
        if not decision.allowed:
            return refuse(403, decision.refusal, assessment.tier)

        be = self.policy.backend(decision.backend)
        use_redacted = (redaction is not None
                        and "redacted" in decision.route.require)
        sent = dict(redaction.body if use_redacted else body)
        sent["model"] = be.model_for(body.get("model"))
        rec.decision = "allow"
        rec.backend = be.name
        rec.model = sent["model"]
        rec.redactions = (redaction.replacements
                          if use_redacted else 0)

        try:
            out = backends.call(be, path, sent)
        except backends.BackendError as exc:
            rec.status = exc.status
            return refuse(502, f"backend failed: {exc}", rec.tier)

        restored = 0
        if use_redacted:
            out, restored = redact.reverse(out, self.scrubmap)
            if self.scrubmap.dirty:
                self.scrubmap.save()
        rec.status = 200
        rec.restored = restored
        rec.tokens = _usage(out)
        rec.cost_usd = cost.estimate(be.prices, rec.model, rec.tokens)
        self.log.write(rec)
        return 200, out


def _usage(response: dict) -> dict:
    u = response.get("usage") or {}
    return {k: v for k, v in (
        ("prompt", u.get("prompt_tokens")),
        ("completion", u.get("completion_tokens")),
    ) if v is not None}


def _error(message: str, call: str) -> dict:
    return {"error": {"message": f"airlock: {message}",
                      "type": "airlock_policy",
                      "code": call}}


def make_handler(gw: Gateway):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "airlock"
        sys_version = ""

        def _send(self, status: int, obj: dict) -> None:
            payload = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n)
            status, obj = gw.handle(self.path, raw)
            self._send(status, obj)

        def do_GET(self):
            if self.path.rstrip("/").endswith("/models"):
                self._send(200, {"object": "list", "data": [
                    {"id": name, "object": "model",
                     "owned_by": "airlock"}
                    for name in sorted(gw.policy.backends)]})
                return
            self._send(404, _error("no such path", ""))

        def log_message(self, *a):
            pass

    return Handler


def serve(gw: Gateway, host: str = "127.0.0.1", port: int = 8111):
    return ThreadingHTTPServer((host, port), make_handler(gw))
