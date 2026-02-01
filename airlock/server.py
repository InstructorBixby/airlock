"""An OpenAI-compatible endpoint.

Everything on this box that talks to a model already honours
`OPENAI_BASE_URL`, so being that URL is the entire adoption strategy.

Only the handlers live here. Classification, policy, routing, redaction,
spend and the audit record are all somewhere else, and this module's
job is to make sure every request passes through all of them exactly
once, in that order, with no path that skips one -- including the
streaming path, which shares `prepare` and differs only after it.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from airlock import (audit, backends, classify, cost, redact, response,
                     route, spend, streaming, tiers)
from airlock.unredact import Reverser


class Refused(Exception):
    def __init__(self, status, why, call=""):
        super().__init__(why)
        self.status = status
        self.why = why
        self.call = call


class Prepared:
    """The outcome of the decision, shared by both response paths."""

    def __init__(self, rec, backend, payload, reverser):
        self.rec = rec
        self.backend = backend
        #: dict when the body was edited, bytes when it was not
        self.payload = payload
        self.reverser = reverser


class Gateway:
    def __init__(self, policy, log, detectors=(), scrubmap=None,
                 engagement=None):
        self.policy = policy
        self.log = log
        self.detectors = list(detectors)
        self.scrubmap = scrubmap
        self.engagement = engagement

    @property
    def deny_hosted(self) -> bool:
        return bool(self.engagement and self.engagement.deny_hosted)

    @property
    def ceiling(self) -> float | None:
        if self.engagement is not None \
                and self.engagement.max_cost_usd is not None:
            return self.engagement.max_cost_usd
        return self.policy.max_cost_usd

    def spent(self) -> float:
        eng = self.engagement.id if self.engagement else None
        return spend.totals(self.log.records(), engagement=eng).usd

    # -- the shared decision ---------------------------------------
    def prepare(self, path: str, raw: bytes) -> Prepared:
        rec = audit.Record(id=audit.call_id(), ts=audit.now(),
                           path=path,
                           request_sha256=audit.body_digest(raw),
                           policy_sha256=self.policy.digest)
        if self.engagement is not None:
            rec.engagements = [self.engagement.id]

        def refuse(status, why, tier=tiers.UNDECIDED):
            rec.tier = rec.tier or tier
            rec.refusal = why
            self.log.write(rec)
            raise Refused(status, why, rec.id)

        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            refuse(400, "request body is not json")
        if not isinstance(body, dict):
            refuse(400, "request body is not an object")

        cap = self.policy.max_outbound_chars
        if cap and len(raw) > cap:
            refuse(413, f"request is {len(raw)} bytes, over the {cap} "
                        f"byte outbound limit; refusing rather than "
                        f"truncating")

        assessment = classify.classify_request(body,
                                               extra=self.detectors)
        rec.tier = assessment.tier
        rec.reasons = assessment.reasons
        rec.engagements = sorted(set(rec.engagements)
                                 | set(assessment.engagements))

        redaction = None
        if (assessment.findings and self.scrubmap is not None
                and assessment.tier != tiers.UNDECIDED):
            redaction = redact.apply(body, assessment.findings,
                                     self.scrubmap)

        decision = route.decide(
            self.policy, assessment,
            redaction_complete=bool(redaction and redaction.complete),
            deny_hosted=self.deny_hosted)
        rec.considered = [c.line() for c in decision.considered]
        if not decision.allowed:
            refuse(403, decision.refusal, assessment.tier)

        be = self.policy.backend(decision.backend)
        # A ceiling only constrains a backend that charges. The local
        # model is not free in any real sense, but it is not spend.
        if be.prices and self.ceiling is not None:
            already = self.spent()
            if spend.would_exceed(already, self.ceiling):
                refuse(402, f"engagement spend ${already:.2f} has "
                            f"reached the ${self.ceiling:.2f} ceiling",
                       assessment.tier)

        use_redacted = (redaction is not None
                        and "redacted" in decision.route.require)
        rec.decision = "allow"
        rec.backend = be.name
        rec.redactions = redaction.replacements if use_redacted else 0

        model = be.model_for(body.get("model"))
        rec.model = model
        if use_redacted:
            payload = dict(redaction.body)
            payload["model"] = model
            rec.reserialised = True
        elif be.preserve_model or model == body.get("model"):
            payload = raw
        else:
            payload = dict(body)
            payload["model"] = model
            rec.reserialised = True

        reverser = (Reverser(self.scrubmap.reverse())
                    if use_redacted else None)
        return Prepared(rec, be, payload, reverser)

    def finish(self, rec, be, usage, restored, response_tier=None):
        rec.status = 200
        rec.restored = restored
        rec.tokens = usage
        rec.cost_usd = cost.estimate(be.prices, rec.model, rec.tokens)
        rec.response_tier = response_tier or ""
        if self.scrubmap is not None and self.scrubmap.dirty:
            self.scrubmap.save()
        self.log.write(rec)

    # -- buffered --------------------------------------------------
    def handle(self, path: str, raw: bytes):
        """(status, body, headers)."""
        try:
            prep = self.prepare(path, raw)
        except Refused as exc:
            return exc.status, _error(exc.why, exc.call), {}
        rec, be = prep.rec, prep.backend
        try:
            out = backends.call(be, path, prep.payload,
                                timeout=be.timeout)
        except backends.BackendError as exc:
            rec.status = exc.status
            rec.refusal = str(exc)
            self.log.write(rec)
            return 502, _error(f"backend failed: {exc}", rec.id), {}
        restored = 0
        if prep.reverser is not None:
            out, restored = redact.reverse(out, self.scrubmap)
        tier = response.assess(out, detectors=self.detectors)
        self.finish(rec, be, _usage(out), restored, tier)
        return 200, out, {response.HEADER: tier}

    # -- streamed --------------------------------------------------
    def handle_stream(self, path: str, raw: bytes):
        prep = self.prepare(path, raw)
        info = {"usage": {}, "restored": 0}
        for payload, info in streaming.relay(prep.backend, path,
                                             prep.payload,
                                             reverser=prep.reverser):
            yield payload
        self.finish(prep.rec, prep.backend,
                    _usage({"usage": info["usage"]}),
                    info.get("restored", 0))


def _usage(response_body: dict) -> dict:
    u = response_body.get("usage") or {}
    return {k: v for k, v in (
        ("prompt", u.get("prompt_tokens")),
        ("completion", u.get("completion_tokens")),
    ) if v is not None}


def _error(message: str, call: str) -> dict:
    out = {"error": {"message": f"airlock: {message}",
                     "type": "airlock_policy"}}
    if call:
        out["error"]["code"] = call
    return out


def make_handler(gw: Gateway):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "airlock"
        sys_version = ""

        def _send(self, status, obj, extra=None):
            payload = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n)
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {}
            if streaming.wants_stream(body if isinstance(body, dict)
                                      else {}):
                self._stream(raw)
                return
            status, obj, extra = gw.handle(self.path, raw)
            self._send(status, obj, extra)

        def _stream(self, raw: bytes) -> None:
            try:
                chunks = gw.handle_stream(self.path, raw)
                first = next(chunks, b"")
            except Refused as exc:
                self._send(exc.status, _error(exc.why, exc.call))
                return
            except backends.BackendError as exc:
                self._send(502, _error(f"backend failed: {exc}", ""))
                return
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-store")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            self._chunk(first)
            for payload in chunks:
                self._chunk(payload)
            self.wfile.write(b"0\r\n\r\n")

        def _chunk(self, payload: bytes) -> None:
            if not payload:
                return
            self.wfile.write(f"{len(payload):x}\r\n".encode())
            self.wfile.write(payload)
            self.wfile.write(b"\r\n")
            self.wfile.flush()

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
