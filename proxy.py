"""Classify the outbound request, then decide whether to forward it.

No routing yet: confidential means refused, and refused means a 403
with a readable reason, because an unexplained failure in the middle of
a pipeline is how a gateway gets routed around.
"""
import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import classify

UPSTREAM = "https://api.openai.com"
LOG = "calls.jsonl"


def outbound_text(body):
    """Everything in a request that will be read by a model."""
    parts = []
    for msg in body.get("messages") or []:
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for piece in content:
                if isinstance(piece, dict) and piece.get("text"):
                    parts.append(piece["text"])
    if isinstance(body.get("prompt"), str):
        parts.append(body["prompt"])
    return "\n".join(parts)


def record(entry):
    with open(LOG, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, obj):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            self.reply(400, {"error": {"message": "airlock: body is "
                                                  "not json"}})
            return

        text = outbound_text(body)
        found = classify.findings(text)
        tier = classify.tier(text)
        entry = {"ts": time.time(), "path": self.path, "tier": tier,
                 "findings": [{"kind": k, "match": v}
                              for k, v in found]}

        if tier == classify.CONFIDENTIAL:
            entry["decision"] = "refused"
            record(entry)
            self.reply(403, {"error": {
                "message": "airlock: refused, classified "
                           + tier + " (" + ", ".join(
                               sorted({k for k, _ in found})) + ")",
                "type": "airlock_policy",
            }})
            return

        r = requests.post(
            UPSTREAM + self.path, data=raw,
            headers={"content-type": "application/json",
                     "authorization": "Bearer " + os.environ.get(
                         "OPENAI_API_KEY", "")},
            timeout=180)
        entry["decision"] = "forwarded"
        entry["status"] = r.status_code
        record(entry)

        payload = r.content
        self.send_response(r.status_code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8111)
    args = ap.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port),
                        Handler).serve_forever()


if __name__ == "__main__":
    main()
