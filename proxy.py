"""Classify the outbound request, then decide whether to forward it."""
import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import classify
import roster

UPSTREAM = "https://api.openai.com"
LOG = "calls.jsonl"
ROSTER = []


def outbound_text(body):
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


def assess(text):
    """(tier, reasons). Reasons never contain the matched text."""
    reasons = [kind for kind, _ in classify.findings(text)]
    tier = classify.tier(text)
    for eng in ROSTER:
        hits = eng.hits(text)
        if hits:
            tier = classify.CONFIDENTIAL
            reasons += [eng.id + ":" + h for h in hits]
    return tier, sorted(set(reasons))


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

        tier, reasons = assess(outbound_text(body))
        entry = {"ts": time.time(), "path": self.path, "tier": tier,
                 "reasons": reasons}

        if tier == classify.CONFIDENTIAL:
            entry["decision"] = "refused"
            record(entry)
            self.reply(403, {"error": {
                "message": "airlock: refused, classified " + tier
                           + " (" + ", ".join(reasons) + ")",
                "type": "airlock_policy"}})
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
    ap.add_argument("--roster", default="roster.yaml")
    args = ap.parse_args()
    global ROSTER
    if os.path.exists(args.roster):
        ROSTER = roster.load(args.roster)
    ThreadingHTTPServer(("127.0.0.1", args.port),
                        Handler).serve_forever()


if __name__ == "__main__":
    main()
