"""Classify the outbound request, then decide whether to forward it.

Every path out of `assess` that is not a confident `public` has to end
in a refusal. A missing roster file is not a quiet default to
unrestricted -- it is the classifier telling you it has no idea what
this engagement is, and that is the most restrictive answer there is.
"""
import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import classify
import roster

UPSTREAM = "https://api.openai.com"
LOG = "calls.jsonl"
ROSTER = []


class Undecided(Exception):
    """The classifier could not reach a confident answer."""


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
                elif isinstance(piece, dict):
                    # an image, audio, a part shape I have not taught
                    # this thing to read yet
                    raise Undecided("unreadable content part: "
                                    + str(sorted(piece))[:60])
    if isinstance(body.get("prompt"), str):
        parts.append(body["prompt"])
    if not parts and body.get("messages") is not None:
        raise Undecided("no readable text in messages")
    return "\n".join(parts)


def assess(text):
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

    def refuse(self, entry, why):
        entry["decision"] = "refused"
        entry["why"] = why
        record(entry)
        self.reply(403, {"error": {
            "message": "airlock: refused -- " + why,
            "type": "airlock_policy"}})

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(n)
        entry = {"ts": time.time(), "path": self.path}
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            self.reply(400, {"error": {"message": "airlock: body is "
                                                  "not json"}})
            return

        try:
            text = outbound_text(body)
            tier, reasons = assess(text)
        except Undecided as exc:
            entry["tier"] = "undecided"
            self.refuse(entry, "cannot classify: " + str(exc))
            return
        except Exception as exc:                     # noqa: BLE001
            # A classifier that crashes must not become a classifier
            # that approves.
            entry["tier"] = "error"
            self.refuse(entry, "classifier error: "
                               + type(exc).__name__)
            return

        entry["tier"] = tier
        entry["reasons"] = reasons
        if tier != classify.PUBLIC:
            self.refuse(entry, "classified " + tier + " ("
                               + ", ".join(reasons) + ")")
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
    if not os.path.exists(args.roster):
        print("airlock: no roster at " + args.roster
              + ", refusing to start", file=sys.stderr)
        return 2
    ROSTER = roster.load(args.roster)
    ThreadingHTTPServer(("127.0.0.1", args.port),
                        Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
